use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::a2a_proxies::A2aProxyStore;
use crate::auth_manager::pat::PatResourceScope;
use crate::authorities::AuthorityStore;
use crate::gateways::GatewayStore;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::identity::state::IdentityApiState;
use crate::issuers::IssuerStore;
use crate::mcp_proxies::McpProxyStore;
use crate::mediators::MediatorStore;
use crate::surface_templates::filesystem::SurfaceTemplateStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, validate_tenant_id,
};
use crate::trust_registries::TrustRegistryStore;

use super::surface_tenancy::collect_surface_reference_keys;

#[derive(Debug)]
pub enum OwnershipApiError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Conflict(OwnershipConflictResponse),
    Internal(String),
}

impl IntoResponse for OwnershipApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::Forbidden(message) => {
                (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::NotFound(message) => {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::Conflict(response) => (StatusCode::CONFLICT, Json(response)).into_response(),
            Self::Internal(message) => {
                tracing::error!(%message, "Tenant ownership operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Tenant ownership operation failed" })),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ReassignOwnershipRequest {
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipEndpoint {
    pub kind: String,
    pub id: String,
    #[serde(skip)]
    scope_id: String,
    pub tenant_id: Option<String>,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipReference {
    pub source: OwnershipEndpoint,
    pub target: OwnershipEndpoint,
    pub context: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipConflict {
    pub direction: String,
    pub source: OwnershipEndpoint,
    pub target: OwnershipEndpoint,
    pub context: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipImpactResponse {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
    pub immutable: bool,
    pub incoming: Vec<OwnershipReference>,
    pub outgoing: Vec<OwnershipReference>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipConflictResponse {
    pub error: &'static str,
    pub kind: String,
    pub id: String,
    pub requested_tenant_id: Option<String>,
    pub conflicts: Vec<OwnershipConflict>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipReassignmentResponse {
    pub kind: String,
    pub id: String,
    pub previous_tenant_id: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Clone)]
struct OwnedResource {
    kind: ResourceKind,
    id: String,
    scope_id: String,
    name: String,
    tenant_id: Option<String>,
    immutable: bool,
}

pub async fn ownership_impact(
    State(state): State<IdentityApiState>,
    Path((raw_kind, id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<OwnershipImpactResponse>, OwnershipApiError> {
    let kind = parse_owned_kind(&raw_kind)?;
    let resource = load_owned_resource(&state, kind, &id)
        .await?
        .ok_or_else(|| OwnershipApiError::NotFound(format!("{} '{}' not found", kind, id)))?;
    let context = context
        .as_ref()
        .map(|Extension(context)| context);
    let scope = scope
        .as_ref()
        .map(|Extension(scope)| scope);
    if !endpoint_visible(&endpoint_from_owned(&resource), context, scope) {
        return Err(OwnershipApiError::NotFound(format!("{} '{}' not found", kind, id)));
    }
    let references = collect_references(&state).await?;
    let incoming = references
        .iter()
        .filter(|reference| {
            endpoint_matches(&reference.target, kind, &id) && reference_visible(reference, context, scope)
        })
        .cloned()
        .collect();
    let outgoing = references
        .iter()
        .filter(|reference| {
            endpoint_matches(&reference.source, kind, &id) && reference_visible(reference, context, scope)
        })
        .cloned()
        .collect();

    Ok(Json(OwnershipImpactResponse {
        kind: kind.to_string(),
        id,
        name: resource.name,
        tenant_id: resource.tenant_id,
        immutable: resource.immutable,
        incoming,
        outgoing,
    }))
}

pub async fn reassign_ownership(
    State(state): State<IdentityApiState>,
    Path((raw_kind, id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ReassignOwnershipRequest>,
) -> Result<Json<OwnershipReassignmentResponse>, OwnershipApiError> {
    if context.is_some() || scope.is_some() {
        return Err(OwnershipApiError::Forbidden(
            "Resource-scoped access tokens cannot reassign tenant ownership".to_string(),
        ));
    }
    if let Some(tenant_id) = request.tenant_id.as_deref() {
        validate_tenant_id(tenant_id).map_err(|message| OwnershipApiError::BadRequest(message.to_string()))?;
    }
    let kind = parse_owned_kind(&raw_kind)?;
    let resource = load_owned_resource(&state, kind, &id)
        .await?
        .ok_or_else(|| OwnershipApiError::NotFound(format!("{} '{}' not found", kind, id)))?;
    if resource.immutable {
        return Err(conflict_response(
            kind,
            &id,
            request.tenant_id,
            vec![OwnershipConflict {
                direction: "immutable".to_string(),
                source: endpoint_from_owned(&resource),
                target: endpoint_from_owned(&resource),
                context: "resource".to_string(),
                reason: "This system-owned resource cannot be reassigned".to_string(),
            }],
        ));
    }

    let references = collect_references(&state).await?;
    let conflicts = reassignment_conflicts(&references, kind, &id, request.tenant_id.as_deref());
    if !conflicts.is_empty() {
        return Err(conflict_response(kind, &id, request.tenant_id, conflicts));
    }

    let previous_tenant_id = resource.tenant_id;
    persist_tenant_id(&state, kind, &id, request.tenant_id.clone()).await?;

    Ok(Json(OwnershipReassignmentResponse {
        kind: kind.to_string(),
        id,
        previous_tenant_id,
        tenant_id: request.tenant_id,
    }))
}

fn parse_owned_kind(raw: &str) -> Result<ResourceKind, OwnershipApiError> {
    let kind = ResourceKind::from_path_family(raw)
        .ok_or_else(|| OwnershipApiError::BadRequest(format!("Unsupported resource kind: {}", raw)))?;
    if matches!(kind, ResourceKind::ApiKeys | ResourceKind::ConnectionPoints) {
        return Err(OwnershipApiError::BadRequest(format!(
            "{} ownership is inherited from its parent and cannot be reassigned directly",
            kind
        )));
    }
    Ok(kind)
}

async fn load_owned_resource(
    state: &IdentityApiState,
    kind: ResourceKind,
    id: &str,
) -> Result<Option<OwnedResource>, OwnershipApiError> {
    let resource = match kind {
        ResourceKind::Gateways => state
            .gateway_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| OwnedResource {
                kind,
                scope_id: resource.id.clone(),
                id: resource.id,
                name: resource.name,
                tenant_id: resource.tenant_id,
                immutable: resource.gateway_type == crate::gateways::types::GatewayType::SelfGateway,
            }),
        ResourceKind::Surfaces => state
            .agent_surface_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.surface_id, resource.name, resource.tenant_id)),
        ResourceKind::Issuers => state
            .issuer_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::Integrations => match state
            .integration_store
            .as_ref()
        {
            Some(store) => store
                .load(id)
                .await
                .ok()
                .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
            None => return Err(unavailable(kind)),
        },
        ResourceKind::Mediators => state
            .mediator_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::TrustRegistries => state
            .trust_registry_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::Authorities => state
            .authority_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::Secrets => state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| {
                owned_with_scope_id(kind, resource.id, resource.secret_id, resource.name, resource.tenant_id)
            }),
        ResourceKind::Certificates => state
            .certificate_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(OwnershipApiError::Internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::McpProxies => state
            .mcp_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::A2aProxies => state
            .a2a_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::CredentialProviders => state
            .credential_provider_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::JwtVerificationStrategies => state
            .jwt_verification_strategy_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::StsClients => state
            .sts_client_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::PolicyDefinitions => state
            .policy_definition_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id)),
        ResourceKind::SurfaceTemplates => state
            .surface_template_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| OwnedResource {
                kind,
                scope_id: resource.id.clone(),
                id: resource.id,
                name: resource.name,
                tenant_id: resource.tenant_id,
                immutable: resource.builtin,
            }),
        ResourceKind::ApiKeys | ResourceKind::ConnectionPoints => None,
    };
    Ok(resource)
}

fn owned(
    kind: ResourceKind,
    id: String,
    name: String,
    tenant_id: Option<String>,
) -> OwnedResource {
    OwnedResource {
        kind,
        scope_id: id.clone(),
        id,
        name,
        tenant_id,
        immutable: false,
    }
}

fn owned_with_scope_id(
    kind: ResourceKind,
    id: String,
    scope_id: String,
    name: String,
    tenant_id: Option<String>,
) -> OwnedResource {
    OwnedResource {
        kind,
        id,
        scope_id,
        name,
        tenant_id,
        immutable: false,
    }
}

async fn collect_references(state: &IdentityApiState) -> Result<Vec<OwnershipReference>, OwnershipApiError> {
    let mut references = Vec::new();

    if let Some(store) = state
        .agent_surface_store
        .as_ref()
    {
        for surface in store
            .list_all()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::Surfaces, &surface.surface_id, surface.tenant_id.clone(), true);
            for reference in collect_surface_reference_keys(&surface).map_err(|error| {
                OwnershipApiError::Internal(format!("Failed to inspect Surface references: {:?}", error))
            })? {
                add_reference(
                    state,
                    &mut references,
                    source.clone(),
                    reference.kind,
                    &reference.id,
                    "surface configuration",
                )
                .await?;
            }
        }
    }

    if let Some(store) = state.gateway_store.as_ref() {
        for gateway in store
            .list_all()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::Gateways, &gateway.id, gateway.tenant_id.clone(), true);
            if let Some(config) = gateway
                .opa_policy_config
                .as_ref()
            {
                if let Some(id) = config
                    .policy_definition_id
                    .as_deref()
                {
                    add_reference(
                        state,
                        &mut references,
                        source.clone(),
                        ResourceKind::PolicyDefinitions,
                        id,
                        "gateway policy",
                    )
                    .await?;
                }
                for id in &config.policy_definition_ids {
                    add_reference(
                        state,
                        &mut references,
                        source.clone(),
                        ResourceKind::PolicyDefinitions,
                        id,
                        "gateway policy set",
                    )
                    .await?;
                }
            }
            for id in &gateway.exposed_channels {
                add_reference(
                    state,
                    &mut references,
                    source.clone(),
                    ResourceKind::Surfaces,
                    id,
                    "gateway exposed surface",
                )
                .await?;
            }
            collect_gateway_integrations(state, &mut references, &gateway, source.clone()).await?;
        }
    }

    collect_connection_point_references(state, &mut references).await?;
    collect_credential_references(state, &mut references).await?;
    collect_global_references(state, &mut references).await?;

    Ok(references)
}

async fn collect_connection_point_references(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    let Some(store) = state
        .connection_point_store
        .as_ref()
    else {
        return Ok(());
    };
    for connection_point in store
        .list_all()
        .await
        .map_err(internal)?
    {
        let Some(gateway) = load_owned_resource(state, ResourceKind::Gateways, &connection_point.gateway_id).await?
        else {
            continue;
        };
        let source = endpoint_from_owned(&gateway);
        let prefix = format!("connection point {}", connection_point.id);
        add_reference(
            state,
            references,
            source.clone(),
            ResourceKind::Mediators,
            &connection_point.mediator_id,
            &format!("{} mediator", prefix),
        )
        .await?;
        if let Some(id) = connection_point
            .integration_id
            .as_deref()
        {
            add_reference(
                state,
                references,
                source.clone(),
                ResourceKind::Integrations,
                id,
                &format!("{} integration", prefix),
            )
            .await?;
        }
        for integration in &connection_point.integrations {
            add_reference(
                state,
                references,
                source.clone(),
                ResourceKind::Integrations,
                &integration.integration_id,
                &format!("{} integration", prefix),
            )
            .await?;
        }
        for id in &connection_point.exposed_channels {
            add_reference(
                state,
                references,
                source.clone(),
                ResourceKind::Surfaces,
                id,
                &format!("{} exposed surface", prefix),
            )
            .await?;
        }
    }
    Ok(())
}

async fn collect_gateway_integrations(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
    gateway: &crate::gateways::types::Gateway,
    source: OwnershipEndpoint,
) -> Result<(), OwnershipApiError> {
    let path = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway.id);
    let storage = crate::integrations::GatewayIntegrationsStorage::new(path)
        .await
        .map_err(internal)?;
    for assignment in storage
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            references,
            source.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "gateway integration assignment",
        )
        .await?;
    }
    Ok(())
}

async fn collect_credential_references(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    if let Some(store) = state
        .credential_provider_store
        .as_ref()
    {
        for provider in store
            .list()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::CredentialProviders, &provider.id, provider.tenant_id.clone(), true);
            for id in [
                provider
                    .client_id_secret_ref
                    .as_deref(),
                provider
                    .client_secret_secret_ref
                    .as_deref(),
                provider
                    .api_key_secret_ref
                    .as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                add_reference(
                    state,
                    references,
                    source.clone(),
                    ResourceKind::Secrets,
                    id,
                    "credential provider secret",
                )
                .await?;
            }
            if let Some(id) = provider
                .consent_identity_strategy_id
                .as_deref()
            {
                add_reference(
                    state,
                    references,
                    source,
                    ResourceKind::JwtVerificationStrategies,
                    id,
                    "credential provider consent identity strategy",
                )
                .await?;
            }
        }
    }
    if let Some(store) = state.a2a_proxy_store.as_ref() {
        for proxy in store
            .list_all()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::A2aProxies, &proxy.id, proxy.tenant_id.clone(), true);
            let crate::a2a_proxies::types::A2aProxyBackend::CopilotDirectLine(config) = &proxy.backend;
            add_reference(state, references, source, ResourceKind::Secrets, &config.secret_id, "A2A proxy secret")
                .await?;
        }
    }
    if let Some(store) = state
        .sts_client_store
        .as_ref()
    {
        for client in store
            .list()
            .await
            .map_err(internal)?
        {
            if let Some(id) = client
                .client_secret_ref
                .as_deref()
            {
                let source = endpoint(ResourceKind::StsClients, &client.id, client.tenant_id.clone(), true);
                add_reference(state, references, source, ResourceKind::Secrets, id, "STS client secret").await?;
            }
        }
    }
    Ok(())
}

async fn collect_global_references(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    let appliance = OwnershipEndpoint {
        kind: "appliance".to_string(),
        id: "global".to_string(),
        scope_id: "global".to_string(),
        tenant_id: None,
        exists: true,
    };
    if let Some(store) = state
        .global_policy_store
        .as_ref()
    {
        for (plane, assignments) in store.get().await.assignments {
            for assignment in assignments {
                add_reference(
                    state,
                    references,
                    appliance.clone(),
                    ResourceKind::PolicyDefinitions,
                    &assignment.policy_id,
                    &format!("global {} policy assignment", plane),
                )
                .await?;
            }
        }
    }

    let root = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .integration_triggers,
    );
    let users = crate::integrations::UserIntegrationsStorage::new(root.join("users"))
        .await
        .map_err(internal)?;
    for assignment in users
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            references,
            appliance.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "global user integration assignment",
        )
        .await?;
    }
    let identities = crate::integrations::IdentityIntegrationsStorage::new(root.join("identities"))
        .await
        .map_err(internal)?;
    for assignment in identities
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            references,
            appliance.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "global identity integration assignment",
        )
        .await?;
    }
    Ok(())
}

async fn add_reference(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
    source: OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
    context: &str,
) -> Result<(), OwnershipApiError> {
    if id.trim().is_empty() {
        return Ok(());
    }
    let normalized_kind = if kind == ResourceKind::ApiKeys {
        ResourceKind::Surfaces
    } else {
        kind
    };
    let resource = if normalized_kind == ResourceKind::Secrets {
        let store = state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable(normalized_kind))?;
        store
            .get_by_secret_id(id)
            .await
            .map_err(internal)?
            .map(|resource| {
                owned_with_scope_id(normalized_kind, resource.id, resource.secret_id, resource.name, resource.tenant_id)
            })
    } else {
        load_owned_resource(state, normalized_kind, id).await?
    };
    let target = match resource {
        Some(resource) => endpoint_from_owned(&resource),
        None => endpoint(normalized_kind, id, None, false),
    };
    references.push(OwnershipReference {
        source,
        target,
        context: context.to_string(),
    });
    Ok(())
}

fn reassignment_conflicts(
    references: &[OwnershipReference],
    kind: ResourceKind,
    id: &str,
    requested_tenant_id: Option<&str>,
) -> Vec<OwnershipConflict> {
    references
        .iter()
        .filter_map(|reference| {
            let incoming = endpoint_matches(&reference.target, kind, id);
            let outgoing = endpoint_matches(&reference.source, kind, id);
            if !incoming && !outgoing {
                return None;
            }
            let source_tenant = if outgoing {
                requested_tenant_id
            } else {
                reference
                    .source
                    .tenant_id
                    .as_deref()
            };
            let target_tenant = if incoming {
                requested_tenant_id
            } else {
                reference
                    .target
                    .tenant_id
                    .as_deref()
            };
            let reason = if !reference.target.exists {
                Some("Referenced resource does not exist".to_string())
            } else if !can_reference(source_tenant, target_tenant) {
                Some("The proposed tenant would make this reference cross-tenant".to_string())
            } else {
                None
            }?;
            Some(OwnershipConflict {
                direction: if incoming {
                    "incoming"
                } else {
                    "outgoing"
                }
                .to_string(),
                source: reference.source.clone(),
                target: reference.target.clone(),
                context: reference.context.clone(),
                reason,
            })
        })
        .collect()
}

async fn persist_tenant_id(
    state: &IdentityApiState,
    kind: ResourceKind,
    id: &str,
    tenant_id: Option<String>,
) -> Result<(), OwnershipApiError> {
    match kind {
        ResourceKind::Gateways => {
            let store = state
                .gateway_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
            if let Some(manager) = state
                .gateway_policy_manager
                .as_ref()
            {
                manager
                    .update_gateway_policy(&resource)
                    .await
                    .map_err(internal)?;
            }
        }
        ResourceKind::Surfaces => {
            let store = state
                .agent_surface_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            super::surface_tenancy::validate_surface_references(state, &resource, None, None)
                .await
                .map_err(|error| {
                    OwnershipApiError::Internal(format!("Surface reference validation failed: {:?}", error))
                })?;
            store
                .save(&resource)
                .await
                .map_err(internal)?;
            super::surfaces::apply_surface_upsert_from_storage(state, resource).await;
        }
        ResourceKind::Issuers => {
            let store = state
                .issuer_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Integrations => {
            let store = state
                .integration_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .load(id)
                .await
                .map_err(internal)?;
            ensure_integration_may_be_owned(&resource, tenant_id.as_deref())?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now().to_rfc3339();
            store
                .update(id, &resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Mediators => {
            let store = state
                .mediator_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::TrustRegistries => {
            let store = state
                .trust_registry_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Authorities => {
            let store = state
                .authority_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Secrets => {
            state
                .secrets_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Certificates => {
            state
                .certificate_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(OwnershipApiError::Internal)?;
        }
        ResourceKind::McpProxies => {
            let store = state
                .mcp_proxy_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::A2aProxies => {
            let store = state
                .a2a_proxy_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::CredentialProviders => {
            let store = state
                .credential_provider_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::JwtVerificationStrategies => {
            let store = state
                .jwt_verification_strategy_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::StsClients => {
            let store = state
                .sts_client_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::PolicyDefinitions => {
            state
                .policy_definition_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(internal)?;
        }
        ResourceKind::SurfaceTemplates => {
            let store = state
                .surface_template_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .save(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::ApiKeys | ResourceKind::ConnectionPoints => {
            return Err(OwnershipApiError::BadRequest(format!("{} cannot be reassigned directly", kind)));
        }
    }
    Ok(())
}

fn endpoint(
    kind: ResourceKind,
    id: &str,
    tenant_id: Option<String>,
    exists: bool,
) -> OwnershipEndpoint {
    OwnershipEndpoint {
        kind: kind.to_string(),
        id: id.to_string(),
        scope_id: id.to_string(),
        tenant_id,
        exists,
    }
}

fn endpoint_from_owned(resource: &OwnedResource) -> OwnershipEndpoint {
    OwnershipEndpoint {
        kind: resource.kind.to_string(),
        id: resource.id.clone(),
        scope_id: resource.scope_id.clone(),
        tenant_id: resource.tenant_id.clone(),
        exists: true,
    }
}

fn endpoint_matches(
    endpoint: &OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
) -> bool {
    endpoint.kind == kind.as_str() && endpoint.id == id
}

fn endpoint_visible(
    endpoint: &OwnershipEndpoint,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    if context.is_none() && scope.is_none() {
        return true;
    }
    let Some(kind) = ResourceKind::from_path_family(&endpoint.kind) else {
        return false;
    };
    can_access(endpoint.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, kind, &endpoint.scope_id)
}

fn reference_visible(
    reference: &OwnershipReference,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    endpoint_visible(&reference.source, context, scope) && endpoint_visible(&reference.target, context, scope)
}

fn conflict_response(
    kind: ResourceKind,
    id: &str,
    requested_tenant_id: Option<String>,
    conflicts: Vec<OwnershipConflict>,
) -> OwnershipApiError {
    OwnershipApiError::Conflict(OwnershipConflictResponse {
        error: "tenant_reassignment_blocked",
        kind: kind.to_string(),
        id: id.to_string(),
        requested_tenant_id,
        conflicts,
    })
}

/// Governance audit integrations receive appliance-wide audit evidence, so they
/// stay appliance-global.
fn ensure_integration_may_be_owned(
    integration: &crate::storage::Integration,
    tenant_id: Option<&str>,
) -> Result<(), OwnershipApiError> {
    if tenant_id.is_some() && crate::integrations::audit_integration_triggers::is_audit_integration(integration) {
        return Err(OwnershipApiError::BadRequest(
            "Governance audit integrations are appliance-wide and cannot belong to a tenant".to_string(),
        ));
    }
    Ok(())
}

fn unavailable(kind: ResourceKind) -> OwnershipApiError {
    OwnershipApiError::Internal(format!("{} store is not configured", kind))
}

fn missing(
    kind: ResourceKind,
    id: &str,
) -> OwnershipApiError {
    OwnershipApiError::NotFound(format!("{} '{}' not found", kind, id))
}

fn internal(error: impl std::fmt::Display) -> OwnershipApiError {
    OwnershipApiError::Internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::sync::Arc;

    fn edge(
        source_tenant: Option<&str>,
        target_tenant: Option<&str>,
    ) -> OwnershipReference {
        OwnershipReference {
            source: endpoint(ResourceKind::Surfaces, "surface-1", source_tenant.map(str::to_string), true),
            target: endpoint(ResourceKind::Secrets, "secret-1", target_tenant.map(str::to_string), true),
            context: "test".to_string(),
        }
    }

    #[test]
    fn moving_source_rejects_foreign_target_and_accepts_global_target() {
        assert_eq!(
            reassignment_conflicts(
                &[edge(Some("tenant-a"), Some("tenant-b"))],
                ResourceKind::Surfaces,
                "surface-1",
                Some("tenant-c")
            )
            .len(),
            1
        );
        assert!(
            reassignment_conflicts(
                &[edge(Some("tenant-a"), None)],
                ResourceKind::Surfaces,
                "surface-1",
                Some("tenant-c")
            )
            .is_empty()
        );
    }

    #[test]
    fn audit_integrations_stay_appliance_global() {
        let integration = |category: &str| {
            crate::storage::Integration::new(
                "Integration".to_string(),
                String::new(),
                "stream".to_string(),
                serde_json::json!({}),
                serde_json::json!({}),
                "active".to_string(),
                Some(category.to_string()),
            )
        };

        assert!(matches!(
            ensure_integration_may_be_owned(&integration("audit"), Some("tenant-a")),
            Err(OwnershipApiError::BadRequest(_))
        ));
        assert!(ensure_integration_may_be_owned(&integration("audit"), None).is_ok());
        assert!(ensure_integration_may_be_owned(&integration("gateway"), Some("tenant-a")).is_ok());
    }

    #[test]
    fn moving_global_target_to_tenant_rejects_global_source() {
        let reference = edge(None, None);
        assert_eq!(reassignment_conflicts(&[reference], ResourceKind::Secrets, "secret-1", Some("tenant-a")).len(), 1);
    }

    #[test]
    fn ownership_impact_visibility_requires_tenant_and_scope_access() {
        let context = PatTenantContext {
            token_id: "token-a".to_string(),
            tenant_id: "tenant-a".to_string(),
        };
        let scope = PatResourceScope(Arc::new(
            Regex::new(r"\ATENANT:tenant-a:(?:surfaces:surface-1|secrets:secret-1)\z").unwrap(),
        ));

        assert!(reference_visible(&edge(Some("tenant-a"), Some("tenant-a")), Some(&context), Some(&scope)));
        assert!(!reference_visible(&edge(Some("tenant-a"), Some("tenant-b")), Some(&context), Some(&scope)));
        assert!(!endpoint_visible(
            &endpoint(ResourceKind::Secrets, "other-secret", Some("tenant-a".to_string()), true),
            Some(&context),
            Some(&scope),
        ));

        let secret = owned_with_scope_id(
            ResourceKind::Secrets,
            "internal-secret-id".to_string(),
            "secret-1".to_string(),
            "Secret".to_string(),
            Some("tenant-a".to_string()),
        );
        let endpoint = endpoint_from_owned(&secret);
        assert_eq!(endpoint.id, "internal-secret-id");
        assert!(endpoint_visible(&endpoint, Some(&context), Some(&scope)));
    }
}
