use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::a2a_proxies::A2aProxyStore;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
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
    PatTenantContext, ResourceKind, breaks_tenant_isolation, can_access, can_reference, scope_allows_resource,
    validate_tenant_id,
};
use crate::trust_registries::TrustRegistryStore;

use super::surface_tenancy::{collect_provider_key_references, collect_surface_reference_keys, provider_key_owners};
use crate::config::credential_policy::RuleMode;

#[derive(Debug)]
pub enum OwnershipApiError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Conflict(OwnershipConflictResponse),
    Refused(String),
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
            Self::Refused(message) => {
                (StatusCode::CONFLICT, Json(serde_json::json!({ "error": message }))).into_response()
            }
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
    /// The source sends the target's credential, so a tenant source may not reference an
    /// appliance-wide target.
    #[serde(skip)]
    same_tenant: bool,
    /// A surface names the target only in custom metadata, which holds it to a tenant only
    /// while the surface has one.
    #[serde(skip)]
    custom_metadata: bool,
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
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
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
    let conflicts = reassignment_conflicts(
        &references,
        kind,
        &id,
        request.tenant_id.as_deref(),
        crate::config::credential_policy::credential_policy().tenant_credential_isolation,
    );
    if !conflicts.is_empty() {
        return Err(conflict_response(kind, &id, request.tenant_id, conflicts));
    }

    let previous_tenant_id = resource.tenant_id;
    let actor = crate::delegation_vault::audit::management_caller_context(
        caller
            .as_ref()
            .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
        delegation
            .as_ref()
            .map(|Extension(delegation)| delegation.token_id.as_str()),
    );
    persist_tenant_id(&state, kind, &id, request.tenant_id.clone(), actor.as_ref()).await?;

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
    if matches!(kind, ResourceKind::ApiKeys | ResourceKind::ConnectionPoints | ResourceKind::DelegationVault) {
        return Err(OwnershipApiError::BadRequest(format!(
            "{} ownership is inherited from its parent and cannot be reassigned directly",
            kind
        )));
    }
    if kind == ResourceKind::Integrations {
        return Err(appliance_wide(kind));
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
        ResourceKind::Integrations => return Err(appliance_wide(kind)),
        ResourceKind::DelegationVault => return Err(inherited(kind)),
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
        let mut key_owners = None;
        for mut surface in store
            .list_all()
            .await
            .map_err(internal)?
        {
            super::surfaces::drop_inbound_api_key_ids(&mut surface);
            let source = endpoint(ResourceKind::Surfaces, &surface.surface_id, surface.tenant_id.clone(), true);
            for reference in collect_surface_reference_keys(&surface).map_err(|error| {
                OwnershipApiError::Internal(format!("Failed to inspect Surface references: {:?}", error))
            })? {
                let same_tenant = reference.same_tenant
                    || (reference.kind == ResourceKind::CredentialProviders
                        && provider_sends_gateway_credential(state, &reference.id).await?);
                if let Some(edge) = ownership_reference(
                    state,
                    source.clone(),
                    reference.kind,
                    &reference.id,
                    "surface configuration",
                    same_tenant,
                )
                .await?
                {
                    references.push(OwnershipReference {
                        custom_metadata: reference.custom_metadata,
                        ..edge
                    });
                }
            }
            let keys = collect_provider_key_references(&surface).map_err(|error| {
                OwnershipApiError::Internal(format!("Failed to inspect Surface references: {:?}", error))
            })?;
            if keys.is_empty() {
                continue;
            }
            if key_owners.is_none() {
                key_owners = Some(
                    provider_key_owners(state)
                        .await
                        .map_err(|error| {
                            OwnershipApiError::Internal(format!("Failed to inspect API key owners: {:?}", error))
                        })?,
                );
            }
            let owners = key_owners
                .as_ref()
                .map(|owners| {
                    keys.iter()
                        .filter_map(|key| owners.get(&key.key_id))
                        .flatten()
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for owner in owners {
                references.extend(
                    ownership_reference(
                        state,
                        source.clone(),
                        ResourceKind::ApiKeys,
                        &owner,
                        "surface identity",
                        false,
                    )
                    .await?,
                );
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
                provider
                    .jwt
                    .jwt_signing_key_secret_ref
                    .as_deref(),
                provider
                    .jwt
                    .jwt_certificate_secret_ref
                    .as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                add_reference_with_rule(
                    state,
                    references,
                    source.clone(),
                    ResourceKind::Secrets,
                    id,
                    "credential provider secret",
                    true,
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
            add_reference_with_rule(
                state,
                references,
                source,
                ResourceKind::Secrets,
                &config.secret_id,
                "A2A proxy secret",
                true,
            )
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
    add_reference_with_rule(state, references, source, kind, id, context, false).await
}

async fn add_reference_with_rule(
    state: &IdentityApiState,
    references: &mut Vec<OwnershipReference>,
    source: OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
    context: &str,
    same_tenant: bool,
) -> Result<(), OwnershipApiError> {
    references.extend(ownership_reference(state, source, kind, id, context, same_tenant).await?);
    Ok(())
}

async fn ownership_reference(
    state: &IdentityApiState,
    source: OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
    context: &str,
    same_tenant: bool,
) -> Result<Option<OwnershipReference>, OwnershipApiError> {
    if id.trim().is_empty() {
        return Ok(None);
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
    Ok(Some(OwnershipReference {
        source,
        target,
        context: context.to_string(),
        same_tenant,
        custom_metadata: false,
    }))
}

async fn provider_sends_gateway_credential(
    state: &IdentityApiState,
    id: &str,
) -> Result<bool, OwnershipApiError> {
    let Some(store) = state
        .credential_provider_store
        .as_ref()
    else {
        return Ok(false);
    };
    Ok(store
        .get(id)
        .await
        .map_err(internal)?
        .is_some_and(|provider| {
            provider
                .provider_type
                .sends_gateway_credential()
        }))
}

/// The conflicts a reassignment would cause. A tenant source that sends an appliance-wide
/// target's credential is a conflict when the reassignment creates that situation, or when
/// `isolation` is enforced; one that already exists is left alone while it is only warned about.
/// A secret a surface names only in custom metadata is held to a tenant only while the surface
/// has one, and may be missing while the surface keeps its tenant.
fn reassignment_conflicts(
    references: &[OwnershipReference],
    kind: ResourceKind,
    id: &str,
    requested_tenant_id: Option<&str>,
    isolation: RuleMode,
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
            let keeps_tenant = source_tenant
                == reference
                    .source
                    .tenant_id
                    .as_deref();
            if reference.custom_metadata && (source_tenant.is_none() || (!reference.target.exists && keeps_tenant)) {
                return None;
            }
            let reason = if !reference.target.exists {
                Some("Referenced resource does not exist".to_string())
            } else if !can_reference(source_tenant, target_tenant) {
                Some("The proposed tenant would make this reference cross-tenant".to_string())
            } else if reference.same_tenant
                && breaks_tenant_isolation(source_tenant, target_tenant)
                && (isolation.is_enforced()
                    || !breaks_tenant_isolation(
                        reference
                            .source
                            .tenant_id
                            .as_deref(),
                        reference
                            .target
                            .tenant_id
                            .as_deref(),
                    ))
            {
                Some("The proposed tenant would give a tenant resource an appliance-wide credential".to_string())
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
    actor: Option<&crate::delegation_vault::audit::AuditCallerContext>,
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
            super::surfaces::drop_inbound_api_key_ids(&mut resource);
            if resource.tenant_id != tenant_id {
                resource.tenant_id = tenant_id;
                super::surface_tenancy::validate_surface_references(state, &resource, Some(&resource), None, None)
                    .await
                    .map_err(|error| {
                        OwnershipApiError::Internal(format!("Surface reference validation failed: {:?}", error))
                    })?;
            }
            super::surface_tenancy::validate_external_consent_bindings(state, &resource)
                .await
                .map_err(|error| match error {
                    super::surfaces::SurfaceApiError::BadRequest(message) => OwnershipApiError::Refused(message),
                    other => OwnershipApiError::Internal(format!("External consent validation failed: {other:?}")),
                })?;
            let allowlist = crate::egress::bdd_egress_allowlist();
            super::surface_grants::write_surface(
                &super::surface_grants::GrantRemoval::of(state, allowlist.as_deref(), actor),
                store.clone(),
                id,
                super::surface_grants::Stored::Any,
                Some(&resource),
                || async {
                    store
                        .save(&resource)
                        .await
                        .map_err(|error| super::surfaces::SurfaceApiError::InternalError(error.to_string()))
                },
            )
            .await
            .map_err(|error| match error {
                super::surfaces::SurfaceApiError::Unavailable(message) => OwnershipApiError::Refused(message),
                other => OwnershipApiError::Internal(format!("Saving the surface failed: {other:?}")),
            })?;
            super::surfaces::apply_surface_from_storage(state, id).await;
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
        ResourceKind::Integrations => return Err(appliance_wide(kind)),
        ResourceKind::DelegationVault => return Err(inherited(kind)),
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
            refuse_provided_mediator(&resource)?;
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
            store
                .modify(
                    id,
                    Box::new(move |resource| {
                        resource.tenant_id = tenant_id;
                        resource.updated_at = chrono::Utc::now();
                    }),
                )
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
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
            // Held until the provider is saved, so no surface write binds it
            // after the check below found it unbound.
            let _bindings = super::surface_grants::hold_provider_bindings_exclusively().await;
            if resource.tenant_id != tenant_id {
                let surfaces = state
                    .agent_surface_store
                    .as_ref()
                    .ok_or_else(|| unavailable(ResourceKind::Surfaces))?
                    .list_all()
                    .await
                    .map_err(internal)?;
                refuse_moving_a_bound_provider(&surfaces, &resource.id)?;
                refuse_a_taken_slug(store.as_ref(), tenant_id.as_deref(), &resource).await?;
            }
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
            let store = state
                .policy_definition_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let _change = store.lock_changes().await;
            let before = store.get(id).await;
            let after = store
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(internal)?;
            if let Some(before) = before
                && let Some(reassigned) = crate::audit::policy_changes::definition_updated(
                    &before,
                    &after,
                    crate::audit::events::PolicyChangeSource::Ownership,
                )
            {
                crate::audit::policy_changes::record(
                    crate::audit::events::PolicyChangeAction::PolicyUpdated,
                    reassigned,
                );
            }
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

/// Integrations, their endpoints and event sets belong to the whole appliance.
/// Grants by binding belong to the surface they serve and move with it.
fn inherited(kind: ResourceKind) -> OwnershipApiError {
    OwnershipApiError::BadRequest(format!(
        "{kind} ownership is inherited from its parent and cannot be reassigned directly"
    ))
}

fn appliance_wide(kind: ResourceKind) -> OwnershipApiError {
    OwnershipApiError::BadRequest(format!("{kind} belong to the whole appliance and cannot be reassigned"))
}

/// A mediator the directory provides belongs to the whole appliance: its record is found
/// by its owner, so a new owner would make the directory entry unusable.
/// A credential provider that any surface binds, of any tenant, in its base or
/// a variant, through `outbound_credentials` or a Transit Point's
/// `transit_credentials`, cannot move to another tenant: its bindings would
/// name another tenant's provider, and moving it back would serve the grants
/// kept for them again. Remove the bindings first.
fn refuse_moving_a_bound_provider(
    surfaces: &[crate::config::agent_surface::AgentSurface],
    credential_provider_id: &str,
) -> Result<(), OwnershipApiError> {
    if surfaces
        .iter()
        .any(|surface| super::surface_tenancy::bound_credential_provider_ids(surface).contains(credential_provider_id))
    {
        return Err(OwnershipApiError::Refused(
            "The credential provider is bound by an agent surface, so it cannot move to another tenant; remove the \
             binding first"
                .to_string(),
        ));
    }
    Ok(())
}

/// A provider's slug is unique within its tenant, so a provider cannot move
/// into a tenant that already has another provider with its slug: both would
/// answer the same callback path.
async fn refuse_a_taken_slug(
    store: &dyn crate::credential_providers::storage::CredentialProviderStorage,
    tenant_id: Option<&str>,
    provider: &crate::credential_providers::CredentialProvider,
) -> Result<(), OwnershipApiError> {
    match store
        .find_by_provider_id(tenant_id, &provider.provider_id)
        .await
        .map_err(internal)?
    {
        Some(other) if other.id != provider.id => Err(OwnershipApiError::Refused(format!(
            "The tenant already has a credential provider with provider_id '{}', so this one cannot move to it",
            provider.provider_id
        ))),
        _ => Ok(()),
    }
}

fn refuse_provided_mediator(mediator: &crate::mediators::types::Mediator) -> Result<(), OwnershipApiError> {
    if mediator.provided {
        return Err(OwnershipApiError::Refused(
            "A mediator provided by the directory belongs to the whole appliance and cannot be reassigned".to_string(),
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
            same_tenant: false,
            custom_metadata: false,
        }
    }

    #[test]
    fn moving_source_rejects_foreign_target_and_accepts_global_target() {
        assert_eq!(
            reassignment_conflicts(
                &[edge(Some("tenant-a"), Some("tenant-b"))],
                ResourceKind::Surfaces,
                "surface-1",
                Some("tenant-c"),
                RuleMode::Warn
            )
            .len(),
            1
        );
        assert!(
            reassignment_conflicts(
                &[edge(Some("tenant-a"), None)],
                ResourceKind::Surfaces,
                "surface-1",
                Some("tenant-c"),
                RuleMode::Warn
            )
            .is_empty()
        );
    }

    fn credential_edge(
        source_tenant: Option<&str>,
        target_tenant: Option<&str>,
    ) -> OwnershipReference {
        OwnershipReference {
            same_tenant: true,
            ..edge(source_tenant, target_tenant)
        }
    }

    fn conflict_reasons(
        reference: OwnershipReference,
        kind: ResourceKind,
        id: &str,
        requested: Option<&str>,
        isolation: RuleMode,
    ) -> Vec<String> {
        reassignment_conflicts(&[reference], kind, id, requested, isolation)
            .into_iter()
            .map(|conflict| conflict.reason)
            .collect()
    }

    #[test]
    fn reassigning_a_surface_to_a_tenant_while_it_sends_an_appliance_wide_secret_is_a_conflict() {
        for isolation in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                conflict_reasons(
                    credential_edge(None, None),
                    ResourceKind::Surfaces,
                    "surface-1",
                    Some("tenant-a"),
                    isolation
                ),
                vec!["The proposed tenant would give a tenant resource an appliance-wide credential".to_string()]
            );
            assert!(
                conflict_reasons(
                    credential_edge(None, Some("tenant-a")),
                    ResourceKind::Surfaces,
                    "surface-1",
                    Some("tenant-a"),
                    isolation
                )
                .is_empty()
            );
        }
        assert!(
            conflict_reasons(
                edge(None, None),
                ResourceKind::Surfaces,
                "surface-1",
                Some("tenant-a"),
                RuleMode::Enforce
            )
            .is_empty()
        );
    }

    #[test]
    fn making_a_secret_a_tenant_surface_sends_appliance_wide_is_a_conflict() {
        for isolation in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                conflict_reasons(
                    credential_edge(Some("tenant-a"), Some("tenant-a")),
                    ResourceKind::Secrets,
                    "secret-1",
                    None,
                    isolation
                )
                .len(),
                1
            );
        }
    }

    fn metadata_edge(
        source_tenant: Option<&str>,
        target_tenant: Option<&str>,
    ) -> OwnershipReference {
        OwnershipReference {
            custom_metadata: true,
            ..credential_edge(source_tenant, target_tenant)
        }
    }

    #[test]
    fn a_metadata_secret_of_a_surface_with_no_tenant_is_held_to_a_tenant_only_once_the_surface_has_one() {
        const CROSS_TENANT: &str = "The proposed tenant would make this reference cross-tenant";
        for isolation in [RuleMode::Warn, RuleMode::Enforce] {
            for (referenced_tenant, requested) in
                [(Some("tenant-a"), Some("tenant-b")), (Some("tenant-a"), None), (None, Some("tenant-b"))]
            {
                assert!(
                    conflict_reasons(
                        metadata_edge(None, referenced_tenant),
                        ResourceKind::Secrets,
                        "secret-1",
                        requested,
                        isolation
                    )
                    .is_empty(),
                    "{referenced_tenant:?} {requested:?} {isolation:?}"
                );
            }
            assert!(
                conflict_reasons(
                    metadata_edge(Some("tenant-a"), Some("tenant-a")),
                    ResourceKind::Surfaces,
                    "surface-1",
                    None,
                    isolation
                )
                .is_empty()
            );
            assert_eq!(
                conflict_reasons(
                    metadata_edge(None, Some("tenant-a")),
                    ResourceKind::Surfaces,
                    "surface-1",
                    Some("tenant-b"),
                    isolation
                ),
                vec![CROSS_TENANT.to_string()]
            );
            assert_eq!(
                conflict_reasons(
                    metadata_edge(Some("tenant-a"), Some("tenant-a")),
                    ResourceKind::Secrets,
                    "secret-1",
                    Some("tenant-b"),
                    isolation
                ),
                vec![CROSS_TENANT.to_string()]
            );
            assert!(
                conflict_reasons(
                    metadata_edge(None, Some("tenant-a")),
                    ResourceKind::Surfaces,
                    "surface-1",
                    Some("tenant-a"),
                    isolation
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn a_missing_metadata_secret_is_a_conflict_only_when_its_surface_changes_tenant() {
        const MISSING: &str = "Referenced resource does not exist";
        let missing = |source_tenant: Option<&str>, custom_metadata: bool| OwnershipReference {
            target: endpoint(ResourceKind::Secrets, "secret-1", None, false),
            custom_metadata,
            ..credential_edge(source_tenant, None)
        };
        let reasons = |reference, requested, isolation| {
            conflict_reasons(reference, ResourceKind::Surfaces, "surface-1", requested, isolation)
        };
        for isolation in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                reasons(missing(Some("tenant-a"), true), Some("tenant-b"), isolation),
                vec![MISSING.to_string()]
            );
            assert_eq!(reasons(missing(None, true), Some("tenant-a"), isolation), vec![MISSING.to_string()]);
            assert!(reasons(missing(Some("tenant-a"), true), Some("tenant-a"), isolation).is_empty());
            assert!(reasons(missing(Some("tenant-a"), true), None, isolation).is_empty());
            assert_eq!(
                reasons(missing(Some("tenant-a"), false), Some("tenant-a"), isolation),
                vec![MISSING.to_string()]
            );
            assert_eq!(reasons(missing(None, false), None, isolation), vec![MISSING.to_string()]);
        }
    }

    #[test]
    fn a_stored_appliance_wide_credential_is_left_alone_in_warn_mode_and_refused_in_enforce_mode() {
        let stored = || credential_edge(Some("tenant-a"), None);

        assert!(
            conflict_reasons(stored(), ResourceKind::Surfaces, "surface-1", Some("tenant-b"), RuleMode::Warn)
                .is_empty()
        );
        assert_eq!(
            conflict_reasons(stored(), ResourceKind::Surfaces, "surface-1", Some("tenant-b"), RuleMode::Enforce).len(),
            1
        );
        assert_eq!(conflict_reasons(stored(), ResourceKind::Surfaces, "surface-1", None, RuleMode::Warn).len(), 0);
    }

    #[test]
    fn a_reassignment_that_gives_a_tenant_a2a_proxy_an_appliance_wide_direct_line_secret_is_a_conflict() {
        let proxy_edge = |proxy_tenant: Option<&str>, secret_tenant: Option<&str>| OwnershipReference {
            source: endpoint(ResourceKind::A2aProxies, "proxy-1", proxy_tenant.map(str::to_string), true),
            context: "A2A proxy secret".to_string(),
            ..credential_edge(None, secret_tenant)
        };
        for isolation in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                conflict_reasons(
                    proxy_edge(None, None),
                    ResourceKind::A2aProxies,
                    "proxy-1",
                    Some("tenant-a"),
                    isolation
                ),
                vec!["The proposed tenant would give a tenant resource an appliance-wide credential".to_string()]
            );
            assert_eq!(
                conflict_reasons(
                    proxy_edge(Some("tenant-a"), Some("tenant-a")),
                    ResourceKind::Secrets,
                    "secret-1",
                    None,
                    isolation
                ),
                vec!["The proposed tenant would give a tenant resource an appliance-wide credential".to_string()]
            );
            assert!(
                conflict_reasons(
                    proxy_edge(Some("tenant-a"), Some("tenant-a")),
                    ResourceKind::A2aProxies,
                    "proxy-1",
                    Some("tenant-a"),
                    isolation
                )
                .is_empty()
            );
            assert!(
                conflict_reasons(proxy_edge(None, None), ResourceKind::A2aProxies, "proxy-1", None, isolation)
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_provider_secret_may_not_become_another_tenants_or_appliance_wide() {
        let provider_secret = credential_edge(Some("tenant-a"), Some("tenant-a"));
        assert_eq!(
            conflict_reasons(
                provider_secret.clone(),
                ResourceKind::Secrets,
                "secret-1",
                Some("tenant-b"),
                RuleMode::Warn
            )
            .len(),
            1
        );
        assert!(
            conflict_reasons(provider_secret, ResourceKind::Secrets, "secret-1", Some("tenant-a"), RuleMode::Warn)
                .is_empty()
        );
    }

    #[test]
    fn a_provided_mediator_cannot_be_reassigned_and_an_operator_one_can() {
        use crate::mediators::types::{Mediator, MediatorStatus};
        let mut mediator = Mediator::new("m".into(), String::new(), "did:web:m.example".into(), None);
        mediator.status = MediatorStatus::Active;
        assert!(refuse_provided_mediator(&mediator).is_ok());

        mediator.provided = true;
        let refused = refuse_provided_mediator(&mediator).unwrap_err();
        assert!(matches!(&refused, OwnershipApiError::Refused(message) if message.contains("provided")));
        assert_eq!(
            refused
                .into_response()
                .status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn a_provider_that_any_surface_binds_cannot_move_to_another_tenant() {
        let surface = |tenant: &str, binding: serde_json::Value| -> crate::config::agent_surface::AgentSurface {
            serde_json::from_value(serde_json::json!({
                "surface_id": format!("surface-{tenant}"), "name": "surface", "tenant_id": tenant,
                "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
                "target": {"endpoint": "https://managed.example/agent"},
                "transit": {"points": [{"id": "tp-1", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                    "require_transit_token": true, "transit_credentials": binding}]}
            }))
            .unwrap()
        };
        let external =
            serde_json::json!({"credential_provider_id": "provider", "consent_mode": "external", "subject": "owner"});
        let other = serde_json::json!({"credential_provider_id": "other-provider"});
        for surfaces in [
            vec![surface("tenant-a", external.clone())],
            vec![surface("tenant-b", other.clone()), surface("tenant-c", external)],
        ] {
            let refused = refuse_moving_a_bound_provider(&surfaces, "provider").unwrap_err();
            assert!(matches!(&refused, OwnershipApiError::Refused(message) if message.contains("bound")));
            assert_eq!(
                refused
                    .into_response()
                    .status(),
                StatusCode::CONFLICT
            );
        }
        assert!(refuse_moving_a_bound_provider(&[surface("tenant-a", other)], "provider").is_ok());
        assert!(refuse_moving_a_bound_provider(&[], "provider").is_ok());
    }

    /// Slugs are unique per tenant, so a provider moves only into a tenant
    /// with no other provider of its slug.
    #[tokio::test]
    async fn a_provider_cannot_move_into_a_tenant_that_has_its_slug() {
        use crate::credential_providers::storage::CredentialProviderStorage;
        let directory = tempfile::tempdir().unwrap();
        let store = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        let provider = |id: &str, tenant: &str| -> crate::credential_providers::CredentialProvider {
            serde_json::from_value(serde_json::json!({
                "id": id, "tenant_id": tenant, "name": "GitHub", "provider_id": "github",
                "provider_type": "oauth2_client_credentials", "token_endpoint": "https://github.example/token",
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            }))
            .unwrap()
        };
        let moving = provider("moving", "tenant-a");
        for stored in [moving.clone(), provider("taken", "tenant-b")] {
            store
                .create(stored)
                .await
                .unwrap();
        }
        let refused = refuse_a_taken_slug(&store, Some("tenant-b"), &moving)
            .await
            .unwrap_err();
        assert!(matches!(&refused, OwnershipApiError::Refused(message) if message.contains("github")));
        assert_eq!(
            refused
                .into_response()
                .status(),
            StatusCode::CONFLICT
        );
        assert!(
            refuse_a_taken_slug(&store, Some("tenant-c"), &moving)
                .await
                .is_ok(),
            "a tenant without the slug takes it"
        );
        assert!(
            refuse_a_taken_slug(&store, Some("tenant-a"), &moving)
                .await
                .is_ok(),
            "the provider's own slug does not count against it"
        );
    }

    #[test]
    fn integrations_belong_to_the_whole_appliance() {
        assert!(matches!(
            parse_owned_kind("integrations"),
            Err(OwnershipApiError::BadRequest(message)) if message.contains("appliance")
        ));
    }

    #[test]
    fn moving_global_target_to_tenant_rejects_global_source() {
        let reference = edge(None, None);
        assert_eq!(
            reassignment_conflicts(&[reference], ResourceKind::Secrets, "secret-1", Some("tenant-a"), RuleMode::Warn)
                .len(),
            1
        );
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
