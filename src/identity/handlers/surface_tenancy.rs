use std::collections::HashSet;

use crate::a2a_proxies::A2aProxyStore;
use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, McpToolGatingConfig};
use crate::config::credential_policy::RuleMode;
use crate::config::{CustomMetadata, TargetAuthConfig, TargetAuthMethod};
use crate::gateways::GatewayStore;
use crate::identity::state::IdentityApiState;
use crate::issuers::IssuerStore;
use crate::mcp_proxies::McpProxyStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, SurfaceTenancy, can_reference, can_reference_with_rule, scope_allows_resource,
};
use crate::trust_registries::TrustRegistryStore;

use super::surfaces::SurfaceApiError;

/// Validates the resources a surface references. A tenant surface may not send an
/// appliance-wide secret or credential provider upstream: a reference that breaks that
/// rule is refused unless `stored` (the surface as stored, if any) already sent it on every
/// leg that sends it now, at the same endpoint, and even then when
/// `tenant_credential_isolation` is `enforce`.
pub async fn validate_surface_references(
    state: &IdentityApiState,
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), SurfaceApiError> {
    let isolation = crate::config::credential_policy::credential_policy().tenant_credential_isolation;
    let grandfathered = match stored {
        Some(stored) if stored.tenant_id == surface.tenant_id => {
            grandfathered_references(&sent_credentials(stored).unwrap_or_default(), &sent_credentials(surface)?)
        }
        _ => Vec::new(),
    };
    let authorizer = ReferenceAuthorizer {
        state,
        owner_tenant_id: surface.tenant_id.as_deref(),
        context,
        scope,
        current_surface_id: &surface.surface_id,
        isolation,
        grandfathered,
    };

    for reference in collect_surface_reference_keys(surface)? {
        if reference.custom_metadata && surface.tenant_id.is_none() {
            continue;
        }
        authorizer
            .validate_reference(&reference)
            .await?;
    }
    validate_target_auth_methods(state, surface).await
}

/// The target authentication methods of every Target and Transit Point, in every
/// variant, must be usable: `credential_lookup` was never implemented, and a provider
/// that needs a user's consent cannot authenticate the gateway to its target.
async fn validate_target_auth_methods(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    use crate::credential_providers::CredentialProviderType;

    for view in resolved_views(surface)? {
        let transit_points = view
            .transit
            .iter()
            .flat_map(|transit| transit.points.iter());
        let methods = view
            .target
            .auth
            .iter()
            .chain(transit_points.filter_map(|point| point.target_auth.as_ref()))
            .map(|authentication| &authentication.method);
        for method in methods {
            match method {
                TargetAuthMethod::StaticSecret { .. } => {}
                TargetAuthMethod::CredentialLookup => {
                    return Err(SurfaceApiError::BadRequest(
                        "Target authentication method credential_lookup is not supported; use static_secret or credential_provider".into(),
                    ));
                }
                TargetAuthMethod::CredentialProvider { provider_id, .. } => {
                    let provider = state
                        .credential_provider_store
                        .as_ref()
                        .ok_or_else(|| unavailable("Credential provider"))?
                        .get(provider_id)
                        .await
                        .map_err(|error| internal("Credential provider", error))?
                        .ok_or_else(|| inaccessible("Credential provider"))?;
                    if provider.provider_type == CredentialProviderType::OAuth2AuthorizationCode {
                        return Err(SurfaceApiError::BadRequest(
                            "Target authentication cannot use an oauth2_authorization_code credential provider: it needs a user's consent".into(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SurfaceReferenceKey {
    pub kind: ResourceKind,
    pub id: String,
    /// A secret a tenant surface sends upstream, which must not be appliance-wide.
    pub same_tenant: bool,
    /// Named only by `$SECRET:` helpers in custom metadata. A surface with no tenant may name
    /// any secret there, even one that does not exist; on a tenant surface only a reference
    /// the stored surface already sent on the same leg may name a missing secret.
    pub custom_metadata: bool,
}

pub(crate) fn collect_surface_reference_keys(
    surface: &AgentSurface
) -> Result<Vec<SurfaceReferenceKey>, SurfaceApiError> {
    let mut references = Vec::new();
    if let Some(issuer_id) = surface.issuer_id.as_deref() {
        push_reference(&mut references, ResourceKind::Issuers, issuer_id);
    }
    for effective in resolved_views(surface)? {
        collect_effective_surface_references(&effective, &mut references);
    }
    references.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then_with(|| left.id.cmp(&right.id))
    });
    references.dedup_by(|later, kept| {
        let duplicate = later.kind == kept.kind && later.id == kept.id;
        if duplicate {
            kept.same_tenant |= later.same_tenant;
            kept.custom_metadata &= later.custom_metadata;
        }
        duplicate
    });
    Ok(references)
}

/// A credential a surface sends upstream, with the leg that sends it: the Target, or a
/// Transit Point by `id`, of the base surface or of a variant by `id`, and that leg's
/// endpoint. Ids, not aliases or positions, name the legs, so renaming or reordering
/// variants and Transit Points keeps them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SentCredential {
    variant_id: Option<String>,
    transit_point_id: Option<String>,
    endpoint: String,
    kind: ResourceKind,
    id: String,
}

/// Every Target authentication secret or provider, every `outbound_credentials` or
/// `transit_credentials` provider and every custom metadata secret, on each leg that sends
/// it. A surface's `outbound_credentials` are sent on its Target and on each of its Transit
/// Points; the Target's custom metadata and both response custom metadata belong to the
/// Target, and the shared transit custom metadata to each Transit Point.
fn sent_credentials(surface: &AgentSurface) -> Result<Vec<SentCredential>, SurfaceApiError> {
    let variant_ids = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(|variant| Some(variant.id.clone())),
    );
    let mut sent = Vec::new();
    for (variant_id, view) in variant_ids.zip(resolved_views(surface)?) {
        let bindings = view
            .outbound_credentials
            .iter()
            .map(|binding| {
                binding
                    .credential_provider_id
                    .as_str()
            });
        let mut legs = vec![(
            None,
            view.target.endpoint.as_str(),
            view.target.auth.as_ref(),
            None,
            target_leg_metadata(&view).to_vec(),
        )];
        legs.extend(
            view.transit
                .iter()
                .flat_map(|transit| transit.points.iter())
                .map(|point| {
                    (
                        Some(point.id.as_str()),
                        point.target_endpoint.as_str(),
                        point.target_auth.as_ref(),
                        point
                            .transit_credentials
                            .as_ref()
                            .map(|credentials| {
                                credentials
                                    .credential_provider_id
                                    .as_str()
                            }),
                        vec![transit_metadata(&view)],
                    )
                }),
        );
        for (transit_point_id, endpoint, authentication, transit_provider, metadata) in legs {
            let mut references = Vec::new();
            collect_target_auth_reference(authentication, &mut references);
            for metadata in metadata {
                collect_custom_metadata_references(metadata, &mut references);
            }
            for id in bindings
                .clone()
                .chain(transit_provider)
            {
                push_reference(&mut references, ResourceKind::CredentialProviders, id);
            }
            sent.extend(
                references
                    .into_iter()
                    .map(|reference| SentCredential {
                        variant_id: variant_id.clone(),
                        transit_point_id: transit_point_id.map(str::to_string),
                        endpoint: endpoint.to_string(),
                        kind: reference.kind,
                        id: reference.id,
                    }),
            );
        }
    }
    Ok(sent)
}

/// The references `saved` keeps from `stored`: those that every leg of `saved` sending them
/// already sent, at the same endpoint, in `stored`.
fn grandfathered_references(
    stored: &[SentCredential],
    saved: &[SentCredential],
) -> Vec<(ResourceKind, String)> {
    let mut grandfathered: Vec<(ResourceKind, String)> = Vec::new();
    for credential in saved {
        let key = (credential.kind, credential.id.clone());
        if !grandfathered.contains(&key)
            && saved
                .iter()
                .filter(|other| other.kind == credential.kind && other.id == credential.id)
                .all(|other| stored.contains(other))
        {
            grandfathered.push(key);
        }
    }
    grandfathered
}

fn resolved_views(surface: &AgentSurface) -> Result<Vec<AgentSurface>, SurfaceApiError> {
    let mut views = vec![surface.clone()];
    for variant in &surface.variants {
        let mut resolvable = surface.clone();
        if let Some(candidate) = resolvable
            .variants
            .iter_mut()
            .find(|candidate| candidate.id == variant.id)
        {
            candidate.enabled = true;
        }
        let resolved = resolvable
            .resolve_variant(Some(&variant.alias))
            .map_err(|error| {
                SurfaceApiError::BadRequest(format!(
                    "Variant '{}' references could not be resolved: {}",
                    variant.alias, error
                ))
            })?;
        views.push(resolved);
    }
    Ok(views)
}

struct ReferenceAuthorizer<'a> {
    state: &'a IdentityApiState,
    owner_tenant_id: Option<&'a str>,
    context: Option<&'a PatTenantContext>,
    scope: Option<&'a PatResourceScope>,
    current_surface_id: &'a str,
    isolation: RuleMode,
    grandfathered: Vec<(ResourceKind, String)>,
}

impl ReferenceAuthorizer<'_> {
    fn rule_for(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> RuleMode {
        reference_rule(&self.grandfathered, self.isolation, kind, id)
    }

    fn is_grandfathered(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> bool {
        is_grandfathered(&self.grandfathered, kind, id)
    }

    async fn validate_reference(
        &self,
        reference: &SurfaceReferenceKey,
    ) -> Result<(), SurfaceApiError> {
        match reference.kind {
            ResourceKind::Issuers => {
                self.issuer(&reference.id)
                    .await
            }
            ResourceKind::PolicyDefinitions => {
                self.policy(&reference.id)
                    .await
            }
            ResourceKind::Secrets => self.secret(reference).await,
            ResourceKind::Certificates => {
                self.certificate(&reference.id)
                    .await
            }
            ResourceKind::JwtVerificationStrategies => {
                self.jwt_strategy(&reference.id)
                    .await
            }
            ResourceKind::CredentialProviders => {
                self.credential_provider(&reference.id)
                    .await
            }
            ResourceKind::McpProxies => {
                self.mcp_proxy(&reference.id)
                    .await
            }
            ResourceKind::A2aProxies => {
                self.a2a_proxy(&reference.id)
                    .await
            }
            ResourceKind::Gateways => {
                self.gateway(&reference.id)
                    .await
            }
            ResourceKind::TrustRegistries => {
                self.trust_registry(&reference.id)
                    .await
            }
            ResourceKind::ApiKeys => {
                self.api_key_parent(&reference.id)
                    .await
            }
            _ => Err(SurfaceApiError::InternalError(format!("Unsupported Surface reference kind: {}", reference.kind))),
        }
    }

    fn ensure(
        &self,
        resource_tenant_id: Option<&str>,
        kind: ResourceKind,
        id: &str,
        label: &str,
    ) -> Result<(), SurfaceApiError> {
        if !can_reference(self.owner_tenant_id, resource_tenant_id)
            || !scope_allows_resource(self.scope, self.context, kind, id)
        {
            return Err(inaccessible(label));
        }
        Ok(())
    }

    async fn issuer(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .issuer_store
            .as_ref()
            .ok_or_else(|| unavailable("Issuer"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Issuer", error))?
            .ok_or_else(|| inaccessible("Issuer"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Issuers, &resource.id, "Issuer")
    }

    async fn policy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .policy_definition_store
            .as_ref()
            .ok_or_else(|| unavailable("Policy definition"))?;
        let resource = store
            .get(id)
            .await
            .ok_or_else(|| inaccessible("Policy definition"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::PolicyDefinitions, &resource.id, "Policy definition")
    }

    async fn secret(
        &self,
        reference: &SurfaceReferenceKey,
    ) -> Result<(), SurfaceApiError> {
        let id = reference.id.as_str();
        let store = self
            .state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable("Secret"))?;
        let Some(resource) = store
            .get_by_secret_id(id)
            .await
            .map_err(|error| internal("Secret", error))?
        else {
            return if reference.custom_metadata && self.is_grandfathered(ResourceKind::Secrets, id) {
                Ok(())
            } else {
                Err(inaccessible("Secret"))
            };
        };
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Secrets, &resource.secret_id, "Secret")?;
        if reference.same_tenant
            && !can_reference_with_rule(
                self.owner_tenant_id,
                resource.tenant_id.as_deref(),
                self.rule_for(ResourceKind::Secrets, id),
            )
        {
            return Err(inaccessible("Secret"));
        }
        Ok(())
    }

    async fn certificate(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .certificate_store
            .as_ref()
            .ok_or_else(|| unavailable("Certificate"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Certificate", error))?
            .ok_or_else(|| inaccessible("Certificate"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Certificates, &resource.id, "Certificate")
    }

    async fn jwt_strategy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .jwt_verification_strategy_store
            .as_ref()
            .ok_or_else(|| unavailable("JWT verification strategy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("JWT verification strategy", error))?
            .ok_or_else(|| inaccessible("JWT verification strategy"))?;
        self.ensure(
            resource.tenant_id.as_deref(),
            ResourceKind::JwtVerificationStrategies,
            &resource.id,
            "JWT verification strategy",
        )
    }

    async fn credential_provider(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .credential_provider_store
            .as_ref()
            .ok_or_else(|| unavailable("Credential provider"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Credential provider", error))?
            .ok_or_else(|| inaccessible("Credential provider"))?;
        let tenancy = SurfaceTenancy {
            tenant_id: self.owner_tenant_id,
            mode: self.rule_for(ResourceKind::CredentialProviders, id),
        };
        if !resource.usable_by(tenancy) {
            return Err(inaccessible("Credential provider"));
        }
        self.ensure(
            resource.tenant_id.as_deref(),
            ResourceKind::CredentialProviders,
            &resource.id,
            "Credential provider",
        )
    }

    async fn mcp_proxy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .mcp_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable("MCP proxy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("MCP proxy", error))?
            .ok_or_else(|| inaccessible("MCP proxy"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::McpProxies, &resource.id, "MCP proxy")
    }

    async fn a2a_proxy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .a2a_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable("A2A proxy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("A2A proxy", error))?
            .ok_or_else(|| inaccessible("A2A proxy"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::A2aProxies, &resource.id, "A2A proxy")
    }

    async fn gateway(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .gateway_store
            .as_ref()
            .ok_or_else(|| unavailable("Gateway"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Gateway", error))?
            .ok_or_else(|| inaccessible("Gateway"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Gateways, &resource.id, "Gateway")
    }

    async fn trust_registry(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .trust_registry_store
            .as_ref()
            .ok_or_else(|| unavailable("Trust Registry"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Trust Registry", error))?
            .ok_or_else(|| inaccessible("Trust Registry"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::TrustRegistries, &resource.id, "Trust Registry")
    }

    async fn api_key_parent(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        if id == self.current_surface_id {
            return self.ensure(self.owner_tenant_id, ResourceKind::ApiKeys, id, "API-key parent Surface");
        }
        let store = self
            .state
            .agent_surface_store
            .as_ref()
            .ok_or_else(|| unavailable("API-key parent Surface"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("API-key parent Surface", error))?
            .ok_or_else(|| inaccessible("API-key parent Surface"))?;
        self.ensure(
            resource.tenant_id.as_deref(),
            ResourceKind::ApiKeys,
            &resource.surface_id,
            "API-key parent Surface",
        )
    }
}

/// How strictly a reference is held to tenant isolation: one the save keeps from the stored
/// surface (`grandfathered`) is held only to `isolation`, any other is held to `enforce`.
fn reference_rule(
    grandfathered: &[(ResourceKind, String)],
    isolation: RuleMode,
    kind: ResourceKind,
    id: &str,
) -> RuleMode {
    if is_grandfathered(grandfathered, kind, id) {
        isolation
    } else {
        RuleMode::Enforce
    }
}

fn is_grandfathered(
    grandfathered: &[(ResourceKind, String)],
    kind: ResourceKind,
    id: &str,
) -> bool {
    grandfathered
        .iter()
        .any(|(stored_kind, stored_id)| *stored_kind == kind && stored_id == id)
}

fn collect_effective_surface_references(
    surface: &AgentSurface,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    let mut policy_ids = HashSet::new();
    collect_policy_ids(surface, &mut policy_ids);
    for id in policy_ids {
        push_reference(references, ResourceKind::PolicyDefinitions, id);
    }

    for trust_check in surface
        .access_point
        .trust_check_list
        .iter()
        .chain(
            surface
                .target
                .trust_check_list
                .iter(),
        )
    {
        push_reference(references, ResourceKind::TrustRegistries, &trust_check.trust_registry_id);
    }
    if let Some(trust_recorder) = surface
        .access_point
        .trust_recorder
        .as_ref()
    {
        for entry in &trust_recorder.entries {
            push_reference(references, ResourceKind::TrustRegistries, &entry.trust_registry_id);
        }
    }

    if let Some(authentication) = surface
        .access_point
        .caller_authentication
        .as_ref()
    {
        for method in &authentication.methods {
            collect_source_auth_references(method, references);
        }
    }
    if let Some(source_auth) = surface
        .transit
        .as_ref()
        .and_then(|transit| {
            transit
                .shared
                .source_auth
                .as_ref()
        })
    {
        collect_source_auth_references(source_auth, references);
    }

    collect_target_auth_reference(surface.target.auth.as_ref(), references);
    for metadata in target_leg_metadata(surface) {
        collect_custom_metadata_references(metadata, references);
    }
    collect_identity_injection_references(
        &surface
            .target
            .identity_injection,
        references,
    );
    for identity in [
        surface
            .identity_slots
            .inbound
            .as_ref(),
        surface
            .identity_slots
            .protected
            .as_ref(),
        surface
            .identity_slots
            .external
            .as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        collect_managed_identity_reference(identity, references);
    }

    for binding in &surface.outbound_credentials {
        push_reference(references, ResourceKind::CredentialProviders, &binding.credential_provider_id);
    }

    if let Some(transit) = surface.transit.as_ref() {
        for point in &transit.points {
            for trust_check in &point.trust_check_list {
                push_reference(references, ResourceKind::TrustRegistries, &trust_check.trust_registry_id);
            }
            collect_target_auth_reference(point.target_auth.as_ref(), references);
            collect_custom_metadata_references(transit_metadata(surface), references);
            if let Some(source_auth) = point.source_auth.as_ref() {
                collect_source_auth_references(source_auth, references);
            }
            collect_identity_injection_references(&point.identity_injection, references);
            if let Some(identity) = point
                .managed_identity
                .as_ref()
            {
                collect_managed_identity_reference(identity, references);
            }
            if let Some(credentials) = point
                .transit_credentials
                .as_ref()
            {
                push_reference(references, ResourceKind::CredentialProviders, &credentials.credential_provider_id);
            }
            if let Some(id) = endpoint_id(&point.target_endpoint, "fabric://") {
                push_reference(references, ResourceKind::Gateways, id);
            }
        }
    }

    if let Some(id) = surface
        .target
        .mcp_proxy_id
        .as_deref()
    {
        push_reference(references, ResourceKind::McpProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "proxy://") {
        push_reference(references, ResourceKind::McpProxies, id);
    }
    if let Some(id) = surface
        .target
        .a2a_proxy_id
        .as_deref()
    {
        push_reference(references, ResourceKind::A2aProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "a2a-proxy://") {
        push_reference(references, ResourceKind::A2aProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "fabric://") {
        push_reference(references, ResourceKind::Gateways, id);
    }
}

/// The Target's custom metadata, its response custom metadata and the Access Point's
/// response custom metadata.
fn target_leg_metadata(surface: &AgentSurface) -> [Option<&CustomMetadata>; 3] {
    [
        surface
            .target
            .custom_metadata
            .as_ref(),
        surface
            .target
            .response_custom_metadata
            .as_ref(),
        surface
            .access_point
            .response_custom_metadata
            .as_ref(),
    ]
}

fn transit_metadata(surface: &AgentSurface) -> Option<&CustomMetadata> {
    surface
        .transit
        .as_ref()
        .and_then(|transit| {
            transit
                .shared
                .custom_metadata
                .as_ref()
        })
}

fn collect_custom_metadata_references(
    metadata: Option<&CustomMetadata>,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    if let Some(payload) = metadata.and_then(|metadata| metadata.payload.as_ref()) {
        collect_secret_helpers(payload, references);
    }
}

fn collect_secret_helpers(
    value: &serde_json::Value,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(id) = crate::protocols::extensions::secret_helper_id(value) {
                push_reference_key(references, ResourceKind::Secrets, id, true, true);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_helpers(item, references);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values() {
                collect_secret_helpers(field, references);
            }
        }
        _ => {}
    }
}

fn collect_target_auth_reference(
    authentication: Option<&TargetAuthConfig>,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match authentication.map(|authentication| &authentication.method) {
        Some(TargetAuthMethod::StaticSecret { secret_id, .. }) => {
            push_reference_with_rule(references, ResourceKind::Secrets, secret_id, true)
        }
        Some(TargetAuthMethod::CredentialProvider { provider_id, .. }) => {
            push_reference(references, ResourceKind::CredentialProviders, provider_id)
        }
        Some(TargetAuthMethod::CredentialLookup) | None => {}
    }
}

fn collect_source_auth_references(
    authentication: &crate::source_auth::SourceAuthConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};
    match authentication {
        SourceAuthConfig::JwtBearer(config) => {
            push_reference(references, ResourceKind::JwtVerificationStrategies, &config.jwt_verification_strategy_id)
        }
        SourceAuthConfig::ApiKey(config) => push_reference(references, ResourceKind::Secrets, &config.secret_id),
        SourceAuthConfig::ApiKeyProvider(config) => push_reference(references, ResourceKind::ApiKeys, &config.agent_id),
        SourceAuthConfig::DidAuth(_) => {}
        SourceAuthConfig::Mtls(config) => {
            let ids = match &config.trust {
                MtlsTrust::Pinned { certificate_ids } => certificate_ids,
                MtlsTrust::Ca { ca_certificate_ids, .. } => ca_certificate_ids,
            };
            for id in ids {
                push_reference(references, ResourceKind::Certificates, id);
            }
        }
    }
}

fn collect_managed_identity_reference(
    identity: &crate::source_auth::ManagedIdentityConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match identity {
        crate::source_auth::ManagedIdentityConfig::FromMtls { certificate_id } => {
            push_reference(references, ResourceKind::Certificates, certificate_id)
        }
        crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id }
            if !api_key_id.starts_with(crate::api_keys::KEY_ID_PREFIX) =>
        {
            push_reference(references, ResourceKind::Secrets, api_key_id)
        }
        _ => {}
    }
}

fn collect_identity_injection_references(
    identity: &crate::config::agent_surface::IdentityInjectionConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    if let Some(certificate_id) = identity
        .certificate_id
        .as_deref()
    {
        push_reference(references, ResourceKind::Certificates, certificate_id);
    }
    if let Some(api_key_id) = identity
        .api_key_id
        .as_deref()
        .filter(|id| !id.starts_with(crate::api_keys::KEY_ID_PREFIX))
    {
        push_reference(references, ResourceKind::Secrets, api_key_id);
    }
}

fn push_reference(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
) {
    push_reference_with_rule(references, kind, id, false);
}

fn push_reference_with_rule(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
    same_tenant: bool,
) {
    push_reference_key(references, kind, id, same_tenant, false);
}

fn push_reference_key(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
    same_tenant: bool,
    custom_metadata: bool,
) {
    if !id.trim().is_empty() {
        references.push(SurfaceReferenceKey {
            kind,
            id: id.to_string(),
            same_tenant,
            custom_metadata,
        });
    }
}

fn collect_policy_ids<'a>(
    surface: &'a AgentSurface,
    ids: &mut HashSet<&'a str>,
) {
    if let Some(policy) = surface
        .access_point
        .inbound_policy
        .as_ref()
    {
        ids.insert(&policy.policy_definition_id);
    }
    if let Some(policy) = surface.target.policy.as_ref() {
        ids.insert(&policy.policy_definition_id);
    }
    if let Some(policy) = surface
        .target
        .response_policy
        .as_ref()
    {
        ids.insert(&policy.policy_definition_id);
    }
    ids.extend(
        surface
            .target
            .mcp_tool_policies
            .iter()
            .map(|policy| {
                policy
                    .policy_definition_id
                    .as_str()
            }),
    );
    collect_gating_policy_ids(
        surface
            .target
            .mcp_tool_gating
            .as_ref(),
        ids,
    );

    if let Some(transit) = surface.transit.as_ref() {
        if let Some(policy) = transit
            .shared
            .transit_policy
            .as_ref()
        {
            ids.insert(&policy.policy_definition_id);
        }
        if let Some(id) = transit
            .shared
            .opa_policy_definition_id
            .as_deref()
        {
            ids.insert(id);
        }
        for point in &transit.points {
            if let Some(policy) = point.policy.as_ref() {
                ids.insert(&policy.policy_definition_id);
            }
            if let Some(policy) = point.response_policy.as_ref() {
                ids.insert(&policy.policy_definition_id);
            }
            collect_gating_policy_ids(point.mcp_tool_gating.as_ref(), ids);
        }
    }
}

fn collect_gating_policy_ids<'a>(
    gating: Option<&'a McpToolGatingConfig>,
    ids: &mut HashSet<&'a str>,
) {
    if let Some(gating) = gating {
        ids.extend(
            gating
                .gates
                .iter()
                .filter_map(|gate| {
                    gate.condition_policy_definition_id
                        .as_deref()
                }),
        );
    }
}

fn endpoint_id<'a>(
    endpoint: &'a str,
    prefix: &str,
) -> Option<&'a str> {
    endpoint
        .strip_prefix(prefix)
        .and_then(|rest| rest.split('/').next())
        .filter(|id| !id.is_empty())
}

fn inaccessible(label: &str) -> SurfaceApiError {
    SurfaceApiError::BadRequest(format!("{label} reference is not accessible"))
}

fn unavailable(label: &str) -> SurfaceApiError {
    SurfaceApiError::InternalError(format!("{label} store is not configured"))
}

fn internal(
    label: &str,
    error: impl std::fmt::Display,
) -> SurfaceApiError {
    SurfaceApiError::InternalError(format!("Failed to validate {label} reference: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface_variants::{
        AccessPointOverrides, SurfaceOverrides, SurfaceVariant, TargetOverrides, TransitOverrides,
    };
    use crate::config::types::{TrustRecorderConfig, TrustRecorderEntry};
    use crate::trust_registry_verification::TrustCheckElement;

    fn trust_check(
        id: &str,
        trust_registry_id: &str,
    ) -> TrustCheckElement {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "trust_registry_id": trust_registry_id,
            "query_type": "authorization",
            "query": {
                "authority_id": "did:web:authority.example",
                "entity_id": "{{ caller.did }}",
                "action": "invoke"
            }
        }))
        .unwrap()
    }

    fn transit_point(
        alias: &str,
        trust_registry_id: &str,
    ) -> crate::config::agent_surface::TransitPoint {
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": alias,
            "target_endpoint": "https://partner.example/a2a",
            "protocol": "a2a"
        }))
        .unwrap();
        point.trust_check_list = vec![trust_check(&format!("{alias}-check"), trust_registry_id)];
        point
    }

    #[test]
    fn a_target_auth_credential_provider_is_a_reference_of_the_target_and_each_transit_point() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(
            serde_json::from_value(
                serde_json::json!({"method": {"credential_provider": {"provider_id": "cp-target"}}}),
            )
            .unwrap(),
        );
        let mut point = transit_point("partner", "tr-partner");
        point.target_auth = Some(
            serde_json::from_value(
                serde_json::json!({"method": {"credential_provider": {"provider_id": "cp-partner"}}}),
            )
            .unwrap(),
        );
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let providers: HashSet<_> = collect_surface_reference_keys(&surface)
            .unwrap()
            .into_iter()
            .filter(|reference| reference.kind == ResourceKind::CredentialProviders)
            .map(|reference| reference.id)
            .collect();

        assert_eq!(providers, HashSet::from(["cp-target".to_string(), "cp-partner".to_string()]));
    }

    fn static_secret_auth(secret_id: &str) -> crate::config::TargetAuthConfig {
        serde_json::from_value(
            serde_json::json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "x-key"}}}),
        )
        .unwrap()
    }

    fn key<'a>(
        keys: &'a [SurfaceReferenceKey],
        kind: ResourceKind,
        id: &str,
    ) -> &'a SurfaceReferenceKey {
        keys.iter()
            .find(|key| key.kind == kind && key.id == id)
            .unwrap()
    }

    #[test]
    fn the_target_auth_secret_of_the_target_and_each_transit_point_must_be_same_tenant_and_a_caller_secret_need_not() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("target-secret"));
        surface.access_point.caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "caller-secret"}
            ]}))
            .unwrap(),
        );
        let mut point = transit_point("partner", "tr-partner");
        point.target_auth = Some(static_secret_auth("point-secret"));
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let keys = collect_surface_reference_keys(&surface).unwrap();

        assert!(key(&keys, ResourceKind::Secrets, "target-secret").same_tenant);
        assert!(key(&keys, ResourceKind::Secrets, "point-secret").same_tenant);
        assert!(!key(&keys, ResourceKind::Secrets, "caller-secret").same_tenant);
    }

    #[test]
    fn a_secret_used_as_target_auth_and_elsewhere_stays_same_tenant_after_deduplication() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("shared-secret"));
        surface.access_point.caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "shared-secret"}
            ]}))
            .unwrap(),
        );

        let keys = collect_surface_reference_keys(&surface).unwrap();

        let shared: Vec<_> = keys
            .iter()
            .filter(|key| key.kind == ResourceKind::Secrets)
            .collect();
        assert_eq!(shared.len(), 1);
        assert!(shared[0].same_tenant);
    }

    #[test]
    fn a_stored_reference_is_held_to_the_mode_and_a_new_one_always_to_enforce() {
        let stored = vec![(ResourceKind::Secrets, "old".to_string())];

        assert_eq!(reference_rule(&stored, RuleMode::Warn, ResourceKind::Secrets, "old"), RuleMode::Warn);
        assert_eq!(reference_rule(&stored, RuleMode::Enforce, ResourceKind::Secrets, "old"), RuleMode::Enforce);
        assert_eq!(reference_rule(&stored, RuleMode::Warn, ResourceKind::Secrets, "new"), RuleMode::Enforce);
        assert_eq!(
            reference_rule(&stored, RuleMode::Warn, ResourceKind::CredentialProviders, "old"),
            RuleMode::Enforce
        );
        assert_eq!(reference_rule(&[], RuleMode::Warn, ResourceKind::Secrets, "old"), RuleMode::Enforce);
    }

    fn legs_surface() -> AgentSurface {
        let mut surface = AgentSurface::default();
        surface.target.endpoint = "https://target.example".into();
        surface.target.auth = Some(static_secret_auth("target-secret"));
        surface.outbound_credentials =
            serde_json::from_value(serde_json::json!([{"credential_provider_id": "bound"}])).unwrap();
        let point = |alias: &str, extra: serde_json::Value| {
            let mut point = serde_json::json!({
                "id": format!("{alias}-id"), "alias": alias,
                "target_endpoint": format!("https://{alias}.example"), "protocol": "a2a"
            });
            point
                .as_object_mut()
                .unwrap()
                .extend(
                    extra
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            serde_json::from_value(point).unwrap()
        };
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![
                point(
                    "partner",
                    serde_json::json!({"target_auth": {"method": {"credential_provider": {"provider_id": "partner-provider"}}}}),
                ),
                point("peer", serde_json::json!({"transit_credentials": {"credential_provider_id": "peer-provider"}})),
            ],
            outbound_listen_address: None,
            shared: Default::default(),
        });
        surface.variants = vec![
            serde_json::from_value(serde_json::json!({
                "id": "staging-id", "alias": "staging", "name": "Staging",
                "overrides": {"target": {"endpoint": "https://staging.example"}}
            }))
            .unwrap(),
        ];
        surface
    }

    fn kept(
        stored: &AgentSurface,
        saved: &AgentSurface,
    ) -> Vec<String> {
        let mut kept: Vec<String> =
            grandfathered_references(&sent_credentials(stored).unwrap(), &sent_credentials(saved).unwrap())
                .into_iter()
                .map(|(kind, id)| format!("{kind}:{id}"))
                .collect();
        kept.sort();
        kept
    }

    fn all_kept() -> Vec<String> {
        let mut all: Vec<String> = [
            (ResourceKind::CredentialProviders, "bound"),
            (ResourceKind::CredentialProviders, "partner-provider"),
            (ResourceKind::CredentialProviders, "peer-provider"),
            (ResourceKind::Secrets, "target-secret"),
        ]
        .into_iter()
        .map(|(kind, id)| format!("{kind}:{id}"))
        .collect();
        all.sort();
        all
    }

    fn without(removed: &[&str]) -> Vec<String> {
        all_kept()
            .into_iter()
            .filter(|key| {
                !removed
                    .iter()
                    .any(|id| key.ends_with(&format!(":{id}")))
            })
            .collect()
    }

    fn points(surface: &mut AgentSurface) -> &mut Vec<crate::config::agent_surface::TransitPoint> {
        &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points
    }

    #[test]
    fn a_credential_is_sent_on_each_leg_of_the_base_and_each_variant_with_the_legs_endpoint() {
        let sent = sent_credentials(&legs_surface()).unwrap();
        let legs: HashSet<_> = sent
            .iter()
            .map(|credential| {
                (
                    credential
                        .variant_id
                        .as_deref(),
                    credential
                        .transit_point_id
                        .as_deref(),
                    credential.endpoint.as_str(),
                    credential.id.as_str(),
                )
            })
            .collect();

        let mut expected = HashSet::new();
        for (variant, target_endpoint) in
            [(None, "https://target.example"), (Some("staging-id"), "https://staging.example")]
        {
            expected.extend([
                (variant, None, target_endpoint, "target-secret"),
                (variant, None, target_endpoint, "bound"),
                (variant, Some("partner-id"), "https://partner.example", "partner-provider"),
                (variant, Some("partner-id"), "https://partner.example", "bound"),
                (variant, Some("peer-id"), "https://peer.example", "peer-provider"),
                (variant, Some("peer-id"), "https://peer.example", "bound"),
            ]);
        }
        assert_eq!(legs, expected);
        assert_eq!(sent.len(), expected.len());
        assert!(
            sent.iter()
                .all(|credential| (credential.kind == ResourceKind::Secrets) == (credential.id == "target-secret"))
        );
    }

    #[test]
    fn a_stored_credential_is_kept_while_each_leg_that_sends_it_keeps_its_endpoint() {
        let stored = legs_surface();
        assert_eq!(kept(&stored, &stored), all_kept());

        let mut renamed = legs_surface();
        renamed.name = "renamed".into();
        points(&mut renamed).reverse();
        for point in points(&mut renamed) {
            point.alias = format!("{}-renamed", point.alias);
            point.name = "Renamed".into();
        }
        renamed.variants[0].alias = "staging-renamed".into();
        assert_eq!(kept(&stored, &renamed), all_kept());

        let mut dropped = legs_surface();
        points(&mut dropped).remove(1);
        assert_eq!(kept(&stored, &dropped), without(&["peer-provider"]));
    }

    #[test]
    fn a_stored_credential_is_not_kept_when_a_leg_that_sends_it_is_redirected_moved_or_new() {
        let stored = legs_surface();

        let mut target = legs_surface();
        target.target.endpoint = "https://tenant.example".into();
        assert_eq!(kept(&stored, &target), without(&["target-secret", "bound"]));

        let mut variant = legs_surface();
        variant.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some("https://tenant.example".into());
        assert_eq!(kept(&stored, &variant), without(&["target-secret", "bound"]));

        let mut partner = legs_surface();
        points(&mut partner)[0].target_endpoint = "https://tenant.example".into();
        assert_eq!(kept(&stored, &partner), without(&["partner-provider", "bound"]));

        let mut moved = legs_surface();
        let authentication = points(&mut moved)[0]
            .target_auth
            .take();
        points(&mut moved)[1].target_auth = authentication;
        assert_eq!(kept(&stored, &moved), without(&["partner-provider"]));

        let mut replaced = legs_surface();
        points(&mut replaced)[1].id = "peer-replacement-id".into();
        assert_eq!(kept(&stored, &replaced), without(&["peer-provider", "bound"]));

        let mut added = legs_surface();
        let mut extra = points(&mut added)[1].clone();
        extra.id = "extra-id".into();
        extra.alias = "extra".into();
        extra.transit_credentials = None;
        extra.target_endpoint = "https://tenant.example".into();
        points(&mut added).push(extra);
        assert_eq!(kept(&stored, &added), without(&["bound"]));

        let mut removed_variant = legs_surface();
        removed_variant.variants[0].id = "other-variant-id".into();
        assert_eq!(kept(&stored, &removed_variant), Vec::<String>::new());

        assert_eq!(kept(&AgentSurface::default(), &stored), Vec::<String>::new());
    }

    #[test]
    fn an_appliance_wide_secret_is_refused_on_a_tenant_surface_when_new_and_when_enforced_but_not_when_stored_in_warn_mode()
     {
        let stored = vec![(ResourceKind::Secrets, "old".to_string())];
        let allowed = |isolation: RuleMode, id: &str, secret_tenant: Option<&str>| {
            can_reference_with_rule(
                Some("tenant-a"),
                secret_tenant,
                reference_rule(&stored, isolation, ResourceKind::Secrets, id),
            )
        };

        assert!(!allowed(RuleMode::Warn, "new", None));
        assert!(allowed(RuleMode::Warn, "old", None));
        assert!(!allowed(RuleMode::Enforce, "old", None));
        assert!(allowed(RuleMode::Warn, "new", Some("tenant-a")));
        assert!(allowed(RuleMode::Enforce, "new", Some("tenant-a")));
        assert!(!allowed(RuleMode::Warn, "old", Some("tenant-b")));
    }

    fn custom_metadata(payload: serde_json::Value) -> Option<crate::config::CustomMetadata> {
        Some(serde_json::from_value(serde_json::json!({"enabled": true, "payload": payload})).unwrap())
    }

    fn metadata_surface() -> AgentSurface {
        let mut surface = legs_surface();
        surface.target.custom_metadata = custom_metadata(serde_json::json!({"a": {"b": ["$SECRET:target-meta"]}}));
        surface
            .target
            .response_custom_metadata = custom_metadata(serde_json::json!({"x": "$SECRET:target-response"}));
        surface
            .access_point
            .response_custom_metadata = custom_metadata(serde_json::json!({"y": [{"z": "$SECRET:ap-response"}]}));
        surface
            .transit
            .as_mut()
            .unwrap()
            .shared
            .custom_metadata = custom_metadata(serde_json::json!({"t": {"u": "$SECRET:transit-meta"}}));
        surface
    }

    fn metadata_secrets(keys: &[SurfaceReferenceKey]) -> Vec<(String, bool, bool)> {
        keys.iter()
            .filter(|key| key.kind == ResourceKind::Secrets && key.id != "target-secret")
            .map(|key| (key.id.clone(), key.same_tenant, key.custom_metadata))
            .collect()
    }

    #[test]
    fn a_secret_helper_nested_in_any_custom_metadata_is_a_same_tenant_custom_metadata_reference() {
        let keys = collect_surface_reference_keys(&metadata_surface()).unwrap();

        assert_eq!(
            metadata_secrets(&keys),
            vec![
                ("ap-response".to_string(), true, true),
                ("target-meta".to_string(), true, true),
                ("target-response".to_string(), true, true),
                ("transit-meta".to_string(), true, true),
            ]
        );
        assert!(!key(&keys, ResourceKind::Secrets, "target-secret").custom_metadata);
    }

    #[test]
    fn only_a_whole_string_secret_helper_in_custom_metadata_is_a_reference() {
        let mut surface = AgentSurface::default();
        surface.target.custom_metadata = custom_metadata(serde_json::json!({
            "timestamp": "$TIMESTAMP", "surface": "$SURFACE_ID", "request": "$REQUEST_ID", "plain": "value",
            "embedded": "prefix $SECRET:embedded", "empty": "$SECRET:", "number": 7, "list": ["$TIMESTAMP", null]
        }));

        let keys = collect_surface_reference_keys(&surface).unwrap();

        assert_eq!(metadata_secrets(&keys), Vec::<(String, bool, bool)>::new());
    }

    #[test]
    fn shared_transit_custom_metadata_is_sent_only_through_a_transit_point() {
        let mut surface = AgentSurface {
            transit: Some(crate::config::agent_surface::TransitConfig {
                points: Vec::new(),
                outbound_listen_address: None,
                shared: serde_json::from_value(
                    serde_json::json!({"custom_metadata": {"payload": {"t": "$SECRET:transit-meta"}}}),
                )
                .unwrap(),
            }),
            ..Default::default()
        };
        assert_eq!(
            metadata_secrets(&collect_surface_reference_keys(&surface).unwrap()),
            Vec::<(String, bool, bool)>::new()
        );

        points(&mut surface).push(transit_point("partner", "tr-partner"));
        assert_eq!(
            metadata_secrets(&collect_surface_reference_keys(&surface).unwrap()),
            vec![("transit-meta".to_string(), true, true)]
        );
    }

    #[test]
    fn a_secret_in_custom_metadata_and_in_target_auth_must_exist_after_deduplication() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("shared-secret"));
        surface.target.custom_metadata = custom_metadata(serde_json::json!({"key": "$SECRET:shared-secret"}));

        let keys = collect_surface_reference_keys(&surface).unwrap();

        let shared = key(&keys, ResourceKind::Secrets, "shared-secret");
        assert!(shared.same_tenant);
        assert!(!shared.custom_metadata);
    }

    #[test]
    fn a_custom_metadata_secret_is_sent_on_the_leg_whose_metadata_names_it() {
        let sent = sent_credentials(&metadata_surface()).unwrap();
        let legs: HashSet<_> = sent
            .iter()
            .filter(|credential| {
                credential
                    .id
                    .ends_with("-meta")
                    || credential
                        .id
                        .ends_with("-response")
            })
            .map(|credential| {
                (
                    credential
                        .variant_id
                        .as_deref(),
                    credential
                        .transit_point_id
                        .as_deref(),
                    credential.endpoint.as_str(),
                    credential.id.as_str(),
                )
            })
            .collect();

        let mut expected = HashSet::new();
        for (variant, target_endpoint) in
            [(None, "https://target.example"), (Some("staging-id"), "https://staging.example")]
        {
            expected.extend([
                (variant, None, target_endpoint, "target-meta"),
                (variant, None, target_endpoint, "target-response"),
                (variant, None, target_endpoint, "ap-response"),
                (variant, Some("partner-id"), "https://partner.example", "transit-meta"),
                (variant, Some("peer-id"), "https://peer.example", "transit-meta"),
            ]);
        }
        assert_eq!(legs, expected);
    }

    #[test]
    fn a_stored_custom_metadata_secret_is_kept_only_while_its_leg_keeps_its_endpoint() {
        let stored = metadata_surface();
        let kept_metadata = |saved: &AgentSurface| -> Vec<String> {
            kept(&stored, saved)
                .into_iter()
                .filter(|key| key.ends_with("-meta") || key.ends_with("-response"))
                .collect()
        };
        let all = vec![
            "secrets:ap-response".to_string(),
            "secrets:target-meta".to_string(),
            "secrets:target-response".to_string(),
            "secrets:transit-meta".to_string(),
        ];
        assert_eq!(kept_metadata(&stored), all);

        let mut target = metadata_surface();
        target.target.endpoint = "https://tenant.example".into();
        assert_eq!(kept_metadata(&target), vec!["secrets:transit-meta".to_string()]);

        let mut partner = metadata_surface();
        points(&mut partner)[0].target_endpoint = "https://tenant.example".into();
        assert_eq!(kept_metadata(&partner), all[..3].to_vec());

        let mut moved = metadata_surface();
        moved.target.custom_metadata = custom_metadata(serde_json::json!({"a": "$SECRET:transit-meta"}));
        assert_eq!(
            kept_metadata(&moved),
            vec!["secrets:ap-response".to_string(), "secrets:target-response".to_string()]
        );
    }

    #[test]
    fn endpoint_id_extracts_only_the_authority_segment() {
        assert_eq!(endpoint_id("fabric://gateway-1/surface-1", "fabric://"), Some("gateway-1"));
        assert_eq!(endpoint_id("proxy://proxy-1", "proxy://"), Some("proxy-1"));
        assert_eq!(endpoint_id("https://example.com", "fabric://"), None);
        assert_eq!(endpoint_id("fabric://", "fabric://"), None);
    }

    #[test]
    fn collects_trust_registries_from_both_legs_and_variants() {
        let mut surface = AgentSurface::default();
        surface
            .access_point
            .trust_check_list = vec![trust_check("base-caller", "tr-base-caller")];
        surface
            .target
            .trust_check_list = vec![trust_check("base-target", "tr-base-target")];
        surface
            .access_point
            .trust_recorder = Some(TrustRecorderConfig {
            entries: vec![TrustRecorderEntry {
                trust_registry_id: "tr-base-recorder".into(),
                issuer_did: "did:example:issuer".into(),
                authority_did: "did:example:authority".into(),
                include_owned_agent: true,
                custom_resources: Vec::new(),
            }],
        });
        surface.variants = vec![SurfaceVariant {
            id: "variant-id".into(),
            alias: "variant".into(),
            name: "Variant".into(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                access_point: Some(AccessPointOverrides {
                    trust_check_list: Some(vec![trust_check("variant-caller", "tr-variant-caller")]),
                    trust_recorder: Some(TrustRecorderConfig {
                        entries: vec![TrustRecorderEntry {
                            trust_registry_id: "tr-variant-recorder".into(),
                            issuer_did: "did:example:variant-issuer".into(),
                            authority_did: "did:example:variant-authority".into(),
                            include_owned_agent: true,
                            custom_resources: Vec::new(),
                        }],
                    }),
                    ..Default::default()
                }),
                target: Some(TargetOverrides {
                    trust_check_list: Some(vec![trust_check("variant-target", "tr-variant-target")]),
                    ..Default::default()
                }),
                transit: Some(TransitOverrides {
                    points: Some(vec![transit_point("variant-tp", "tr-variant-tp")]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        }];
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![transit_point("base-tp", "tr-base-tp")],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let references = collect_surface_reference_keys(&surface).unwrap();
        let trust_registries: HashSet<_> = references
            .iter()
            .filter(|reference| reference.kind == ResourceKind::TrustRegistries)
            .map(|reference| reference.id.as_str())
            .collect();

        assert_eq!(
            trust_registries,
            HashSet::from([
                "tr-base-caller",
                "tr-base-target",
                "tr-base-recorder",
                "tr-variant-caller",
                "tr-variant-target",
                "tr-variant-recorder",
                "tr-base-tp",
                "tr-variant-tp",
            ])
        );
    }

    /// A Transit Point's own `source_auth` names secrets, JWT strategies, API-key
    /// parents and certificates that are checked like an Access Point's.
    #[test]
    fn collects_transit_point_source_auth_references_from_the_base_and_variants() {
        let point = |alias: &str, source_auth: serde_json::Value| -> crate::config::agent_surface::TransitPoint {
            serde_json::from_value(serde_json::json!({
                "alias": alias, "target_endpoint": "https://partner.example/a2a", "protocol": "a2a",
                "source_auth": source_auth
            }))
            .unwrap()
        };
        let header = serde_json::json!({"source": "http_header", "field": "x-api-key"});
        let transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![
                point("key", serde_json::json!({"type": "api_key", "extraction": header, "secret_id": "tp-secret"})),
                point(
                    "jwt",
                    serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "tp-strategy",
                                       "audiences": ["tp-audience"]}),
                ),
                point(
                    "mtls",
                    serde_json::json!({"type": "mtls", "trust": {"type": "pinned", "certificate_ids": ["tp-cert"]},
                                       "identity_binding": {"type": "fingerprint"}}),
                ),
            ],
            outbound_listen_address: None,
            shared: Default::default(),
        });
        let variants = vec![SurfaceVariant {
            id: "variant-id".into(),
            alias: "variant".into(),
            name: "Variant".into(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                transit: Some(TransitOverrides {
                    points: Some(vec![point(
                        "provider",
                        serde_json::json!({"type": "api_key_provider", "extraction": header,
                                           "agent_id": "tp-key-parent"}),
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        }];
        let surface = AgentSurface {
            transit,
            variants,
            ..Default::default()
        };

        let references: HashSet<_> = collect_surface_reference_keys(&surface)
            .unwrap()
            .into_iter()
            .map(|reference| (reference.kind.as_str(), reference.id))
            .collect();
        for (kind, id) in [
            (ResourceKind::Secrets, "tp-secret"),
            (ResourceKind::JwtVerificationStrategies, "tp-strategy"),
            (ResourceKind::Certificates, "tp-cert"),
            (ResourceKind::ApiKeys, "tp-key-parent"),
        ] {
            assert!(references.contains(&(kind.as_str(), id.to_string())), "{kind} {id} missing from {references:?}");
        }
    }
}
