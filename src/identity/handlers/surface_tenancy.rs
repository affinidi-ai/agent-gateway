use std::collections::HashSet;

use crate::a2a_proxies::A2aProxyStore;
use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, McpToolGatingConfig};
use crate::config::{TargetAuthConfig, TargetAuthMethod};
use crate::gateways::GatewayStore;
use crate::identity::state::IdentityApiState;
use crate::issuers::IssuerStore;
use crate::mcp_proxies::McpProxyStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_reference, scope_allows_resource};
use crate::trust_registries::TrustRegistryStore;

use super::surfaces::SurfaceApiError;

pub async fn validate_surface_references(
    state: &IdentityApiState,
    surface: &AgentSurface,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), SurfaceApiError> {
    let authorizer = ReferenceAuthorizer {
        state,
        owner_tenant_id: surface.tenant_id.as_deref(),
        context,
        scope,
        current_surface_id: &surface.surface_id,
    };

    for reference in collect_surface_reference_keys(surface)? {
        authorizer
            .validate_reference(&reference)
            .await?;
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SurfaceReferenceKey {
    pub kind: ResourceKind,
    pub id: String,
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
    references.dedup_by(|left, right| left.kind == right.kind && left.id == right.id);
    Ok(references)
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
}

impl ReferenceAuthorizer<'_> {
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
            ResourceKind::Secrets => {
                self.secret(&reference.id)
                    .await
            }
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
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable("Secret"))?;
        let resource = store
            .get_by_secret_id(id)
            .await
            .map_err(|error| internal("Secret", error))?
            .ok_or_else(|| inaccessible("Secret"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Secrets, &resource.secret_id, "Secret")
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
            collect_target_auth_reference(point.target_auth.as_ref(), references);
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

fn collect_target_auth_reference(
    authentication: Option<&TargetAuthConfig>,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    if let Some(TargetAuthConfig {
        method: TargetAuthMethod::StaticSecret { secret_id, .. },
        ..
    }) = authentication
    {
        push_reference(references, ResourceKind::Secrets, secret_id);
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
    if !id.trim().is_empty() {
        references.push(SurfaceReferenceKey { kind, id: id.to_string() });
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
        AccessPointOverrides, SurfaceOverrides, SurfaceVariant, TargetOverrides,
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
                ..Default::default()
            },
        }];

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
            ])
        );
    }
}
