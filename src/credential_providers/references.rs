//! What still uses a credential provider, a secret, a JWT verification strategy or an
//! Authority, so deleting it, or retyping a provider, can be refused while something would
//! break.

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::auth::types::UserRole;
use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard, pat_scope_allows};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::config::TargetAuthMethod;
use crate::config::agent_surface::AgentSurface;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource};
use crate::trust_registry_verification::authority_source::{
    AuthorityReference, AuthorityUse, surface_references, trust_check_references,
};

use super::storage::CredentialProviderStorage;

/// The stores whose records may name a credential provider or a secret. A store that is not
/// configured holds no records.
#[derive(Clone, Default)]
pub struct ReferenceStores {
    pub surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    pub credential_providers: Option<Arc<dyn CredentialProviderStorage>>,
    pub a2a_proxies: Option<Arc<dyn crate::a2a_proxies::A2aProxyStore>>,
    pub sts_clients: Option<Arc<dyn crate::sts::store::StsClientStorage>>,
}

/// A record that names the credential provider, secret or Authority being changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referrer {
    pub kind: ResourceKind,
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
    /// The record's Trust Checks and Trust Recorder entries that use the Authority being
    /// deleted; empty for any other resource.
    pub uses: Vec<AuthorityUse>,
}

/// The kinds of referrer whose view permission the caller holds. A referrer of any other kind
/// is counted, not named.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewableKinds(Vec<ResourceKind>);

impl ViewableKinds {
    /// The kinds the authenticated caller may view: none when the request carries no
    /// authenticated user or the routes have no RBAC guard.
    pub async fn of_caller(
        rbac: Option<&RbacGuard>,
        caller: Option<&AuthGuardOk>,
        pat: Option<&PatContext>,
    ) -> Self {
        let (Some(rbac), Some(AuthGuardOk(user_id))) = (rbac, caller) else {
            return Self::default();
        };
        match rbac
            .storage
            .load_user_by_id(user_id)
            .await
        {
            Ok(Some(user)) => Self::for_role(&rbac.rbac_config, &user.role, pat),
            Ok(None) => Self::default(),
            Err(error) => {
                tracing::warn!(%error, "Failed to load the caller to list the references it may view");
                Self::default()
            }
        }
    }

    /// The kinds whose view permission `role` holds and an access token's scopes, if
    /// restricted, include.
    pub fn for_role(
        config: &RbacConfig,
        role: &UserRole,
        pat: Option<&PatContext>,
    ) -> Self {
        Self(
            [
                (ResourceKind::Surfaces, Feature::SurfacesView),
                (ResourceKind::CredentialProviders, Feature::CredentialProvidersView),
                (ResourceKind::A2aProxies, Feature::A2aProxiesView),
                (ResourceKind::StsClients, Feature::StsClientsView),
            ]
            .into_iter()
            .filter(|(_, feature)| config.has_permission(role, feature) && pat_scope_allows(pat, feature))
            .map(|(kind, _)| kind)
            .collect(),
        )
    }
}

impl Referrer {
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            ResourceKind::Surfaces => "surface",
            ResourceKind::CredentialProviders => "credential_provider",
            ResourceKind::A2aProxies => "a2a_proxy",
            ResourceKind::StsClients => "sts_client",
            other => other.as_str(),
        }
    }

    fn visible_to(
        &self,
        viewable: &ViewableKinds,
        context: Option<&PatTenantContext>,
        scope: Option<&PatResourceScope>,
    ) -> bool {
        viewable
            .0
            .contains(&self.kind)
            && can_access(self.tenant_id.as_deref(), context)
            && scope_allows_resource(scope, context, self.kind, &self.id)
    }

    fn sts_client(client: &crate::sts::store::StsClient) -> Self {
        Self {
            kind: ResourceKind::StsClients,
            id: client.id.clone(),
            name: client.name.clone(),
            tenant_id: client.tenant_id.clone(),
            uses: Vec::new(),
        }
    }

    pub fn credential_provider(provider: &super::CredentialProvider) -> Self {
        Self {
            kind: ResourceKind::CredentialProviders,
            id: provider.id.clone(),
            name: provider.name.clone(),
            tenant_id: provider.tenant_id.clone(),
            uses: Vec::new(),
        }
    }

    fn surface(surface: &AgentSurface) -> Self {
        Self {
            kind: ResourceKind::Surfaces,
            id: surface.surface_id.clone(),
            name: surface.name.clone(),
            tenant_id: surface.tenant_id.clone(),
            uses: Vec::new(),
        }
    }
}

impl ReferenceStores {
    /// The surfaces whose Target authentication, on the Target or a Transit Point of the base
    /// surface or any variant, uses credential provider `provider_id`.
    pub async fn target_auth_referrers_of_provider(
        &self,
        provider_id: &str,
    ) -> anyhow::Result<Vec<Referrer>> {
        self.surfaces_where(|surface| {
            target_auth_provider_ids(surface)
                .iter()
                .any(|id| id == provider_id)
        })
        .await
    }

    /// The surfaces, credential providers, A2A proxies and STS clients that name secret
    /// `secret_id`.
    pub async fn referrers_of_secret(
        &self,
        secret_id: &str,
    ) -> anyhow::Result<Vec<Referrer>> {
        let mut referrers = self
            .surfaces_where(|surface| {
                surface_reference_ids(surface, ResourceKind::Secrets).contains(&secret_id.to_string())
            })
            .await?;
        if let Some(store) = &self.credential_providers {
            referrers.extend(
                store
                    .list()
                    .await?
                    .into_iter()
                    .filter(|provider| {
                        provider
                            .secret_refs()
                            .contains(&secret_id)
                    })
                    .map(|provider| Referrer {
                        kind: ResourceKind::CredentialProviders,
                        id: provider.id,
                        name: provider.name,
                        tenant_id: provider.tenant_id,
                        uses: Vec::new(),
                    }),
            );
        }
        if let Some(store) = &self.a2a_proxies {
            referrers.extend(
                store
                    .list_all()
                    .await?
                    .into_iter()
                    .filter(|proxy| match &proxy.backend {
                        crate::a2a_proxies::types::A2aProxyBackend::CopilotDirectLine(backend) => {
                            backend.secret_id == secret_id
                        }
                    })
                    .map(|proxy| Referrer {
                        kind: ResourceKind::A2aProxies,
                        id: proxy.id,
                        name: proxy.name,
                        tenant_id: proxy.tenant_id,
                        uses: Vec::new(),
                    }),
            );
        }
        if let Some(store) = &self.sts_clients {
            referrers.extend(
                store
                    .list()
                    .await?
                    .into_iter()
                    .filter(|client| {
                        client
                            .client_secret_ref
                            .as_deref()
                            == Some(secret_id)
                    })
                    .map(|client| Referrer::sts_client(&client)),
            );
        }
        Ok(referrers)
    }

    /// The surfaces and STS clients whose Trust Checks or Trust Recorder entries name the
    /// Authority whose DID is `did` and owned by `tenant_id`, each with the elements that name
    /// it. A record of a tenant that may not use the Authority only names the same DID, so it
    /// neither holds the Authority nor learns of it.
    pub async fn referrers_of_authority(
        &self,
        did: &str,
        tenant_id: Option<&str>,
    ) -> anyhow::Result<Vec<Referrer>> {
        let mut referrers = Vec::new();
        if let Some(store) = &self.surfaces {
            for surface in store
                .list_all()
                .await?
                .into_iter()
                .filter(|surface| can_reference(surface.tenant_id.as_deref(), tenant_id))
            {
                let uses = uses_of_authority(surface_references(&surface), did);
                if !uses.is_empty() {
                    referrers.push(Referrer {
                        uses,
                        ..Referrer::surface(&surface)
                    });
                }
            }
        }
        if let Some(store) = &self.sts_clients {
            for client in store
                .list()
                .await?
                .into_iter()
                .filter(|client| can_reference(client.tenant_id.as_deref(), tenant_id))
            {
                let uses = uses_of_authority(trust_check_references(&client.trust_check_list), did);
                if !uses.is_empty() {
                    referrers.push(Referrer {
                        uses,
                        ..Referrer::sts_client(&client)
                    });
                }
            }
        }
        Ok(referrers)
    }

    /// The credential providers whose `consent_confirmation` or
    /// `consent_identity_strategy_id` names JWT verification strategy `strategy_id`.
    pub async fn referrers_of_jwt_strategy(
        &self,
        strategy_id: &str,
    ) -> anyhow::Result<Vec<Referrer>> {
        Ok(self
            .providers_of_jwt_strategy(strategy_id)
            .await?
            .iter()
            .map(Referrer::credential_provider)
            .collect())
    }

    /// The credential providers [`Self::referrers_of_jwt_strategy`] names.
    pub async fn providers_of_jwt_strategy(
        &self,
        strategy_id: &str,
    ) -> anyhow::Result<Vec<super::CredentialProvider>> {
        let Some(store) = &self.credential_providers else {
            return Ok(Vec::new());
        };
        Ok(store
            .list()
            .await?
            .into_iter()
            .filter(|provider| {
                provider
                    .consent_confirmation
                    .as_ref()
                    .is_some_and(|confirmation| confirmation.jwt_verification_strategy_id == strategy_id)
                    || provider
                        .consent_identity_strategy_id
                        .as_deref()
                        == Some(strategy_id)
            })
            .collect())
    }

    async fn surfaces_where(
        &self,
        names_it: impl Fn(&AgentSurface) -> bool,
    ) -> anyhow::Result<Vec<Referrer>> {
        let Some(store) = &self.surfaces else {
            return Ok(Vec::new());
        };
        Ok(store
            .list_all()
            .await?
            .iter()
            .filter(|surface| names_it(surface))
            .map(Referrer::surface)
            .collect())
    }
}

fn uses_of_authority(
    references: Vec<AuthorityReference>,
    did: &str,
) -> Vec<AuthorityUse> {
    references
        .into_iter()
        .filter(|reference| reference.did == did)
        .map(|reference| reference.used_by)
        .collect()
}

/// The ids of `kind` the surface references. A surface whose variants cannot be resolved
/// counts as naming every id its stored record contains, so the scan never misses one.
fn surface_reference_ids(
    surface: &AgentSurface,
    kind: ResourceKind,
) -> Vec<String> {
    match crate::identity::handlers::surface_tenancy::collect_surface_reference_keys(surface) {
        Ok(references) => references
            .into_iter()
            .filter(|reference| reference.kind == kind)
            .map(|reference| reference.id)
            .collect(),
        Err(_) => string_values(surface),
    }
}

pub(crate) fn target_auth_provider_ids(surface: &AgentSurface) -> Vec<String> {
    let Ok(views) = crate::identity::handlers::surface_tenancy::resolved_views(surface) else {
        return string_values(surface);
    };
    views
        .iter()
        .flat_map(|view| {
            let transit_points = view
                .transit
                .iter()
                .flat_map(|transit| transit.points.iter())
                .filter_map(|point| point.target_auth.as_ref());
            view.target
                .auth
                .iter()
                .chain(transit_points)
                .filter_map(|authentication| match &authentication.method {
                    TargetAuthMethod::CredentialProvider { provider_id, .. } => Some(provider_id.clone()),
                    TargetAuthMethod::StaticSecret { .. } | TargetAuthMethod::CredentialLookup => None,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn string_values(surface: &AgentSurface) -> Vec<String> {
    fn walk(
        value: &serde_json::Value,
        found: &mut Vec<String>,
    ) {
        match value {
            serde_json::Value::String(text) => found.push(text.clone()),
            serde_json::Value::Array(items) => items
                .iter()
                .for_each(|item| walk(item, found)),
            serde_json::Value::Object(fields) => fields
                .values()
                .for_each(|field| walk(field, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(&serde_json::to_value(surface).unwrap_or_default(), &mut found);
    found
}

#[derive(serde::Serialize)]
struct ReferenceView<'a> {
    kind: &'static str,
    id: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "<[AuthorityUse]>::is_empty")]
    uses: &'a [AuthorityUse],
}

/// Whether the caller may view every one of `referrers`.
pub fn all_visible(
    referrers: &[Referrer],
    viewable: &ViewableKinds,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    referrers
        .iter()
        .all(|referrer| referrer.visible_to(viewable, context, scope))
}

/// The 409 answer for a change refused while `referrers` use the resource: the referrers the
/// caller may view (a kind in `viewable`, its tenant's or appliance-wide, within its resource
/// pattern), and a count of the rest.
pub fn conflict_response(
    message: &str,
    referrers: &[Referrer],
    viewable: &ViewableKinds,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Response {
    let (visible, hidden): (Vec<&Referrer>, Vec<&Referrer>) = referrers
        .iter()
        .partition(|referrer| referrer.visible_to(viewable, context, scope));
    let references: Vec<ReferenceView<'_>> = visible
        .iter()
        .map(|referrer| ReferenceView {
            kind: referrer.kind_label(),
            id: &referrer.id,
            name: &referrer.name,
            uses: &referrer.uses,
        })
        .collect();
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "message": message,
            "references": references,
            "hidden_references": hidden.len(),
        })),
    )
        .into_response()
}

/// An authenticated administrator for handler tests, with the RBAC guard that knows them.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) struct Administrator {
        pub rbac: RbacGuard,
        pub caller: AuthGuardOk,
        _storage: tempfile::TempDir,
    }

    pub(crate) async fn administrator() -> Administrator {
        let storage = tempfile::tempdir().unwrap();
        let users = storage.path().join("users");
        let avatars = storage.path().join("avatars");
        std::fs::create_dir_all(&users).unwrap();
        std::fs::create_dir_all(&avatars).unwrap();
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let user = serde_json::json!({
            "user_id": user_id, "username": "reference-admin", "passkeys": [],
            "role": "administrator", "status": "approved", "created_at": now, "updated_at": now
        });
        std::fs::write(users.join(format!("{user_id}.json")), user.to_string()).unwrap();
        let passkeys = crate::auth::storage::PasskeyStorage::new(
            users
                .to_string_lossy()
                .into_owned(),
            avatars
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        Administrator {
            rbac: RbacGuard::new(Arc::new(passkeys), Arc::new(RbacConfig::default())),
            caller: AuthGuardOk(user_id),
            _storage: storage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn surface() -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "s", "name": "S",
            "access_point": {
                "listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "secret_id": "caller-key",
                    "extraction": {"source": "http_header", "field": "X-Caller-Key"}
                }]}
            },
            "target": {"endpoint": "https://api.example.com"},
            "caller_key": {"secret_id": "memory-keys"},
            "outbound_credentials": [{"credential_provider_id": "bound-provider"}],
            "transit": {"points": [{
                "id": "partner-id", "alias": "partner", "target_endpoint": "https://partner.example.com",
                "protocol": "a2a",
                "target_auth": {"method": {"static_secret": {"secret_id": "partner-key", "header_name": "X-Key"}}},
                "transit_credentials": {"credential_provider_id": "transit-provider"}
            }]},
            "variants": [{
                "id": "staging-id", "alias": "staging", "name": "Staging",
                "overrides": {"target": {"endpoint": "https://staging.example.com", "auth": {"method": {
                    "credential_provider": {"provider_id": "variant-provider"}
                }}}}
            }]
        }))
        .unwrap()
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids.dedup();
        ids
    }

    #[test]
    fn a_surface_names_the_providers_and_secrets_of_every_leg_and_variant() {
        assert_eq!(
            sorted(surface_reference_ids(&surface(), ResourceKind::CredentialProviders)),
            ["bound-provider", "transit-provider", "variant-provider"]
        );
        assert_eq!(
            sorted(surface_reference_ids(&surface(), ResourceKind::Secrets)),
            ["caller-key", "memory-keys", "partner-key"]
        );
        assert_eq!(sorted(target_auth_provider_ids(&surface())), ["variant-provider"]);
    }

    #[test]
    fn the_fallback_for_an_unresolvable_surface_holds_every_id_it_stores() {
        let values = string_values(&surface());
        for id in ["caller-key", "memory-keys", "partner-key", "bound-provider", "transit-provider", "variant-provider"]
        {
            assert!(values.contains(&id.to_string()), "{id}");
        }
    }

    #[tokio::test]
    async fn no_store_means_no_referrer() {
        let stores = ReferenceStores::default();
        assert!(
            stores
                .referrers_of_secret("caller-key")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            stores
                .target_auth_referrers_of_provider("bound-provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_authority_is_used_by_the_surfaces_and_sts_clients_whose_checks_name_it() {
        use crate::sts::store::StsClientStorage;
        use crate::surfaces::AgentSurfaceStore;

        let dir = tempfile::tempdir().unwrap();
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(dir.path().join("surfaces"))
                .await
                .unwrap(),
        );
        let sts_clients = Arc::new(
            crate::sts::store::FileSystemStsClientStore::new(dir.path().join("sts"))
                .await
                .unwrap(),
        );
        let check = |id: &str, did: &str| {
            json!({
                "id": id, "trust_registry_id": "tr-1", "query_type": "recognition", "authority_source": "authority",
                "query": {"authority_id": did, "entity_id": "{{ input.agent.did }}"}
            })
        };
        let surface = |id: &str, did: &str| -> AgentSurface {
            serde_json::from_value(json!({
                "surface_id": id, "name": format!("{id} name"),
                "access_point": {
                    "listen_address": "0.0.0.0:8443", "route": format!("/{id}"), "protocol": "a2a",
                    "trust_check_list": [check(&format!("{id}-check"), did)],
                    "trust_recorder": {"entries": [{
                        "trust_registry_id": "tr-rec", "issuer_did": "did:web:issuer", "authority_did": did
                    }]}
                },
                "target": {"endpoint": "https://api.example.com"}
            }))
            .unwrap()
        };
        surfaces
            .save(&surface("orders", "did:web:acme"))
            .await
            .unwrap();
        surfaces
            .save(&surface("billing", "did:web:other"))
            .await
            .unwrap();
        let mut partners = surface("partners", "did:web:other");
        partners
            .access_point
            .trust_check_list = vec![
            serde_json::from_value(json!({
                "id": "partners-check", "trust_registry_id": "tr-1", "query_type": "recognition",
                "query": {"authority_ids": ["did:web:other", "did:web:acme"], "entity_id": "{{ input.agent.did }}"},
                "authority_sources": {"did:web:acme": "authority"}
            }))
            .unwrap(),
        ];
        surfaces
            .save(&partners)
            .await
            .unwrap();
        let client: crate::sts::store::StsClient = serde_json::from_value(json!({
            "id": "client-1", "client_id": "cli", "name": "CLI",
            "trust_check_list": [check("sts-check", "did:web:acme")],
            "created_at": chrono::Utc::now(), "updated_at": chrono::Utc::now()
        }))
        .unwrap();
        sts_clients
            .create(client)
            .await
            .unwrap();
        let stores = ReferenceStores {
            surfaces: Some(surfaces),
            sts_clients: Some(sts_clients),
            ..Default::default()
        };

        let mut referrers = stores
            .referrers_of_authority("did:web:acme", None)
            .await
            .unwrap();
        referrers.sort_by(|a, b| a.id.cmp(&b.id));
        assert!(
            stores
                .referrers_of_authority("did:web:unused", None)
                .await
                .unwrap()
                .is_empty()
        );

        let all = ViewableKinds::for_role(&RbacConfig::default(), &UserRole::Administrator, None);
        let refusal = body(conflict_response("in use", &referrers, &all, None, None)).await;
        assert_eq!(
            refusal["references"],
            json!([
                {"kind": "sts_client", "id": "client-1", "name": "CLI", "uses": [
                    {"element": "trust_check", "id": "sts-check"}
                ]},
                {"kind": "surface", "id": "orders", "name": "orders name", "uses": [
                    {"element": "trust_check", "id": "orders-check", "placement": "access_point"},
                    {"element": "trust_recorder", "trust_registry_id": "tr-rec"}
                ]},
                {"kind": "surface", "id": "partners", "name": "partners name", "uses": [
                    {"element": "trust_check", "id": "partners-check", "placement": "access_point"}
                ]}
            ])
        );
        let surfaces_only = ViewableKinds(vec![ResourceKind::Surfaces]);
        let partial = body(conflict_response("in use", &referrers, &surfaces_only, None, None)).await;
        assert_eq!(partial["references"][0]["id"], "orders");
        assert_eq!(partial["hidden_references"], 1, "the STS client is counted, not named or described");
    }

    #[tokio::test]
    async fn a_tenant_authority_is_used_only_by_records_of_its_own_tenant() {
        use crate::surfaces::AgentSurfaceStore;

        let dir = tempfile::tempdir().unwrap();
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(dir.path().join("surfaces"))
                .await
                .unwrap(),
        );
        for (id, tenant) in [("own", Some("tenant-a")), ("other", Some("tenant-b")), ("appliance", None)] {
            let surface: AgentSurface = serde_json::from_value(json!({
                "surface_id": id, "name": id, "tenant_id": tenant,
                "access_point": {
                    "listen_address": "0.0.0.0:8443", "route": format!("/{id}"), "protocol": "a2a",
                    "trust_check_list": [{
                        "id": "check", "trust_registry_id": "tr-1", "query_type": "recognition",
                        "query": {"authority_id": "did:web:acme", "entity_id": "{{ input.agent.did }}"}
                    }]
                },
                "target": {"endpoint": "https://api.example.com"}
            }))
            .unwrap();
            surfaces
                .save(&surface)
                .await
                .unwrap();
        }
        let stores = ReferenceStores {
            surfaces: Some(surfaces),
            ..Default::default()
        };
        let ids = |referrers: Vec<Referrer>| {
            let mut ids: Vec<String> = referrers
                .into_iter()
                .map(|referrer| referrer.id)
                .collect();
            ids.sort();
            ids
        };

        let tenant_owned = stores
            .referrers_of_authority("did:web:acme", Some("tenant-a"))
            .await
            .unwrap();
        let appliance_wide = stores
            .referrers_of_authority("did:web:acme", None)
            .await
            .unwrap();

        assert_eq!(ids(tenant_owned), ["own"], "another tenant's or an appliance-wide record does not hold it");
        assert_eq!(ids(appliance_wide), ["appliance", "other", "own"]);
    }

    #[tokio::test]
    async fn a_consent_confirmation_client_id_and_secret_make_their_provider_a_referrer_of_the_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
                directory.path().to_path_buf(),
            )
            .await
            .unwrap(),
        );
        let provider =
            |id: &str, consent_confirmation: serde_json::Value| -> crate::credential_providers::CredentialProvider {
                serde_json::from_value(json!({
                    "id": id, "name": id, "provider_id": id, "provider_type": "oauth2_authorization_code",
                    "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                    "consent_confirmation": consent_confirmation,
                    "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"
                }))
                .unwrap()
            };
        let confirmation = json!({
            "client_id_secret_ref": "LOGIN_CLIENT_ID", "client_secret_secret_ref": "LOGIN_SECRET",
            "authorization_endpoint": "https://idp.example/authorize", "token_endpoint": "https://idp.example/token",
            "jwt_verification_strategy_id": "strategy"
        });
        for stored in [provider("confirming", confirmation), provider("plain", serde_json::Value::Null)] {
            store
                .create(stored)
                .await
                .unwrap();
        }
        let stores = ReferenceStores {
            credential_providers: Some(store),
            ..Default::default()
        };
        let ids = |referrers: Vec<Referrer>| {
            sorted(
                referrers
                    .into_iter()
                    .map(|referrer| referrer.id)
                    .collect(),
            )
        };
        for (case, login_secret) in ["LOGIN_CLIENT_ID", "LOGIN_SECRET"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                ids(stores
                    .referrers_of_secret(login_secret)
                    .await
                    .unwrap()),
                ["confirming"],
                "login client secret {case}"
            );
        }
        assert_eq!(
            ids(stores
                .referrers_of_secret("CLIENT_SECRET")
                .await
                .unwrap()),
            ["confirming", "plain"]
        );
    }

    async fn body(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_conflict_lists_the_referrers_the_caller_may_view_and_counts_the_rest() {
        let referrer = |kind, id: &str, tenant_id: Option<&str>| Referrer {
            kind,
            id: id.into(),
            name: format!("{id} name"),
            tenant_id: tenant_id.map(str::to_string),
            uses: Vec::new(),
        };
        let referrers = [
            referrer(ResourceKind::Surfaces, "own-surface", Some("tenant-a")),
            referrer(ResourceKind::Surfaces, "other-surface", Some("tenant-b")),
            referrer(ResourceKind::CredentialProviders, "shared-provider", None),
            referrer(ResourceKind::StsClients, "own-client", Some("tenant-a")),
        ];
        let all = ViewableKinds::for_role(&RbacConfig::default(), &UserRole::Administrator, None);
        let everything = body(conflict_response("in use", &referrers, &all, None, None)).await;
        assert_eq!(everything["message"], "in use");
        assert_eq!(
            everything["references"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(everything["hidden_references"], 0);

        let tenant = PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(regex::Regex::new("^TENANT:tenant-a:surfaces:.*$").unwrap()));
        let scoped = body(conflict_response("in use", &referrers, &all, Some(&tenant), Some(&scope))).await;
        assert_eq!(scoped["references"], json!([{"kind": "surface", "id": "own-surface", "name": "own-surface name"}]));
        assert_eq!(scoped["hidden_references"], 3);
        let unscoped = body(conflict_response("in use", &referrers, &all, Some(&tenant), None)).await;
        assert_eq!(
            unscoped["references"],
            json!([
                {"kind": "surface", "id": "own-surface", "name": "own-surface name"},
                {"kind": "credential_provider", "id": "shared-provider", "name": "shared-provider name"},
                {"kind": "sts_client", "id": "own-client", "name": "own-client name"}
            ])
        );
        assert_eq!(unscoped["hidden_references"], 1);
    }

    #[test]
    fn a_referrer_is_named_only_when_the_caller_holds_the_view_permission_of_its_kind() {
        let config = RbacConfig::default();
        let delete_only = PatContext(Some(vec!["credential_providers.delete".into()]));
        assert_eq!(
            ViewableKinds::for_role(&config, &UserRole::Administrator, Some(&delete_only)),
            ViewableKinds::default()
        );
        let with_surfaces = PatContext(Some(vec!["credential_providers.delete".into(), "surfaces.view".into()]));
        assert_eq!(
            ViewableKinds::for_role(&config, &UserRole::Administrator, Some(&with_surfaces)),
            ViewableKinds(vec![ResourceKind::Surfaces])
        );
        assert_eq!(
            ViewableKinds::for_role(&config, &UserRole::Administrator, None),
            ViewableKinds(vec![
                ResourceKind::Surfaces,
                ResourceKind::CredentialProviders,
                ResourceKind::A2aProxies,
                ResourceKind::StsClients
            ])
        );
        let mut no_surfaces = RbacConfig::default();
        no_surfaces
            .permissions
            .insert("surfaces.view".into(), "administrator".into());
        assert!(
            !ViewableKinds::for_role(&no_surfaces, &UserRole::User, None)
                .0
                .contains(&ResourceKind::Surfaces),
            "a role without surfaces.view"
        );
    }

    #[tokio::test]
    async fn a_caller_without_an_authenticated_user_or_guard_may_view_no_kind() {
        let admin = test_support::administrator().await;
        assert_eq!(ViewableKinds::of_caller(None, Some(&admin.caller), None).await, ViewableKinds::default());
        assert_eq!(ViewableKinds::of_caller(Some(&admin.rbac), None, None).await, ViewableKinds::default());
        let unknown = AuthGuardOk("no-such-user".into());
        assert_eq!(ViewableKinds::of_caller(Some(&admin.rbac), Some(&unknown), None).await, ViewableKinds::default());
        assert_eq!(
            ViewableKinds::of_caller(Some(&admin.rbac), Some(&admin.caller), None)
                .await
                .0
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn a_referrer_of_a_kind_the_caller_may_not_view_is_counted_not_named() {
        let referrers = [Referrer {
            kind: ResourceKind::Surfaces,
            id: "orders".into(),
            name: "Orders".into(),
            tenant_id: None,
            uses: Vec::new(),
        }];
        let providers_only = ViewableKinds(vec![ResourceKind::CredentialProviders]);
        let hidden = body(conflict_response("in use", &referrers, &providers_only, None, None)).await;
        assert_eq!(hidden["references"], json!([]));
        assert_eq!(hidden["hidden_references"], 1);
        assert!(
            !hidden
                .to_string()
                .contains("Orders"),
            "{hidden}"
        );
    }
}
