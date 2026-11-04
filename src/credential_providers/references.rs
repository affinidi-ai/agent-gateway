//! What still uses a credential provider or a secret, so deleting it, or retyping a provider,
//! can be refused while something would break.

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
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

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

/// A record that names the credential provider or secret being changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referrer {
    pub kind: ResourceKind,
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
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
    fn kind_label(&self) -> &'static str {
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

    fn surface(surface: &AgentSurface) -> Self {
        Self {
            kind: ResourceKind::Surfaces,
            id: surface.surface_id.clone(),
            name: surface.name.clone(),
            tenant_id: surface.tenant_id.clone(),
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
                    .map(|client| Referrer {
                        kind: ResourceKind::StsClients,
                        id: client.id,
                        name: client.name,
                        tenant_id: client.tenant_id,
                    }),
            );
        }
        Ok(referrers)
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

fn target_auth_provider_ids(surface: &AgentSurface) -> Vec<String> {
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
    let references: Vec<serde_json::Value> = visible
        .iter()
        .map(|referrer| serde_json::json!({ "kind": referrer.kind_label(), "id": referrer.id, "name": referrer.name }))
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
        assert_eq!(sorted(surface_reference_ids(&surface(), ResourceKind::Secrets)), ["caller-key", "partner-key"]);
        assert_eq!(sorted(target_auth_provider_ids(&surface())), ["variant-provider"]);
    }

    #[test]
    fn the_fallback_for_an_unresolvable_surface_holds_every_id_it_stores() {
        let values = string_values(&surface());
        for id in ["caller-key", "partner-key", "bound-provider", "transit-provider", "variant-provider"] {
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
