//! Save-time checks for a signing choice: a surface's or an issuer's `signing` block and the
//! gateway-wide `default_signing`. All three are checked the same way, so a choice that one of
//! them refuses can't be stored through another.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard, caller_allows};
use crate::auth_manager::pat::PatContext;
use crate::config::agent_surface::{SigningBackendKind, SurfaceSigningConfig};
use crate::config::vta::{KeyPurpose, VtaConfig};
use crate::rbac::Feature;
use crate::vta::connections::VtaConnectionStorage;

/// What a signing choice is saved for.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SigningOwner<'a> {
    /// A surface or an issuer, owned by this tenant or, with `None`, by the whole appliance.
    Resource(Option<&'a str>),
    /// The gateway-wide default that every surface and issuer without a choice of its own follows.
    Appliance,
}

#[derive(Debug)]
pub(crate) enum SigningChoiceError {
    /// The choice can't be stored; the message says why.
    Invalid(String),
    /// The trust agent connection store could not be read.
    Store(String),
}

pub(crate) const VTA_BLOCK_REQUIRED: &str = "signing.connection_id is required: with none, or with `default` or \
     `vta-bootstrap`, the choice signs through the `[vta]` block, which is not enabled on this gateway";

/// Whether `signing` signs through the `[vta]` block: it names no connection, or the
/// ids that stand for that block.
fn names_the_vta_block(signing: &SurfaceSigningConfig) -> bool {
    signing
        .connection_id
        .as_deref()
        .is_none_or(|id| {
            id == crate::vta::key_directory::DEFAULT_CONNECTION_ID
                || id == crate::vta::connections::BOOTSTRAP_CONNECTION_ID
        })
}

pub(crate) const APPLIANCE_CONNECTION_REQUIRED: &str =
    "signing.connection_id must name an existing trust agent connection that belongs to the whole appliance";

/// Refuses a signing choice that can't sign a token, that asks for a context this gateway can't
/// create, or that names a trust agent connection its owner may not sign through. The gateway-wide
/// default may only name an existing connection that belongs to no tenant.
pub(crate) async fn validate_signing_choice(
    signing: &SurfaceSigningConfig,
    owner: SigningOwner<'_>,
    connections: Option<&dyn VtaConnectionStorage>,
    vta: &VtaConfig,
) -> Result<(), SigningChoiceError> {
    crate::vta::key_directory::signing_key_ref(signing, KeyPurpose::Jwt)
        .map_err(|error| SigningChoiceError::Invalid(error.log_detail().to_string()))?;
    if signing.backend == Some(SigningBackendKind::Vta)
        && signing.context_id.is_none()
        && !crate::vta::key_directory::provisions_contexts_on(
            vta,
            signing
                .connection_id
                .as_deref(),
        )
    {
        return Err(SigningChoiceError::Invalid(
            "signing.context_id is required because this gateway creates VTA contexts only through an enabled \
             `[vta]` connection with `auto_provision_contexts` set (the agent grant must carry `context-create`); \
             name an existing context"
                .to_string(),
        ));
    }
    if signing.backend == Some(SigningBackendKind::Vta) && !vta.enabled && names_the_vta_block(signing) {
        return Err(SigningChoiceError::Invalid(VTA_BLOCK_REQUIRED.to_string()));
    }
    match owner {
        SigningOwner::Resource(tenant_id) => {
            super::surface_tenancy::check_signing_connection(connections, tenant_id, signing)
                .await
                .map_err(|error| match error {
                    super::surface_tenancy::SigningConnectionError::NotAccessible
                    | super::surface_tenancy::SigningConnectionError::ContextNotOwned => {
                        SigningChoiceError::Invalid(error.message())
                    }
                    super::surface_tenancy::SigningConnectionError::Store(_) => {
                        SigningChoiceError::Store(error.message())
                    }
                })
        }
        SigningOwner::Appliance => check_appliance_connection(signing, connections).await,
    }
}

async fn check_appliance_connection(
    signing: &SurfaceSigningConfig,
    connections: Option<&dyn VtaConnectionStorage>,
) -> Result<(), SigningChoiceError> {
    let Some(connection_id) = signing
        .connection_id
        .as_deref()
    else {
        return Ok(());
    };
    if connection_id == crate::vta::connections::BOOTSTRAP_CONNECTION_ID
        || connection_id == crate::vta::key_directory::DEFAULT_CONNECTION_ID
    {
        return Ok(());
    }
    let Some(store) = connections else {
        return Err(SigningChoiceError::Invalid(APPLIANCE_CONNECTION_REQUIRED.to_string()));
    };
    let connection = store
        .get(connection_id)
        .await
        .map_err(|error| SigningChoiceError::Store(format!("could not read the trust agent connection: {error}")))?;
    match connection {
        Some(connection) if connection.tenant_id.is_none() => Ok(()),
        _ => Err(SigningChoiceError::Invalid(APPLIANCE_CONNECTION_REQUIRED.to_string())),
    }
}

/// Whether a save changes the signing choice. An empty block is the same as none.
pub(crate) fn signing_changed(
    stored: Option<&SurfaceSigningConfig>,
    saved: Option<&SurfaceSigningConfig>,
) -> bool {
    stored.filter(|signing| !signing.is_empty()) != saved.filter(|signing| !signing.is_empty())
}

pub(crate) const SIGNING_CHANGE_FORBIDDEN: &str =
    "changing the signing choice requires the key_management.edit permission";

/// The management caller of a save, as the session and access-token middleware describe it.
/// Changing which trust agent signs is key management, so a save that changes a signing choice
/// asks this caller for `key_management.edit` on top of the permission of its route.
pub struct SigningEditor {
    guard: Option<RbacGuard>,
    user_id: Option<String>,
    pat: Option<PatContext>,
    #[cfg(test)]
    _users: Option<std::sync::Arc<tempfile::TempDir>>,
}

impl SigningEditor {
    /// Whether the caller may change a signing choice. A request without an RBAC guard or an
    /// authenticated user may not.
    pub(crate) async fn may_change_signing(&self) -> bool {
        caller_allows(self.guard.as_ref(), self.user_id.as_deref(), self.pat.as_ref(), &Feature::KeyManagementEdit)
            .await
    }
}

#[cfg(test)]
impl SigningEditor {
    /// A signed-in user of `role`, under the default permissions, with no access token.
    pub(crate) async fn signed_in_as(role: crate::auth::types::UserRole) -> Self {
        Self::with_token(role, None).await
    }

    /// A user of `role` calling with an access token limited to `scopes`, if any.
    pub(crate) async fn with_token(
        role: crate::auth::types::UserRole,
        scopes: Option<&[&str]>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::auth::storage::PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = chrono::Utc::now();
        storage
            .save_user(&crate::auth::storage::UserData {
                user_id: "editor".to_string(),
                username: "editor".to_string(),
                passkeys: Vec::new(),
                role,
                status: crate::auth::types::UserStatus::Approved,
                is_primary: false,
                first_name: None,
                last_name: None,
                email: None,
                department: None,
                job_title: None,
                avatar_path: None,
                created_at: now,
                updated_at: now,
                last_logged_in: None,
                saml_id: None,
                oidc: None,
            })
            .await
            .unwrap();
        Self {
            guard: Some(RbacGuard::new(
                std::sync::Arc::new(storage),
                std::sync::Arc::new(crate::rbac::RbacConfig::default()),
            )),
            user_id: Some("editor".to_string()),
            pat: scopes.map(|scopes| {
                PatContext(Some(
                    scopes
                        .iter()
                        .map(|scope| scope.to_string())
                        .collect(),
                ))
            }),
            _users: Some(std::sync::Arc::new(dir)),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for SigningEditor {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            guard: parts
                .extensions
                .get::<RbacGuard>()
                .cloned(),
            user_id: parts
                .extensions
                .get::<AuthGuardOk>()
                .map(|AuthGuardOk(user_id)| user_id.clone()),
            pat: parts
                .extensions
                .get::<PatContext>()
                .cloned(),
            #[cfg(test)]
            _users: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::connections::{FileSystemVtaConnectionStore, VtaConnection};

    fn through(connection_id: &str) -> SurfaceSigningConfig {
        SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Vta),
            connection_id: Some(connection_id.to_string()),
            context_id: Some("ctx".to_string()),
            key_id: Some("key-1".to_string()),
        }
    }

    fn connection(
        id: &str,
        tenant_id: Option<&str>,
    ) -> VtaConnection {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "tenant_id": tenant_id,
            "name": id,
            "enabled": true,
            "endpoint": "https://vta.example.test",
            "vta_did": "did:web:vta.example.test",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("a connection record")
    }

    async fn store_with(connections: &[VtaConnection]) -> (FileSystemVtaConnectionStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSystemVtaConnectionStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        for connection in connections {
            store
                .create(connection.clone())
                .await
                .unwrap();
        }
        (store, tmp)
    }

    fn invalid(result: Result<(), SigningChoiceError>) -> String {
        match result {
            Err(SigningChoiceError::Invalid(message)) => message,
            other => panic!("expected the choice to be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_gateway_default_may_sign_through_an_appliance_wide_connection() {
        let (store, _tmp) = store_with(&[connection("shared", None)]).await;
        validate_signing_choice(&through("shared"), SigningOwner::Appliance, Some(&store), &VtaConfig::default())
            .await
            .expect("an appliance-wide connection is a valid default");
    }

    #[tokio::test]
    async fn the_gateway_default_cannot_sign_through_a_tenants_connection() {
        let (store, _tmp) = store_with(&[connection("tenant-agent", Some("tenant-a"))]).await;
        let message = invalid(
            validate_signing_choice(
                &through("tenant-agent"),
                SigningOwner::Appliance,
                Some(&store),
                &VtaConfig::default(),
            )
            .await,
        );
        assert_eq!(message, APPLIANCE_CONNECTION_REQUIRED);
    }

    #[tokio::test]
    async fn the_gateway_default_cannot_name_a_connection_that_does_not_exist() {
        let (store, _tmp) = store_with(&[]).await;
        let message = invalid(
            validate_signing_choice(&through("missing"), SigningOwner::Appliance, Some(&store), &VtaConfig::default())
                .await,
        );
        assert_eq!(message, APPLIANCE_CONNECTION_REQUIRED);
    }

    #[tokio::test]
    async fn an_appliance_wide_resource_may_name_a_connection_the_store_does_not_hold() {
        let (store, _tmp) = store_with(&[]).await;
        validate_signing_choice(&through("missing"), SigningOwner::Resource(None), Some(&store), &VtaConfig::default())
            .await
            .expect("an appliance-wide surface keeps its existing rule");
    }

    #[tokio::test]
    async fn a_tenant_resource_cannot_sign_through_another_tenants_connection() {
        let (store, _tmp) = store_with(&[connection("agent-a", Some("tenant-a"))]).await;
        let message = invalid(
            validate_signing_choice(
                &through("agent-a"),
                SigningOwner::Resource(Some("tenant-b")),
                Some(&store),
                &VtaConfig::default(),
            )
            .await,
        );
        assert!(message.contains("does not reference a trust agent connection"), "{message}");
    }

    #[tokio::test]
    async fn every_owner_is_refused_a_trust_agent_choice_without_a_key() {
        let (store, _tmp) = store_with(&[connection("shared", None)]).await;
        let keyless = SurfaceSigningConfig {
            key_id: None,
            ..through("shared")
        };
        for owner in [SigningOwner::Appliance, SigningOwner::Resource(None), SigningOwner::Resource(Some("t"))] {
            let message = invalid(validate_signing_choice(&keyless, owner, Some(&store), &VtaConfig::default()).await);
            assert!(message.contains("key_id"), "{owner:?}: {message}");
        }
    }

    #[tokio::test]
    async fn every_owner_is_refused_a_context_this_gateway_cannot_create() {
        let (store, _tmp) = store_with(&[connection("shared", None)]).await;
        let contextless = SurfaceSigningConfig {
            context_id: None,
            ..through("shared")
        };
        for owner in [SigningOwner::Appliance, SigningOwner::Resource(None)] {
            let message =
                invalid(validate_signing_choice(&contextless, owner, Some(&store), &VtaConfig::default()).await);
            assert!(message.contains("signing.context_id is required"), "{owner:?}: {message}");
        }
        let provisioning = VtaConfig {
            enabled: true,
            auto_provision_contexts: true,
            ..VtaConfig::default()
        };
        let message =
            invalid(validate_signing_choice(&contextless, SigningOwner::Appliance, Some(&store), &provisioning).await);
        assert!(message.contains("signing.context_id is required"), "{message}");
        let on_vta_block = SurfaceSigningConfig {
            connection_id: None,
            ..contextless
        };
        validate_signing_choice(&on_vta_block, SigningOwner::Appliance, Some(&store), &provisioning)
            .await
            .expect("the [vta] connection creates contexts, so a choice through it may name none");
        let disabled = VtaConfig { enabled: false, ..provisioning };
        let message =
            invalid(validate_signing_choice(&on_vta_block, SigningOwner::Appliance, Some(&store), &disabled).await);
        assert!(message.contains("signing.context_id is required"), "{message}");
    }

    #[tokio::test]
    async fn a_choice_through_the_vta_block_is_refused_while_the_block_is_off() {
        let (store, _tmp) = store_with(&[]).await;
        let on = VtaConfig {
            enabled: true,
            ..VtaConfig::default()
        };
        for connection_id in [None, Some(crate::vta::key_directory::DEFAULT_CONNECTION_ID), Some("vta-bootstrap")] {
            let choice = SurfaceSigningConfig {
                connection_id: connection_id.map(str::to_string),
                ..through("unused")
            };
            for owner in [SigningOwner::Appliance, SigningOwner::Resource(None), SigningOwner::Resource(Some("t"))] {
                let message =
                    invalid(validate_signing_choice(&choice, owner, Some(&store), &VtaConfig::default()).await);
                assert_eq!(message, VTA_BLOCK_REQUIRED, "{connection_id:?} {owner:?}");
            }
            for owner in [SigningOwner::Appliance, SigningOwner::Resource(None)] {
                validate_signing_choice(&choice, owner, Some(&store), &on)
                    .await
                    .unwrap_or_else(|e| panic!("{connection_id:?} {owner:?}: the [vta] block serves it: {e:?}"));
            }
        }
    }

    #[tokio::test]
    async fn a_tenant_resource_cannot_name_a_context_of_the_appliances_own_agent() {
        let (store, _tmp) = store_with(&[]).await;
        let provisioning = VtaConfig {
            enabled: true,
            auto_provision_contexts: true,
            ..VtaConfig::default()
        };
        for connection_id in [None, Some(crate::vta::key_directory::DEFAULT_CONNECTION_ID), Some("vta-bootstrap")] {
            let named = SurfaceSigningConfig {
                connection_id: connection_id.map(str::to_string),
                context_id: Some("another-tenants-context".to_string()),
                ..through("unused")
            };
            let message = invalid(
                validate_signing_choice(&named, SigningOwner::Resource(Some("t")), Some(&store), &provisioning).await,
            );
            assert!(message.contains("creates that tenant's contexts itself"), "{connection_id:?}: {message}");
            validate_signing_choice(&named, SigningOwner::Resource(None), Some(&store), &provisioning)
                .await
                .expect("an appliance-wide resource may name the appliance's contexts");
            let unnamed = SurfaceSigningConfig { context_id: None, ..named };
            validate_signing_choice(&unnamed, SigningOwner::Resource(Some("t")), Some(&store), &provisioning)
                .await
                .expect("the gateway creates the tenant's own context");
        }
    }

    #[tokio::test]
    async fn a_tenant_resource_cannot_name_a_context_of_an_appliance_wide_connection() {
        let (store, _tmp) = store_with(&[connection("shared", None), connection("own", Some("t"))]).await;
        let message = invalid(
            validate_signing_choice(
                &through("shared"),
                SigningOwner::Resource(Some("t")),
                Some(&store),
                &VtaConfig::default(),
            )
            .await,
        );
        assert!(message.contains("creates that tenant's contexts itself"), "{message}");
        validate_signing_choice(&through("shared"), SigningOwner::Resource(None), Some(&store), &VtaConfig::default())
            .await
            .expect("an appliance-wide resource may name an appliance-wide connection's context");
        validate_signing_choice(
            &through("own"),
            SigningOwner::Resource(Some("t")),
            Some(&store),
            &VtaConfig::default(),
        )
        .await
        .expect("a tenant names a context of its own connection");
    }

    #[tokio::test]
    async fn without_a_connection_store_a_tenant_resource_signs_only_through_the_appliances_own_agent() {
        let provisioning = VtaConfig {
            enabled: true,
            auto_provision_contexts: true,
            ..VtaConfig::default()
        };
        let message = invalid(
            validate_signing_choice(&through("own"), SigningOwner::Resource(Some("t")), None, &VtaConfig::default())
                .await,
        );
        assert!(message.contains("does not reference a trust agent connection"), "{message}");
        let named = SurfaceSigningConfig {
            connection_id: None,
            ..through("unused")
        };
        let message =
            invalid(validate_signing_choice(&named, SigningOwner::Resource(Some("t")), None, &provisioning).await);
        assert!(message.contains("creates that tenant's contexts itself"), "{message}");
        validate_signing_choice(&through("own"), SigningOwner::Resource(None), None, &VtaConfig::default())
            .await
            .expect("an appliance-wide resource keeps its rule without a store");
    }

    #[tokio::test]
    async fn the_local_key_is_a_valid_choice_for_every_owner() {
        let local = SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Local),
            ..Default::default()
        };
        for owner in [SigningOwner::Appliance, SigningOwner::Resource(Some("t"))] {
            validate_signing_choice(&local, owner, None, &VtaConfig::default())
                .await
                .expect("the gateway's own key needs no connection");
        }
    }

    #[test]
    fn an_empty_block_is_the_same_choice_as_none() {
        let empty = SurfaceSigningConfig::default();
        assert!(!signing_changed(None, Some(&empty)));
        assert!(!signing_changed(Some(&empty), None));
        assert!(!signing_changed(Some(&through("a")), Some(&through("a"))));
    }

    #[test]
    fn setting_clearing_or_repointing_a_choice_is_a_change() {
        assert!(signing_changed(None, Some(&through("a"))));
        assert!(signing_changed(Some(&through("a")), None));
        assert!(signing_changed(Some(&through("a")), Some(&through("b"))));
    }

    #[tokio::test]
    async fn an_administrator_may_change_signing() {
        let editor = SigningEditor::signed_in_as(crate::auth::types::UserRole::Administrator).await;
        assert!(
            editor
                .may_change_signing()
                .await
        );
    }

    #[tokio::test]
    async fn a_power_user_may_not_change_signing() {
        let editor = SigningEditor::signed_in_as(crate::auth::types::UserRole::PowerUser).await;
        assert!(
            !editor
                .may_change_signing()
                .await
        );
    }

    #[tokio::test]
    async fn an_access_token_must_carry_key_management_edit_to_change_signing() {
        let role = crate::auth::types::UserRole::Administrator;
        let without = SigningEditor::with_token(role.clone(), Some(&["surfaces.edit", "issuers.edit"])).await;
        assert!(
            !without
                .may_change_signing()
                .await
        );
        let with = SigningEditor::with_token(role, Some(&["surfaces.edit", "key_management.edit"])).await;
        assert!(
            with.may_change_signing()
                .await
        );
    }

    #[tokio::test]
    async fn a_caller_without_a_guard_or_a_user_may_not_change_signing() {
        let editor = SigningEditor {
            guard: None,
            user_id: Some("ada".to_string()),
            pat: None,
            _users: None,
        };
        assert!(
            !editor
                .may_change_signing()
                .await
        );
    }
}
