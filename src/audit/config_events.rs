//! Emit helpers for the governance events raised when the management API
//! changes a trust anchor: a JWT verification strategy, a credential provider,
//! or the Target Authentication of a surface.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::audit::events::{ConfigChange, TargetAuthKind};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatDelegationContext;
use crate::config::{TargetAuthConfig, TargetAuthMethod};
use crate::credential_providers::CredentialProvider;
use crate::delegation_vault::audit::{
    AuditCallerContext, DelegationAuditAction, DelegationAuditEvent, audit_event, emit, management_caller_context,
};
use crate::jwt_bearer::models::{JwksSource, JwtVerificationStrategy};

/// Who made a management change: the signed-in user, or the access token they
/// presented. Empty when the request carried no authenticated principal.
#[derive(Debug, Clone, Default)]
pub struct ManagementActor(Option<AuditCallerContext>);

impl ManagementActor {
    pub fn new(
        user_id: Option<&str>,
        access_token_id: Option<&str>,
    ) -> Self {
        Self(management_caller_context(user_id, access_token_id))
    }

    fn stamp(
        &self,
        mut event: DelegationAuditEvent,
    ) -> DelegationAuditEvent {
        event.caller = self.0.clone();
        event
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ManagementActor {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .extensions
            .get::<AuthGuardOk>()
            .map(|AuthGuardOk(id)| id.as_str())
            .or_else(|| {
                parts
                    .extensions
                    .get::<String>()
                    .map(String::as_str)
            });
        let token_id = parts
            .extensions
            .get::<PatDelegationContext>()
            .map(|context| context.token_id.as_str());
        Ok(Self::new(user_id, token_id))
    }
}

/// A strategy was created, updated or deleted. `before` is the stored strategy
/// an update replaced or a delete removed.
pub fn verification_strategy_changed(
    actor: &ManagementActor,
    change: ConfigChange,
    before: Option<&JwtVerificationStrategy>,
    after: &JwtVerificationStrategy,
) {
    emit("verification_strategy_changed", || {
        let deleted = change == ConfigChange::Deleted;
        let pin_changed = if deleted {
            after
                .authorization_server
                .is_some()
        } else {
            before.map(|strategy| &strategy.authorization_server) != Some(&after.authorization_server)
        };
        actor.stamp(audit_event(
            DelegationAuditAction::VerificationStrategyChanged {
                change,
                strategy_id: after.id.clone(),
                name: after.name.clone(),
                expected_issuer: after.expected_issuer.clone(),
                jwks_source: match after.jwks_source {
                    JwksSource::Remote { .. } => "remote",
                    JwksSource::Static { .. } => "static",
                }
                .to_string(),
                pinned: !deleted
                    && after
                        .authorization_server
                        .is_some(),
                pin_changed,
            },
            None,
            None,
            None,
            None,
        ))
    })
}

pub fn credential_provider_changed(
    actor: &ManagementActor,
    change: ConfigChange,
    provider: &CredentialProvider,
) {
    emit("credential_provider_changed", || {
        let mut event = audit_event(
            DelegationAuditAction::CredentialProviderChanged {
                change,
                provider_type: provider
                    .provider_type
                    .as_str()
                    .to_string(),
            },
            None,
            None,
            Some(&provider.provider_id),
            None,
        );
        event.provider_name = Some(provider.name.clone());
        actor.stamp(event)
    })
}

/// One place a Target Authentication is saved: the surface itself, or a single variant.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetAuthEntry {
    /// The variant's id; absent for the surface's own Target Authentication.
    pub variant_id: Option<String>,
    pub variant_alias: Option<String>,
    /// The Target Authentication in force there, after the variant's overrides are applied.
    pub auth: Option<TargetAuthConfig>,
    /// The variant sets no Target Authentication of its own and takes the surface's.
    pub inherits: bool,
}

/// The Target Authentication of a surface and of each of its variants, as saved.
pub type TargetAuthSet = Vec<TargetAuthEntry>;

fn find_entry<'a>(
    set: Option<&'a TargetAuthSet>,
    variant_id: Option<&str>,
) -> Option<&'a TargetAuthEntry> {
    set?.iter()
        .find(|entry| entry.variant_id.as_deref() == variant_id)
}

fn changed_ids<'a>(
    before: Option<&'a TargetAuthSet>,
    after: Option<&'a TargetAuthSet>,
) -> Vec<Option<&'a str>> {
    let mut ids = vec![None];
    for entry in after
        .into_iter()
        .chain(before)
        .flatten()
    {
        let id = entry.variant_id.as_deref();
        if id.is_some() && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// A surface's Target Authentication changed between `before` and `after`.
/// One event is raised for the surface and for each variant whose own Target Authentication
/// differs, matched by variant id so adding, deleting or reordering variants shifts nothing.
/// A variant that takes the surface's Target Authentication before and after raises none, because
/// the surface's event covers it.
pub fn target_auth_changed(
    actor: &ManagementActor,
    surface_id: &str,
    surface_name: &str,
    before: Option<&TargetAuthSet>,
    after: Option<&TargetAuthSet>,
) {
    for id in changed_ids(before, after) {
        let old_entry = find_entry(before, id);
        let new_entry = find_entry(after, id);
        let inherited = |entry: Option<&TargetAuthEntry>| entry.is_none_or(|entry| entry.inherits);
        if id.is_some() && inherited(old_entry) && inherited(new_entry) {
            continue;
        }
        let old = old_entry.and_then(|entry| entry.auth.as_ref());
        let new = new_entry.and_then(|entry| entry.auth.as_ref());
        let (change, auth) = match (old, new) {
            (None, None) => continue,
            (None, Some(new)) => (ConfigChange::Created, new),
            (Some(old), None) => (ConfigChange::Deleted, old),
            (Some(old), Some(new)) if old == new => continue,
            (Some(_), Some(new)) => (ConfigChange::Updated, new),
        };
        let variant_alias = new_entry
            .or(old_entry)
            .and_then(|entry| entry.variant_alias.clone());
        emit("target_auth_changed", || {
            let (method, credential_provider_id) = match &auth.method {
                TargetAuthMethod::CredentialLookup => (TargetAuthKind::CredentialLookup, None),
                TargetAuthMethod::StaticSecret { .. } => (TargetAuthKind::StaticSecret, None),
                TargetAuthMethod::CredentialProvider { credential_provider_id, .. } => {
                    (TargetAuthKind::CredentialProvider, Some(credential_provider_id.clone()))
                }
            };
            let mut event = audit_event(
                DelegationAuditAction::TargetAuthChanged {
                    change,
                    method,
                    credential_provider_id,
                    variant_id: id.map(str::to_string),
                    variant_alias,
                },
                None,
                None,
                None,
                Some(surface_id),
            );
            event.channel_name = Some(surface_name.to_string());
            actor.stamp(event)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::producer::capture;
    use crate::config::{CredentialInjection, TargetAuthFallback};

    fn actor() -> ManagementActor {
        ManagementActor::new(Some("admin-1"), None)
    }

    fn provider_auth(provider_id: &str) -> TargetAuthConfig {
        TargetAuthConfig {
            method: TargetAuthMethod::CredentialProvider {
                credential_provider_id: provider_id.into(),
                scopes: vec![],
                inject_as: CredentialInjection::default(),
            },
            auth_type: None,
            target_identifier: None,
            fallback: TargetAuthFallback::Reject,
        }
    }

    fn static_auth() -> TargetAuthConfig {
        TargetAuthConfig {
            method: TargetAuthMethod::StaticSecret {
                secret_id: "SECRET".into(),
                header_name: "X-Key".into(),
                header_format: "{value}".into(),
            },
            auth_type: None,
            target_identifier: None,
            fallback: TargetAuthFallback::Reject,
        }
    }

    fn base(auth: Option<TargetAuthConfig>) -> TargetAuthEntry {
        TargetAuthEntry {
            variant_id: None,
            variant_alias: None,
            auth,
            inherits: false,
        }
    }

    fn own(
        id: &str,
        auth: Option<TargetAuthConfig>,
    ) -> TargetAuthEntry {
        TargetAuthEntry {
            variant_id: Some(id.into()),
            variant_alias: Some(format!("alias-{id}")),
            auth,
            inherits: false,
        }
    }

    fn inheriting(
        id: &str,
        base_auth: Option<TargetAuthConfig>,
    ) -> TargetAuthEntry {
        TargetAuthEntry {
            variant_id: Some(id.into()),
            variant_alias: Some(format!("alias-{id}")),
            auth: base_auth,
            inherits: true,
        }
    }

    async fn target_events(
        before: Option<TargetAuthSet>,
        after: Option<TargetAuthSet>,
    ) -> Vec<DelegationAuditEvent> {
        capture(async { target_auth_changed(&actor(), "surf-1", "Alpha", before.as_ref(), after.as_ref()) })
            .await
            .1
    }

    fn summary(events: &[DelegationAuditEvent]) -> Vec<(ConfigChange, Option<String>, Option<String>)> {
        events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::TargetAuthChanged {
                    change,
                    credential_provider_id,
                    variant_id,
                    ..
                } => (*change, credential_provider_id.clone(), variant_id.clone()),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn setting_target_authentication_records_who_set_it_and_through_which_provider() {
        let events = target_events(Some(vec![base(None)]), Some(vec![base(Some(provider_auth("provider-1")))])).await;
        assert_eq!(events.len(), 1);
        match &events[0].event {
            DelegationAuditAction::TargetAuthChanged {
                change,
                method,
                credential_provider_id,
                variant_id,
                variant_alias,
            } => {
                assert_eq!(*variant_id, None);
                assert_eq!(*variant_alias, None);
                assert_eq!(*change, ConfigChange::Created);
                assert_eq!(*method, TargetAuthKind::CredentialProvider);
                assert_eq!(credential_provider_id.as_deref(), Some("provider-1"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            events[0]
                .surface_id
                .as_deref(),
            Some("surf-1")
        );
        assert_eq!(
            events[0]
                .channel_name
                .as_deref(),
            Some("Alpha")
        );
        let caller = events[0]
            .caller
            .as_ref()
            .expect("the change is attributed");
        assert_eq!(caller.auth_method, "session");
        assert_eq!(caller.sub.as_deref(), Some("admin-1"));
    }

    #[tokio::test]
    async fn changing_and_removing_target_authentication_are_distinct_changes() {
        let updated =
            target_events(Some(vec![base(Some(provider_auth("a")))]), Some(vec![base(Some(provider_auth("b")))])).await;
        assert_eq!(summary(&updated), vec![(ConfigChange::Updated, Some("b".into()), None)]);
        let removed = target_events(Some(vec![base(Some(static_auth()))]), Some(vec![base(None)])).await;
        assert!(matches!(
            &removed[0].event,
            DelegationAuditAction::TargetAuthChanged {
                change: ConfigChange::Deleted,
                method: TargetAuthKind::StaticSecret,
                credential_provider_id: None,
                variant_id: None,
                variant_alias: None,
            }
        ));
    }

    #[tokio::test]
    async fn unchanged_target_authentication_raises_nothing() {
        let same = Some(vec![base(Some(provider_auth("a"))), own("v1", Some(provider_auth("b")))]);
        assert!(
            target_events(same.clone(), same)
                .await
                .is_empty()
        );
        assert!(
            target_events(None, Some(vec![base(None)]))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_variant_that_alone_changes_its_target_authentication_is_named_by_id_and_alias() {
        let events = target_events(
            Some(vec![base(None), own("v1", Some(provider_auth("a")))]),
            Some(vec![base(None), own("v1", Some(provider_auth("b")))]),
        )
        .await;
        assert_eq!(summary(&events), vec![(ConfigChange::Updated, Some("b".into()), Some("v1".into()))]);
        assert!(matches!(
            &events[0].event,
            DelegationAuditAction::TargetAuthChanged { variant_alias: Some(alias), .. } if alias == "alias-v1"
        ));
    }

    #[tokio::test]
    async fn a_base_and_a_variant_that_both_change_are_recorded_separately() {
        let events = target_events(
            Some(vec![base(Some(provider_auth("x"))), own("v1", Some(provider_auth("a")))]),
            Some(vec![base(Some(provider_auth("y"))), own("v1", Some(provider_auth("b")))]),
        )
        .await;
        assert_eq!(
            summary(&events),
            vec![
                (ConfigChange::Updated, Some("y".into()), None),
                (ConfigChange::Updated, Some("b".into()), Some("v1".into())),
            ]
        );
    }

    #[tokio::test]
    async fn deleting_a_middle_variant_records_only_that_variants_authentication_as_deleted() {
        let events = target_events(
            Some(vec![base(None), own("a", Some(provider_auth("pa"))), own("b", Some(provider_auth("pb")))]),
            Some(vec![base(None), own("b", Some(provider_auth("pb")))]),
        )
        .await;
        assert_eq!(summary(&events), vec![(ConfigChange::Deleted, Some("pa".into()), Some("a".into()))]);
    }

    #[tokio::test]
    async fn deleting_a_variant_that_shares_another_variants_authentication_does_not_blame_the_other() {
        let shared = Some(provider_auth("shared"));
        let events = target_events(
            Some(vec![base(None), own("a", shared.clone()), own("b", shared.clone())]),
            Some(vec![base(None), own("b", shared)]),
        )
        .await;
        assert_eq!(summary(&events), vec![(ConfigChange::Deleted, Some("shared".into()), Some("a".into()))]);
    }

    #[tokio::test]
    async fn reordering_or_promoting_variants_records_nothing() {
        let events = target_events(
            Some(vec![
                base(Some(provider_auth("x"))),
                own("a", Some(provider_auth("pa"))),
                own("b", Some(provider_auth("pb"))),
            ]),
            Some(vec![
                base(Some(provider_auth("x"))),
                own("b", Some(provider_auth("pb"))),
                own("a", Some(provider_auth("pa"))),
            ]),
        )
        .await;
        assert!(events.is_empty(), "{events:?}");
    }

    #[tokio::test]
    async fn changing_the_surface_alone_does_not_repeat_the_event_for_inheriting_variants() {
        let events = target_events(
            Some(vec![
                base(Some(provider_auth("x"))),
                inheriting("a", Some(provider_auth("x"))),
                own("b", Some(provider_auth("pb"))),
            ]),
            Some(vec![
                base(Some(provider_auth("y"))),
                inheriting("a", Some(provider_auth("y"))),
                own("b", Some(provider_auth("pb"))),
            ]),
        )
        .await;
        assert_eq!(summary(&events), vec![(ConfigChange::Updated, Some("y".into()), None)]);
    }

    #[tokio::test]
    async fn a_variant_that_starts_or_stops_overriding_is_recorded_when_its_authentication_differs() {
        let started = target_events(
            Some(vec![base(Some(provider_auth("x"))), inheriting("a", Some(provider_auth("x")))]),
            Some(vec![base(Some(provider_auth("x"))), own("a", Some(provider_auth("pa")))]),
        )
        .await;
        assert_eq!(summary(&started), vec![(ConfigChange::Updated, Some("pa".into()), Some("a".into()))]);

        let cleared = target_events(
            Some(vec![base(Some(provider_auth("x"))), inheriting("a", Some(provider_auth("x")))]),
            Some(vec![base(Some(provider_auth("x"))), own("a", None)]),
        )
        .await;
        assert_eq!(summary(&cleared), vec![(ConfigChange::Deleted, Some("x".into()), Some("a".into()))]);

        let same_value = target_events(
            Some(vec![base(Some(provider_auth("x"))), own("a", Some(provider_auth("x")))]),
            Some(vec![base(Some(provider_auth("x"))), inheriting("a", Some(provider_auth("x")))]),
        )
        .await;
        assert!(same_value.is_empty());
    }

    #[tokio::test]
    async fn adding_a_variant_records_its_own_authentication_but_an_inheriting_one_records_nothing() {
        let added =
            target_events(Some(vec![base(None)]), Some(vec![base(None), own("a", Some(provider_auth("pa")))])).await;
        assert_eq!(summary(&added), vec![(ConfigChange::Created, Some("pa".into()), Some("a".into()))]);

        let inherited = target_events(
            Some(vec![base(Some(provider_auth("x")))]),
            Some(vec![base(Some(provider_auth("x"))), inheriting("a", Some(provider_auth("x")))]),
        )
        .await;
        assert!(inherited.is_empty());
    }

    #[tokio::test]
    async fn a_strategy_change_reports_the_issuer_and_whether_the_pin_moved() {
        let before = JwtVerificationStrategy {
            id: "strategy-1".into(),
            name: "Auth0".into(),
            expected_issuer: "https://issuer.example/".into(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://issuer.example/jwks".into(),
            },
            ..Default::default()
        };
        let mut after = before.clone();
        after.name = "Auth0 renamed".into();

        let (_, unpinned) =
            capture(async { verification_strategy_changed(&actor(), ConfigChange::Updated, Some(&before), &after) })
                .await;
        match &unpinned[0].event {
            DelegationAuditAction::VerificationStrategyChanged {
                change,
                strategy_id,
                name,
                expected_issuer,
                jwks_source,
                pinned,
                pin_changed,
            } => {
                assert_eq!(*change, ConfigChange::Updated);
                assert_eq!(strategy_id, "strategy-1");
                assert_eq!(name, "Auth0 renamed");
                assert_eq!(expected_issuer, "https://issuer.example/");
                assert_eq!(jwks_source, "remote");
                assert!(!pinned);
                assert!(!pin_changed, "a rename leaves the pin alone");
            }
            other => panic!("unexpected {other:?}"),
        }

        after.authorization_server = Some(crate::jwt_bearer::models::AuthorizationServerMetadata {
            issuer: "https://issuer.example/".into(),
            metadata_url: "https://issuer.example/.well-known/oauth-authorization-server".into(),
            token_endpoint: "https://issuer.example/token".into(),
            jwks_uri: "https://issuer.example/jwks".into(),
        });
        let (_, pinned) =
            capture(async { verification_strategy_changed(&actor(), ConfigChange::Updated, Some(&before), &after) })
                .await;
        assert!(matches!(
            &pinned[0].event,
            DelegationAuditAction::VerificationStrategyChanged {
                pinned: true,
                pin_changed: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_strategy_with_its_own_keys_is_reported_as_static() {
        let strategy = JwtVerificationStrategy {
            id: "strategy-2".into(),
            name: "Pinned keys".into(),
            expected_issuer: "https://issuer.example/".into(),
            jwks_source: JwksSource::Static { jwks: Vec::new() },
            ..Default::default()
        };
        let (_, events) =
            capture(async { verification_strategy_changed(&actor(), ConfigChange::Created, None, &strategy) }).await;
        assert!(matches!(
            &events[0].event,
            DelegationAuditAction::VerificationStrategyChanged { change: ConfigChange::Created, jwks_source, .. }
                if jwks_source == "static"
        ));
    }

    #[tokio::test]
    async fn switching_to_credential_lookup_authentication_names_that_method_and_no_provider() {
        let lookup = TargetAuthConfig {
            method: TargetAuthMethod::CredentialLookup,
            auth_type: None,
            target_identifier: None,
            fallback: TargetAuthFallback::Reject,
        };
        let events = target_events(Some(vec![base(None)]), Some(vec![base(Some(lookup))])).await;
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event,
            DelegationAuditAction::TargetAuthChanged {
                change: ConfigChange::Created,
                method: TargetAuthKind::CredentialLookup,
                credential_provider_id: None,
                variant_id: None,
                variant_alias: None,
            }
        ));
    }

    #[tokio::test]
    async fn deleting_a_pinned_strategy_reports_the_pin_as_cleared() {
        let strategy = JwtVerificationStrategy {
            id: "strategy-1".into(),
            name: "Auth0".into(),
            expected_issuer: "https://issuer.example/".into(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://issuer.example/jwks".into(),
            },
            authorization_server: Some(crate::jwt_bearer::models::AuthorizationServerMetadata {
                issuer: "https://issuer.example/".into(),
                metadata_url: "https://issuer.example/.well-known/oauth-authorization-server".into(),
                token_endpoint: "https://issuer.example/token".into(),
                jwks_uri: "https://issuer.example/jwks".into(),
            }),
            ..Default::default()
        };
        let (_, events) = capture(async {
            verification_strategy_changed(&actor(), ConfigChange::Deleted, Some(&strategy), &strategy)
        })
        .await;
        assert!(matches!(
            &events[0].event,
            DelegationAuditAction::VerificationStrategyChanged {
                change: ConfigChange::Deleted,
                pinned: false,
                pin_changed: true,
                ..
            }
        ));

        let mut unpinned = strategy.clone();
        unpinned.authorization_server = None;
        let (_, events) = capture(async {
            verification_strategy_changed(&actor(), ConfigChange::Deleted, Some(&unpinned), &unpinned)
        })
        .await;
        assert!(matches!(
            &events[0].event,
            DelegationAuditAction::VerificationStrategyChanged {
                pinned: false,
                pin_changed: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn an_access_token_is_named_as_the_actor_when_one_was_presented() {
        let actor = ManagementActor::new(Some("admin-1"), Some("token-9"));
        let provider = serde_json::from_value::<CredentialProvider>(serde_json::json!({
            "id": "p-1", "name": "Provider", "provider_id": "provider",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .expect("provider deserializes");
        let (_, events) =
            capture(async { credential_provider_changed(&actor, ConfigChange::Created, &provider) }).await;
        let caller = events[0]
            .caller
            .as_ref()
            .expect("attributed");
        assert_eq!(caller.auth_method, "access_token");
        assert_eq!(caller.token_id.as_deref(), Some("token-9"));
        assert_eq!(
            events[0]
                .provider_id
                .as_deref(),
            Some("provider")
        );
        assert_eq!(
            events[0]
                .provider_name
                .as_deref(),
            Some("Provider")
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_request_leaves_the_change_unattributed() {
        let provider = serde_json::from_value::<CredentialProvider>(serde_json::json!({
            "id": "p-1", "name": "Provider", "provider_id": "provider",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .expect("provider deserializes");
        let (_, events) = capture(async {
            credential_provider_changed(&ManagementActor::default(), ConfigChange::Deleted, &provider)
        })
        .await;
        assert!(events[0].caller.is_none());
    }
}
