//! Validation of the appliance-wide trigger mappings that attach integrations to user and
//! identity events (`PUT /v1/users/integrations`, `PUT /v1/identities/integrations`).

use axum::{http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use tracing::{error, info};

use crate::auth_manager::pat::PatResourceScope;
use crate::storage::IntegrationStorage;
use crate::tenancy::PatTenantContext;

pub type Rejection = (StatusCode, Json<Value>);

pub const MAX_MAPPINGS: usize = 50;
pub const MAX_VARIABLES: usize = 32;
pub const MAX_VARIABLE_NAME_LEN: usize = 64;
pub const MAX_VARIABLE_VALUE_LEN: usize = 2048;

/// One integration attached to a resource's events, as a caller submits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingRequest {
    pub integration_id: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingsRequest {
    pub integration_integrations: Vec<MappingRequest>,
}

/// What a resource's mappings may name: integrations of `category` (or `general`) and the
/// events the resource raises.
pub struct MappingRules {
    pub category: &'static str,
    pub event_types: &'static [&'static str],
}

/// Where one resource's mappings are kept.
pub(crate) trait MappingStore {
    /// The integrations currently stored with no event filter.
    async fn unfiltered_integration_ids(&self) -> anyhow::Result<HashSet<String>>;
    /// Stores `mappings` in place of the current ones and returns them as stored.
    async fn replace(
        &self,
        mappings: Vec<MappingRequest>,
    ) -> anyhow::Result<Vec<MappingRequest>>;
}

/// Who is changing the mappings.
pub(crate) struct Caller<'a> {
    pub actor: Option<&'a str>,
    pub context: Option<&'a PatTenantContext>,
    pub scope: Option<&'a PatResourceScope>,
}

/// Stores `request` as the resource's mappings once the caller and every mapping are accepted;
/// a refusal leaves the stored mappings as they were.
pub(crate) async fn replace_mappings(
    store: &impl MappingStore,
    request: MappingsRequest,
    rules: &MappingRules,
    integrations: &IntegrationStorage,
    caller: Caller<'_>,
) -> Result<Vec<MappingRequest>, Rejection> {
    ensure_appliance_wide_caller(caller.context, caller.scope)?;
    let previously_unfiltered = store
        .unfiltered_integration_ids()
        .await
        .map_err(|error| {
            error!(category = rules.category, %error, "Failed to load integration mappings");
            reject(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load integrations")
        })?;
    let mappings = validate_mappings(request, rules, integrations, &previously_unfiltered).await?;
    let mappings = store
        .replace(mappings)
        .await
        .map_err(|error| {
            error!(category = rules.category, %error, "Failed to save integration mappings");
            reject(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save integrations")
        })?;
    info!(
        event = "integrations.mappings.updated",
        category = rules.category,
        actor = caller.actor.unwrap_or_default(),
        mappings = ?mappings
            .iter()
            .map(|mapping| (mapping.integration_id.as_str(), mapping.event_types.as_slice()))
            .collect::<Vec<_>>(),
        "Integration mappings updated"
    );
    Ok(mappings)
}

/// Returns the mappings when every one of them is attachable under `rules`. A mapping must name
/// its event types unless its integration is in `previously_unfiltered`, the integrations already
/// stored with no event filter, which keep firing on every event.
pub async fn validate_mappings(
    request: MappingsRequest,
    rules: &MappingRules,
    integrations: &IntegrationStorage,
    previously_unfiltered: &HashSet<String>,
) -> Result<Vec<MappingRequest>, Rejection> {
    let mappings = request.integration_integrations;
    if mappings.len() > MAX_MAPPINGS {
        return Err(reject(StatusCode::BAD_REQUEST, "Too many integrations"));
    }
    let mut seen = HashSet::new();
    if !mappings
        .iter()
        .all(|mapping| {
            seen.insert(
                mapping
                    .integration_id
                    .as_str(),
            )
        })
    {
        return Err(reject(StatusCode::BAD_REQUEST, "An integration is attached more than once"));
    }
    let prefix = crate::integrations::runtime_variables::custom_variable_prefix();
    for mapping in &mappings {
        validate_variables(&mapping.variables, &prefix)?;
        validate_event_types(mapping, rules, previously_unfiltered)?;
        ensure_attachable(integrations, &mapping.integration_id, rules).await?;
    }
    Ok(mappings)
}

/// User and identity mappings belong to the whole appliance, so a tenant or resource-scoped token
/// cannot change them.
pub fn ensure_appliance_wide_caller(
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), Rejection> {
    if context.is_some() || scope.is_some() {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "These integrations are appliance-wide and need an appliance-wide caller",
        ));
    }
    Ok(())
}

fn validate_variables(
    variables: &HashMap<String, String>,
    custom_prefix: &str,
) -> Result<(), Rejection> {
    let within_limits = variables.len() <= MAX_VARIABLES
        && variables
            .iter()
            .all(|(name, value)| {
                name.starts_with(custom_prefix)
                    && name.len() > custom_prefix.len()
                    && name.len() <= MAX_VARIABLE_NAME_LEN
                    && value.len() <= MAX_VARIABLE_VALUE_LEN
            });
    if within_limits {
        Ok(())
    } else {
        Err(reject(StatusCode::BAD_REQUEST, "Variables must be custom variables within the size limits"))
    }
}

fn validate_event_types(
    mapping: &MappingRequest,
    rules: &MappingRules,
    previously_unfiltered: &HashSet<String>,
) -> Result<(), Rejection> {
    if mapping.event_types.is_empty() {
        return if previously_unfiltered.contains(&mapping.integration_id) {
            Ok(())
        } else {
            Err(reject(StatusCode::BAD_REQUEST, "Select at least one event type"))
        };
    }
    if mapping
        .event_types
        .iter()
        .all(|event_type| {
            rules
                .event_types
                .contains(&event_type.as_str())
        })
    {
        Ok(())
    } else {
        Err(reject(StatusCode::BAD_REQUEST, "Unknown event type"))
    }
}

async fn ensure_attachable(
    integrations: &IntegrationStorage,
    integration_id: &str,
    rules: &MappingRules,
) -> Result<(), Rejection> {
    let not_accessible = || reject(StatusCode::BAD_REQUEST, "Integration reference is not accessible");
    let integration = integrations
        .load(integration_id)
        .await
        .map_err(|_| not_accessible())?;
    if integration
        .tenant_id
        .is_some()
    {
        return Err(not_accessible());
    }
    if crate::integrations::audit_integration_triggers::is_audit_integration(&integration) {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            crate::gateways::connection_points::handlers::AUDIT_INTEGRATION_NOT_LINKABLE,
        ));
    }
    match integration
        .category
        .as_deref()
    {
        Some(category) if category == rules.category || category == "general" => Ok(()),
        _ => {
            Err(reject(StatusCode::BAD_REQUEST, &format!("Integration category must be {} or general", rules.category)))
        }
    }
}

fn reject(
    status: StatusCode,
    error: &str,
) -> Rejection {
    (status, Json(json!({ "error": error })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Integration;
    use std::sync::Arc;

    const RULES: MappingRules = MappingRules {
        category: "user",
        event_types: &["user.created", "user.login"],
    };

    struct Fixture {
        _dir: tempfile::TempDir,
        store: IntegrationStorage,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = IntegrationStorage::new(dir.path().to_path_buf())
                .await
                .expect("integration storage");
            Self { _dir: dir, store }
        }

        async fn add(
            &self,
            category: &str,
            tenant_id: Option<&str>,
        ) -> String {
            let mut integration = Integration::new(
                "Sink".to_string(),
                String::new(),
                "webhook".to_string(),
                json!({}),
                json!({}),
                "active".to_string(),
                Some(category.to_string()),
            );
            integration.tenant_id = tenant_id.map(str::to_string);
            self.store
                .save(&integration)
                .await
                .expect("save integration");
            integration.id
        }

        async fn validate(
            &self,
            mappings: Vec<MappingRequest>,
        ) -> Result<Vec<MappingRequest>, Rejection> {
            self.validate_with_unfiltered(mappings, &HashSet::new())
                .await
        }

        async fn validate_with_unfiltered(
            &self,
            mappings: Vec<MappingRequest>,
            previously_unfiltered: &HashSet<String>,
        ) -> Result<Vec<MappingRequest>, Rejection> {
            validate_mappings(
                MappingsRequest {
                    integration_integrations: mappings,
                },
                &RULES,
                &self.store,
                previously_unfiltered,
            )
            .await
        }
    }

    fn mapping(integration_id: &str) -> MappingRequest {
        MappingRequest {
            integration_id: integration_id.to_string(),
            variables: HashMap::new(),
            event_types: vec!["user.created".to_string()],
        }
    }

    fn assert_rejected(
        result: Result<Vec<MappingRequest>, Rejection>,
        status: StatusCode,
        error: &str,
    ) {
        let (actual_status, body) = result.expect_err("the mapping is refused");
        assert_eq!(actual_status, status);
        assert_eq!(body.0["error"], error);
    }

    #[tokio::test]
    async fn a_valid_mapping_is_accepted_as_submitted() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted
            .variables
            .insert("_TEAM".to_string(), "platform".to_string());

        let accepted = fixture
            .validate(vec![submitted])
            .await
            .expect("valid mapping");

        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].integration_id, id);
        assert_eq!(accepted[0].event_types, vec!["user.created"]);
        assert_eq!(accepted[0].variables["_TEAM"], "platform");
    }

    #[tokio::test]
    async fn a_general_integration_may_be_attached() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("general", None)
            .await;

        assert!(
            fixture
                .validate(vec![mapping(&id)])
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_unknown_integration_is_refused() {
        let fixture = Fixture::new().await;

        assert_rejected(
            fixture
                .validate(vec![mapping("missing")])
                .await,
            StatusCode::BAD_REQUEST,
            "Integration reference is not accessible",
        );
    }

    #[tokio::test]
    async fn a_tenant_owned_integration_cannot_receive_appliance_wide_events() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("general", Some("tenant-a"))
            .await;

        assert_rejected(
            fixture
                .validate(vec![mapping(&id)])
                .await,
            StatusCode::BAD_REQUEST,
            "Integration reference is not accessible",
        );
    }

    #[tokio::test]
    async fn an_audit_integration_is_refused() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("audit", None)
            .await;

        assert_rejected(
            fixture
                .validate(vec![mapping(&id)])
                .await,
            StatusCode::BAD_REQUEST,
            crate::gateways::connection_points::handlers::AUDIT_INTEGRATION_NOT_LINKABLE,
        );
    }

    #[tokio::test]
    async fn an_integration_of_another_category_is_refused() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("gateway", None)
            .await;

        assert_rejected(
            fixture
                .validate(vec![mapping(&id)])
                .await,
            StatusCode::BAD_REQUEST,
            "Integration category must be user or general",
        );
    }

    #[tokio::test]
    async fn an_unknown_event_type_is_refused() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted.event_types = vec!["gateway.created".to_string()];

        assert_rejected(
            fixture
                .validate(vec![submitted])
                .await,
            StatusCode::BAD_REQUEST,
            "Unknown event type",
        );
    }

    #[tokio::test]
    async fn a_new_mapping_must_name_its_event_types() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted.event_types = Vec::new();

        assert_rejected(
            fixture
                .validate(vec![submitted])
                .await,
            StatusCode::BAD_REQUEST,
            "Select at least one event type",
        );
    }

    #[tokio::test]
    async fn a_stored_unfiltered_mapping_may_be_saved_again_unchanged() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted.event_types = Vec::new();

        let accepted = fixture
            .validate_with_unfiltered(vec![submitted], &HashSet::from([id.clone()]))
            .await
            .expect("an existing unfiltered mapping is kept");

        assert!(
            accepted[0]
                .event_types
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_same_integration_cannot_be_attached_twice() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;

        assert_rejected(
            fixture
                .validate(vec![mapping(&id), mapping(&id)])
                .await,
            StatusCode::BAD_REQUEST,
            "An integration is attached more than once",
        );
    }

    #[tokio::test]
    async fn the_number_of_mappings_is_bounded() {
        let fixture = Fixture::new().await;
        let mappings = (0..=MAX_MAPPINGS)
            .map(|index| mapping(&format!("integration-{index}")))
            .collect();

        assert_rejected(
            fixture
                .validate(mappings)
                .await,
            StatusCode::BAD_REQUEST,
            "Too many integrations",
        );
    }

    #[tokio::test]
    async fn only_custom_variables_may_be_supplied() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted
            .variables
            .insert("USER_ID".to_string(), "forged".to_string());

        assert_rejected(
            fixture
                .validate(vec![submitted])
                .await,
            StatusCode::BAD_REQUEST,
            "Variables must be custom variables within the size limits",
        );
    }

    #[tokio::test]
    async fn an_oversized_variable_value_is_refused() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted
            .variables
            .insert("_NOTE".to_string(), "x".repeat(MAX_VARIABLE_VALUE_LEN + 1));

        assert_rejected(
            fixture
                .validate(vec![submitted])
                .await,
            StatusCode::BAD_REQUEST,
            "Variables must be custom variables within the size limits",
        );
    }

    #[tokio::test]
    async fn too_many_variables_are_refused() {
        let fixture = Fixture::new().await;
        let id = fixture
            .add("user", None)
            .await;
        let mut submitted = mapping(&id);
        submitted.variables = (0..=MAX_VARIABLES)
            .map(|index| (format!("_V{index}"), "value".to_string()))
            .collect();

        assert_rejected(
            fixture
                .validate(vec![submitted])
                .await,
            StatusCode::BAD_REQUEST,
            "Variables must be custom variables within the size limits",
        );
    }

    mod replacing {
        use super::*;
        use crate::integrations::user_integration_triggers::USER_MAPPING_RULES;
        use crate::integrations::user_integrations_storage::UserIntegrationsStorage;

        struct Stored {
            fixture: Fixture,
            _triggers: tempfile::TempDir,
            mappings: UserIntegrationsStorage,
        }

        impl Stored {
            async fn new() -> Self {
                let triggers = tempfile::tempdir().expect("tempdir");
                let mappings = UserIntegrationsStorage::new(triggers.path().to_path_buf())
                    .await
                    .expect("user mappings storage");
                Self {
                    fixture: Fixture::new().await,
                    _triggers: triggers,
                    mappings,
                }
            }

            async fn replace(
                &self,
                submitted: Vec<MappingRequest>,
                caller: Caller<'_>,
            ) -> Result<Vec<MappingRequest>, Rejection> {
                replace_mappings(
                    &self.mappings,
                    MappingsRequest {
                        integration_integrations: submitted,
                    },
                    &USER_MAPPING_RULES,
                    &self.fixture.store,
                    caller,
                )
                .await
            }

            async fn stored_ids(&self) -> Vec<String> {
                self.mappings
                    .load()
                    .await
                    .expect("load mappings")
                    .integration_integrations
                    .into_iter()
                    .map(|mapping| mapping.integration_id)
                    .collect()
            }
        }

        fn admin() -> Caller<'static> {
            Caller {
                actor: Some("admin-user"),
                context: None,
                scope: None,
            }
        }

        #[tokio::test]
        async fn valid_mappings_are_stored() {
            let stored = Stored::new().await;
            let id = stored
                .fixture
                .add("user", None)
                .await;

            stored
                .replace(vec![mapping(&id)], admin())
                .await
                .expect("stored");

            let saved = stored
                .mappings
                .load()
                .await
                .unwrap()
                .integration_integrations;
            assert_eq!(saved.len(), 1);
            assert_eq!(saved[0].integration_id, id);
            assert_eq!(saved[0].event_types, vec!["user.created"]);
        }

        #[tokio::test]
        async fn a_refused_caller_leaves_the_stored_mappings_unchanged() {
            let stored = Stored::new().await;
            let kept = stored
                .fixture
                .add("user", None)
                .await;
            let other = stored
                .fixture
                .add("user", None)
                .await;
            stored
                .replace(vec![mapping(&kept)], admin())
                .await
                .expect("seeded");
            let tenant = PatTenantContext {
                token_id: "agat_test".into(),
                tenant_id: "tenant-a".into(),
            };

            let (status, _) = stored
                .replace(
                    vec![mapping(&other)],
                    Caller {
                        actor: Some("tenant-user"),
                        context: Some(&tenant),
                        scope: None,
                    },
                )
                .await
                .expect_err("refused");

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(stored.stored_ids().await, vec![kept]);
        }

        #[tokio::test]
        async fn a_refused_mapping_leaves_the_stored_mappings_unchanged() {
            let stored = Stored::new().await;
            let kept = stored
                .fixture
                .add("user", None)
                .await;
            let audit = stored
                .fixture
                .add("audit", None)
                .await;
            stored
                .replace(vec![mapping(&kept)], admin())
                .await
                .expect("seeded");

            let (status, _) = stored
                .replace(vec![mapping(&kept), mapping(&audit)], admin())
                .await
                .expect_err("refused");

            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(stored.stored_ids().await, vec![kept]);
        }

        #[tokio::test]
        async fn a_stored_unfiltered_mapping_survives_a_save() {
            let stored = Stored::new().await;
            let legacy = stored
                .fixture
                .add("general", None)
                .await;
            let mut unfiltered = mapping(&legacy);
            unfiltered.event_types = Vec::new();
            stored
                .mappings
                .replace(vec![unfiltered.clone()])
                .await
                .expect("legacy mapping on disk");

            let accepted = stored
                .replace(vec![unfiltered], admin())
                .await
                .expect("kept");

            assert!(
                accepted[0]
                    .event_types
                    .is_empty()
            );
        }
    }

    #[test]
    fn unknown_request_fields_are_refused() {
        let mapping_field = serde_json::from_value::<MappingsRequest>(json!({
            "integration_integrations": [{ "integration_id": "i-1", "event_types": [], "tenant_id": "t" }]
        }));
        let top_level_field = serde_json::from_value::<MappingsRequest>(json!({
            "integration_integrations": [],
            "owner": "someone"
        }));

        assert!(mapping_field.is_err());
        assert!(top_level_field.is_err());
    }

    #[test]
    fn an_appliance_wide_caller_may_change_mappings() {
        assert!(ensure_appliance_wide_caller(None, None).is_ok());
    }

    #[test]
    fn a_tenant_token_cannot_change_appliance_wide_mappings() {
        let tenant = PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        };

        let (status, _) = ensure_appliance_wide_caller(Some(&tenant), None).expect_err("refused");

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_resource_scoped_token_cannot_change_appliance_wide_mappings() {
        let scope = PatResourceScope(Arc::new(regex::Regex::new("^integrations/.*$").unwrap()));

        let (status, _) = ensure_appliance_wide_caller(None, Some(&scope)).expect_err("refused");

        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
