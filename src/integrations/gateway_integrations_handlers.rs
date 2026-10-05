use axum::{Extension, extract::Path, http::StatusCode, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};

use crate::auth_manager::pat::PatResourceScope;
use crate::config::BootstrapConfig;
use crate::gateways::GatewayStore;
use crate::integrations::gateway_integrations_storage::{GatewayIntegrationsConfig, GatewayIntegrationsStorage};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_mutate, can_reference, scope_allows_resource};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

async fn load_gateway(
    gateway_store: &crate::gateways::FileSystemGatewayStore,
    gateway_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    mutation: bool,
) -> Result<crate::gateways::types::Gateway, (StatusCode, Json<Value>)> {
    let gateway = gateway_store
        .get(gateway_id)
        .await
        .map_err(|error| {
            error!(%gateway_id, %error, "Failed to load gateway for integration assignment");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to load gateway" })))
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "Gateway not found" }))))?;
    let tenant_allowed = if mutation {
        can_mutate(gateway.tenant_id.as_deref(), tenant_context(context))
    } else {
        can_access(gateway.tenant_id.as_deref(), tenant_context(context))
    };
    let allowed = tenant_allowed
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Gateways, &gateway.id);
    if !allowed {
        let status = if mutation {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::NOT_FOUND
        };
        return Err((status, Json(json!({ "error": "Gateway not accessible" }))));
    }
    Ok(gateway)
}

/// GET /api/v1/gateways/:id/integrations
/// Get the gateway integrations configuration for a specific gateway
pub async fn get_gateway_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Extension(gateway_store): Extension<Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_gateway(gateway_store.as_ref(), &gateway_id, &context, &scope, false).await?;
    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway_id);

    let storage = GatewayIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create gateway integrations storage for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    let config = storage
        .load()
        .await
        .map_err(|e| {
            error!("Failed to load gateway integrations for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to load gateway integrations"
                })),
            )
        })?;

    Ok(Json(json!(config)))
}

/// Whether a gateway owned by `gateway_tenant` may link `integration`: the
/// caller must be able to reference it, and a governance audit integration is
/// never linkable, since it receives only VP Audit Log records.
fn ensure_linkable(
    gateway_tenant: Option<&str>,
    integration: &crate::storage::Integration,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), (StatusCode, Json<Value>)> {
    if !can_reference(
        gateway_tenant,
        integration
            .tenant_id
            .as_deref(),
    ) || !scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::Integrations,
        &integration.id,
    ) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "Integration reference is not accessible" }))));
    }
    if crate::integrations::audit_integration_triggers::is_audit_integration(integration) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": crate::gateways::connection_points::handlers::AUDIT_INTEGRATION_NOT_LINKABLE })),
        ));
    }
    Ok(())
}

/// PUT /api/v1/gateways/:id/integrations
/// Update the gateway integrations configuration for a specific gateway
pub async fn update_gateway_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Extension(gateway_store): Extension<Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(integration_store): Extension<Option<Arc<crate::storage::IntegrationStorage>>>,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(payload): Json<GatewayIntegrationsConfig>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let gateway = load_gateway(gateway_store.as_ref(), &gateway_id, &context, &scope, true).await?;
    let integration_store = integration_store.ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Integration store not configured" })))
    })?;
    for assignment in &payload.integration_integrations {
        let integration = integration_store
            .load(&assignment.integration_id)
            .await
            .map_err(|_| {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": "Integration reference is not accessible" })))
            })?;
        ensure_linkable(gateway.tenant_id.as_deref(), &integration, &context, &scope)?;
    }
    info!(
        "Updating gateway integrations for gateway {} with {} integrations",
        gateway_id,
        payload
            .integration_integrations
            .len()
    );

    // Log each integration's event_types for debugging
    for (idx, integration) in payload
        .integration_integrations
        .iter()
        .enumerate()
    {
        info!(
            "Integration {}: integration_id={}, event_types={:?}, variables={:?}",
            idx,
            integration.integration_id,
            integration.event_types,
            integration.variables.keys()
        );
    }

    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway_id);

    let storage = GatewayIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create gateway integrations storage for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    storage
        .save(&payload)
        .await
        .map_err(|e| {
            error!("Failed to save gateway integrations for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to save gateway integrations"
                })),
            )
        })?;

    info!("Successfully saved gateway integrations for gateway {}", gateway_id);
    Ok(Json(json!({
        "message": "Gateway integrations updated successfully",
        "integration_integrations": payload.integration_integrations
    })))
}

#[cfg(test)]
mod tests {
    use super::{ensure_linkable, load_gateway};
    use crate::gateways::connection_points::handlers::AUDIT_INTEGRATION_NOT_LINKABLE;
    use crate::storage::Integration;
    use axum::http::StatusCode;

    fn integration(category: &str) -> Integration {
        Integration::new(
            "Sink".to_string(),
            String::new(),
            "stream".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            "active".to_string(),
            Some(category.to_string()),
        )
    }

    #[test]
    fn a_gateway_cannot_link_an_audit_integration() {
        let (status, body) = ensure_linkable(None, &integration("audit"), &None, &None).unwrap_err();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], AUDIT_INTEGRATION_NOT_LINKABLE);
    }

    #[test]
    fn a_gateway_can_link_other_integrations() {
        assert!(ensure_linkable(None, &integration("gateway"), &None, &None).is_ok());
    }

    #[tokio::test]
    async fn a_tenant_token_reads_but_cannot_change_an_appliance_gateways_integrations() {
        use crate::gateways::GatewayStore;
        use crate::gateways::types::{Gateway, GatewayCreationType, GatewayType};
        use crate::tenancy::PatTenantContext;
        use axum::Extension;

        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            crate::gateways::FileSystemGatewayStore::new(dir.path().to_path_buf(), Some("did:web:self.example".into()))
                .await
                .expect("gateway store");
        let mut appliance = Gateway::new_with_creation_type(
            "Peer".to_string(),
            "Appliance-wide peer".to_string(),
            "did:web:peer.example".to_string(),
            GatewayType::Remote,
            GatewayCreationType::User,
        );
        appliance.id = "appliance-peer".into();
        let mut owned = appliance.clone();
        owned.id = "tenant-peer".into();
        owned.did = "did:web:tenant-peer.example".into();
        owned.tenant_id = Some("tenant-a".into());
        for gateway in [&appliance, &owned] {
            store
                .create(gateway)
                .await
                .expect("create gateway");
        }
        let tenant = Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        }));

        assert!(
            load_gateway(&store, "appliance-peer", &tenant, &None, false)
                .await
                .is_ok(),
            "a tenant may read an appliance gateway's integrations"
        );
        let (status, _) = load_gateway(&store, "appliance-peer", &tenant, &None, true)
            .await
            .expect_err("a tenant cannot change an appliance gateway's integrations");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            load_gateway(&store, "tenant-peer", &tenant, &None, true)
                .await
                .is_ok(),
            "a tenant changes its own gateway's integrations"
        );
        assert!(
            load_gateway(&store, "appliance-peer", &None, &None, true)
                .await
                .is_ok(),
            "an appliance-wide caller is unaffected"
        );
    }
}
