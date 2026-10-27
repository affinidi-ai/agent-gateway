//! VTA connection CRUD HTTP handlers.
//!
//! Administrator-gated (`vta_connections.*`); non-admin callers receive `403`.
//! A response never contains key material — only the `control_key_ref` into the
//! secrets store is stored and returned.
//!
//! Every write **invalidates** the connection's cached connector, which is what
//! makes an edit or a disable take effect without a restart.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::rbac::{Feature, RbacConfig};
use crate::secrets::SecretsStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, tenant_for_create,
};
use crate::vta::connections::{VtaConnection, VtaConnectionStatus, VtaConnectionStorage, VtaConnectionTransport};
use crate::vta::registry::VtaConnectionRegistry;

/// Axum state: the record store plus the live registry whose cache a write
/// must invalidate.
#[derive(Clone)]
pub struct VtaConnectionAdminState {
    pub store: Arc<dyn VtaConnectionStorage>,
    pub registry: Option<Arc<VtaConnectionRegistry>>,
    /// The bootstrap `[vta]` block, for the deployment-tier report. Read-only
    /// here: it is startup config, not a managed record.
    pub vta_config: Arc<crate::config::vta::VtaConfig>,
    /// Context provisioner, for reporting which contexts exist and which no
    /// surface claims any more (VTA-20).
    pub provisioner: Option<Arc<crate::vta::provisioning::ContextProvisioner>>,
    /// What this appliance signs with when nobody has said, and why (VTA-26).
    /// Resolved once at startup — it is a property of the install, not of a
    /// request.
    pub default_resolution: Arc<crate::vta::onboarding_default::DefaultResolution>,
}

/// Body for create / update.
#[derive(Debug, Default, Deserialize)]
pub struct VtaConnectionRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub transport: VtaConnectionTransport,
    pub endpoint: String,
    pub vta_did: String,
    #[serde(default)]
    pub default_context_id: Option<String>,
    #[serde(default)]
    pub control_key_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn json(msg: impl Into<String>) -> Json<Self> {
        Json(Self { error: msg.into() })
    }
}

fn unauthorized() -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::UNAUTHORIZED, ErrorBody::json("Unauthorized"))
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::FORBIDDEN, ErrorBody::json("Forbidden"))
}

fn not_found() -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::NOT_FOUND, ErrorBody::json("connection not found"))
}

async fn require_permission(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    feature: &Feature,
    pat: Option<&PatContext>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| {
            error!("Failed to load user {} for RBAC check: {}", user_id, e);
            unauthorized()
        })?
        .ok_or_else(|| {
            warn!(user_id = %user_id, "VTA connection CRUD rejected — user not found");
            unauthorized()
        })?;
    if !rbac_config.has_permission(&user.role, feature) {
        warn!(user_id = %user_id, feature = %feature.as_str(), "VTA connection CRUD rejected — insufficient permissions");
        return Err(forbidden());
    }
    if let Some(PatContext(Some(scopes))) = pat
        && !scopes
            .iter()
            .any(|scope| scope == feature.as_str())
    {
        warn!(user_id = %user_id, feature = %feature.as_str(), "VTA connection CRUD rejected — access-token scope excludes permission");
        return Err(forbidden());
    }
    Ok(())
}

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

fn connection_allowed(
    connection: &VtaConnection,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(
        connection
            .tenant_id
            .as_deref(),
        tenant_context(context),
    ) && scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::VtaConnections,
        &connection.id,
    )
}

/// The control key is the credential this gateway authenticates to the VTA
/// with, so the reference must point at a secret the caller may actually use —
/// otherwise a tenant could borrow another tenant's VTA identity.
async fn validate_control_key_reference(
    owner_tenant_id: Option<&str>,
    secret_ref: Option<&str>,
    secrets_store: Option<&Arc<dyn SecretsStore>>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let Some(secret_ref) = secret_ref.filter(|r| !r.trim().is_empty()) else {
        return Ok(());
    };
    let store = secrets_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Secrets store is not configured")))?;
    let secret = store
        .get_by_secret_id(secret_ref)
        .await
        .map_err(|e| {
            error!(secret_ref = %secret_ref, error = %e, "Failed to validate VTA control key reference");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, ErrorBody::json("control_key_ref does not reference an accessible secret"))
        })?;
    if !can_reference(owner_tenant_id, secret.tenant_id.as_deref())
        || !scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            ErrorBody::json("control_key_ref does not reference an accessible secret"),
        ));
    }
    Ok(())
}

fn to_connection(
    id: String,
    body: VtaConnectionRequest,
    status: VtaConnectionStatus,
) -> VtaConnection {
    let now = chrono::Utc::now();
    VtaConnection {
        id,
        tenant_id: body.tenant_id,
        name: body.name,
        description: body.description,
        enabled: body.enabled,
        transport: body.transport,
        endpoint: body.endpoint,
        vta_did: body.vta_did,
        default_context_id: body.default_context_id,
        control_key_ref: body.control_key_ref,
        status,
        keys: Default::default(),
        pairing: Default::default(),
        created_at: now,
        updated_at: now,
    }
}

async fn invalidate(
    state: &VtaConnectionAdminState,
    id: &str,
) {
    if let Some(registry) = &state.registry {
        registry.invalidate(id).await;
    }
}

/// Take a newly-written connection's address off the data plane (VTA-21).
///
/// Reservations are never removed: an address that was a VTA stays one for
/// this process, so deleting a connection cannot be used to make the agent
/// that still holds keys proxy-reachable.
fn reserve_endpoint(connection: &VtaConnection) {
    crate::vta::isolation::reserve(&connection.endpoint);
}

/// `POST /v1/vta/connections` — create a connection.
pub async fn create_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    secrets_store: Option<Extension<Arc<dyn SecretsStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<VtaConnectionRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    body.tenant_id = match tenant_for_create(body.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, ErrorBody::json(message)).into_response(),
    };
    if let Err(response) = validate_control_key_reference(
        body.tenant_id.as_deref(),
        body.control_key_ref
            .as_deref(),
        secrets_store
            .as_ref()
            .map(|Extension(store)| store),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await
    {
        return response.into_response();
    }
    let mut connection = to_connection(uuid::Uuid::new_v4().to_string(), body, VtaConnectionStatus::Unpaired);

    // Every connection gets its **own** control key (VTA-24): revoking one
    // must not strand the others, and a leaked seed must not authenticate the
    // gateway to every VTA it knows. The seed is written to the secrets store
    // and only its reference lands on the record, so no key material is ever
    // persisted in connection JSON.
    if connection
        .control_key_ref
        .as_deref()
        .map(|r| r.trim().is_empty())
        .unwrap_or(true)
        && let Some(Extension(secrets)) = secrets_store.as_ref()
    {
        match mint_connection_control_key(secrets, &connection.id, connection.tenant_id.clone()).await {
            Ok(secret_ref) => connection.control_key_ref = Some(secret_ref),
            Err(response) => return response.into_response(),
        }
    }

    if let Err(message) = connection.validate() {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }
    if !connection_allowed(&connection, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("VTA connection is outside this token's permitted scope"))
            .into_response();
    }
    match state
        .store
        .create(connection)
        .await
    {
        Ok(created) => {
            info!(id = %created.id, name = %created.name, "VTA connection created");
            reserve_endpoint(&created);
            invalidate(&state, &created.id).await;
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => {
            error!("Failed to create VTA connection: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to create connection")).into_response()
        }
    }
}

/// `GET /v1/vta/connections` — list connections.
pub async fn list_connections(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match state.store.list().await {
        Ok(mut connections) => {
            connections.retain(|connection| connection_allowed(connection, &context, &scope));
            (StatusCode::OK, Json(connections)).into_response()
        }
        Err(e) => {
            error!("Failed to list VTA connections: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to list connections")).into_response()
        }
    }
}

/// `GET /v1/vta/connections/{id}` — fetch one connection.
pub async fn get_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match state.store.get(&id).await {
        Ok(Some(connection)) if connection_allowed(&connection, &context, &scope) => {
            (StatusCode::OK, Json(connection)).into_response()
        }
        Ok(_) => not_found().into_response(),
        Err(e) => {
            error!("Failed to get VTA connection {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to get connection")).into_response()
        }
    }
}

/// `PUT /v1/vta/connections/{id}` — update a connection.
pub async fn update_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    secrets_store: Option<Extension<Arc<dyn SecretsStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<VtaConnectionRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    let existing = match state.store.get(&id).await {
        Ok(Some(existing)) => existing,
        Ok(None) => return not_found().into_response(),
        Err(e) => {
            error!(id = %id, error = %e, "Failed to load VTA connection before update");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    };
    if !connection_allowed(&existing, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("VTA connection is outside this token's permitted scope"))
            .into_response();
    }
    // The bootstrap record mirrors the `[vta]` TOML block, which is re-applied
    // on every boot. Allowing an edit here would make "which one wins after a
    // restart" unanswerable, so the block stays the only way to change it.
    if existing.is_bootstrap() {
        return (
            StatusCode::CONFLICT,
            ErrorBody::json("the bootstrap connection is managed by the [vta] configuration block"),
        )
            .into_response();
    }
    // Ownership is not reassignable here (see the tenancy section of AGENTS.md).
    body.tenant_id = existing.tenant_id.clone();
    if let Err(response) = validate_control_key_reference(
        body.tenant_id.as_deref(),
        body.control_key_ref
            .as_deref(),
        secrets_store
            .as_ref()
            .map(|Extension(store)| store),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await
    {
        return response.into_response();
    }
    let updated = to_connection(id.clone(), body, existing.status);
    if let Err(message) = updated.validate() {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }
    match state
        .store
        .update(updated)
        .await
    {
        Ok(updated) => {
            info!(id = %id, enabled = updated.enabled, "VTA connection updated");
            reserve_endpoint(&updated);
            // Take effect now: the next signing call rebuilds, or fails closed
            // if the connection was just disabled.
            invalidate(&state, &id).await;
            (StatusCode::OK, Json(updated)).into_response()
        }
        Err(e) => {
            error!("Failed to update VTA connection {}: {}", id, e);
            not_found().into_response()
        }
    }
}

/// `DELETE /v1/vta/connections/{id}` — remove a connection.
pub async fn delete_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsDelete,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match state.store.get(&id).await {
        Ok(Some(connection)) if connection_allowed(&connection, &context, &scope) => {
            if connection.is_bootstrap() {
                return (
                    StatusCode::CONFLICT,
                    ErrorBody::json("the bootstrap connection is managed by the [vta] configuration block"),
                )
                    .into_response();
            }
        }
        Ok(Some(_)) => {
            return (StatusCode::FORBIDDEN, ErrorBody::json("VTA connection is outside this token's permitted scope"))
                .into_response();
        }
        Ok(None) => return not_found().into_response(),
        Err(e) => {
            error!(id = %id, error = %e, "Failed to load VTA connection before delete");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    }
    match state.store.delete(&id).await {
        Ok(()) => {
            info!(id = %id, "VTA connection deleted");
            invalidate(&state, &id).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("Failed to delete VTA connection {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to delete connection")).into_response()
        }
    }
}

/// Load a connection for a pairing operation, applying the same RBAC, tenancy
/// and PAT-scope gates the CRUD routes use.
async fn load_for_pairing(
    user_id: &str,
    passkey_storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    state: &VtaConnectionAdminState,
    id: &str,
    feature: &Feature,
    pat: Option<&Extension<PatContext>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<VtaConnection, (StatusCode, Json<ErrorBody>)> {
    require_permission(user_id, passkey_storage, rbac_config, feature, pat.map(|Extension(pat)| pat)).await?;
    let connection = state
        .store
        .get(id)
        .await
        .map_err(|e| {
            error!(id = %id, error = %e, "Failed to load VTA connection for pairing");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(not_found)?;
    if !connection_allowed(&connection, context, scope) {
        // Indistinguishable from "does not exist", so a scoped token cannot
        // probe for connections it may not see.
        return Err(not_found());
    }
    Ok(connection)
}

async fn persist_pairing(
    state: &VtaConnectionAdminState,
    mut connection: VtaConnection,
    pairing: crate::vta::pairing::PairingRecord,
) -> Result<VtaConnection, (StatusCode, Json<ErrorBody>)> {
    connection.status = pairing.state.into();
    connection.pairing = pairing;
    let id = connection.id.clone();
    let updated = state
        .store
        .update(connection)
        .await
        .map_err(|e| {
            error!(id = %id, error = %e, "Failed to persist VTA pairing state");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?;
    // Pairing changes whether the connection may sign, so the cached connector
    // must go: a revoke has to take effect on the very next request.
    invalidate(state, &id).await;
    Ok(updated)
}

/// `POST /v1/vta/connections/{id}/pair` — begin pairing and return the artifact
/// the customer approves on their own VTA.
///
/// Minting the per-connection control key is the caller's responsibility once a
/// secrets store is wired; until then an existing `control_key_ref` is required,
/// so a pairing artifact always names a key the gateway actually holds.
pub async fn pair_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    secrets_store: Option<Extension<Arc<dyn SecretsStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::VtaConnectionsEdit,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };

    let control_did = match resolve_control_did(
        &connection,
        secrets_store
            .as_ref()
            .map(|Extension(store)| store),
        &state.vta_config,
    )
    .await
    {
        Ok(did) => did,
        Err(e) => return e.into_response(),
    };

    let (payload, pairing) = match crate::vta::pairing::begin_pairing(&connection, &control_did, chrono::Utc::now()) {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_REQUEST, ErrorBody::json(e.log_detail())).into_response(),
    };
    info!(
        target: "vta_audit",
        connection_id = %id,
        control_did = %control_did,
        "VTA pairing started",
    );
    // A re-pair must not take a working connection out of service, so the
    // record is only advanced when the connection is not already connected.
    if !connection
        .pairing
        .state
        .is_usable()
        && let Err(e) = persist_pairing(&state, connection, pairing).await
    {
        return e.into_response();
    }
    (StatusCode::OK, Json(payload)).into_response()
}

/// `POST /v1/vta/connections/{id}/verify` — check the grant and pin the VTA.
pub async fn verify_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::VtaConnectionsEdit,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };

    let Some(registry) = state.registry.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, ErrorBody::json("VTA connections are not active on this gateway"))
            .into_response();
    };

    // Reaching the VTA at all is the verification: the registry builds the
    // connector, which authenticates with this connection's control key.
    let previous = connection.pairing.clone();
    let outcome = match registry
        .verify(&connection)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            // Never a fallback to local signing — the connection stays
            // unusable and the operator is told why.
            let pairing = crate::vta::pairing::apply_failure(&previous, e.log_detail());
            warn!(
                target: "vta_audit",
                connection_id = %id,
                error = %e.log_detail(),
                "VTA pairing verification failed",
            );
            return match persist_pairing(&state, connection, pairing).await {
                Ok(updated) => (StatusCode::BAD_GATEWAY, Json(updated)).into_response(),
                Err(e) => e.into_response(),
            };
        }
    };

    let pairing = crate::vta::pairing::apply_verification(&connection, &previous, &outcome, chrono::Utc::now());
    info!(
        target: "vta_audit",
        connection_id = %id,
        pairing_state = %pairing.state.as_str(),
        "VTA pairing verified",
    );
    let connected = pairing.state.is_usable();
    match persist_pairing(&state, connection, pairing).await {
        Ok(updated) if connected => (StatusCode::OK, Json(updated)).into_response(),
        // Reached the VTA, but the grant or the identity is wrong: the
        // operator has to act, so this is not a success.
        Ok(updated) => (StatusCode::CONFLICT, Json(updated)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /v1/vta/connections/{id}/revoke` — stop using this connection now.
pub async fn revoke_connection(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::VtaConnectionsDelete,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };

    let pairing = crate::vta::pairing::revoke(&connection.pairing);
    info!(target: "vta_audit", connection_id = %id, "VTA connection revoked");
    match persist_pairing(&state, connection, pairing).await {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /v1/vta/connections/{id}/status` — live pairing state for the UI.
pub async fn connection_status(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::VtaConnectionsView,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };
    let usable = crate::vta::pairing::assert_usable(&connection, &connection.pairing).is_ok();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": connection.id,
            "enabled": connection.enabled,
            "status": connection.status,
            "pairing": connection.pairing,
            "usable": usable,
        })),
    )
        .into_response()
}

/// Mint this connection's own Ed25519 control key and store the seed in the
/// secrets store, returning the reference to record.
///
/// The seed never touches the connection record, so a leaked record file
/// cannot authenticate to the VTA; and the key is per connection, so revoking
/// one cannot strand the others.
async fn mint_connection_control_key(
    secrets: &Arc<dyn SecretsStore>,
    connection_id: &str,
    tenant_id: Option<String>,
) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let (control_did, seed) = crate::vta::pairing::mint_control_key();
    let secret_id = format!("vta-control-key-{connection_id}");
    secrets
        .create(crate::secrets::CreateSecretRequest {
            tenant_id,
            name: format!("VTA control key ({connection_id})"),
            secret_id: secret_id.clone(),
            description: Some(format!(
                "Ed25519 control-key seed the gateway authenticates to this VTA with ({control_did})."
            )),
            value: seed,
            secret_type: "General".to_string(),
            tags: vec!["vta".to_string()],
        })
        .await
        .map_err(|e| {
            error!(connection_id = %connection_id, error = %e, "Failed to store the VTA control key");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to store the control key"))
        })?;
    info!(
        target: "vta_audit",
        connection_id = %connection_id,
        control_did = %control_did,
        "minted a per-connection VTA control key",
    );
    Ok(secret_id)
}

/// The control DID the customer is asked to grant, resolved from the
/// connection's secrets-store reference.
///
/// Derived from the stored seed rather than recorded on the record, so the DID
/// and the key the gateway will actually authenticate with cannot drift apart.
async fn resolve_control_did(
    connection: &VtaConnection,
    secrets_store: Option<&Arc<dyn SecretsStore>>,
    vta_config: &crate::config::vta::VtaConfig,
) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let secret_ref = match connection
        .control_key_ref
        .as_deref()
        .filter(|r| !r.trim().is_empty())
    {
        Some(secret_ref) => secret_ref,
        // The bootstrap record carries no `control_key_ref` by design — its key
        // comes from `[vta] auth_key_source`, not the secrets store. Without
        // this branch the operator could not pair it, and the DID they must
        // grant appears nowhere they can read: it is redacted in the logs and
        // the key itself is encrypted at rest. An operator cannot grant what
        // they cannot see, so derive it from the same source the connector used.
        None if connection.is_bootstrap() => return bootstrap_control_did(vta_config).await,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                ErrorBody::json("this connection has no control_key_ref; set one before pairing"),
            ));
        }
    };
    let store = secrets_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Secrets store is not configured")))?;
    let secret = store
        .get_by_secret_id(secret_ref)
        .await
        .map_err(|e| {
            error!(secret_ref = %secret_ref, error = %e, "Failed to read the VTA control key");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, ErrorBody::json("control_key_ref does not reference an accessible secret"))
        })?;
    crate::vta::control_key_did(secret.value.trim())
        .map_err(|e| (StatusCode::BAD_REQUEST, ErrorBody::json(e.log_detail())))
}

/// The control DID the `[vta]` block authenticates with, for the pairing view.
///
/// Requires `auth_key_source` to be set, and says so rather than falling back.
/// With no source the gateway generates a **fresh key on every boot**, so a DID
/// derived here would neither match the running connector nor survive a
/// restart — showing it would send the operator to grant something that stops
/// being true as soon as the gateway restarts.
async fn bootstrap_control_did(
    vta_config: &crate::config::vta::VtaConfig
) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    if vta_config
        .auth_key_source
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            ErrorBody::json(
                "the [vta] block has no auth_key_source, so its control key is regenerated on every \
                 restart and cannot be granted; set auth_key_source (env:// or file://) and restart",
            ),
        ));
    }
    let key = crate::vta::build_control_key_material(vta_config)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, ErrorBody::json(e.log_detail())))?;
    crate::vta::control_key_did(&key.seed_hex()).map_err(|e| (StatusCode::BAD_REQUEST, ErrorBody::json(e.log_detail())))
}

/// `GET /v1/vta/status` — the appliance's signing-deployment tier.
///
/// The dashboard renders this verbatim. `custody_claim` is deliberately part
/// of the payload rather than inferred client-side: a bundled sidecar shares a
/// host, a disk and an operator with the gateway, so "the keys are held by a
/// separate agent" is not a property that deployment has, and the backend —
/// which is the only thing that knows the mode — says so explicitly rather
/// than leaving the UI to guess.
pub async fn vta_status(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    pat: Option<Extension<PatContext>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::VtaConnectionsView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    let config = &state.vta_config;
    // The identity an operator grants on their trust agent. Exposed here
    // because it is redacted in logs and encrypted on disk, so this authorised
    // response is the only place it can be read — and an operator cannot grant
    // what they cannot see. `None` when no stable key is configured, which is
    // the case where showing one would be worse than showing nothing.
    let control_did = bootstrap_control_did(config)
        .await
        .ok();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": config.enabled,
            "tier": config.tier(),
            // False for both local signing and a bundled sidecar. Nothing in
            // product copy may claim custody when this is false.
            "custody_claim": config.supports_custody_claim(),
            "self_administered": config.mode.allows_self_administration(),
            "auto_provision_contexts": config.auto_provision_contexts,
            "control_did": control_did,
            // What this appliance signs with when nobody has said, and why
            // (VTA-26). Reported so "why is it signing with this?" never
            // requires reading config or code.
            "default_resolution": state.default_resolution.as_ref(),
            // Addresses that are off-limits as proxy targets, so an operator
            // can see why a surface pointing at one was refused.
            "reserved_origins": crate::vta::isolation::reserved_origins(),
        })),
    )
        .into_response()
}

/// `GET /v1/key-management/inventory` — every key this appliance signs with,
/// which surface maps to what, and which contexts no surface claims.
///
/// Derived on every read from the live records rather than cached: a second
/// source of truth for "which key signs this" is one more thing that can drift
/// from the thing that actually signs.
pub async fn key_inventory(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    surfaces: Option<Extension<Arc<dyn crate::surfaces::AgentSurfaceStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::KeyManagementView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }

    let connections = match state.store.list().await {
        Ok(mut connections) => {
            // Same tenancy and PAT-scope filter as the connections list: the
            // inventory must not become a way to enumerate connections the
            // caller cannot otherwise see.
            connections.retain(|connection| connection_allowed(connection, &context, &scope));
            connections
        }
        Err(e) => {
            error!("Failed to list VTA connections for the key inventory: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to build the key inventory"))
                .into_response();
        }
    };

    let surface_list = match surfaces.as_ref() {
        Some(Extension(store)) => store
            .list_all()
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let known_contexts: Vec<String> = match &state.provisioner {
        Some(provisioner) => {
            provisioner
                .known_names()
                .await
        }
        None => Vec::new(),
    };

    (
        StatusCode::OK,
        Json(crate::vta::inventory::build(&state.vta_config, &connections, &surface_list, &known_contexts)),
    )
        .into_response()
}

/// Body for `POST /v1/vta/connections/{id}/rotate`.
#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    /// The VTA key record id to start signing with — also its published `kid`.
    pub key_id: String,
    /// Multibase public half. Required in practice for an internal
    /// (non-exportable) key, whose record the VTA will not return.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

/// `POST /v1/vta/connections/{id}/rotate` — start signing with a new key.
///
/// The previous key is **retired, never deleted**: a verifier selects between
/// keys by `kid`, so dropping the old public half would invalidate every token
/// it signed that is still in flight. Both keys keep being published.
pub async fn rotate_connection_key(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<RotateKeyRequest>,
) -> impl IntoResponse {
    let mut connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::KeyManagementEdit,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };

    let previous = connection
        .keys
        .active
        .as_ref()
        .map(|k| k.key_id.clone());
    if let Err(message) = connection.keys.rotate_to(
        crate::vta::connections::SigningKey {
            key_id: body.key_id.trim().to_string(),
            public_key: body.public_key,
            label: body.label,
            added_at: chrono::Utc::now(),
            retired_at: None,
        },
        chrono::Utc::now(),
    ) {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }

    match state
        .store
        .update(connection)
        .await
    {
        Ok(updated) => {
            info!(
                target: "vta_audit",
                connection_id = %id,
                new_key_id = %body.key_id,
                retired_key_id = previous.as_deref().unwrap_or("none"),
                "VTA signing key rotated",
            );
            // Rebuild on next use so the new key signs immediately.
            invalidate(&state, &id).await;
            (StatusCode::OK, Json(updated)).into_response()
        }
        Err(e) => {
            error!("Failed to rotate the VTA signing key for {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to rotate the key")).into_response()
        }
    }
}

/// `POST /v1/vta/connections/{id}/keys` — mint a signing key **inside the
/// trust agent** and start signing with it.
///
/// Distinct from `/rotate`, which only records a `key_id` the caller already
/// knows: nothing could create that key. The VTA CLI has no `keys create`, and
/// the gateway is the only party holding a session scoped to the granted
/// context, so without this a connection could be paired and verified and
/// still never sign — the appliance and surface pickers both require an active
/// key.
///
/// The private half is generated by the agent and never leaves it. `internal`
/// mints a **non-exportable** key: not by an operator, not by a super-admin,
/// not through a backup. That is the custody property the integration exists
/// to provide, and the trade — it cannot be recovered if the agent is lost —
/// is the one the runbook's seed-backup owner covers.
///
/// Mint one Ed25519 signing key inside the agent.
///
/// `internal: true` keeps the private half non-exportable — the reason to use
/// a trust agent at all. The public half is captured **here** because the
/// agent will not return an internal key's record to any caller at any role
/// afterwards, so this is the only moment it can be recorded for publication.
///
/// A fresh id per key so provisioning twice never collides with a key the
/// agent already holds, and so the `kid` in a token points at exactly one.
async fn mint_signing_key(
    client: &Arc<crate::vta::client::VtaRestClient>
) -> Result<crate::vta::connections::SigningKey, crate::vta::VtaError> {
    const LABEL: &str = "agent-gateway signing key";
    let key_id = format!("gateway-jwt-{}", uuid::Uuid::new_v4());
    let created: serde_json::Value = client
        .dispatch_signed(
            "https://trusttasks.org/spec/keys/create/0.1",
            serde_json::json!({
                "keyType": "ed25519",
                "keyId": key_id,
                "label": LABEL,
                "internal": true,
            }),
        )
        .await?;

    // The agent answers with a `#response` Trust-Task envelope; a flat `{ key }`
    // is tolerated for the same reason the rest of the client tolerates it.
    let key = created
        .get("payload")
        .and_then(|p| p.get("key"))
        .or_else(|| created.get("key"))
        .unwrap_or(&created);
    let public_key = key
        .get("publicKeyMultibase")
        .or_else(|| key.get("publicKey"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Ok(crate::vta::connections::SigningKey {
        key_id,
        public_key,
        label: Some(LABEL.to_string()),
        added_at: chrono::Utc::now(),
        retired_at: None,
    })
}

/// Requires the grant to carry `key-mint`, which the `initiator` role derives
/// and `application` does not; a connection granted the narrower role fails
/// here with the agent's own refusal rather than a gateway-invented one.
pub async fn provision_connection_key(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<VtaConnectionAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let mut connection = match load_for_pairing(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &state,
        &id,
        &Feature::KeyManagementEdit,
        pat.as_ref(),
        &context,
        &scope,
    )
    .await
    {
        Ok(connection) => connection,
        Err(e) => return e.into_response(),
    };

    let Some(registry) = state.registry.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorBody::json("Trust agent connections are not available on this gateway"),
        )
            .into_response();
    };
    let client = match registry.client(&id).await {
        Ok(client) => client,
        Err(e) => {
            // Already operator-facing and redacted of agent internals.
            return (StatusCode::BAD_REQUEST, ErrorBody::json(e.log_detail())).into_response();
        }
    };

    let created = match mint_signing_key(&client).await {
        Ok(created) => created,
        Err(e) => {
            error!(target: "vta_audit", connection_id = %id, error = %e.log_detail(), "could not mint a signing key");
            return (StatusCode::BAD_GATEWAY, ErrorBody::json(e.log_detail())).into_response();
        }
    };
    let key_id = created.key_id.clone();

    if let Err(message) = connection
        .keys
        .rotate_to(created, chrono::Utc::now())
    {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }

    match state
        .store
        .update(connection)
        .await
    {
        Ok(updated) => {
            info!(
                target: "vta_audit",
                connection_id = %id,
                key_id = %key_id,
                "minted a signing key in the trust agent",
            );
            invalidate(&state, &id).await;
            (StatusCode::CREATED, Json(updated)).into_response()
        }
        Err(e) => {
            // The key exists in the agent but is unrecorded here. Say so: the
            // operator can provision again (ids are unique) and the orphan is
            // inert, but silently reporting failure would hide a real artifact.
            error!(
                target: "vta_audit",
                connection_id = %id,
                key_id = %key_id,
                error = %e,
                "minted a signing key but could not record it on the connection",
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::json("The key was created in the trust agent but could not be recorded; provision again"),
            )
                .into_response()
        }
    }
}

/// Build the VTA connection admin router. The caller layers the session-auth
/// middleware and the `Extension<Arc<PasskeyStorage>>` /
/// `Extension<Arc<RbacConfig>>` extensions before merging, mirroring the STS
/// client router.
pub fn create_vta_connection_router(
    state: VtaConnectionAdminState,
    secrets_store: Option<Arc<dyn SecretsStore>>,
) -> Router {
    let router = Router::new()
        .route("/v1/vta/connections", post(create_connection))
        .route("/v1/vta/connections", get(list_connections))
        .route("/v1/vta/connections/{id}", get(get_connection))
        .route("/v1/vta/connections/{id}", put(update_connection))
        .route("/v1/vta/connections/{id}", delete(delete_connection))
        .route("/v1/vta/connections/{id}/pair", post(pair_connection))
        .route("/v1/vta/connections/{id}/verify", post(verify_connection))
        .route("/v1/vta/connections/{id}/revoke", post(revoke_connection))
        .route("/v1/vta/connections/{id}/status", get(connection_status))
        .route("/v1/vta/connections/{id}/rotate", post(rotate_connection_key))
        .route("/v1/vta/connections/{id}/keys", post(provision_connection_key))
        .route("/v1/vta/status", get(vta_status))
        .route("/v1/key-management/inventory", get(key_inventory))
        .with_state(state);
    if let Some(secrets_store) = secrets_store {
        router.layer(Extension(secrets_store))
    } else {
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::vta::VtaConfig;

    fn bootstrap_config(auth_key_source: Option<&str>) -> VtaConfig {
        VtaConfig {
            enabled: true,
            base_url: Some("https://vta.example.com".to_string()),
            vta_did: Some("did:webvh:QmScid:vta.example.com".to_string()),
            context_id: Some("ctx".to_string()),
            auth_key_source: auth_key_source.map(str::to_string),
            ..Default::default()
        }
    }

    /// The whole point of the fallback: an operator pairing the `[vta]` block
    /// must be shown the DID to grant. Before this it was a 400, and the DID
    /// appeared nowhere readable — redacted in logs, encrypted on disk.
    #[tokio::test]
    async fn pairing_the_bootstrap_connection_resolves_the_did_from_the_block() {
        let var = "TG_TEST_VTA_BOOTSTRAP_DID_KEY";
        let seed = "2a".repeat(32);
        unsafe { std::env::set_var(var, &seed) };
        let config = bootstrap_config(Some(&format!("env://{var}")));
        let connection = VtaConnection::from_bootstrap(&config).expect("a bootstrap record");
        assert!(
            connection
                .control_key_ref
                .is_none(),
            "the bootstrap record carries no secrets-store reference, which is why the fallback exists"
        );

        let did = resolve_control_did(&connection, None, &config)
            .await
            .expect("the bootstrap DID must resolve without a secrets-store reference");

        assert_eq!(
            did,
            crate::vta::control_key_did(&seed).expect("derive"),
            "the DID shown must be the one the connector actually authenticates with"
        );
        unsafe { std::env::remove_var(var) };
    }

    /// With no key source the gateway mints a fresh key every boot, so any DID
    /// shown here would stop being true at the next restart. Say that, rather
    /// than send the operator to grant something transient.
    #[tokio::test]
    async fn a_bootstrap_block_without_a_key_source_explains_itself_instead_of_showing_a_did() {
        let config = bootstrap_config(None);
        let connection = VtaConnection::from_bootstrap(&config).expect("a bootstrap record");

        let (status, body) = resolve_control_did(&connection, None, &config)
            .await
            .expect_err("a regenerated-every-boot key must not be offered for granting");

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let rendered = serde_json::to_string(&body.0).expect("serialise");
        assert!(rendered.contains("auth_key_source"), "the error must name the setting that fixes it: {rendered}");
    }

    /// The fallback is scoped to the bootstrap record. An ordinary connection
    /// without a key must keep failing, or pairing one would silently hand back
    /// the appliance-wide block's DID.
    #[tokio::test]
    async fn an_ordinary_connection_without_a_key_still_refuses_to_pair() {
        let config = bootstrap_config(None);
        let mut connection = VtaConnection::from_bootstrap(&config).expect("a bootstrap record");
        connection.id = "some-other-connection".to_string();
        assert!(!connection.is_bootstrap());

        let (status, body) = resolve_control_did(&connection, None, &config)
            .await
            .expect_err("a non-bootstrap connection has no block key to fall back to");

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let rendered = serde_json::to_string(&body.0).expect("serialise");
        assert!(rendered.contains("control_key_ref"), "it must still point at the missing reference: {rendered}");
    }
}

/// End-to-end coverage of the key the connect wizard mints, against a **real**
/// agent.
///
/// The wizard's final step calls `POST /v1/vta/connections/{id}/keys` and then
/// expects every picker to accept the connection. Nothing proved that the key
/// it creates can actually sign — the unit tests stop at the HTTP boundary,
/// and the surface-mapping suites start from a key that was already there.
///
/// Run with a live agent:
/// ```text
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID='did:webvh:...' \
/// VTA_LIVE_PARENT_CONTEXT=gwtest \
///   cargo test --bin agent-trust-gateway connections_admin::live_key_tests \
///     -- --ignored --test-threads=1
/// ```
/// The agent rate-limits authentication, so keep `--test-threads=1`.
#[cfg(test)]
mod live_key_tests {
    use super::*;
    use crate::vta::connections::SigningKeys;

    /// The seed the other live suites authenticate with, so one ACL grant
    /// covers them all.
    const LIVE_SEED: [u8; 32] = [0x2a; 32];

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("set {name}; see the module docs"))
    }

    async fn live_client() -> Arc<crate::vta::client::VtaRestClient> {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = env("VTA_LIVE_DID");
        let control = Arc::new(crate::vta::control_key::ControlKey::from_seed(LIVE_SEED));
        Arc::new(
            crate::vta::client::VtaRestClient::new(
                &url,
                &vta_did,
                control,
                std::time::Duration::from_secs(15),
                8,
                None,
            )
            .expect("build a live client"),
        )
    }

    /// The key the wizard mints is real, non-exportable, and can sign.
    ///
    /// Asserts the whole contract the dashboard relies on: an id is returned,
    /// the public half is captured at creation (the agent will never hand it
    /// back later), and a JWT signed with it carries that id as `kid` — which
    /// is how an operator correlates a token to the key that produced it.
    #[tokio::test]
    #[ignore = "requires a running VTA; see the module docs"]
    async fn a_minted_key_can_sign_and_names_itself_as_kid() {
        let client = live_client().await;
        let context = env("VTA_LIVE_PARENT_CONTEXT");

        let key = mint_signing_key(&client)
            .await
            .expect("mint a signing key against the live agent");

        assert!(
            key.key_id
                .starts_with("gateway-jwt-"),
            "the dashboard shows this id as the kid: {}",
            key.key_id
        );
        assert!(
            key.public_key.is_some(),
            "the public half must be captured at creation — the agent will not \
             return an internal key's record afterwards, so missing it here \
             means it can never be published for verification"
        );

        // Sign with exactly that key, the way the registry does for a surface.
        use crate::identity::authority::CredentialAuthority;
        let authority = crate::vta::authority::VtaCredentialAuthority::new(
            Arc::clone(&client),
            env("VTA_LIVE_DID"),
            key.key_id.clone(),
            None,
        );
        let jwt = authority
            .sign_token(&serde_json::json!({ "sub": "wizard-live-test", "ctx": context }))
            .await
            .expect("the minted key must be able to sign");

        use base64::Engine;
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(
                    jwt.split('.')
                        .next()
                        .expect("a JWT has three parts"),
                )
                .expect("base64url header"),
        )
        .expect("JSON header");

        assert_eq!(
            header
                .get("kid")
                .and_then(|v| v.as_str()),
            Some(key.key_id.as_str()),
            "the token must name the key that signed it: {header}"
        );
        assert_eq!(
            header
                .get("alg")
                .and_then(|v| v.as_str()),
            Some("EdDSA")
        );
    }

    /// Provisioning a second time retires the first key rather than dropping
    /// it — the reason the wizard only mints when there is no active key.
    ///
    /// A verifier selects by `kid`, so a retired key must keep being published
    /// or every token it signed that is still in flight stops verifying.
    #[tokio::test]
    #[ignore = "requires a running VTA; see the module docs"]
    async fn provisioning_again_retires_the_previous_key() {
        let client = live_client().await;
        let mut keys = SigningKeys::default();

        let first = mint_signing_key(&client)
            .await
            .expect("mint the first key");
        keys.rotate_to(first.clone(), chrono::Utc::now())
            .expect("adopt the first key");
        let second = mint_signing_key(&client)
            .await
            .expect("mint a second key");
        keys.rotate_to(second.clone(), chrono::Utc::now())
            .expect("adopt the second key");

        assert_eq!(
            keys.active
                .as_ref()
                .map(|k| k.key_id.as_str()),
            Some(second.key_id.as_str()),
            "the newest key signs"
        );
        assert!(
            keys.retiring
                .iter()
                .any(|k| k.key_id == first.key_id),
            "the previous key must still be published, not dropped: {:?}",
            keys.retiring
                .iter()
                .map(|k| &k.key_id)
                .collect::<Vec<_>>()
        );
        assert_ne!(first.key_id, second.key_id, "each provisioning must create a distinct key");
    }
}
