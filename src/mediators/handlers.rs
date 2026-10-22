use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::comm::client::CommClient;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::mediators::utils::extract_mediator_info;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, can_reference, scope_allows_resource, tenant_for_create,
};

use super::MediatorStore;
use super::types::{Mediator, MediatorResponse, MediatorStatus};
use crate::event_hook::{DirectoryEntry, MediatorDirectory, is_directory_mediator_id};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, RwLock};

/// One lock per directory mediator DID while a request is storing its record, so
/// concurrent requests store it once. An entry is dropped when its last user is done.
static MATERIALIZE_LOCKS: std::sync::LazyLock<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

struct GlobalCommClientCache {
    clients: RwLock<HashMap<String, Arc<CommClient>>>,
}

static COMM_CLIENT_CACHE: OnceCell<GlobalCommClientCache> = OnceCell::const_new();

async fn get_comm_client_cache() -> &'static GlobalCommClientCache {
    COMM_CLIENT_CACHE
        .get_or_init(|| async {
            GlobalCommClientCache {
                clients: RwLock::new(HashMap::new()),
            }
        })
        .await
}

async fn get_or_create_comm_client(
    cache_key: &str,
    did: String,
    secrets: Vec<affinidi_tdk_common::secrets_resolver::secrets::Secret>,
    alias: Option<String>,
) -> Result<Arc<CommClient>, String> {
    let cache = get_comm_client_cache().await;
    {
        let read = cache.clients.read().await;
        if let Some(client) = read.get(cache_key) {
            tracing::info!("Client for did = {} found in cache", did);
            return Ok(client.clone());
        }
    }

    let new_client = Arc::new(CommClient::new_with_didcomm(did, secrets, None, alias).await?);

    let mut write = cache.clients.write().await;
    if let Some(existing) = write.get(cache_key) {
        return Ok(existing.clone());
    }
    write.insert(cache_key.to_string(), new_client.clone());

    Ok(new_client)
}

async fn remove_cached_clients_for_mediator(mediator_did: &str) -> usize {
    let cache = get_comm_client_cache().await;
    let mut write = cache.clients.write().await;
    remove_cached_client_entries(&mut write, mediator_did)
}

/// Best-effort classification of a mediator error string as a stale/dropped
/// connection (the cached client's socket was reset because the mediator
/// restarted or its store was wiped). Used to decide whether to evict the
/// cached comm client and retry with a fresh, re-authenticated connection.
fn is_stale_connection_error(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("disconnect")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
        || lower.contains("websocket")
        || lower.contains("reset while awaiting")
        || lower.contains("closed")
}

fn remove_cached_client_entries<T>(
    clients: &mut HashMap<String, T>,
    mediator_did: &str,
) -> usize {
    let before = clients.len();
    let key_prefix = format!("{}:", mediator_did);
    clients.retain(|k, _| !k.starts_with(&key_prefix));
    before.saturating_sub(clients.len())
}

/// Request body for creating a mediator
#[derive(Debug, Deserialize)]
pub struct CreateMediatorRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
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

/// Whether `mediator` is visible/usable by the caller identified by `context`
/// / `scope`. Reused outside this module (e.g. `connect_via_oob`'s
/// `acceptor_mediator_id` selection) so every mediator lookup enforces the
/// same tenant/resource-scope boundary.
pub(crate) fn mediator_allowed(
    mediator: &Mediator,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(mediator.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, &mediator.id)
}

/// May this caller change or delete the mediator? Requires [`can_mutate`]
/// ownership and a resource scope that matches the mediator id.
fn mediator_writable(
    mediator: &Mediator,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_mutate(mediator.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, &mediator.id)
}

/// A provided record can be removed once nothing uses it, so a stale one can be
/// refreshed: the next use stores it again from the directory.
async fn reject_provided_in_use(
    mediator: &Mediator,
    connection_points: Option<&crate::gateways::FileSystemConnectionPointStore>,
) -> Result<(), (StatusCode, String)> {
    let in_use_message = || {
        (StatusCode::CONFLICT, "Mediator is provided by the directory and is used by a connection point".to_string())
    };
    let in_flight = IN_USE
        .get(&mediator.id)
        .is_some_and(|holders| *holders > 0);
    let Some(connection_points) = connection_points else {
        return Err(in_use_message());
    };
    let referenced = connection_points
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list connection points: {}", e)))?
        .iter()
        .any(|point| point.mediator_id == mediator.id);
    if referenced || in_flight {
        return Err(in_use_message());
    }
    Ok(())
}

fn reject_provided(mediator: &Mediator) -> Result<(), (StatusCode, String)> {
    if mediator.provided {
        return Err((StatusCode::CONFLICT, "Mediator is provided by the directory and cannot be changed".to_string()));
    }
    Ok(())
}

/// Request body for updating a mediator
#[derive(Debug, Deserialize)]
pub struct UpdateMediatorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub did: Option<String>,
    pub status: Option<MediatorStatus>,
}

/// Request body for checking authentication compatibility
#[derive(Debug, Deserialize)]
pub struct CheckAuthRequest {
    pub did_document: serde_json::Value,
}

/// Response body for authentication compatibility check
#[derive(Debug, Serialize)]
pub struct CheckAuthResponse {
    pub compatible: bool,
    pub error: Option<String>,
    pub endpoint_url: Option<String>,
}

/// Directory entries first, a stored record the directory created for the same
/// DID taking the entry's place, then the remaining stored records. A mediator
/// the operator added themselves wins over a directory entry for the same DID:
/// it stays as it is and the entry is not listed. Without entries the stored
/// records are returned as they are.
fn merge_directory_entries(
    entries: Vec<DirectoryEntry>,
    mut stored: Vec<Mediator>,
    listed_at: chrono::DateTime<chrono::Utc>,
) -> Vec<MediatorResponse> {
    let mut items = Vec::with_capacity(entries.len() + stored.len());
    for entry in entries {
        let same_did: Vec<usize> = (0..stored.len())
            .filter(|&index| stored[index].did == entry.did)
            .collect();
        let operator_added = same_did
            .iter()
            .any(|&index| !stored[index].provided);
        let mut provided: Vec<usize> = same_did
            .into_iter()
            .filter(|&index| stored[index].provided)
            .collect();
        let stands_in = provided
            .iter()
            .copied()
            .min_by(|&a, &b| record_order(&stored[a]).cmp(&record_order(&stored[b])))
            .map(|index| stored[index].clone());
        provided.sort_unstable_by(|a, b| b.cmp(a));
        for index in provided {
            stored.remove(index);
        }
        if operator_added {
            continue;
        }
        let mediator = stands_in.unwrap_or_else(|| directory_mediator(&entry, listed_at));
        let mut item = MediatorResponse::from(mediator);
        item.provided = true;
        item.name = entry.name;
        items.push(item);
    }
    items.extend(
        stored
            .into_iter()
            .map(MediatorResponse::from),
    );
    items
}

/// Orders the records for one DID: operator-added before provided ones, then
/// oldest first, so the choice never depends on the order of the list.
fn record_order(mediator: &Mediator) -> (bool, chrono::DateTime<chrono::Utc>, &str) {
    (mediator.provided, mediator.created_at, mediator.id.as_str())
}

fn directory_mediator(
    entry: &DirectoryEntry,
    listed_at: chrono::DateTime<chrono::Utc>,
) -> Mediator {
    Mediator {
        id: entry.id(),
        tenant_id: None,
        name: entry.name.clone(),
        description: String::new(),
        did: entry.did.clone(),
        status: MediatorStatus::Active,
        did_document: None,
        our_did: None,
        our_secrets: None,
        provided: true,
        created_at: listed_at,
        updated_at: listed_at,
    }
}

async fn list_accessible_mediators<S: MediatorStore>(
    store: &S,
    directory: Option<&Arc<MediatorDirectory>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Vec<MediatorResponse>, (StatusCode, String)> {
    let mut mediators = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?;
    mediators.retain(|mediator| mediator_allowed(mediator, context, scope));

    let Some(directory) = directory else {
        return Ok(mediators
            .into_iter()
            .map(MediatorResponse::from)
            .collect());
    };
    let mut items = merge_directory_entries(directory.entries().await, mediators, chrono::Utc::now());
    items.retain(|item| {
        !is_directory_mediator_id(&item.id)
            || scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, &item.id)
    });
    Ok(items)
}

/// List all mediators
pub async fn list_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(directory): Extension<Option<Arc<MediatorDirectory>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    list_accessible_mediators(store.as_ref(), directory.as_ref(), &context, &scope)
        .await
        .map(Json)
}

/// List mediators compatible with OOB invitation creation
/// All stored mediators are compatible (validated during addition)
pub async fn list_compatible_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(directory): Extension<Option<Arc<MediatorDirectory>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    let mediators = list_accessible_mediators(store.as_ref(), directory.as_ref(), &context, &scope).await?;
    tracing::info!("Returning {} mediators (all are compatible)", mediators.len());
    Ok(Json(mediators))
}

/// Get a mediator by ID
pub async fn get_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }

    Ok(Json(mediator.into()))
}

/// Create a new mediator
pub async fn create_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("connections.mediators")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    create_mediator_record(store.as_ref(), notification_store.as_ref(), req, &context, &scope)
        .await
        .map(|mediator| Json(mediator.into()))
}

fn new_mediator_with_identity(
    req: CreateMediatorRequest,
    provided: bool,
) -> Result<Mediator, (StatusCode, String)> {
    use affinidi_tdk_common::secrets_resolver::secrets::Secret;
    use did_peer::{DIDPeer, DIDPeerCreateKeys, DIDPeerKeys};

    // Generate did:peer for this mediator connection
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret = Secret::generate_x25519(None, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate X25519 key: {}", e)))?;

    // Extract public key multibase from secrets
    let ed25519_multibase = ed25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get Ed25519 multibase: {:?}", e)))?;
    let x25519_multibase = x25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get X25519 multibase: {:?}", e)))?;

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(ed25519_multibase),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(x25519_multibase),
        },
    ];

    let (our_did, _) = DIDPeer::create_peer_did(&keys, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create did:peer: {}", e)))?;

    tracing::info!("Generated did:peer {} for mediator connection", our_did);

    // Update secret IDs to match the did:peer
    ed25519_secret.id = format!("{}#key-1", our_did);
    x25519_secret.id = format!("{}#key-2", our_did);

    let secrets = vec![ed25519_secret, x25519_secret];
    let secrets_json = serde_json::to_value(&secrets)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize secrets: {}", e)))?;

    // Fix malformed service endpoints in the DID document
    // Some mediators incorrectly use colons instead of slashes in URLs
    let fixed_did_document = req
        .did_document
        .map(|doc| fix_malformed_service_endpoints(doc, &req.did));

    let mut mediator = Mediator::new(req.name, req.description, req.did, fixed_did_document);
    mediator.tenant_id = req.tenant_id;
    mediator.provided = provided;
    mediator.our_did = Some(our_did);
    mediator.our_secrets = Some(secrets_json);
    Ok(mediator)
}

async fn create_mediator_record<S: MediatorStore>(
    store: &S,
    notification_store: Option<&std::sync::Arc<crate::integrations::FileSystemNotificationStore>>,
    req: CreateMediatorRequest,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Mediator, (StatusCode, String)> {
    let mediator = new_mediator_with_identity(req, false)?;
    if !mediator_writable(&mediator, context, scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }
    store_new_mediator(store, notification_store, &mediator).await?;
    Ok(mediator)
}

async fn store_new_mediator<S: MediatorStore>(
    store: &S,
    notification_store: Option<&std::sync::Arc<crate::integrations::FileSystemNotificationStore>>,
    mediator: &Mediator,
) -> Result<(), (StatusCode, String)> {
    store
        .create(mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store mediator: {}", e)))?;

    if let Some(notif_store) = notification_store {
        spawn_mediator_created_trigger(notif_store, mediator);
    }

    Ok(())
}

fn spawn_mediator_created_trigger(
    notif_store: &std::sync::Arc<crate::integrations::FileSystemNotificationStore>,
    mediator: &Mediator,
) {
    let mediator_clone = mediator.clone();
    let notif = std::sync::Arc::clone(notif_store);
    tokio::spawn(async move {
        let status_str = match mediator_clone.status {
            crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
            crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
        };
        let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
            id: mediator_clone.id.clone(),
            name: mediator_clone.name.clone(),
            description: mediator_clone
                .description
                .clone(),
            did: mediator_clone.did.clone(),
            status: status_str,
            our_did: mediator_clone.our_did.clone(),
            created_at: Some(
                mediator_clone
                    .created_at
                    .to_rfc3339(),
            ),
            updated_at: Some(
                mediator_clone
                    .updated_at
                    .to_rfc3339(),
            ),
        };
        crate::integrations::mediator_integration_triggers::trigger_mediator_created(&notif, &mediator_trigger).await;
    });
}

/// Why a `directory:` mediator id could not be resolved.
pub(crate) enum DirectoryResolveError {
    Response(StatusCode, String),
    DirectoryUnavailable,
}

impl From<(StatusCode, String)> for DirectoryResolveError {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self::Response(status, message)
    }
}

impl DirectoryResolveError {
    /// The status, the message, and the seconds a client should wait before
    /// asking again when the failure is temporary.
    pub(crate) fn into_parts(self) -> (StatusCode, String, Option<u32>) {
        match self {
            Self::Response(status, message) => (status, message, None),
            Self::DirectoryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "The mediator directory is not available yet; try again shortly".to_string(),
                Some(5),
            ),
        }
    }
}

/// How many requests currently rely on each stored directory record, by record
/// id, so a request that fails cannot remove a record another one still uses.
static IN_USE: std::sync::LazyLock<dashmap::DashMap<String, usize>> = std::sync::LazyLock::new(dashmap::DashMap::new);

/// Held by a request for as long as it relies on a stored directory record.
pub(crate) struct DirectoryRecordUse {
    id: String,
}

impl DirectoryRecordUse {
    fn hold(id: &str) -> Self {
        *IN_USE
            .entry(id.to_string())
            .or_insert(0) += 1;
        Self { id: id.to_string() }
    }
}

impl Drop for DirectoryRecordUse {
    fn drop(&mut self) {
        if let Some(mut holders) = IN_USE.get_mut(&self.id) {
            *holders = holders.saturating_sub(1);
        }
        IN_USE.remove_if(&self.id, |_, holders| *holders == 0);
    }
}

/// Keeps a DID's lock entry in the map for as long as it is in use and removes
/// it when the last user is gone, also when a request is cancelled mid-wait.
struct LockEntry {
    did: String,
    lock: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl LockEntry {
    fn acquire(did: &str) -> Self {
        let lock = MATERIALIZE_LOCKS
            .entry(did.to_string())
            .or_default()
            .clone();
        Self {
            did: did.to_string(),
            lock: Some(lock),
        }
    }

    fn lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.lock
            .clone()
            .expect("the lock is held until the entry is dropped")
    }
}

impl Drop for LockEntry {
    fn drop(&mut self) {
        self.lock.take();
        MATERIALIZE_LOCKS.remove_if(&self.did, |_, lock| Arc::strong_count(lock) == 1);
    }
}

async fn under_did_lock<T>(
    did: &str,
    work: impl std::future::Future<Output = T>,
) -> T {
    let entry = LockEntry::acquire(did);
    let _one_at_a_time = entry
        .lock()
        .lock_owned()
        .await;
    work.await
}

/// A directory mediator turned into a mediator record. `Pending` has not been
/// stored yet: the caller stores it with [`store_pending_directory_mediator`]
/// once the rest of its request has succeeded.
pub(crate) enum DirectoryMediator {
    Stored(Mediator, DirectoryRecordUse),
    Pending(Mediator),
}

/// Resolves a `directory:*` mediator id to the record a Connection Point on a
/// gateway of `gateway_tenant` can use. The caller's resource scope is checked
/// against the directory id, as the list does, and the DID document is
/// resolved here, before anything is stored. A record the directory created
/// earlier, one the gateway may reference, is reused; a new one is only built.
/// It carries no `mediators.edit` check and does not count toward the mediator
/// limit.
pub(crate) async fn resolve_directory_mediator<S: MediatorStore>(
    store: &S,
    directory: Option<&Arc<MediatorDirectory>>,
    id: &str,
    gateway_tenant: Option<&str>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<DirectoryMediator, DirectoryResolveError> {
    let not_found = || (StatusCode::NOT_FOUND, "Mediator not found".to_string());
    let directory = directory.ok_or_else(not_found)?;
    let Some(entry) = directory.find(id).await else {
        return Err(if directory.has_loaded() {
            not_found().into()
        } else {
            DirectoryResolveError::DirectoryUnavailable
        });
    };
    if !scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, id) {
        return Err(not_found().into());
    }
    let tenant_id = tenant_for_create(None, false, tenant_context(context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let existing = under_did_lock(&entry.did, async {
        let found = find_directory_record(store, &entry.did, gateway_tenant, context, scope).await?;
        Ok::<_, (StatusCode, String)>(found.map(|mediator| {
            let usage = DirectoryRecordUse::hold(&mediator.id);
            (mediator, usage)
        }))
    })
    .await?;
    if let Some((existing, usage)) = existing {
        return Ok(DirectoryMediator::Stored(existing, usage));
    }
    let hidden_by_scope = store
        .get(&directory_record_id(tenant_id.as_deref(), &entry.did))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .is_some();
    if hidden_by_scope {
        return Err(not_found().into());
    }
    let did_document = super::utils::resolve_did(&entry.did)
        .await
        .map_err(|e| {
            tracing::warn!("Could not resolve the DID document of a directory mediator: {e}");
            (StatusCode::BAD_GATEWAY, "Could not resolve the mediator's DID document".to_string())
        })?;
    let mut mediator = new_mediator_with_identity(
        CreateMediatorRequest {
            tenant_id,
            name: entry.name,
            description: String::new(),
            did: entry.did,
            did_document: Some(did_document),
        },
        true,
    )?;
    mediator.id = directory_record_id(mediator.tenant_id.as_deref(), &mediator.did);
    Ok(DirectoryMediator::Pending(mediator))
}

/// The id of the record stored for a directory mediator: fixed by the owner and
/// the DID, so the id known before the record exists is the id it gets.
fn directory_record_id(
    tenant_id: Option<&str>,
    did: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("directory-mediator\n{}\n{did}", tenant_id.unwrap_or_default()));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes)
        .into_uuid()
        .to_string()
}

async fn find_directory_record<S: MediatorStore>(
    store: &S,
    did: &str,
    gateway_tenant: Option<&str>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Option<Mediator>, (StatusCode, String)> {
    Ok(store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?
        .into_iter()
        .filter(|mediator| {
            mediator.did == did
                && can_access(mediator.tenant_id.as_deref(), tenant_context(context))
                && can_reference(gateway_tenant, mediator.tenant_id.as_deref())
                && mediator_allowed(mediator, context, scope)
        })
        .min_by(|a, b| record_order(a).cmp(&record_order(b))))
}

/// Stores a pending directory mediator, unless a record for the same DID the
/// gateway may reference is already there, and returns the record in use,
/// whether this call created it, and the hold that keeps it from being rolled
/// back under this request. Concurrent callers for the same DID share one
/// record. The mediator created trigger is left to
/// [`announce_mediator_created`], once the request that needed the record has
/// succeeded.
pub(crate) async fn store_pending_directory_mediator<S: MediatorStore>(
    store: &S,
    pending: Mediator,
    gateway_tenant: Option<&str>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(Mediator, bool, DirectoryRecordUse), (StatusCode, String)> {
    under_did_lock(&pending.did, async {
        match find_directory_record(store, &pending.did, gateway_tenant, context, scope).await? {
            Some(existing) => {
                let usage = DirectoryRecordUse::hold(&existing.id);
                Ok((existing, false, usage))
            }
            None => {
                store_new_mediator(store, None, &pending).await?;
                let usage = DirectoryRecordUse::hold(&pending.id);
                Ok((pending.clone(), true, usage))
            }
        }
    })
    .await
}

/// Removes a directory mediator record the failed request created, unless
/// another request relies on it or a stored Connection Point references it.
pub(crate) async fn roll_back_directory_mediator<S: MediatorStore, C: ConnectionPointStore>(
    store: &S,
    connection_points: &C,
    record: &Mediator,
) {
    under_did_lock(&record.did, async {
        let others_rely_on_it = IN_USE
            .get(&record.id)
            .is_some_and(|holders| *holders > 1);
        if others_rely_on_it {
            return;
        }
        match connection_points
            .list_all()
            .await
        {
            Ok(stored)
                if stored
                    .iter()
                    .all(|point| point.mediator_id != record.id) => {}
            _ => return,
        }
        if let Err(e) = store.delete(&record.id).await {
            tracing::warn!("Could not remove the directory mediator record created by a failed request: {e}");
        }
    })
    .await;
}

pub(crate) fn announce_mediator_created(
    notification_store: &std::sync::Arc<crate::integrations::FileSystemNotificationStore>,
    mediator: &Mediator,
) {
    spawn_mediator_created_trigger(notification_store, mediator);
}

/// Fix malformed service endpoints in DID documents
/// Some mediators incorrectly generate serviceEndpoint URLs with colons instead of slashes
/// Example: https://domain:path:to -> https://domain/path/to
fn fix_malformed_service_endpoints(
    mut did_document: serde_json::Value,
    did: &str,
) -> serde_json::Value {
    // Extract the domain from the DID
    // did:web:domain:path:segments -> domain
    // did:webvh:scid:domain:path:segments -> domain
    let domain = if let Some(domain_part) = did.strip_prefix("did:web:") {
        domain_part
            .split(':')
            .next()
            .unwrap_or("")
    } else if let Some(domain_part) = did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = domain_part
            .split(':')
            .collect();
        if parts.is_empty() {
            return did_document;
        }
        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };
        parts
            .get(domain_idx)
            .copied()
            .unwrap_or("")
    } else {
        return did_document; // Not a did:web, return as-is
    };

    // Process services array
    if let Some(services) = did_document
        .get_mut("service")
        .and_then(|v| v.as_array_mut())
    {
        for service in services.iter_mut() {
            if let Some(endpoint) = service.get_mut("serviceEndpoint")
                && let Some(url_str) = endpoint.as_str()
            {
                // Check if URL has malformed colons after the domain
                // Pattern: https://domain:something -> https://domain/something
                if let Some(fixed_url) = fix_malformed_url(url_str, domain) {
                    tracing::warn!("Fixed malformed service endpoint: {} -> {}", url_str, fixed_url);
                    *endpoint = serde_json::Value::String(fixed_url);
                }
            }
        }
    }

    did_document
}

/// Fix a malformed URL by replacing colons with slashes after the domain
fn fix_malformed_url(
    url: &str,
    domain: &str,
) -> Option<String> {
    // Check if URL contains the domain followed by colons
    if let Some(after_https) = url.strip_prefix("https://")
        && after_https.starts_with(domain)
        && after_https.len() > domain.len()
    {
        let rest = &after_https[domain.len()..];
        // If the character after domain is a colon (not part of port), it's malformed
        if rest.starts_with(':')
            && !rest[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        {
            // Replace colons with slashes in the path portion
            let fixed_path = rest.replace(':', "/");
            return Some(format!("https://{}{}", domain, fixed_path));
        }
    }
    None
}

/// Update a mediator
pub async fn update_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mut mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }
    reject_provided(&mediator)?;
    if !mediator_writable(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    let old_mediator = mediator.clone();

    if let Some(name) = req.name {
        mediator.name = name;
    }
    if let Some(description) = req.description {
        mediator.description = description;
    }
    if let Some(did) = req.did {
        mediator.did = did;
    }
    if let Some(status) = req.status {
        mediator.status = status;
    }

    mediator.updated_at = chrono::Utc::now();

    store
        .update(&mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update mediator: {}", e)))?;

    // Trigger mediator updated event
    if let Some(ref notif_store) = notification_store {
        let old_mediator_clone = old_mediator.clone();
        let new_mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let old_status_str = match old_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let new_status_str = match new_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let old_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: old_mediator_clone.id.clone(),
                name: old_mediator_clone
                    .name
                    .clone(),
                description: old_mediator_clone
                    .description
                    .clone(),
                did: old_mediator_clone.did.clone(),
                status: old_status_str,
                our_did: old_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    old_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    old_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            let new_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: new_mediator_clone.id.clone(),
                name: new_mediator_clone
                    .name
                    .clone(),
                description: new_mediator_clone
                    .description
                    .clone(),
                did: new_mediator_clone.did.clone(),
                status: new_status_str,
                our_did: new_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    new_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    new_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_updated(
                &notif,
                &old_mediator_trigger,
                &new_mediator_trigger,
            )
            .await;
        });
    }

    Ok(Json(mediator.into()))
}

/// Delete a mediator
pub async fn delete_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(cp_store): Extension<Option<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    Extension(listener_manager): Extension<
        Option<std::sync::Arc<crate::gateways::connection_points::ws_listener::ConnectionPointListenerManager>>,
    >,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::info!("Deleting mediator: {}", id);

    // Get mediator before deletion for trigger
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }
    if mediator.provided {
        reject_provided_in_use(&mediator, cp_store.as_deref()).await?;
    }
    if !mediator_writable(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    // Stop all connection point listeners using this mediator
    if let (Some(cp_store_ref), Some(listener_mgr)) = (cp_store.as_ref(), listener_manager.as_ref()) {
        tracing::info!("Finding connection points using mediator '{}'...", id);

        // Get all connection points
        match cp_store_ref.list_all().await {
            Ok(connection_points) => {
                // Filter to those using this mediator
                let affected_cps: Vec<_> = connection_points
                    .into_iter()
                    .filter(|cp| cp.mediator_id == id)
                    .collect();

                if !affected_cps.is_empty() {
                    tracing::info!("Found {} connection point(s) using this mediator", affected_cps.len());

                    // Stop listener for each affected connection point
                    for cp in affected_cps {
                        tracing::info!("  Stopping listener for connection point '{}'...", cp.id);
                        if let Err(e) = listener_mgr
                            .stop_listener(&cp.id)
                            .await
                        {
                            tracing::warn!("    Failed to stop listener for connection point '{}': {}", cp.id, e);
                        } else {
                            tracing::info!("    ✓ Listener stopped for connection point '{}'", cp.id);
                        }
                    }
                } else {
                    tracing::info!("No connection points using this mediator");
                }
            }
            Err(e) => {
                tracing::error!("Failed to list connection points: {}", e);
                // Continue with mediator deletion even if we can't clean up listeners
            }
        }
    } else {
        tracing::warn!("Cannot stop connection point listeners: store or listener manager not available");
    }
    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete mediator: {}", e)))?;

    let removed_clients = remove_cached_clients_for_mediator(&mediator.did).await;
    tracing::info!("Removed {} cached comm client(s) for mediator DID {}", removed_clients, mediator.did);

    // Trigger mediator deleted event
    if let Some(ref notif_store) = notification_store {
        let mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: mediator_clone.id.clone(),
                name: mediator_clone.name.clone(),
                description: mediator_clone
                    .description
                    .clone(),
                did: mediator_clone.did.clone(),
                status: status_str,
                our_did: mediator_clone.our_did.clone(),
                created_at: Some(
                    mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_deleted(&notif, &mediator_trigger)
                .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Check if a mediator's authentication endpoints are accessible
/// Uses the actual SDK authentication flow to verify compatibility
pub async fn check_auth_compatibility(
    Extension(vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    Json(req): Json<CheckAuthRequest>,
) -> Result<Json<CheckAuthResponse>, (StatusCode, String)> {
    // Extract the mediator DID from the DID document's id field
    let mediator_did = req
        .did_document
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "DID document missing 'id' field".to_string()))?
        .to_string();

    tracing::info!("Extracting mediator info from DID: {}", mediator_did);

    // Extract DIDCommMessaging service endpoint (could be URL or DID)
    let (mediator_url, final_did_document) = extract_mediator_info(&req.did_document)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    tracing::info!("Testing authentication with mediator: {} (DID: {})", mediator_url, mediator_did);

    // Get gateway DID and secrets from VC issuer
    let gateway_did_doc = vc_issuer
        .get_did_document()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway DID: {}", e)))?;

    let gateway_did = gateway_did_doc
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Gateway DID not found".to_string()))?
        .to_string();

    let secrets = vc_issuer
        .get_signing_secrets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway secrets: {}", e)))?;

    tracing::info!("Testing authentication: {} -> {}", gateway_did, mediator_did);

    let comm_client = CommClient::new_with_didcomm(
        gateway_did.clone(),
        secrets,
        None,
        Some(format!("auth-test-{}", uuid::Uuid::new_v4())),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize Comm client: {}", e)))?;

    comm_client
        .didcomm()
        .cache_did_document(&gateway_did, gateway_did_doc)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache gateway DID document: {}", e)))?;

    comm_client
        .didcomm()
        .cache_did_document(&mediator_did, final_did_document)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache mediator DID document: {}", e)))?;

    let auth_result = comm_client
        .didcomm()
        .test_mediator_authentication(&mediator_did, Duration::from_secs(5))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to test mediator authentication: {}", e)))?;

    match auth_result.compatible {
        true => {
            tracing::info!("✓ Authentication successful with mediator: {}", mediator_url);
            Ok(Json(CheckAuthResponse {
                compatible: true,
                error: None,
                endpoint_url: Some(mediator_url),
            }))
        }
        false => {
            let error = auth_result
                .error
                .unwrap_or_else(|| "Authentication failed".to_string());
            tracing::warn!("✗ Authentication failed with mediator {}: {}", mediator_url, error);
            Ok(Json(CheckAuthResponse {
                compatible: false,
                error: Some(error),
                endpoint_url: Some(mediator_url),
            }))
        }
    }
}

/// Extract the base URL from a DIDCommMessaging service endpoint
fn extract_didcomm_service_endpoint(did_document: &serde_json::Value) -> Option<String> {
    tracing::debug!(
        "Extracting DIDComm service endpoint from DID document: {}",
        serde_json::to_string_pretty(did_document).unwrap_or_default()
    );

    let services = did_document
        .get("service")?
        .as_array()?;
    tracing::debug!("Found {} services in DID document", services.len());

    // Find DIDCommMessaging service
    let didcomm_service = services
        .iter()
        .find(|service| {
            if let Some(service_type) = service.get("type") {
                tracing::debug!("Checking service type: {:?}", service_type);
                if let Some(type_str) = service_type.as_str() {
                    return type_str == "DIDCommMessaging";
                }
                if let Some(type_array) = service_type.as_array() {
                    return type_array
                        .iter()
                        .any(|t| t.as_str() == Some("DIDCommMessaging"));
                }
            }
            false
        })?;

    tracing::debug!(
        "Found DIDCommMessaging service: {}",
        serde_json::to_string_pretty(didcomm_service).unwrap_or_default()
    );

    // Extract serviceEndpoint
    let service_endpoint = didcomm_service.get("serviceEndpoint")?;

    let base_url = if let Some(url_str) = service_endpoint.as_str() {
        // Simple string endpoint
        // support for port:
        // url_str.replace("%3A", ":").to_string()
        url_str.to_string()
    } else if let Some(uri) = service_endpoint
        .get("uri")
        .and_then(|v| v.as_str())
    {
        // Object with uri field
        uri.to_string()
    } else if let Some(url) = service_endpoint
        .get("url")
        .and_then(|v| v.as_str())
    {
        // Object with url field
        url.to_string()
    } else if let Some(endpoint_array) = service_endpoint.as_array() {
        // Array of endpoint objects - find the first HTTPS endpoint
        endpoint_array
            .iter()
            .find_map(|ep| {
                if let Some(uri) = ep
                    .get("uri")
                    .and_then(|v| v.as_str())
                    && uri.starts_with("https://")
                {
                    return Some(uri.to_string());
                }
                None
            })
            .or_else(|| {
                // If no HTTPS found, try any URI
                endpoint_array
                    .first()
                    .and_then(|ep| ep.get("uri"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })?
    } else {
        tracing::warn!("Could not extract URL from serviceEndpoint: {:?}", service_endpoint);
        return None;
    };

    // Extract base URL (protocol + host)
    if let Ok(parsed_url) = url::Url::parse(&base_url) {
        Some(format!("{}://{}", parsed_url.scheme(), parsed_url.host_str()?))
    } else {
        // Try to extract with regex
        let re = regex::Regex::new(r"^(https?://[^/]+)").ok()?;
        re.captures(&base_url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }
}

/// Response body for trust ping
#[derive(Debug, Serialize)]
pub struct TrustPingResponse {
    pub success: bool,
    pub message: String,
    pub round_trip_ms: Option<u64>,
}

/// Send a trust ping to `mediator`, evicting the cached comm client and
/// retrying once if the first attempt fails with a stale/dropped connection.
///
/// A cached comm client whose mediator was restarted or had its store wiped
/// surfaces as a disconnect / connection reset. On that failure the stale
/// cached client is dropped and the ping retried with a fresh one, which
/// re-authenticates from scratch — the mediator re-creates the account on the
/// auth challenge, so the ping recovers.
async fn trust_ping_with_reconnect(
    request_id: &str,
    cache_key: &str,
    mediator: &Mediator,
    our_did: &str,
    secrets: &[affinidi_tdk_common::secrets_resolver::secrets::Secret],
) -> Result<crate::comm::didcomm::mediator::MediatorTrustPingResult, (StatusCode, String)> {
    let mut attempt = 0;
    loop {
        attempt += 1;

        let comm_client = get_or_create_comm_client(
            cache_key,
            our_did.to_string(),
            secrets.to_vec(),
            Some("trust-ping-global".to_string()),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize comm client: {}", e)))?;

        if let Some(ref mediator_did_doc) = mediator.did_document {
            comm_client
                .didcomm()
                .cache_did_document(&mediator.did, mediator_did_doc.clone())
                .await
                .map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache mediator DID document: {}", e))
                })?;
        } else {
            tracing::warn!("⚠ Mediator has no cached DID document - authentication may fail!");
            tracing::warn!("  This mediator may need to be re-added to cache its DID document");
        }

        let result = comm_client
            .didcomm()
            .trust_ping_mediator(&mediator.did, Duration::from_secs(5))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to execute trust ping: {}", e)))?;

        if !result.success
            && attempt < 2
            && result
                .error
                .as_deref()
                .map(is_stale_connection_error)
                .unwrap_or(false)
        {
            tracing::warn!(
                "🔄 [{request_id}] Trust ping to {} failed with a stale connection ({}); evicting cached client and reconnecting...",
                mediator.name,
                result
                    .error
                    .as_deref()
                    .unwrap_or("")
            );
            remove_cached_clients_for_mediator(&mediator.did).await;
            continue;
        }

        return Ok(result);
    }
}

/// Send a trust ping to a mediator to test connectivity
pub async fn trust_ping_mediator<S: MediatorStore>(
    Path(id): Path<String>,
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(_vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    _listener_manager: Option<Extension<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustPingResponse>, (StatusCode, String)> {
    use std::time::Instant;

    let total_start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    tracing::info!("[{request_id}] Trust ping requested for mediator: {}", id);

    // Get mediator from store
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }

    tracing::warn!("🆕 [{request_id}] Mediator: {} ({})", mediator.name, mediator.did);

    // Trust ping uses the gateway DID (did:web) which is separate from connection point DIDs (did:key)
    // Each connection point has its own unique DID, so no conflicts occur

    // Extract mediator URL from DID
    let mediator_url = if let Some(ref did_doc) = mediator.did_document {
        extract_didcomm_service_endpoint(did_doc)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "No DIDComm service endpoint found".to_string()))?
    } else {
        // Fallback: try to extract from DID
        crate::gateways::connection_points::extract_mediator_url(&mediator.did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to extract mediator URL: {}", e)))?
    };

    tracing::info!("Mediator URL: {}", mediator_url);

    // Get our stored did:peer and secrets for this mediator
    let (our_did, secrets) = if let (Some(did), Some(secrets_json)) = (&mediator.our_did, &mediator.our_secrets) {
        use affinidi_tdk_common::secrets_resolver::secrets::Secret;

        let secrets: Vec<Secret> = serde_json::from_value(secrets_json.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deserialize secrets: {}", e)))?;

        tracing::info!("Using stored did:peer {} for trust ping", did);
        (did.clone(), secrets)
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Mediator missing did:peer configuration. Please recreate the mediator.".to_string(),
        ));
    };

    let cache_key = format!("{}:{}", mediator.did, our_did);

    tracing::info!("🔵 [{request_id}] Sending trust ping...");

    let ping_result = trust_ping_with_reconnect(&request_id, &cache_key, &mediator, &our_did, &secrets).await?;

    let total_elapsed = total_start.elapsed();
    tracing::warn!("🏁 [{request_id}] Trust ping operation COMPLETE - total time: {}ms", total_elapsed.as_millis());

    if ping_result.success {
        tracing::info!("✓ Received pong response from {}", mediator.name);
        tracing::info!(
            "✓ Trust ping successful: {}ms RTT, {}ms total",
            ping_result
                .round_trip_ms
                .unwrap_or_default(),
            total_elapsed.as_millis()
        );
        Ok(Json(TrustPingResponse {
            success: true,
            message: format!(
                "Trust ping successful ({}ms)",
                ping_result
                    .round_trip_ms
                    .unwrap_or_default()
            ),
            round_trip_ms: ping_result.round_trip_ms,
        }))
    } else {
        let error = ping_result
            .error
            .unwrap_or_else(|| "No pong response received".to_string());
        tracing::warn!("✗ Trust ping failed for {}: {}", mediator.name, error);
        Ok(Json(TrustPingResponse {
            success: false,
            message: error,
            round_trip_ms: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fix_malformed_service_endpoints, is_stale_connection_error, mediator_allowed, mediator_writable,
        remove_cached_client_entries,
    };
    use crate::auth_manager::pat::PatResourceScope;
    use crate::mediators::types::Mediator;
    use crate::tenancy::PatTenantContext;
    use axum::Extension;
    use regex::Regex;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn mediator_actions_require_tenant_and_scope_access() {
        let mut mediator = Mediator::new("Mediator".into(), String::new(), "did:example:mediator".into(), None);
        mediator.id = "mediator-a".into();
        mediator.tenant_id = Some("tenant-a".into());
        let context = PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:mediators:mediator-a\z").unwrap()));

        assert!(mediator_allowed(
            &mediator,
            &Some(axum::Extension(context.clone())),
            &Some(axum::Extension(scope.clone()))
        ));
        mediator.tenant_id = Some("tenant-b".into());
        assert!(!mediator_allowed(&mediator, &Some(axum::Extension(context)), &Some(axum::Extension(scope))));
    }

    #[test]
    fn stale_connection_error_matches_dropped_sockets() {
        assert!(is_stale_connection_error(
            "Trust ping error: Disconnected(\"Connection reset while awaiting response for abc\")"
        ));
        assert!(is_stale_connection_error("websocket closed"));
        assert!(is_stale_connection_error("broken pipe"));
    }

    #[test]
    fn stale_connection_error_ignores_semantic_failures() {
        assert!(!is_stale_connection_error("No pong response received"));
        assert!(!is_stale_connection_error("Trust ping timed out"));
        assert!(!is_stale_connection_error("DID is blocked"));
    }

    #[test]
    fn fix_malformed_service_endpoints_supports_didwebvh() {
        let doc = json!({
            "service": [{
                "serviceEndpoint": "https://mediator.example.com:mediator:v1"
            }]
        });

        let fixed = fix_malformed_service_endpoints(doc, "did:webvh:z6MkScid123:mediator.example.com:mediator:v1");

        assert_eq!(fixed["service"][0]["serviceEndpoint"], json!("https://mediator.example.com/mediator/v1"));
    }

    #[test]
    fn remove_cached_client_entries_removes_matching_mediator_prefix() {
        let mut cache = HashMap::new();
        cache.insert("did:example:mediator-a:did:peer:one".to_string(), 1u8);
        cache.insert("did:example:mediator-a:did:peer:two".to_string(), 2u8);
        cache.insert("did:example:mediator-b:did:peer:three".to_string(), 3u8);

        let removed = remove_cached_client_entries(&mut cache, "did:example:mediator-a");

        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("did:example:mediator-b:did:peer:three"));
    }

    #[test]
    fn a_tenant_may_read_an_appliance_wide_mediator_but_not_change_it() {
        let tenant = Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }));
        let mut record = Mediator::new("Mediator".into(), String::new(), "did:example:mediator".into(), None);
        record.id = "mediator-a".into();
        record.tenant_id = None;
        assert!(mediator_allowed(&record, &tenant, &None));
        assert!(!mediator_writable(&record, &tenant, &None));
        assert!(mediator_writable(&record, &None, &None));

        record.tenant_id = Some("tenant-a".into());
        assert!(mediator_writable(&record, &tenant, &None));

        record.tenant_id = Some("tenant-b".into());
        assert!(!mediator_writable(&record, &tenant, &None));
    }

    fn record(
        did: &str,
        provided: bool,
        age_secs: i64,
        id: &str,
    ) -> Mediator {
        let mut mediator = Mediator::new(id.into(), String::new(), did.into(), None);
        mediator.id = id.into();
        mediator.provided = provided;
        mediator.created_at = chrono::Utc::now() - chrono::Duration::seconds(age_secs);
        mediator
    }

    fn entry(did: &str) -> crate::event_hook::DirectoryEntry {
        crate::event_hook::DirectoryEntry {
            did: did.into(),
            name: "Entry".into(),
        }
    }

    fn tenant_record(
        did: &str,
        age_secs: i64,
        id: &str,
        tenant: Option<&str>,
    ) -> Mediator {
        let mut mediator = record(did, true, age_secs, id);
        mediator.tenant_id = tenant.map(str::to_string);
        mediator
    }

    #[test]
    fn an_operator_record_wins_over_a_provided_one_and_is_the_only_row_for_the_did() {
        let operator = record("did:web:a", false, 10, "operator");
        let provided = record("did:web:a", true, 100, "provided");
        for stored in [vec![operator.clone(), provided.clone()], vec![provided.clone(), operator.clone()]] {
            let items = super::merge_directory_entries(vec![entry("did:web:a")], stored, chrono::Utc::now());
            assert_eq!(items.len(), 1, "one row per DID");
            assert_eq!(items[0].id, "operator");
            assert!(!items[0].provided);
            assert_ne!(items[0].name, "Entry", "the entry is not applied to the operator's record");
        }
    }

    #[test]
    fn among_provided_records_one_stands_for_the_entry_and_the_others_are_not_listed() {
        let older = record("did:web:a", true, 100, "older");
        let newer = record("did:web:a", true, 10, "newer");
        for stored in [vec![older.clone(), newer.clone()], vec![newer.clone(), older.clone()]] {
            let items = super::merge_directory_entries(vec![entry("did:web:a")], stored, chrono::Utc::now());
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, "older");
            assert!(items[0].provided);
            assert_eq!(items[0].name, "Entry", "a stored provided record shows the entry's current name");
        }
    }

    #[test]
    fn provided_records_of_other_tenants_for_one_did_make_one_row() {
        let stored = vec![
            tenant_record("did:web:a", 50, "tenant-a-record", Some("tenant-a")),
            tenant_record("did:web:a", 10, "tenant-b-record", Some("tenant-b")),
            record("did:web:other", false, 5, "unrelated"),
        ];
        let items = super::merge_directory_entries(vec![entry("did:web:a")], stored, chrono::Utc::now());
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        assert_eq!(ids, ["tenant-a-record", "unrelated"]);
    }

    #[tokio::test]
    async fn the_record_a_request_reuses_is_the_operators_then_the_gateways_tenants() {
        use crate::mediators::MediatorStore;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::mediators::FileSystemMediatorStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for stored in [record("did:web:a", true, 100, "provided"), record("did:web:a", false, 10, "operator")] {
            store
                .create(&stored)
                .await
                .unwrap();
        }
        for _ in 0..3 {
            let found = super::find_directory_record(&store, "did:web:a", None, &None, &None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.id, "operator");
        }
    }

    #[tokio::test]
    async fn the_provided_record_a_request_reuses_is_one_the_target_gateway_may_reference() {
        use crate::mediators::MediatorStore;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::mediators::FileSystemMediatorStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for stored in [
            tenant_record("did:web:a", 100, "tenant-a-record", Some("tenant-a")),
            tenant_record("did:web:a", 10, "tenant-b-record", Some("tenant-b")),
        ] {
            store
                .create(&stored)
                .await
                .unwrap();
        }
        let find = |tenant: Option<&'static str>| {
            let store = &store;
            async move {
                super::find_directory_record(store, "did:web:a", tenant, &None, &None)
                    .await
                    .unwrap()
                    .map(|mediator| mediator.id)
            }
        };
        assert_eq!(
            find(Some("tenant-b"))
                .await
                .as_deref(),
            Some("tenant-b-record")
        );
        assert_eq!(
            find(Some("tenant-a"))
                .await
                .as_deref(),
            Some("tenant-a-record")
        );
        assert_eq!(find(Some("tenant-c")).await, None);
        assert_eq!(find(None).await, None, "an appliance-wide gateway cannot reference another owner's record");
    }

    #[test]
    fn a_directory_record_id_is_fixed_by_the_owner_and_the_did() {
        let id = super::directory_record_id(None, "did:web:a");
        assert_eq!(id, super::directory_record_id(None, "did:web:a"));
        assert_ne!(id, super::directory_record_id(None, "did:web:b"));
        assert_ne!(id, super::directory_record_id(Some("tenant-a"), "did:web:a"));
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    async fn pending_for(did: &str) -> Mediator {
        let mut pending = record(did, true, 0, "unused");
        pending.id = super::directory_record_id(None, did);
        pending
    }

    async fn stores()
    -> (crate::mediators::FileSystemMediatorStore, crate::gateways::FileSystemConnectionPointStore, tempfile::TempDir)
    {
        let dir = tempfile::tempdir().unwrap();
        let mediators = crate::mediators::FileSystemMediatorStore::new(dir.path().join("mediators"))
            .await
            .unwrap();
        let points = crate::gateways::FileSystemConnectionPointStore::new(dir.path().join("points"))
            .await
            .unwrap();
        (mediators, points, dir)
    }

    fn point_on(mediator_id: &str) -> crate::gateways::connection_points::types::GatewayConnectionPoint {
        crate::gateways::connection_points::types::GatewayConnectionPoint::new(
            "gateway".into(),
            mediator_id.into(),
            "did:web:cp".into(),
            "cp".into(),
            String::new(),
            "oob".into(),
            "https://m.invalid/oob".into(),
            serde_json::json!({}),
            None,
            crate::gateways::connection_points::ConnectionPointType::User,
            "secret".into(),
        )
    }

    #[tokio::test]
    async fn a_stored_pending_record_is_shared_and_its_creator_alone_rolls_it_back() {
        use crate::mediators::MediatorStore;
        let (store, points, _dir) = stores().await;
        let (first, created, first_use) =
            super::store_pending_directory_mediator(&store, pending_for("did:web:a").await, None, &None, &None)
                .await
                .unwrap();
        assert!(created);
        let (second, created_again, second_use) =
            super::store_pending_directory_mediator(&store, pending_for("did:web:a").await, None, &None, &None)
                .await
                .unwrap();
        assert!(!created_again);
        assert_eq!(first.id, second.id);
        assert!(
            super::MATERIALIZE_LOCKS
                .get("did:web:a")
                .is_none(),
            "the lock entry is dropped when its last user is done"
        );

        super::roll_back_directory_mediator(&store, &points, &first).await;
        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()
                .len(),
            1,
            "a second request still relies on the record"
        );

        drop(second_use);
        super::roll_back_directory_mediator(&store, &points, &first).await;
        assert!(
            store
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        drop(first_use);
        assert!(
            super::IN_USE
                .get(&first.id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_record_a_stored_connection_point_references_is_not_rolled_back() {
        use crate::gateways::connection_points::ConnectionPointStore;
        use crate::mediators::MediatorStore;
        let (store, points, _dir) = stores().await;
        let (created, _, usage) =
            super::store_pending_directory_mediator(&store, pending_for("did:web:b").await, None, &None, &None)
                .await
                .unwrap();
        points
            .create(&point_on(&created.id))
            .await
            .unwrap();
        super::roll_back_directory_mediator(&store, &points, &created).await;
        drop(usage);
        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    struct FailingStore;

    #[async_trait::async_trait]
    impl crate::mediators::MediatorStore for FailingStore {
        async fn create(
            &self,
            _: &Mediator,
        ) -> anyhow::Result<()> {
            anyhow::bail!("down")
        }

        async fn get(
            &self,
            _: &str,
        ) -> anyhow::Result<Option<Mediator>> {
            anyhow::bail!("down")
        }

        async fn list_all(&self) -> anyhow::Result<Vec<Mediator>> {
            anyhow::bail!("down")
        }

        async fn delete(
            &self,
            _: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("down")
        }

        async fn update(
            &self,
            _: &Mediator,
        ) -> anyhow::Result<()> {
            anyhow::bail!("down")
        }
    }

    #[tokio::test]
    async fn a_failing_store_does_not_leave_a_lock_entry_behind() {
        let result =
            super::store_pending_directory_mediator(&FailingStore, pending_for("did:web:c").await, None, &None, &None)
                .await;
        assert!(result.is_err());
        assert!(
            super::MATERIALIZE_LOCKS
                .get("did:web:c")
                .is_none()
        );
    }

    #[test]
    fn a_provided_record_cannot_be_changed_through_the_api() {
        let provided = record("did:web:a", true, 0, "provided");
        let operator = record("did:web:a", false, 0, "operator");
        let rejected = super::reject_provided(&provided).unwrap_err();
        assert_eq!(rejected.0, axum::http::StatusCode::CONFLICT);
        assert!(
            rejected
                .1
                .contains("provided by the directory")
        );
        assert!(super::reject_provided(&operator).is_ok());
    }

    #[tokio::test]
    async fn a_cancelled_request_does_not_leak_its_lock_entry() {
        let did = "did:web:cancelled.example";
        let holder = tokio::spawn(super::under_did_lock(did, async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let waiter = tokio::spawn(super::under_did_lock(did, async {}));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        waiter.abort();
        let _ = waiter.await;
        assert!(
            super::MATERIALIZE_LOCKS
                .get(did)
                .is_some(),
            "the holder still uses the entry"
        );
        holder.abort();
        let _ = holder.await;
        assert!(
            super::MATERIALIZE_LOCKS
                .get(did)
                .is_none(),
            "dropping the last user, cancelled or not, removes the entry"
        );
    }

    #[tokio::test]
    async fn a_provided_record_can_be_deleted_only_while_nothing_uses_it() {
        use crate::gateways::connection_points::ConnectionPointStore;
        let (store, points, _dir) = stores().await;
        let (created, _, usage) =
            super::store_pending_directory_mediator(&store, pending_for("did:web:d").await, None, &None, &None)
                .await
                .unwrap();

        let busy = super::reject_provided_in_use(&created, Some(&points))
            .await
            .unwrap_err();
        assert_eq!(busy.0, axum::http::StatusCode::CONFLICT, "a request still relies on it");
        drop(usage);
        assert!(
            super::reject_provided_in_use(&created, Some(&points))
                .await
                .is_ok(),
            "nothing uses it any more"
        );

        points
            .create(&point_on(&created.id))
            .await
            .unwrap();
        let referenced = super::reject_provided_in_use(&created, Some(&points))
            .await
            .unwrap_err();
        assert_eq!(referenced.0, axum::http::StatusCode::CONFLICT);
        assert!(
            referenced
                .1
                .contains("used by a connection point")
        );
        assert!(
            super::reject_provided_in_use(&created, None)
                .await
                .is_err(),
            "without a connection point store a provided record is not removed"
        );
    }

    #[tokio::test]
    async fn a_scoped_token_reuses_only_the_provided_records_its_scope_allows() {
        use crate::mediators::MediatorStore;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::mediators::FileSystemMediatorStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for id in ["allowed-record", "blocked-record"] {
            store
                .create(&tenant_record("did:web:a", 10, id, Some("tenant-a")))
                .await
                .unwrap();
        }
        let scope = |pattern: &str| Some(Extension(PatResourceScope(Arc::new(Regex::new(pattern).unwrap()))));
        let narrow = scope(r"\ATENANT:tenant-a:mediators:allowed-record\z");
        let found = super::find_directory_record(&store, "did:web:a", Some("tenant-a"), &tenant_a(), &narrow)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, "allowed-record");

        let none = scope(r"\ATENANT:tenant-a:mediators:something-else\z");
        assert!(
            super::find_directory_record(&store, "did:web:a", Some("tenant-a"), &tenant_a(), &none)
                .await
                .unwrap()
                .is_none(),
            "a stored provided record outside the scope is not reused"
        );
    }

    async fn stored_mediator(
        tenant_id: Option<&str>
    ) -> (Arc<crate::mediators::FileSystemMediatorStore>, Mediator, tempfile::TempDir) {
        use crate::mediators::MediatorStore;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::mediators::FileSystemMediatorStore::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let mut mediator =
            Mediator::new("Operator mediator".into(), String::new(), "did:example:mediator".into(), None);
        mediator.tenant_id = tenant_id.map(str::to_string);
        store
            .create(&mediator)
            .await
            .unwrap();
        (store, mediator, dir)
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn rename() -> axum::Json<super::UpdateMediatorRequest> {
        axum::Json(super::UpdateMediatorRequest {
            name: Some("Tenant mediator".into()),
            description: None,
            did: None,
            status: None,
        })
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_update_or_delete_an_appliance_wide_mediator() {
        use crate::mediators::MediatorStore;
        use axum::extract::Path;
        use axum::http::StatusCode;
        let (store, mediator, _dir) = stored_mediator(None).await;

        let axum::Json(read) =
            super::get_mediator(Extension(store.clone()), Path(mediator.id.clone()), tenant_a(), None)
                .await
                .unwrap();
        assert_eq!(read.name, "Operator mediator");

        let update = super::update_mediator(
            Extension(store.clone()),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::FORBIDDEN)
        );

        let delete = super::delete_mediator(
            Extension(store.clone()),
            Extension(None),
            Extension(None),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
        )
        .await;
        assert_eq!(
            delete
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::FORBIDDEN)
        );

        let after = store
            .get(&mediator.id)
            .await
            .unwrap()
            .expect("appliance-wide mediator must survive");
        assert_eq!(after.name, "Operator mediator");
        assert_eq!(after.updated_at, mediator.updated_at);
    }

    #[tokio::test]
    async fn another_tenants_mediator_is_not_found_on_update_or_delete() {
        use crate::mediators::MediatorStore;
        use axum::extract::Path;
        use axum::http::StatusCode;
        let (store, mediator, _dir) = stored_mediator(Some("tenant-b")).await;

        let update = super::update_mediator(
            Extension(store.clone()),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );

        let delete = super::delete_mediator(
            Extension(store.clone()),
            Extension(None),
            Extension(None),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
        )
        .await;
        assert_eq!(
            delete
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );

        let after = store
            .get(&mediator.id)
            .await
            .unwrap()
            .expect("another tenant's mediator must survive");
        assert_eq!(after.name, "Operator mediator");
        assert_eq!(after.updated_at, mediator.updated_at);
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_and_delete_its_own_mediator() {
        use crate::mediators::MediatorStore;
        use axum::extract::Path;
        use axum::http::StatusCode;
        let (store, mediator, _dir) = stored_mediator(Some("tenant-a")).await;

        let axum::Json(updated) = super::update_mediator(
            Extension(store.clone()),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Tenant mediator");

        let status = super::delete_mediator(
            Extension(store.clone()),
            Extension(None),
            Extension(None),
            Extension(None),
            Path(mediator.id.clone()),
            tenant_a(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            store
                .get(&mediator.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
