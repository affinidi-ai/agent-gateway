//! Message processing for different DIDComm message types

use hyper::Method;
use serde_json::Value;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, instrument, warn};

use super::filesystem::ConnectionPointStore;
use super::messages::ReceivedMessage;
use crate::gateways::filesystem::GatewayStore;
use crate::messages::MessageType;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::proxy::protocol_router::join_endpoint_path;
use crate::surfaces::AgentSurfaceStore;
use crate::{channel_debug, channel_error, channel_info, channel_warn};

/// Global metrics store for GW2 - set during initialization
static GLOBAL_METRICS_STORE: OnceCell<Arc<crate::metrics::MetricsStore>> = OnceCell::const_new();

/// Global WebSocket state for GW2 - set during initialization for payload capture broadcasting
static GLOBAL_WS_STATE: OnceCell<Arc<crate::server::WsState>> = OnceCell::const_new();

/// Global VC issuer for GW2 - separate identity space from GW1
static GLOBAL_VC_ISSUER: OnceCell<Arc<crate::identity::VCIssuer>> = OnceCell::const_new();

/// Global MCP proxy store for GW2 - for handling proxy:// backends
static GLOBAL_MCP_PROXY_STORE: OnceCell<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>> = OnceCell::const_new();

/// Global A2A proxy store for GW2 - for handling a2a-proxy:// backends
static GLOBAL_A2A_PROXY_STORE: OnceCell<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>> = OnceCell::const_new();

/// Global policy manager for GW2 - for handling rate limiting and policies
static GLOBAL_POLICY_MANAGER: OnceCell<Arc<crate::policies::SurfacePolicyManager>> = OnceCell::const_new();

/// Global task monitor for GW2 - for tracking bytes and throughput
static GLOBAL_TASK_MONITOR: OnceCell<Arc<crate::observability::TaskMonitor>> = OnceCell::const_new();

/// Global HTTP client for GW2 - for MCP proxy requests with policies
static GLOBAL_HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();
static GLOBAL_FORWARD_TIMEOUT: OnceCell<std::time::Duration> = OnceCell::const_new();
/// Byte cap for a buffered Target response on a fabric forward (`a2a.max_body_size`).
static GLOBAL_MAX_RESPONSE_BYTES: OnceCell<usize> = OnceCell::const_new();

/// Global agent-surface store for GW2 — preferred over re-opening the
/// filesystem store on every fabric request. Provides O(1) surface lookup via
/// the underlying cached storage backend.
static GLOBAL_AGENT_SURFACE_STORE: OnceCell<Arc<dyn AgentSurfaceStore>> = OnceCell::const_new();

/// Global notification store for GW2 - for integration triggers
static GLOBAL_NOTIFICATION_STORE: OnceCell<Arc<crate::integrations::FileSystemNotificationStore>> =
    OnceCell::const_new();

/// Global facilitator mode for GW2 - controls which facilitator features are enabled
static GLOBAL_FACILITATOR_MODE: OnceCell<crate::config::types::FacilitatorMode> = OnceCell::const_new();

/// Global transaction store for GW2 - for unified x402 lifecycle tracking
static GLOBAL_TRANSACTION_STORE: OnceCell<Arc<crate::x402::TransactionStore>> = OnceCell::const_new();

/// Global MPP transaction store for GW2 - for MPP payment audit trail
static GLOBAL_MPP_TRANSACTION_STORE: OnceCell<Arc<crate::mpp::MppTransactionStore>> = OnceCell::const_new();

/// Global trust registry listener manager for GW2 - for AAP-specific policy context building
static GLOBAL_TRUST_REGISTRY_LISTENER_MANAGER: OnceCell<Arc<crate::trust_registries::TrustRegistryListenerManager>> =
    OnceCell::const_new();

/// Global unified source authentication middleware for GW2.
static GLOBAL_SOURCE_AUTH_MIDDLEWARE: OnceCell<Arc<crate::source_auth::SourceAuthMiddleware>> = OnceCell::const_new();

static GLOBAL_MCP_AUTH_NETWORK: OnceCell<Arc<crate::config::NetworkConfig>> = OnceCell::const_new();

pub fn init_mcp_auth_network(network: Arc<crate::config::NetworkConfig>) {
    let _ = GLOBAL_MCP_AUTH_NETWORK.set(network);
}

/// Global gateway-level OPA policy manager for GW2 - for gateway-wide policy enforcement on fabric requests
static GLOBAL_GATEWAY_POLICY_MANAGER: OnceCell<Arc<crate::policies::GatewayPolicyManager>> = OnceCell::const_new();

/// Global appliance-wide (global) policy manager for GW2 - enforces the
/// appliance-wide gateway/surface policy sets on fabric requests.
static GLOBAL_APPLIANCE_POLICY_MANAGER: OnceCell<Arc<crate::policies::GlobalPolicyManager>> = OnceCell::const_new();

/// Global issuer store for GW2 - for trust registry validation lookups
static GLOBAL_ISSUER_STORE: OnceCell<Arc<dyn crate::issuers::IssuerStore>> = OnceCell::const_new();
static GLOBAL_AUTHORITY_STORE: OnceCell<Arc<dyn crate::authorities::AuthorityStore>> = OnceCell::const_new();

/// Global secrets store for GW2 - for target_auth and credential delegation secret resolution
static GLOBAL_SECRETS_STORE: OnceCell<Arc<dyn crate::secrets::SecretsStore>> = OnceCell::const_new();

/// Global credential provider store for GW2 - for outbound credential delegation
static GLOBAL_CREDENTIAL_PROVIDER_STORE: OnceCell<
    Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
> = OnceCell::const_new();

/// Global delegation vault store for GW2 - for outbound credential delegation token lookup
static GLOBAL_DELEGATION_VAULT_STORE: OnceCell<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> =
    OnceCell::const_new();

/// Gateway base URL for GW2 — used to build OAuth authorization redirect URLs
static GLOBAL_GATEWAY_BASE_URL: OnceCell<String> = OnceCell::const_new();

/// Initialize the global metrics store for GW2
pub async fn init_metrics_store(metrics_store: Arc<crate::metrics::MetricsStore>) {
    let _ = GLOBAL_METRICS_STORE.set(metrics_store);
    info!("GW2: Global metrics store initialized");
}

/// Initialize the global WebSocket state for GW2
pub async fn init_ws_state(ws_state: Arc<crate::server::WsState>) {
    let _ = GLOBAL_WS_STATE.set(ws_state);
    info!("GW2: Global WebSocket state initialized for payload capture broadcasting");
}

/// Initialize the global VC issuer for GW2 (separate identity space)
pub async fn init_vc_issuer(
    vc_issuer: Arc<crate::identity::VCIssuer>,
    did_cache: Option<Arc<crate::gateways::did_cache::DIDCache>>,
) {
    // Set DID cache if available
    if let Some(cache) = did_cache {
        info!("GW2: Setting DID cache for VC issuer to enable cached DID resolution");
        vc_issuer
            .set_did_cache(cache)
            .await;
    } else {
        warn!("GW2: No DID cache provided - VP verification will use temporary resolver");
    }

    let _ = GLOBAL_VC_ISSUER.set(vc_issuer);
    info!("GW2: Global VC issuer initialized for agent identity tracking");
}

/// Get the global VC issuer, if initialized.
pub fn get_vc_issuer() -> Option<Arc<crate::identity::VCIssuer>> {
    GLOBAL_VC_ISSUER
        .get()
        .cloned()
}

/// Listener manager, used on the fabric-receive path to resolve the sending
/// peer's Remote gateway record and run the issuer exchange on demand.
static GLOBAL_LISTENER_MANAGER: OnceCell<Arc<super::ConnectionPointListenerManager>> = OnceCell::const_new();

/// Initialize the global listener manager for GW2
pub async fn init_listener_manager(listener_manager: Arc<super::ConnectionPointListenerManager>) {
    let _ = GLOBAL_LISTENER_MANAGER.set(listener_manager);
    info!("GW2: Global listener manager initialized for peer gateway resolution");
}

/// Initialize the global MCP proxy store for GW2
pub async fn init_mcp_proxy_store(mcp_proxy_store: Arc<crate::mcp_proxies::FileSystemMcpProxyStore>) {
    let _ = GLOBAL_MCP_PROXY_STORE.set(mcp_proxy_store);
    info!("GW2: Global MCP proxy store initialized");
}

/// Initialize the global A2A proxy store for GW2
pub async fn init_a2a_proxy_store(a2a_proxy_store: Arc<crate::a2a_proxies::FileSystemA2aProxyStore>) {
    let _ = GLOBAL_A2A_PROXY_STORE.set(a2a_proxy_store);
    info!("GW2: Global A2A proxy store initialized");
}

/// Initialize the global policy manager for GW2
pub async fn init_policy_manager(policy_manager: Arc<crate::policies::SurfacePolicyManager>) {
    let _ = GLOBAL_POLICY_MANAGER.set(policy_manager);
    info!("GW2: Global policy manager initialized for rate limiting and policies");
}

/// Initialize the global task monitor for GW2
pub async fn init_task_monitor(task_monitor: Arc<crate::observability::TaskMonitor>) {
    let _ = GLOBAL_TASK_MONITOR.set(task_monitor);
    info!("GW2: Global task monitor initialized for bytes and throughput tracking");
}

/// Initialize the global notification store for GW2
pub async fn init_notification_store(notification_store: Arc<crate::integrations::FileSystemNotificationStore>) {
    let _ = GLOBAL_NOTIFICATION_STORE.set(notification_store);
    info!("GW2: Global notification store initialized for integration triggers");
}

/// Initialize the global HTTP client for GW2, the timeout a forward to an
/// HTTP(S) Target uses when its pinned client is built per request, and the
/// byte cap for the Target's buffered response.
pub async fn init_http_client(
    client: reqwest::Client,
    forward_timeout: std::time::Duration,
    max_response_bytes: usize,
) {
    let _ = GLOBAL_HTTP_CLIENT.set(client);
    let _ = GLOBAL_FORWARD_TIMEOUT.set(forward_timeout);
    let _ = GLOBAL_MAX_RESPONSE_BYTES.set(max_response_bytes);
    info!("GW2: Global HTTP client initialized for MCP proxy requests");
}

/// Initialize the global agent-surface store for GW2.
///
/// When set, fabric forward-request handlers use this in-process store
/// (with cached O(1) `get(config_id)`) instead of re-instantiating a
/// `FileSystemAgentSurfaceStore` and linear-scanning `list_all()` on every
/// inbound message.
pub async fn init_agent_surface_store(store: Arc<dyn AgentSurfaceStore>) {
    if GLOBAL_AGENT_SURFACE_STORE
        .set(store)
        .is_err()
    {
        warn!(
            "GW2: GLOBAL_AGENT_SURFACE_STORE already initialised — ignoring re-init. \
               Hot-reloaded surface config will not be visible to the fabric path until restart."
        );
    } else {
        info!("GW2: Global agent-surface store initialized for O(1) surface lookup");
    }
}

/// Get the global agent-surface store, if initialized.
pub fn get_agent_surface_store() -> Option<Arc<dyn AgentSurfaceStore>> {
    GLOBAL_AGENT_SURFACE_STORE
        .get()
        .cloned()
}

/// Initialize the global facilitator mode for GW2
pub async fn init_facilitator_mode(facilitator_mode: crate::config::types::FacilitatorMode) {
    let fabric_enabled = facilitator_mode.facilitator_via_fabric;
    let http_enabled = facilitator_mode.facilitator_via_http;
    let _ = GLOBAL_FACILITATOR_MODE.set(facilitator_mode);
    info!("GW2: Global facilitator mode initialized (fabric={}, http={})", fabric_enabled, http_enabled);
}

/// Initialize the global transaction store for GW2
pub async fn init_transaction_store(transaction_store: Arc<crate::x402::TransactionStore>) {
    let _ = GLOBAL_TRANSACTION_STORE.set(transaction_store);
    info!("GW2: Global transaction store initialized for unified x402 lifecycle tracking");
}

/// Get the global transaction store (for admin API access)
pub fn get_transaction_store() -> Option<Arc<crate::x402::TransactionStore>> {
    GLOBAL_TRANSACTION_STORE
        .get()
        .cloned()
}

/// Initialize the global MPP transaction store
pub async fn init_mpp_transaction_store(store: Arc<crate::mpp::MppTransactionStore>) {
    let _ = GLOBAL_MPP_TRANSACTION_STORE.set(store);
    info!("Global MPP transaction store initialized for payment audit trail");
}

/// Get the global MPP transaction store
pub fn get_mpp_transaction_store() -> Option<Arc<crate::mpp::MppTransactionStore>> {
    GLOBAL_MPP_TRANSACTION_STORE
        .get()
        .cloned()
}

/// Initialize the global trust registry listener manager for GW2 AAP-specific policy
pub async fn init_trust_registry_listener_manager(manager: Arc<crate::trust_registries::TrustRegistryListenerManager>) {
    let _ = GLOBAL_TRUST_REGISTRY_LISTENER_MANAGER.set(manager);
    info!("GW2: Global trust registry listener manager initialized for AAP-specific policy");
}

/// Get the global trust registry listener manager
pub fn get_trust_registry_listener_manager() -> Option<Arc<crate::trust_registries::TrustRegistryListenerManager>> {
    GLOBAL_TRUST_REGISTRY_LISTENER_MANAGER
        .get()
        .cloned()
}

/// Initialize the global unified source authentication middleware for GW2.
pub async fn init_source_auth_middleware(middleware: Arc<crate::source_auth::SourceAuthMiddleware>) {
    let _ = GLOBAL_SOURCE_AUTH_MIDDLEWARE.set(middleware);
    info!("GW2: Global source auth middleware initialized");
}

/// Get the global unified source authentication middleware.
pub fn get_source_auth_middleware() -> Option<Arc<crate::source_auth::SourceAuthMiddleware>> {
    GLOBAL_SOURCE_AUTH_MIDDLEWARE
        .get()
        .cloned()
}

async fn resolve_fabric_surface_auth_config(
    auth_config: &crate::source_auth::SourceAuthConfig,
    vc_issuer: Option<&crate::identity::VCIssuer>,
    surface_id: &str,
) -> crate::source_auth::errors::SourceAuthResult<crate::source_auth::SourceAuthConfig> {
    crate::source_auth::middleware::resolve_surface_audience(auth_config, vc_issuer, surface_id).await
}

/// Initialize the global gateway-level OPA policy manager for GW2.
pub async fn init_gateway_policy_manager(manager: Arc<crate::policies::GatewayPolicyManager>) {
    let _ = GLOBAL_GATEWAY_POLICY_MANAGER.set(manager);
    info!("GW2: Global gateway policy manager initialized for gateway-level OPA enforcement");
}

/// Initialize the global appliance-wide policy manager for GW2.
pub async fn init_appliance_policy_manager(manager: Arc<crate::policies::GlobalPolicyManager>) {
    let _ = GLOBAL_APPLIANCE_POLICY_MANAGER.set(manager);
    info!("GW2: Global appliance-wide policy manager initialized");
}

/// Get the global appliance-wide policy manager, if initialized.
pub fn get_appliance_policy_manager() -> Option<Arc<crate::policies::GlobalPolicyManager>> {
    GLOBAL_APPLIANCE_POLICY_MANAGER
        .get()
        .cloned()
}

/// Initialize the global issuer store for GW2 trust registry validation lookups.
pub async fn init_issuer_store(store: Arc<dyn crate::issuers::IssuerStore>) {
    let _ = GLOBAL_ISSUER_STORE.set(store);
    info!("GW2: Global issuer store initialized for trust registry validation");
}

/// Get the global issuer store.
#[allow(dead_code)]
pub fn get_issuer_store() -> Option<Arc<dyn crate::issuers::IssuerStore>> {
    GLOBAL_ISSUER_STORE
        .get()
        .cloned()
}

/// Initialize the global authority store used to name Trust Recorder authorities.
pub fn init_authority_store(store: Arc<dyn crate::authorities::AuthorityStore>) {
    let _ = GLOBAL_AUTHORITY_STORE.set(store);
}

/// Get the global authority store.
pub fn get_authority_store() -> Option<Arc<dyn crate::authorities::AuthorityStore>> {
    GLOBAL_AUTHORITY_STORE
        .get()
        .cloned()
}

/// Initialize the global secrets store for GW2.
pub async fn init_secrets_store(store: Arc<dyn crate::secrets::SecretsStore>) {
    let _ = GLOBAL_SECRETS_STORE.set(store);
    info!("GW2: Global secrets store initialized for credential delegation");
}

/// Get the global secrets store.
pub(crate) fn get_secrets_store() -> Option<Arc<dyn crate::secrets::SecretsStore>> {
    GLOBAL_SECRETS_STORE
        .get()
        .cloned()
}

/// Initialize the global credential provider store for GW2.
pub async fn init_credential_provider_store(
    store: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>
) {
    let _ = GLOBAL_CREDENTIAL_PROVIDER_STORE.set(store);
    info!("GW2: Global credential provider store initialized");
}

/// Get the global credential provider store.
fn get_credential_provider_store() -> Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>> {
    GLOBAL_CREDENTIAL_PROVIDER_STORE
        .get()
        .cloned()
}

/// Initialize the global delegation vault store for GW2.
pub async fn init_delegation_vault_store(store: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>) {
    let _ = GLOBAL_DELEGATION_VAULT_STORE.set(store);
    info!("GW2: Global delegation vault store initialized");
}

/// Get the global delegation vault store.
fn get_delegation_vault_store() -> Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> {
    GLOBAL_DELEGATION_VAULT_STORE
        .get()
        .cloned()
}

/// Initialize the gateway base URL for GW2 OAuth authorization URLs.
pub async fn init_gateway_base_url(url: String) {
    let _ = GLOBAL_GATEWAY_BASE_URL.set(url);
    info!("GW2: Gateway base URL initialized for credential delegation");
}

/// Get the gateway base URL.
fn get_gateway_base_url() -> Option<String> {
    GLOBAL_GATEWAY_BASE_URL
        .get()
        .cloned()
}

/// Ensure a channel task is registered in the TaskMonitor for bytes tracking.
/// Returns the `task_id` of the AP TaskInfo for this surface (existing or
/// newly created) so callers can route bytes/connection metrics to the
/// correct entry without having to guess the id scheme.
async fn ensure_task_registered(surface: &crate::config::agent_surface::AgentSurface) -> Option<String> {
    let task_monitor = GLOBAL_TASK_MONITOR.get()?;
    let config_id = surface.config_id();

    // Prefer matching an already-registered AP task by config_id so we
    // don't insert a second entry alongside the one created by the port
    // listener at startup (which uses a `task-<config_id>-<uuid>` id).
    if let Some(cid) = config_id
        && let Some(existing) = task_monitor
            .find_ap_task_id_by_config_id(cid)
            .await
    {
        return Some(existing);
    }

    let task_id = config_id
        .unwrap_or(&surface.name)
        .to_string();
    if task_monitor
        .get_task(&task_id)
        .await
        .is_none()
    {
        let listen_address = surface.listen_address();
        // Register the task
        let task_info = crate::observability::TaskInfo {
            task_id: task_id.to_string(),
            config_id: surface
                .config_id()
                .map(str::to_string),
            channel_name: surface.name.clone(),
            transit_point: None,
            listen_address: if listen_address.is_empty() {
                "fabric".to_string()
            } else {
                listen_address.to_string()
            },
            target_endpoint: surface
                .target_endpoint()
                .to_string(),
            started_at: chrono::Utc::now(),
            status: crate::observability::TaskStatus::Running,
            total_connections: 0,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: None,
            error_count: 0,
            recent_bytes_sent: 0,
            recent_bytes_received: 0,
            recent_window_start: chrono::Utc::now(),
        };

        task_monitor
            .register_task(task_info)
            .await;
        debug!("GW2: Registered task {} in TaskMonitor for bytes tracking", task_id);
    }
    Some(task_id)
}

/// Process a received DIDComm message based on its type
///
/// This is the legacy entry point. New code should use the dispatcher module.
#[allow(dead_code)]
pub async fn process_message(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message type: {}", message.message_type);

    let message_type = MessageType::from_str(&message.message_type);
    process_message_internal(message, &message_type).await
}

/// Internal message processor that uses the MessageType enum
///
/// This is called by the dispatcher and provides type-safe routing
#[instrument(name = "didcomm.process_message", skip(message), fields(msg.type = %message.message_type, msg.id = %message.didcomm_message_id, msg.from = ?message.from_did))]
pub async fn process_message_internal(
    message: &ReceivedMessage,
    message_type: &MessageType,
) -> ProcessingResult {
    match message_type {
        // Trust ping protocol
        MessageType::TrustPing => process_trust_ping(message).await,
        MessageType::TrustPingResponse => {
            info!("Received trust-ping response from {:?}", message.from_did);
            ProcessingResult::ProcessedNoResponse
        }

        // Forward protocol - handle forwarded messages
        MessageType::Forward => process_forward(message).await,

        // Problem reports
        MessageType::ProblemReport => process_problem_report(message).await,

        // Basic message protocol
        MessageType::BasicMessage => process_basic_message(message).await,

        // Discover features protocol
        MessageType::DiscoverFeaturesQuery => process_discover_features(message).await,
        MessageType::DiscoverFeaturesDisclose => process_feature_disclosure(message).await,

        // Out of band invitations
        MessageType::OOBInvitation => process_oob_invitation(message).await,

        // Connection setup protocol (Affinidi custom)
        MessageType::ConnectionSetup => process_connection_setup(message).await,
        MessageType::ConnectionAccepted => process_connection_accepted(message).await,
        MessageType::ConnectionRejected => process_connection_rejected(message).await,

        // Gateway ping protocol (Affinidi custom)
        MessageType::GatewayPing => process_gateway_ping(message).await,
        MessageType::GatewayPong => process_gateway_pong(message).await,

        // Gateway issuer protocol (Affinidi custom)
        MessageType::GatewayIssuerRequest => process_gateway_issuer_request(message).await,
        MessageType::GatewayIssuerResponse => process_gateway_issuer_response(message).await,

        // Gateway channel query protocol (Affinidi custom)
        MessageType::GetSurfaces => process_get_surfaces(message).await,
        MessageType::GetSurfacesResponse => process_get_surfaces_response(message).await,

        // Gateway request forwarding protocol (Affinidi custom)
        // Box::pin moves the large future (~2700 lines) to the heap to prevent
        // tokio worker thread stack overflow. Installs the per-request policy
        // decision collector (a task-local otherwise only set by the HTTP
        // `multi_channel_proxy_handler`) so surface/gateway OPA decisions on the fabric leg
        // are captured and can be embedded as `workloadBinding.policyDecisions`
        // in the backend-agent VP GW2 injects into the response.
        MessageType::ForwardRequest => {
            // Continue the upstream gateway's trace (from the message `trace_id`),
            // seeded into `REQUEST_TRACE_ID` so audit + the injected VP `traceId`
            // share it. Trace-id termination is applied at EGRESS (the onward
            // forward), not here, so this gateway's own VP/audit stay on the
            // incoming trace (past stays traceable).
            let req_trace_id = message
                .message_body
                .get("trace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            crate::observability::policy_audit::REQUEST_TRACE_ID
                .scope(
                    req_trace_id,
                    crate::observability::policy_audit::POLICY_DECISION_COLLECTOR.scope(
                        std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                        Box::pin(process_forward_request(message)),
                    ),
                )
                .await
        }
        MessageType::ForwardResponse => process_forward_response(message).await,
        MessageType::ForwardStreamFrame | MessageType::ForwardStreamQuery | MessageType::ForwardStreamDisclose => {
            match crate::proxy::fabric_stream::global() {
                Ok(runtime) => runtime.process(message, message_type),
                Err(reason) => ProcessingResult::Failed { reason },
            }
        }

        // x402 Facilitator protocol (Affinidi custom)
        MessageType::X402VerifyRequest => process_x402_verify_request(message).await,
        MessageType::X402VerifyResponse => process_x402_verify_response(message).await,
        MessageType::X402SettleRequest => process_x402_settle_request(message).await,
        MessageType::X402SettleResponse => process_x402_settle_response(message).await,
        MessageType::X402SettlementComplete => process_x402_settlement_complete(message).await,

        // Message pickup protocol
        MessageType::MessagePickupStatusRequest => process_status_request(message).await,
        MessageType::MessagePickupStatus => process_status_response(message).await,
        MessageType::MessagePickupDeliveryRequest => process_delivery_request(message).await,
        MessageType::MessagePickupDelivery => process_delivery_response(message).await,
        MessageType::MessagePickupMessagesReceived => process_messages_received(message).await,
        MessageType::MessagePickupLiveDeliveryChange => process_live_delivery_change(message).await,

        // Presentation protocols
        MessageType::PresentProofRequestPresentation => process_presentation_request(message).await,
        MessageType::PresentProofPresentation => process_presentation(message).await,

        // Issuance protocols
        MessageType::IssueCredentialOffer => process_credential_offer(message).await,
        MessageType::IssueCredentialRequest => process_credential_request(message).await,
        MessageType::IssueCredentialIssue => process_credential_issuance(message).await,

        // AccountManagement
        MessageType::AccountManagement => process_account_management(message).await,

        // Unknown message types - store but don't process
        MessageType::Unknown(type_str) => {
            info!("Received unknown message type: {}", type_str);
            ProcessingResult::Stored
        }
    }
}

/// Payload of a received connection-accepted (ACCEPTOR side). Boxed inside
/// `ProcessingResult` so the enum stays small enough to use as an error type.
#[derive(Debug, Clone)]
pub struct OobConnectionAccepted {
    pub inviter_temporary_did: String,
    pub inviter_secure_did: String,
    /// The inviter's issuer attestation, verified against `nonce` (the message thread id)
    pub issuer_attestation: Option<String>,
    pub nonce: Option<String>,
}

/// Payload of a received connection-setup (INVITER side). Boxed inside
/// `ProcessingResult` so the enum stays small enough to use as an error type.
#[derive(Debug, Clone)]
pub struct OobConnectionSetup {
    pub acceptor_temporary_did: String,
    pub acceptor_secure_did: String,
    pub invitation_id: String,
    pub secret: String,
    /// The acceptor's issuer attestation, verified against `nonce` (the message thread id)
    pub issuer_attestation: Option<String>,
    pub nonce: Option<String>,
}

/// Result of message processing
#[derive(Debug)]
pub enum ProcessingResult {
    /// Message was stored only
    Stored,
    /// Message was processed and requires a response
    RequiresResponse {
        response_type: String,
        response_body: Value,
    },
    StreamingResponse {
        response: axum::response::Response,
    },
    /// Message was processed successfully with no response needed
    ProcessedNoResponse,
    /// Message processing failed
    Failed {
        reason: String,
    },
    /// OOB connection-accepted received - needs gateway finalization
    OOBConnectionAccepted(Box<OobConnectionAccepted>),
    /// OOB connection-setup received - needs to send connection-accepted
    OOBConnectionSetup(Box<OobConnectionSetup>),
    /// OOB connection-rejected received - connection failed
    OOBConnectionRejected {
        reason: String,
    },
}

// Trust Ping Protocol
async fn process_trust_ping(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing trust-ping from {:?}", message.from_did);

    // Check if response_requested field is true
    let response_requested = message
        .message_body
        .get("response_requested")
        .and_then(|v| v.as_bool())
        .unwrap_or(true); // Default to true if not specified

    if response_requested {
        // Return ping-response (note: mediator stores and sends back to sender)
        info!("Trust-ping requests response - acknowledging");
        ProcessingResult::ProcessedNoResponse
    } else {
        info!("Trust-ping does not request response");
        ProcessingResult::ProcessedNoResponse
    }
}

// Forward Protocol
async fn process_forward(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing forwarded message from {:?}", message.from_did);

    // Extract the forwarded message
    if let Some(forwarded_msg) = message
        .message_body
        .get("next")
    {
        debug!("Extracted forwarded message: {:?}", forwarded_msg);
        // In a real implementation, you would decrypt and process the forwarded message
        ProcessingResult::ProcessedNoResponse
    } else {
        ProcessingResult::Failed {
            reason: "Forward message missing 'next' field".to_string(),
        }
    }
}

// Problem Report
async fn process_problem_report(message: &ReceivedMessage) -> ProcessingResult {
    warn!("Received problem report from {:?}: {:?}", message.from_did, message.message_body);

    // Extract problem code and description
    let code = message
        .message_body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let comment = message
        .message_body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    info!("Problem code: {}, comment: {}", code, comment);

    ProcessingResult::ProcessedNoResponse
}

// Basic Message
async fn process_basic_message(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing basic message from {:?}", message.from_did);

    if let Some(content) = message
        .message_body
        .get("content")
        .and_then(|v| v.as_str())
    {
        info!("Basic message content: {}", content);
    }

    ProcessingResult::ProcessedNoResponse
}

// Discover Features
async fn process_discover_features(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing discover features query from {:?}", message.from_did);

    // Respond with supported protocols
    let response = serde_json::json!({
        "type": "https://didcomm.org/discover-features/2.0/disclose",
        "id": uuid::Uuid::new_v4().to_string(),
        "thid": message.didcomm_message_id,
        "body": {
            "disclosures": [
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/trust-ping/2.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/routing/2.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/messagepickup/3.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/present-proof/3.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/issue-credential/3.0"
                }
            ]
        }
    });

    ProcessingResult::RequiresResponse {
        response_type: "discover-features-disclose".to_string(),
        response_body: response,
    }
}

async fn process_feature_disclosure(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received feature disclosure from {:?}", message.from_did);
    ProcessingResult::ProcessedNoResponse
}

// Out of Band Invitation
async fn process_oob_invitation(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing out-of-band invitation from {:?}", message.from_did);
    // Store the invitation for potential connection establishment
    ProcessingResult::ProcessedNoResponse
}

// Connection Setup Protocol (Affinidi custom)
async fn process_connection_setup(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Processing connection-setup (INVITER receiving request from ACCEPTOR)");

    // Extract the acceptor's secure DID from the message body
    let acceptor_secure_did = message
        .message_body
        .get("channel_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if acceptor_secure_did.is_none() {
        warn!("connection-setup missing 'channel_did' field");
        return ProcessingResult::Failed {
            reason: "Missing channel_did in connection-setup message".to_string(),
        };
    }

    let acceptor_secure_did = acceptor_secure_did.unwrap();

    // Extract the secret from the message body
    let secret = message
        .message_body
        .get("secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Get the acceptor's temporary DID (the sender of this message)
    let acceptor_temporary_did = match &message.from_did {
        Some(did) => did.clone(),
        None => {
            warn!("connection-setup missing 'from' DID");
            return ProcessingResult::Failed {
                reason: "Missing from DID in connection-setup message".to_string(),
            };
        }
    };

    let Some(inviter_temporary_did) = message.to_dids.first() else {
        warn!("connection-setup missing 'to' DID");
        return ProcessingResult::Failed {
            reason: "Missing to DID in connection-setup message".to_string(),
        };
    };

    let connection_point = match load_invited_connection_point(message).await {
        Ok(connection_point) => connection_point,
        Err(reason) => {
            warn!("connection-setup on connection point {} refused: {}", message.connection_point_id, reason);
            return ProcessingResult::Failed { reason };
        }
    };

    let Some(proof) = message
        .message_body
        .get("channel_did_proof")
        .and_then(|v| v.as_str())
    else {
        warn!("connection-setup from {} missing 'channel_did_proof' field", acceptor_temporary_did);
        return ProcessingResult::Failed {
            reason: "Missing channel_did_proof in connection-setup message".to_string(),
        };
    };
    let challenge = channel_did_proof_challenge(&acceptor_temporary_did, inviter_temporary_did, &acceptor_secure_did);
    if let Err(reason) = verify_channel_did_proof(&acceptor_secure_did, proof, &challenge).await {
        warn!(
            "connection-setup from {} refused: control of channel_did {} not proven: {}",
            acceptor_temporary_did, acceptor_secure_did, reason
        );
        return ProcessingResult::Failed {
            reason: format!("Invalid channel_did_proof: {}", reason),
        };
    }

    // Only a sender that proved control of its channel_did on a live
    // invitation may add to the seen set.
    if let Err(refused) = admit_pairing_envelope(message) {
        return refused;
    }

    info!("✓ Acceptor temporary DID: {}", acceptor_temporary_did);
    info!("✓ Acceptor secure DID: {} (control proven)", acceptor_secure_did);
    info!("✓ Invitation reference: {}", connection_point.oob_id);
    info!("✓ Secret received: [REDACTED]");

    // Return special result type to trigger connection-accepted response and gateway creation
    ProcessingResult::OOBConnectionSetup(Box::new(OobConnectionSetup {
        acceptor_temporary_did,
        acceptor_secure_did,
        invitation_id: connection_point.oob_id,
        secret,
        issuer_attestation: issuer_attestation_from_body(&message.message_body),
        nonce: message.didcomm_thid.clone(),
    }))
}

fn issuer_attestation_from_body(body: &Value) -> Option<String> {
    body.get("issuer_attestation")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Seconds a connection-setup `channel_did_proof` stays valid after signing.
const CHANNEL_DID_PROOF_TTL_SECONDS: i64 = 300;

/// The challenge an acceptor signs with the key behind its permanent
/// `channel_did`. Binding it to both temporary DIDs ties the proof to this
/// authenticated envelope, so it cannot be replayed by another sender or
/// against another inviter.
pub(crate) fn channel_did_proof_challenge(
    acceptor_temporary_did: &str,
    inviter_temporary_did: &str,
    channel_did: &str,
) -> String {
    format!("connection-setup:{acceptor_temporary_did}:{inviter_temporary_did}:{channel_did}")
}

/// Sign the connection-setup challenge as a compact JWS with the Ed25519 key of
/// the connection point identity that owns `channel_did`.
pub(crate) fn sign_channel_did_proof(
    secrets: &[affinidi_tdk_common::secrets_resolver::secrets::Secret],
    challenge: &str,
) -> Result<String, String> {
    use affinidi_tdk_common::secrets_resolver::secrets::KeyType;
    use base64::Engine;
    use ed25519_dalek::Signer;

    let secret = secrets
        .iter()
        .find(|secret| secret.get_key_type() == KeyType::Ed25519)
        .ok_or_else(|| "connection point identity has no Ed25519 key".to_string())?;
    let seed: [u8; 32] = secret
        .get_private_bytes()
        .try_into()
        .map_err(|_| "Ed25519 private key is not 32 bytes".to_string())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let now = chrono::Utc::now().timestamp();
    let header = serde_json::json!({ "alg": "EdDSA", "kid": secret.id });
    let payload = serde_json::json!({
        "challenge": challenge,
        "iat": now,
        "exp": now + CHANNEL_DID_PROOF_TTL_SECONDS,
    });
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let signing_input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(&header).map_err(|e| e.to_string())?),
        b64(&serde_json::to_vec(&payload).map_err(|e| e.to_string())?)
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!("{}.{}", signing_input, b64(&signature.to_bytes())))
}

fn channel_did_proof_config() -> crate::source_auth::models::DidAuthAuthConfig {
    crate::source_auth::models::DidAuthAuthConfig {
        extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
            field: "Authorization".to_string(),
        },
        allowed_dids: vec![],
        challenge_ttl_seconds: None,
        session_ttl_seconds: None,
        audience: None,
        allowed_algorithms: vec![],
    }
}

/// Verify that `proof` was signed over `challenge` by a verification method in
/// the resolved DID document of `channel_did`. The DIDComm envelope only
/// authenticates the acceptor's temporary DID; without this check the body
/// could name any DID and it would be recorded as the peer.
async fn verify_channel_did_proof(
    channel_did: &str,
    proof: &str,
    challenge: &str,
) -> Result<(), String> {
    crate::didauth::verify::verify_challenge_response(
        channel_did,
        proof,
        challenge,
        &channel_did_proof_config(),
        crate::gateways::did_cache::shared_resolver(),
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// The connection point a connection-setup arrived on must still be a live
/// invitation: present, enabled and not past `expires_at`. Listener activation
/// prunes expired invitations, but a listener that was already running keeps
/// accepting on its socket after the invitation expires.
async fn load_invited_connection_point(
    message: &ReceivedMessage
) -> Result<crate::gateways::connection_points::types::GatewayConnectionPoint, String> {
    let storage_root =
        storage_root_from_context(message).ok_or_else(|| "storage path not found in message context".to_string())?;
    let store =
        crate::gateways::connection_points::FileSystemConnectionPointStore::new(storage_root.join("connection_points"))
            .await
            .map_err(|e| format!("failed to open connection point store: {}", e))?;
    let connection_point = store
        .get(&message.connection_point_id)
        .await
        .map_err(|e| format!("failed to load connection point: {}", e))?
        .ok_or_else(|| "connection point not found".to_string())?;
    if !connection_point.enabled {
        return Err("connection point is disabled".to_string());
    }
    if connection_point
        .expires_at
        .is_some_and(|expires_at| expires_at < chrono::Utc::now())
    {
        return Err("invitation has expired".to_string());
    }
    Ok(connection_point)
}

async fn process_connection_accepted(message: &ReceivedMessage) -> ProcessingResult {
    info!("🎉 Processing connection-accepted (ACCEPTOR receiving final confirmation from INVITER)");

    // Sender identity is cryptographically verified by the SDK's authcrypt-only
    // UnpackPolicy before the message reaches this handler, so the `from` field
    // here is trustworthy. The connection is still bound to the expected
    // counterparty by the their_temporary_did check in
    // finalize_oob_connection_as_acceptor.

    // Extract the inviter's secure DID from the message body
    let inviter_secure_did = message
        .message_body
        .get("channel_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if inviter_secure_did.is_none() {
        warn!("connection-accepted missing 'channel_did' field");
        return ProcessingResult::Failed {
            reason: "Missing channel_did in connection-accepted message".to_string(),
        };
    }

    let inviter_secure_did = inviter_secure_did.unwrap();

    // Get the inviter's temporary DID (the sender of this message)
    let inviter_temporary_did = match &message.from_did {
        Some(did) => did.clone(),
        None => {
            warn!("connection-accepted missing 'from' DID");
            return ProcessingResult::Failed {
                reason: "Missing from DID in connection-accepted message".to_string(),
            };
        }
    };

    if let Err(refused) = admit_pairing_envelope(message) {
        return refused;
    }

    info!("✓ Inviter temporary DID: {}", inviter_temporary_did);
    info!("✓ Inviter secure DID: {}", inviter_secure_did);

    // Return special result type to trigger gateway finalization
    ProcessingResult::OOBConnectionAccepted(Box::new(OobConnectionAccepted {
        inviter_temporary_did,
        inviter_secure_did,
        issuer_attestation: issuer_attestation_from_body(&message.message_body),
        nonce: message.didcomm_thid.clone(),
    }))
}

async fn process_connection_rejected(message: &ReceivedMessage) -> ProcessingResult {
    info!("❌ Processing connection-rejected (ACCEPTOR receiving rejection from INVITER)");

    // Extract the rejection reason from the message body
    let reason = message
        .message_body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown reason")
        .to_string();

    error!("Connection rejected by inviter: {}", reason);

    // Return special result type to trigger pending connection cleanup
    ProcessingResult::OOBConnectionRejected { reason }
}

// Message Pickup Protocol
async fn process_status_request(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message pickup status request from {:?}", message.from_did);

    // In a real implementation, check how many messages are queued
    let response = serde_json::json!({
        "type": "https://didcomm.org/messagepickup/3.0/status",
        "id": uuid::Uuid::new_v4().to_string(),
        "thid": message.didcomm_message_id,
        "body": {
            "message_count": 0,
            "longest_waited_seconds": 0,
            "newest_received_time": null,
            "oldest_received_time": null,
            "total_bytes": 0
        }
    });

    ProcessingResult::RequiresResponse {
        response_type: "message-pickup-status".to_string(),
        response_body: response,
    }
}

async fn process_status_response(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Received message pickup status response");

    // Extract status information
    let message_count = message
        .message_body
        .get("message_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let live_delivery = message
        .message_body
        .get("live_delivery")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    debug!("Message pickup status: {} messages queued, live_delivery: {}", message_count, live_delivery);

    if let Some(recipient_did) = message
        .message_body
        .get("recipient_did")
        .and_then(|v| v.as_str())
    {
        debug!("Status for recipient DID: {}", recipient_did);
    }

    // This is a response from the mediator - no further action needed
    ProcessingResult::ProcessedNoResponse
}

async fn process_delivery_request(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message pickup delivery request from {:?}", message.from_did);
    // Deliver any queued messages
    ProcessingResult::ProcessedNoResponse
}

async fn process_delivery_response(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Received message pickup delivery response");

    // Extract delivered messages from attachments
    if let Some(attachments) = message
        .message_body
        .get("attachments")
        .and_then(|v| v.as_array())
    {
        debug!("Received {} message(s) from mediator", attachments.len());
        // In a real implementation, unpack and process each attached message
    } else {
        debug!("No messages in delivery response");
    }

    ProcessingResult::ProcessedNoResponse
}

async fn process_messages_received(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing messages-received acknowledgment from {:?}", message.from_did);
    // Mark messages as delivered
    ProcessingResult::ProcessedNoResponse
}

async fn process_live_delivery_change(message: &ReceivedMessage) -> ProcessingResult {
    let live_delivery = message
        .message_body
        .get("live_delivery")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    debug!("Live delivery change request: {}", live_delivery);

    // Mediator will respond with a status message
    ProcessingResult::ProcessedNoResponse
}

// Presentation Protocol
async fn process_presentation_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received presentation request from {:?}", message.from_did);
    // Store for user/agent to respond
    ProcessingResult::ProcessedNoResponse
}

async fn process_presentation(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received presentation from {:?}", message.from_did);
    // Verify and process presentation
    ProcessingResult::ProcessedNoResponse
}

// Credential Issuance Protocol
async fn process_credential_offer(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential offer from {:?}", message.from_did);
    // Store for user/agent to accept
    ProcessingResult::ProcessedNoResponse
}

async fn process_credential_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential request from {:?}", message.from_did);
    // Process and issue credential
    ProcessingResult::ProcessedNoResponse
}

async fn process_credential_issuance(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential issuance from {:?}", message.from_did);
    // Store received credential
    ProcessingResult::ProcessedNoResponse
}

// Account Management Protocol
async fn process_account_management(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received account management message from {:?}", message.from_did);
    // no need to process it
    ProcessingResult::ProcessedNoResponse
}

// Gateway Ping Protocol (Affinidi custom)
async fn process_gateway_ping(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-ping from {:?}", message.from_did);

    // Respond with gateway-pong using MessageType enum
    let response_body = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "original_timestamp": message.message_body.get("timestamp"),
    });

    info!("📤 Sending gateway-pong response");

    ProcessingResult::RequiresResponse {
        response_type: MessageType::GatewayPong.to_string(),
        response_body,
    }
}

async fn process_gateway_pong(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-pong from {:?}", message.from_did);
    // Pong is handled by the live_stream_get waiting for it
    ProcessingResult::ProcessedNoResponse
}

// Gateway Issuer Protocol (Affinidi custom)

/// Message context key under which the listener records the Connection Point
/// DID a message was received on.
pub const CONNECTION_POINT_DID_CONTEXT_KEY: &str = "connection_point_did";

async fn process_gateway_issuer_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-issuer-request from {:?}", message.from_did);
    let Some(vc_issuer) = GLOBAL_VC_ISSUER.get() else {
        return ProcessingResult::Failed {
            reason: "VC issuer not initialised".to_string(),
        };
    };
    build_gateway_issuer_response(vc_issuer, message).await
}

/// Answer an issuer request with an attestation of our gateway DID over the
/// Connection Point DID the request arrived on, bound to the requester's nonce.
async fn build_gateway_issuer_response(
    vc_issuer: &crate::identity::VCIssuer,
    message: &ReceivedMessage,
) -> ProcessingResult {
    let Some(nonce) = message
        .message_body
        .get("nonce")
        .and_then(|v| v.as_str())
        .filter(|nonce| !nonce.is_empty())
    else {
        return ProcessingResult::Failed {
            reason: "Missing nonce in gateway-issuer-request".to_string(),
        };
    };
    let Some(requester_did) = message.from_did.as_deref() else {
        return ProcessingResult::Failed {
            reason: "Missing from DID in gateway-issuer-request".to_string(),
        };
    };
    let Some(our_connection_point_did) = receiving_connection_point_did(message) else {
        return ProcessingResult::Failed {
            reason: "Receiving connection point DID unknown for gateway-issuer-request".to_string(),
        };
    };

    match crate::gateways::issuer_attestation::build_issuer_attestation(
        vc_issuer,
        our_connection_point_did,
        requester_did,
        nonce,
    )
    .await
    {
        Ok(issuer_attestation) => {
            info!("📤 Sending gateway-issuer-response for connection point {}", our_connection_point_did);
            ProcessingResult::RequiresResponse {
                response_type: MessageType::GatewayIssuerResponse.to_string(),
                response_body: serde_json::json!({ "issuer_attestation": issuer_attestation }),
            }
        }
        Err(e) => ProcessingResult::Failed {
            reason: format!("Failed to build issuer attestation: {e}"),
        },
    }
}

/// The Connection Point DID a message was received on: the listener records it
/// in the message context, with the envelope recipient as fallback.
fn receiving_connection_point_did(message: &ReceivedMessage) -> Option<&str> {
    message
        .context
        .get(CONNECTION_POINT_DID_CONTEXT_KEY)
        .and_then(|v| v.as_str())
        .or_else(|| {
            message
                .to_dids
                .first()
                .map(String::as_str)
        })
}

async fn process_gateway_issuer_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-issuer-response from {:?}", message.from_did);
    if !crate::proxy::fabric_response_waiter::complete_forward_response_waiter(message) {
        warn!(
            "No pending issuer request for gateway-issuer-response thread {:?} from {:?}",
            message.didcomm_thid, message.from_did
        );
    }
    ProcessingResult::ProcessedNoResponse
}

// Gateway Channel Query Protocol (Affinidi custom)
async fn process_get_surfaces(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received get-channels query from {:?}", message.from_did);

    // Enumerating this appliance's channels is only for peers it has registered
    // and approved, the same bar the forward path applies.
    let Some(peer) = active_sender_peer(message).await else {
        warn!("Refusing get-channels from unregistered sender {:?}", message.from_did);
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::GetSurfacesResponse.to_string(),
            response_body: serde_json::json!({ "channels": [], "error": "Sender is not a registered gateway" }),
        };
    };

    // Load channels from the configured channel storage file
    let channels: Vec<serde_json::Value> = match load_channels_from_config(message).await {
        Ok(channel_list) => {
            info!("Found {} total channels", channel_list.len());

            // Get exposed channel filter from connection point
            let exposed_channel_ids = get_exposed_channels_from_context(message).await;

            // Convert active channels to SurfaceInfo format
            let filtered_channels: Vec<serde_json::Value> = channel_list
                .iter()
                .filter(|ch| {
                    // First check if channel is active
                    if ch.status != crate::config::agent_surface::SurfaceStatus::Active
                        || !fabric_peer_may_reach_surface(peer.tenant_id.as_deref(), ch.tenant_id.as_deref())
                    {
                        return false;
                    }

                    // If no exposed channels configured, return all active channels
                    if exposed_channel_ids.is_empty() {
                        return true;
                    }

                    // Otherwise, only return channels in the exposed list
                    if let Some(config_id) = ch.config_id() {
                        exposed_channel_ids.contains(&config_id.to_string())
                    } else {
                        false
                    }
                })
                .map(|ch| {
                    serde_json::json!({
                        "config_id": ch.config_id(),
                        "name": ch.name,
                        "description": ch.description,
                        "listen_address": ch.listen_address(),
                        "protocol": ch.channel_protocol().to_string(),
                    })
                })
                .collect();

            info!("Filtered to {} channels based on connection point configuration", filtered_channels.len());
            filtered_channels
        }
        Err(e) => {
            warn!("Failed to load channels: {} - returning empty channel list", e);
            Vec::new()
        }
    };

    let response_body = serde_json::json!({
        "channels": channels,
        "count": channels.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    info!("📤 Sending get-channels-response with {} channels", channels.len());

    ProcessingResult::RequiresResponse {
        response_type: MessageType::GetSurfacesResponse.to_string(),
        response_body,
    }
}

/// Base storage directory of this appliance, derived from the agent-surface
/// storage path the listener attaches to every received message.
fn storage_root_from_context(message: &ReceivedMessage) -> Option<std::path::PathBuf> {
    let path = std::path::Path::new(
        message
            .context
            .get("agent_surface_storage_path")
            .and_then(|v| v.as_str())?,
    );
    Some(
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| path.to_path_buf()),
    )
}

/// Get the list of exposed channel IDs from the gateway configuration
async fn get_exposed_channels_from_context(message: &ReceivedMessage) -> Vec<String> {
    info!("🔍 Getting exposed channels for remote gateway...");
    info!("   Message ID: {}", message.id);
    info!("   Connection Point ID: {}", message.connection_point_id);
    info!("   From DID: {:?}", message.from_did);

    let storage_path = match storage_root_from_context(message) {
        Some(base_path) => {
            info!("   Base storage path: {}", base_path.display());
            base_path
        }
        None => {
            warn!("Agent surface storage path not found in message context");
            return Vec::new();
        }
    };

    // First, load the connection point to get the gateway_id
    let cp_store = match crate::gateways::connection_points::FileSystemConnectionPointStore::new(
        storage_path.join("connection_points"),
    )
    .await
    {
        Ok(store) => store,
        Err(e) => {
            warn!("Failed to create connection point store: {}", e);
            return Vec::new();
        }
    };

    let cp_id = &message.connection_point_id;
    let gateway_id = match cp_store.get(cp_id).await {
        Ok(Some(cp)) => {
            info!("   ✓ Found connection point '{}' for gateway {}", cp.name, cp.gateway_id);
            cp.gateway_id
        }
        Ok(None) => {
            warn!("   ✗ Connection point {} not found", cp_id);
            return Vec::new();
        }
        Err(e) => {
            warn!("   ✗ Failed to load connection point: {}", e);
            return Vec::new();
        }
    };

    // Now load the gateway to get exposed_channels configuration
    let gateway_store = match crate::gateways::FileSystemGatewayStore::new(
        storage_path.join("gateways"),
        None, // proxy_did not needed for reading
    )
    .await
    {
        Ok(store) => store,
        Err(e) => {
            warn!("Failed to create gateway store: {}", e);
            return Vec::new();
        }
    };

    info!("   Looking up gateway: {}", gateway_id);
    match gateway_store
        .get(&gateway_id)
        .await
    {
        Ok(Some(gateway)) => {
            info!("   ✓ Found gateway '{}' ({})", gateway.name, gateway.id);
            info!("   Exposed channels config: {:?}", gateway.exposed_channels);
            if gateway
                .exposed_channels
                .is_empty()
            {
                info!("   → No exposed_channels filter - will return all channels");
            } else {
                info!("   → Will filter to {} specific channels", gateway.exposed_channels.len());
            }
            gateway.exposed_channels
        }
        Ok(None) => {
            warn!("   ✗ Gateway {} not found", gateway_id);
            Vec::new()
        }
        Err(e) => {
            warn!("   ✗ Failed to load gateway: {}", e);
            Vec::new()
        }
    }
}

/// Load channels from the configured storage location
async fn load_channels_from_config(
    message: &ReceivedMessage
) -> Result<Vec<crate::config::agent_surface::AgentSurface>, String> {
    // Prefer the in-process global store (cached) when initialised — avoids
    // re-reading every surface file from disk on each fabric request.
    if let Some(store) = GLOBAL_AGENT_SURFACE_STORE.get() {
        return store
            .list_all()
            .await
            .map_err(|e| format!("Failed to load surfaces from global store: {}", e));
    }

    // Get surface storage path from message context
    let storage_path = message
        .context
        .get("agent_surface_storage_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Agent surface storage path not found in message context".to_string())?;

    info!("Loading surfaces from: {}", storage_path);

    let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(storage_path))
        .await
        .map_err(|e| format!("Failed to create agent surface store: {}", e))?;

    let channels = agent_surface_store
        .list_all()
        .await
        .map_err(|e| format!("Failed to load surfaces: {}", e))?;

    Ok(channels)
}

/// Resolve a single channel by `channel_id` in O(1) when the global channel
/// store is initialised, otherwise fall back to the legacy load-and-scan path.
async fn lookup_channel(
    message: &ReceivedMessage,
    channel_id: &str,
) -> Result<Option<crate::config::agent_surface::AgentSurface>, String> {
    if let Some(store) = GLOBAL_AGENT_SURFACE_STORE.get() {
        return store
            .get(channel_id)
            .await
            .map_err(|e| format!("Failed to look up surface {}: {}", channel_id, e));
    }
    let channels = load_channels_from_config(message).await?;
    Ok(channels
        .into_iter()
        .find(|ch| ch.config_id() == Some(channel_id)))
}

async fn process_get_surfaces_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received get-channels-response from {:?}", message.from_did);
    // Response is handled by whoever initiated the query
    ProcessingResult::ProcessedNoResponse
}

/// Payment verification for fabric-forwarded requests (x402, MPP, or both).
/// Extracted from `process_forward_request` to reduce async state-machine size.
async fn verify_payment_fabric(
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    config_id: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    body_bytes: &[u8],
    path: &str,
    message_context: &std::collections::HashMap<String, Value>,
) -> Result<Option<crate::surface_context::PaymentContext>, ProcessingResult> {
    let surface_protocol = surface.channel_protocol();
    let x402_required = surface
        .x402_config()
        .is_some_and(|p| crate::x402::should_require_payment(p, &surface_protocol, body_bytes, None));
    let mpp_required = surface
        .mpp_config()
        .is_some_and(|p| crate::mpp::should_require_payment(p, &surface_protocol, body_bytes, None));

    if !x402_required && !mpp_required {
        return Ok(None);
    }

    // Extract x402 context if needed
    let (payment_signature, x402_effective_policy, x402_headers_extracted) = if x402_required {
        let payment_policy = surface.x402_config().unwrap();

        let effective_policy = std::borrow::Cow::Borrowed(payment_policy);

        // Extract x402 headers from message context
        let x402_headers = if let Some(headers_json) = message_context.get("x402_headers") {
            let payment_signature_header = headers_json
                .get("payment_signature")
                .and_then(|v| v.as_str())
                .unwrap_or("PAYMENT-SIGNATURE");
            let payment_required_header = headers_json
                .get("payment_required")
                .and_then(|v| v.as_str())
                .unwrap_or("PAYMENT-REQUIRED");
            let payment_response_header = headers_json
                .get("payment_response")
                .and_then(|v| v.as_str())
                .unwrap_or("PAYMENT-RESPONSE");

            crate::config::types::X402Headers {
                payment_signature: payment_signature_header.to_string(),
                payment_required: payment_required_header.to_string(),
                payment_response: payment_response_header.to_string(),
            }
        } else {
            crate::config::types::X402Headers::default()
        };

        // Extract payment signature from DIDComm headers
        let payment_signature = headers
            .and_then(|h| h.get(&x402_headers.payment_signature))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        (payment_signature, Some(effective_policy), Some(x402_headers))
    } else {
        (None, None, None)
    };

    // Extract MPP credential from DIDComm headers
    let mpp_credential = if mpp_required {
        headers
            .and_then(|h| {
                h.get("Authorization")
                    .or_else(|| h.get("authorization"))
            })
            .and_then(|v| v.as_str())
            .and_then(|auth_str| auth_str.strip_prefix("Payment "))
            .and_then(|b64| crate::mpp::challenge::base64url_decode_nopad(b64.trim()).ok())
            .and_then(|bytes| serde_json::from_slice::<crate::mpp::MppCredential>(&bytes).ok())
    } else {
        None
    };

    if x402_required && payment_signature.is_some() {
        channel_info!(
            config_id,
            "Checking x402 payment - has_signature: true, header_name: {}",
            x402_headers_extracted
                .as_ref()
                .map(|h| h.payment_signature.as_str())
                .unwrap_or("?")
        );

        match crate::x402::process_payment(
            payment_signature,
            &x402_effective_policy.unwrap(),
            channel_id,
            config_id,
            x402_headers_extracted
                .as_ref()
                .unwrap(),
            path,
            None,
            get_transaction_store(),
        )
        .await
        {
            Ok(response_header) => {
                channel_info!(config_id, "Payment verified successfully for fabric-forwarded request");
                Ok(Some(crate::surface_context::PaymentContext {
                    verified: true,
                    response_header,
                }))
            }
            Err(err_response) => {
                channel_warn!(config_id, "Payment verification failed for fabric-forwarded request");
                Err(axum_response_to_forward_result(err_response).await)
            }
        }
    } else if mpp_required && mpp_credential.is_some() {
        match crate::mpp::process_payment(
            mpp_credential,
            surface.mpp_config().unwrap(),
            channel_id,
            config_id,
            path,
            get_mpp_transaction_store(),
            &get_secrets_store(),
        )
        .await
        {
            Ok(_receipt_header) => {
                channel_info!(config_id, "MPP payment verified for fabric-forwarded request");
                Ok(None)
            }
            Err(err_response) => {
                channel_warn!(config_id, "MPP verification failed for fabric-forwarded request");
                Err(axum_response_to_forward_result(err_response).await)
            }
        }
    } else {
        channel_warn!(config_id, "Payment required for fabric-forwarded request");

        let err_response = if x402_required {
            let x402_resp = crate::x402::process_payment(
                None,
                &x402_effective_policy.unwrap(),
                channel_id,
                config_id,
                x402_headers_extracted
                    .as_ref()
                    .unwrap(),
                path,
                None,
                get_transaction_store(),
            )
            .await
            .unwrap_err();
            if mpp_required {
                crate::mpp::fire_challenge_issued_events(config_id, channel_id, path, get_mpp_transaction_store());
                crate::mpp::errors::add_mpp_challenges_to_response_resolved(
                    x402_resp,
                    surface.mpp_config().unwrap(),
                    path,
                    &get_secrets_store(),
                )
                .await
            } else {
                x402_resp
            }
        } else {
            crate::mpp::process_payment(
                None,
                surface.mpp_config().unwrap(),
                channel_id,
                config_id,
                path,
                get_mpp_transaction_store(),
                &get_secrets_store(),
            )
            .await
            .unwrap_err()
        };

        Err(axum_response_to_forward_result(err_response).await)
    }
}

async fn process_modern_payment_fabric(
    surface: &crate::config::agent_surface::AgentSurface,
    x402_headers: &crate::config::types::X402Headers,
    headers: &axum::http::HeaderMap,
    body: bytes::Bytes,
    path: &str,
    evidence: Option<&crate::mcp::continuations::protected::ContinuationPayment>,
) -> Result<crate::proxy::handler::surface_payment::SurfacePayment, ProcessingResult> {
    use crate::proxy::handler::surface_payment::{LocalPaymentServices, process_local};

    match process_local(
        surface,
        LocalPaymentServices {
            x402_headers,
            listener_manager: None,
            transaction_store: get_transaction_store(),
            mpp_transaction_store: get_mpp_transaction_store(),
            secrets_store: &get_secrets_store(),
        },
        headers,
        body,
        None,
        path,
        evidence,
    )
    .await
    {
        Ok(payment) => Ok(payment),
        Err(response) => Err(axum_response_to_forward_result(response).await),
    }
}

/// Extract caller identity from inbound fabric request (VP, extensions, MCP _meta).
/// Extracted from `process_forward_request` to reduce async state-machine size.
/// The verified gateway DID of the peer that sent a fabric envelope from
/// `from_did`, running the issuer exchange when its Remote gateway record does
/// not hold it yet. Fails closed: an unknown Connection Point, or a peer that
/// cannot prove its issuer DID, is rejected.
/// The issuers a forward-request's sender may present identities from: the
/// paired gateway's attested issuer DID (fetched on demand when missing) plus
/// the issuer DIDs an operator trusts for that connection. A peer with
/// neither is rejected; a peer with operator-trusted issuers is admitted even
/// when the attestation exchange fails, so a legacy peer can be trusted by hand.
async fn resolve_peer_issuers(from_did: Option<&str>) -> Result<crate::gateways::types::PeerIssuers, String> {
    let from_did = from_did.ok_or_else(|| "forward-request has no sender DID".to_string())?;
    let manager = GLOBAL_LISTENER_MANAGER
        .get()
        .ok_or_else(|| "listener manager not available".to_string())?;
    let gateway = manager
        .find_gateway_by_did(from_did)
        .await
        .ok_or_else(|| format!("unknown peer gateway {from_did}"))?;
    let trusted = gateway.trusted_issuer_dids;
    let attested = match gateway.issuer_did {
        Some(issuer_did) => Some(issuer_did),
        None => match manager
            .ensure_peer_issuer_did(&gateway.id)
            .await
        {
            Ok(issuer_did) => Some(issuer_did),
            Err(e) if !trusted.is_empty() => {
                warn!(
                    gateway_id = gateway.id,
                    "peer issuer DID not established ({e}); accepting only operator-trusted issuers for this connection"
                );
                None
            }
            Err(e) => return Err(format!("peer issuer DID not established for gateway {}: {e}", gateway.id)),
        },
    };
    Ok(crate::gateways::types::PeerIssuers { attested, trusted })
}

fn forbidden_forward_response(message: &str) -> Value {
    refused_forward_response(403, "Forbidden", message)
}

fn refused_forward_response(
    status: u16,
    error: &str,
    message: &str,
) -> Value {
    let body = serde_json::json!({ "error": error, "message": message });
    serde_json::json!({
        "status": status,
        "body": serde_json::to_string(&body).unwrap_or_else(|_| body.to_string()),
        "headers": { "content-type": "application/json" },
        "error": message,
    })
}

/// Refuses a `forward-request` envelope that is expired, malformed in time or
/// already processed. Runs after the sender is authorized so only registered
/// peers can populate the seen set.
///
/// A duplicate is dropped without a reply. The mediator re-delivers a message
/// that was not deleted after dispatch (a reconnect mid-dispatch, a first run
/// still in progress), and a `forward-response` threaded to the original id
/// would reach the sender before, or instead of, the real one; the sender's
/// waiter keeps only the first reply.
#[allow(clippy::result_large_err)] // ProcessingResult carries a streaming Response
fn admit_forward_request_envelope(message: &ReceivedMessage) -> Result<(), ProcessingResult> {
    super::envelope_replay::admit_forward_request(message)
        .map_err(|rejection| forward_request_envelope_refusal(message, rejection))
}

/// A duplicate gets no reply, since a reply threaded to the original id would
/// displace the real response at the sender.
fn forward_request_envelope_refusal(
    message: &ReceivedMessage,
    rejection: super::envelope_replay::EnvelopeRejection,
) -> ProcessingResult {
    use super::envelope_replay::EnvelopeRejection;
    warn!(
        from = ?message.from_did,
        message_id = %message.didcomm_message_id,
        "Refusing fabric forward-request envelope: {rejection}"
    );
    let (status, error) = match rejection {
        EnvelopeRejection::Duplicate { .. } => return ProcessingResult::ProcessedNoResponse,
        EnvelopeRejection::Expired { .. } => (504, "Gateway Timeout"),
        _ => (403, "Forbidden"),
    };
    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: refused_forward_response(status, error, &format!("Envelope refused: {rejection}")),
    }
}

/// How a `forward-request` that finds every dispatch slot busy is answered.
/// It runs the dispatched task's sender and envelope checks, in the same order
/// and with the same outcomes, but without remembering the envelope, so it
/// never makes the task's own admission see a replay. `None` means the request
/// would be admitted, so the listener sheds it with a retryable 503; a refused
/// request is answered, or dropped, exactly as the task would.
///
/// It runs on the listener's reader, so it looks the sender up in the
/// listener's long-lived `gateways` store, an in-memory read, rather than
/// loading the directory from disk. That copy can trail a write made through
/// another store instance; it only chooses how a shed request is refused and
/// never admits one, since the dispatched task repeats the authoritative
/// lookup.
pub(crate) async fn forward_request_refusal_before_dispatch(
    message: &ReceivedMessage,
    gateways: Option<&crate::gateways::FileSystemGatewayStore>,
) -> Option<ProcessingResult> {
    let channel_id = message
        .message_body
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if channel_id.is_empty() {
        return Some(ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({ "error": "Missing channel_id in forward-request", "status": 400 }),
        });
    }
    if let Err(refused) = authorize_fabric_sender(message, channel_id, gateways).await {
        return Some(refused);
    }
    super::envelope_replay::check_forward_request(message)
        .err()
        .map(|rejection| forward_request_envelope_refusal(message, rejection))
}

/// Refuses a pairing envelope that is expired or already processed.
/// `connection-setup` runs it after proving control of its `channel_did` on a
/// live invitation; `connection-accepted` runs it once its sender and
/// `channel_did` are present, before its issuer attestation is verified.
#[allow(clippy::result_large_err)] // ProcessingResult carries a streaming Response
fn admit_pairing_envelope(message: &ReceivedMessage) -> Result<(), ProcessingResult> {
    super::envelope_replay::admit_pairing_message(message).map_err(|rejection| {
        warn!(
            from = ?message.from_did,
            message_id = %message.didcomm_message_id,
            message_type = %message.message_type,
            "Refusing pairing envelope: {rejection}"
        );
        ProcessingResult::Failed {
            reason: format!("Envelope refused: {rejection}"),
        }
    })
}

/// An identity presentation is attributed to the sending gateway only when its
/// issuer is one of that connection's issuers: the peer's attested issuer DID
/// or an issuer DID the operator trusts for the connection.
fn issuer_matches_peer(
    issuer_did: Option<&str>,
    peer_issuers: &crate::gateways::types::PeerIssuers,
) -> bool {
    issuer_did.is_some_and(|issuer| peer_issuers.accepts(issuer))
}

fn require_peer_issuer(
    verified: crate::identity::VerifiedAgentPresentation,
    peer_issuers: &crate::gateways::types::PeerIssuers,
) -> anyhow::Result<crate::identity::VerifiedAgentPresentation> {
    if issuer_matches_peer(verified.issuer_did.as_deref(), peer_issuers) {
        Ok(verified)
    } else {
        anyhow::bail!(
            "identity presentation issuer {:?} is not an issuer of the sending connection {peer_issuers}",
            verified.issuer_did
        )
    }
}

async fn extract_caller_identity_inbound(
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    config_id: &str,
    body_bytes: &[u8],
    identity_ext_rules: Option<&crate::config::types::ExtensionRules>,
    mcp_binding: Option<&crate::surface_context::IdentityBindingContext>,
    peer_issuers: &crate::gateways::types::PeerIssuers,
    vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
) -> (Option<String>, Option<String>, crate::surface_context::IdentityVerification) {
    use crate::surface_context::IdentityVerification;
    if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
        return mcp_binding
            .map(|binding| {
                let verification = if binding.verified {
                    IdentityVerification::Vp
                } else {
                    IdentityVerification::Unverified
                };
                (Some(binding.agent_did.clone()), Some(binding.gateway_did.clone()), verification)
            })
            .unwrap_or((None, None, IdentityVerification::Unverified));
    }
    let mut caller_identity: Option<String> = None;
    // `Vp` only when the DID came from a presentation that verified and whose
    // issuer is a connection issuer; every other source below is unverified.
    let mut caller_identity_verification = IdentityVerification::Unverified;
    // Once a presented VP has failed, no weaker identity source is consulted.
    let mut presentation_rejected = false;
    let mut caller_issuer_did: Option<String> = None;

    channel_info!(
        config_id,
        "Checking for identity extraction - has_identity_ext_rules: {}, body_empty: {}",
        identity_ext_rules.is_some(),
        body_bytes.is_empty()
    );

    if body_bytes.is_empty() {
        channel_info!(config_id, "GW2: Body is empty, cannot extract identity");
        return (None, None, IdentityVerification::Unverified);
    }

    let body_json = match serde_json::from_slice::<serde_json::Value>(body_bytes) {
        Ok(j) => j,
        Err(_) => {
            channel_info!(config_id, "GW2: Failed to parse body as JSON");
            return (None, None, IdentityVerification::Unverified);
        }
    };
    info!("GW2: Successfully parsed body as JSON, checking for extensions");

    let message = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .or_else(|| body_json.get("message"));

    if let Some(msg) = message {
        if let Some(extensions) = msg
            .get("extensions")
            .and_then(|e| e.as_array())
        {
            channel_info!(config_id, "GW2: Found {} extension URIs in request", extensions.len());

            // Check if GW1 sent a VP credential (preferred method)
            let has_credential_ext = extensions
                .iter()
                .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION));

            if has_credential_ext {
                channel_debug!(config_id, "GW2: Found identity credential extension (VP) from GW1");

                if let Some(metadata) = msg.get("metadata")
                    && let Some(credential_ext) =
                        metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
                {
                    channel_debug!(config_id, "GW2: Found credential extension in metadata");

                    if let Some(vp_jwt) = credential_ext
                        .get("verifiablePresentation")
                        .and_then(|v| v.as_str())
                        && let Some(vc_issuer) = vc_issuer
                    {
                        match vc_issuer
                            .verify_agent_presentation_full(vp_jwt)
                            .await
                            .and_then(|verified| require_peer_issuer(verified, peer_issuers))
                        {
                            Ok(verified) => {
                                let verified_did = verified.holder_did.clone();
                                let identity_fields = verified
                                    .identity_fields
                                    .clone();
                                caller_issuer_did = verified.issuer_did.clone();
                                caller_identity = Some(verified_did.clone());
                                caller_identity_verification = IdentityVerification::Vp;
                                channel_info!(config_id, "✓ GW2: VP verification succeeded for DID: {}", verified_did);
                                let identity_store = vc_issuer.get_identity_store();
                                if let Err(e) = identity_store
                                    .store_external_did(
                                        &verified_did,
                                        identity_fields,
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        true,
                                    )
                                    .await
                                {
                                    channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                                }
                            }
                            Err(e) => {
                                presentation_rejected = true;
                                channel_warn!(
                                    config_id,
                                    "✗ GW2: VP verification FAILED: {:#} - request carries no caller identity",
                                    e
                                );
                            }
                        }
                    }

                    if caller_identity.is_none()
                        && let Some(did) = credential_ext
                            .get("did")
                            .and_then(|d| d.as_str())
                    {
                        channel_warn!(
                            config_id,
                            "⚠ GW2: Ignoring DID claim from credential extension without a verified VP: {}",
                            did
                        );
                        if let Some(vc_issuer) = vc_issuer {
                            let identity_store = vc_issuer.get_identity_store();
                            if let Err(e) = identity_store
                                .store_external_did(
                                    did,
                                    std::collections::HashMap::new(),
                                    surface
                                        .config_id()
                                        .map(str::to_string),
                                    false,
                                )
                                .await
                            {
                                channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                            }
                        }
                    }
                }
            }

            // The direct-fabric (no transit point) send path injects the caller's
            // identity binding VP under agent-identity-binding/v1 rather than the
            // credential extension. Verify it the same way so the caller DID crosses
            // the fabric hop instead of being re-minted under this gateway's domain.
            if caller_identity.is_none() && !presentation_rejected {
                let has_binding_ext = extensions
                    .iter()
                    .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION));

                if has_binding_ext {
                    channel_info!(config_id, "GW2: Found identity binding VP extension from GW1");

                    if let Some(metadata) = msg.get("metadata")
                        && let Some(binding_ext) =
                            metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION)
                        && let Some(vp_jwt) = binding_ext
                            .get("verifiablePresentation")
                            .and_then(|v| v.as_str())
                        && let Some(vc_issuer) = vc_issuer
                    {
                        match vc_issuer
                            .verify_agent_presentation_full(vp_jwt)
                            .await
                            .and_then(|verified| require_peer_issuer(verified, peer_issuers))
                        {
                            Ok(verified) => {
                                let verified_did = verified.holder_did.clone();
                                let identity_fields = verified
                                    .identity_fields
                                    .clone();
                                caller_issuer_did = verified.issuer_did.clone();
                                caller_identity = Some(verified_did.clone());
                                caller_identity_verification = IdentityVerification::Vp;
                                channel_info!(
                                    config_id,
                                    "✓ GW2: Binding VP verification succeeded for DID: {}",
                                    verified_did
                                );
                                let identity_store = vc_issuer.get_identity_store();
                                if let Err(e) = identity_store
                                    .store_external_did(
                                        &verified_did,
                                        identity_fields,
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        true,
                                    )
                                    .await
                                {
                                    channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                                }
                            }
                            Err(e) => {
                                presentation_rejected = true;
                                channel_warn!(
                                    config_id,
                                    "✗ GW2: Binding VP verification FAILED: {:#} - request carries no caller identity",
                                    e
                                );
                            }
                        }
                    }
                }
            }

            // Without a presentation, fall back to the raw identity extension. A
            // presentation that failed verification blocks this: the request then
            // carries no caller identity at all.
            if caller_identity.is_none() && !presentation_rejected {
                let has_identity_ext = extensions
                    .iter()
                    .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION));

                if has_identity_ext {
                    channel_info!(config_id, "GW2: No VP found, checking raw identity extension");

                    if let Some(metadata) = msg.get("metadata") {
                        if let Some(identity_ext) = metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION) {
                            channel_info!(
                                config_id,
                                "GW2: Found identity extension in metadata: {}",
                                serde_json::to_string_pretty(identity_ext).unwrap_or_default()
                            );

                            if let Some(did) = identity_ext
                                .get("did")
                                .and_then(|d| d.as_str())
                            {
                                channel_warn!(
                                    config_id,
                                    "GW2: Ignoring caller-asserted did in raw identity extension: {}",
                                    did
                                );
                            }
                            let identity_selector =
                                if let (Some(ext_rules), Some(vc_issuer)) = (identity_ext_rules, vc_issuer) {
                                    if let Some(json_schema) = &ext_rules.json_schema {
                                        match crate::identity::IdentitySelector::new(json_schema, vc_issuer.clone()) {
                                            Ok(selector) if selector.has_identity_fields() => Some(Arc::new(selector)),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                            if let Some(ref selector) = identity_selector {
                                channel_info!(config_id, "GW2: Computing caller identity using IdentitySelector");
                                match selector
                                    .compute_identity(
                                        identity_ext,
                                        channel_id,
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        surface.issuer_id.clone(),
                                        crate::identity::filesystem::IdentityOrigin::ExternalCaller,
                                    )
                                    .await
                                {
                                    Ok(identity_result) => {
                                        caller_identity = Some(identity_result.did.clone());
                                        crate::observability::record_caller_did_on_current_span(&identity_result.did);
                                        channel_info!(
                                            config_id,
                                            "GW2: Caller identity computed: {} (is_new: {})",
                                            identity_result.did,
                                            identity_result.is_new
                                        );
                                        if identity_result.is_new
                                            && let Some(notif_store) = GLOBAL_NOTIFICATION_STORE.get()
                                        {
                                            let did_clone = identity_result.did.clone();
                                            let channel_id_clone = channel_id.to_string();
                                            let notif = (*notif_store).clone();
                                            crate::observability::spawn_traced_task(
                                                "integration.identity_appeared",
                                                async move {
                                                    crate::integrations::async_triggers::trigger_identity_appeared(
                                                        Some(notif.clone()),
                                                        &did_clone,
                                                        &channel_id_clone,
                                                    )
                                                    .await;
                                                },
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        channel_warn!(config_id, "GW2: Failed to compute caller identity: {}", e);
                                    }
                                }
                            }

                            if caller_identity.is_none() {
                                channel_info!(config_id, "GW2: No IdentitySelector available, using SHA256 fallback");
                                let identity_value = identity_ext
                                    .get("agentIdentity")
                                    .or_else(|| identity_ext.get("agentId"))
                                    .or_else(|| identity_ext.get("id"))
                                    .or_else(|| identity_ext.get("agent_id"));

                                let hash_input = if let Some(id_val) = identity_value {
                                    serde_json::to_string(id_val).unwrap_or_default()
                                } else {
                                    let mut without_did = identity_ext.clone();
                                    if let Some(fields) = without_did.as_object_mut() {
                                        fields.remove("did");
                                    }
                                    serde_json::to_string(&without_did).unwrap_or_default()
                                };

                                use sha2::{Digest, Sha256};
                                let mut hasher = Sha256::new();
                                hasher.update(hash_input.as_bytes());
                                let hash = hasher.finalize();
                                let hash_str = format!("sha256:{:x}", hash);
                                caller_identity = Some(hash_str.clone());
                                channel_info!(config_id, "GW2: Caller identity computed from SHA256: {}", hash_str);
                            }
                        } else {
                            channel_info!(config_id, "GW2: Raw identity extension declared but not found in metadata");
                        }
                    } else {
                        channel_info!(config_id, "GW2: No metadata found for raw identity extension");
                    }
                } else {
                    channel_info!(config_id, "GW2: No raw identity extension declared (VP or raw)");
                }
            }
        } else {
            channel_info!(config_id, "GW2: No extensions array found in message");
        }
    } else {
        channel_info!(config_id, "GW2: No message object found in body");

        if let Ok(Some(metadata)) = crate::mcp::meta::read_metadata(&body_json) {
            channel_info!(config_id, "GW2: Found _meta field, checking for identity credential (MCP format)");

            if let Some(credential_ext) = metadata.get(crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY) {
                channel_info!(config_id, "GW2: Found identity credential extension in _meta (MCP format)");

                if let Some(vp_jwt) = credential_ext
                    .get("verifiablePresentation")
                    .and_then(|v| v.as_str())
                    && let Some(vc_issuer) = vc_issuer
                {
                    match vc_issuer
                        .verify_agent_presentation_full(vp_jwt)
                        .await
                        .and_then(|verified| require_peer_issuer(verified, peer_issuers))
                    {
                        Ok(verified) => {
                            let verified_did = verified.holder_did.clone();
                            let identity_fields = verified
                                .identity_fields
                                .clone();
                            caller_issuer_did = verified.issuer_did.clone();
                            caller_identity = Some(verified_did.clone());
                            caller_identity_verification = IdentityVerification::Vp;
                            channel_info!(
                                config_id,
                                "✓ GW2: VP verification succeeded for DID (from _meta): {}",
                                verified_did
                            );
                            let identity_store = vc_issuer.get_identity_store();
                            if let Err(e) = identity_store
                                .store_external_did(
                                    &verified_did,
                                    identity_fields,
                                    surface
                                        .config_id()
                                        .map(str::to_string),
                                    true,
                                )
                                .await
                            {
                                channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                            }
                        }
                        Err(e) => {
                            presentation_rejected = true;
                            channel_warn!(
                                config_id,
                                "✗ GW2: VP verification FAILED (from _meta): {:#} - request carries no caller identity",
                                e
                            );
                            if let Some(did) = credential_ext
                                .get("did")
                                .and_then(|d| d.as_str())
                            {
                                let identity_store = vc_issuer.get_identity_store();
                                if let Err(store_err) = identity_store
                                    .store_external_did(
                                        did,
                                        std::collections::HashMap::new(),
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        false,
                                    )
                                    .await
                                {
                                    channel_warn!(config_id, "GW2: Failed to store unverified DID: {}", store_err);
                                }
                            }
                        }
                    }
                }
            } else {
                channel_info!(config_id, "GW2: No identity credential found in _meta field");
            }
        }
    }

    channel_info!(
        config_id,
        "Request inspection - caller_identity: {:?} ({:?}, presentation_rejected: {})",
        caller_identity,
        caller_identity_verification,
        presentation_rejected
    );
    (caller_identity, caller_issuer_did, caller_identity_verification)
}

async fn evaluate_gateway_policy_for_fabric(
    global_policy: Option<&crate::policies::GlobalPolicyManager>,
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    method: &str,
    path: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    from_did: Option<String>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> Result<(), ProcessingResult> {
    // Appliance-wide (global) gateway policy — enforced deny-overrides ahead of
    // the per-gateway policy, evaluated on every fabric request (public
    // discovery reads included, as on the direct path) regardless of the
    // gateway's own OPA configuration. Gateway OPA never sees caller-leg
    // trust check results (those run post-identity and feed only surface OPA).
    if let Some(global_pm) = global_policy
        && global_pm.has_global(crate::policies::global_policy::PLANE_GATEWAY)
    {
        let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);
        let mut g_input = crate::surface_context::PolicyInput::new(
            method,
            path,
            http_headers,
            "inbound",
            from_did.clone(),
            None,
            surface
                .config_id()
                .map(str::to_string),
            &surface.name,
        );
        g_input.source_auth = source_auth_context.cloned();
        g_input.mcp = mcp_context.cloned();
        let g_input_value = serde_json::to_value(&g_input).unwrap_or_default();
        let gd = global_pm.evaluate_global(crate::policies::global_policy::PLANE_GATEWAY, &g_input_value);
        let self_gateway_id = GLOBAL_GATEWAY_POLICY_MANAGER
            .get()
            .and_then(|pm| pm.get_self_gateway_id());
        let global_policy_name = gd.policy_name.as_deref();
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::Gateway,
            flow: crate::observability::PolicyFlow::Fabric,
            allow: gd.allow,
            reason: gd.reason.as_deref(),
            policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
            policy_definition_id: gd.policy_id.as_deref(),
            policy_name: global_policy_name,
            surface_id: surface.config_id(),
            http_method: Some(method),
            path: Some(path),
            identity: authenticated_identity,
            gateway_did: self_gateway_id.as_deref(),
            policy_version: gd.version,
            policy_content_hash: gd.content_hash.as_deref(),
            ..Default::default()
        });
        if !gd.allow {
            info!(channel = config_id, "[GW-POLICY] GW2 fabric path: blocked by appliance-wide gateway policy");
            return Err(ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: serde_json::json!({
                    "status": 403,
                    "body": r#"{"error":"Forbidden","message":"Request blocked by appliance-wide policy"}"#,
                    "error": "Request blocked by appliance-wide policy",
                }),
            });
        }
    }

    // The per-gateway policy does not apply to public discovery reads.
    if crate::proxy::paths::is_public_request(method, path) {
        return Ok(());
    }

    if let Some(gw_pm) = GLOBAL_GATEWAY_POLICY_MANAGER.get()
        && let Some(self_gateway_id) = gw_pm.get_self_gateway_id()
        && gw_pm.is_enforced(&self_gateway_id)
    {
        info!(
            channel = config_id,
            path = path,
            self_gateway_id = %self_gateway_id,
            "[GW-POLICY] GW2 fabric path: evaluating gateway-level OPA policy"
        );

        let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);
        let mut gw_input = crate::surface_context::PolicyInput::new(
            method,
            path,
            http_headers,
            "inbound",
            from_did,
            None,
            surface
                .config_id()
                .map(str::to_string),
            &surface.name,
        );
        gw_input.source_auth = source_auth_context.cloned();
        gw_input.mcp = mcp_context.cloned();
        // Gateway OPA never sees caller-leg trust check results — the
        // caller-leg Trust Check stage runs post-identity in
        // `enrich_and_evaluate_surface_policies` and is observed only by
        // surface OPA.
        let gw_input_value = serde_json::to_value(&gw_input).unwrap_or_default();
        let (gw_policy_def_id, gw_policy_version, gw_policy_hash) = match gw_pm.policy_evidence(&self_gateway_id) {
            Some((id, v, h)) => (id, v, Some(h)),
            None => (None, None, None),
        };
        let gw_policy_name = gw_pm
            .resolve_policy_name_or_default(gw_policy_def_id.as_deref())
            .await;

        match gw_pm.evaluate_policy_decision(&self_gateway_id, gw_input_value) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Gateway,
                    flow: crate::observability::PolicyFlow::Fabric,
                    allow: true,
                    policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
                    policy_definition_id: gw_policy_def_id.as_deref(),
                    policy_name: Some(gw_policy_name.as_str()),
                    surface_id: surface.config_id(),
                    http_method: Some(method),
                    path: Some(path),
                    identity: authenticated_identity,
                    gateway_did: Some(&self_gateway_id),
                    policy_version: gw_policy_version,
                    policy_content_hash: gw_policy_hash.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Gateway,
                    flow: crate::observability::PolicyFlow::Fabric,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
                    policy_definition_id: gw_policy_def_id.as_deref(),
                    policy_name: Some(gw_policy_name.as_str()),
                    surface_id: surface.config_id(),
                    http_method: Some(method),
                    path: Some(path),
                    identity: authenticated_identity,
                    gateway_did: Some(&self_gateway_id),
                    policy_version: gw_policy_version,
                    policy_content_hash: gw_policy_hash.as_deref(),
                    ..Default::default()
                });
                return Err(ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 403,
                        "body": r#"{"error":"Forbidden","message":"Request blocked by gateway policy"}"#,
                        "error": "Request blocked by gateway policy",
                    }),
                });
            }
            Err(e) => {
                info!(channel = config_id, "[GW-POLICY] GW2: gateway-level policy evaluation error (denying): {}", e);
                return Err(ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 403,
                        "body": r#"{"error":"Forbidden","message":"Request blocked by gateway policy"}"#,
                        "error": "Request blocked by gateway policy",
                    }),
                });
            }
        }
    } else {
        info!(
            channel = config_id,
            path = path,
            has_manager = GLOBAL_GATEWAY_POLICY_MANAGER
                .get()
                .is_some(),
            "[GW-POLICY] GW2 fabric path: no gateway-level OPA policy configured, allowing"
        );
    }

    Ok(())
}

/// Injects custom metadata and trust registry extensions into the request body,
/// then evaluates surface-level OPA policies. Returns the (potentially modified)
/// body bytes on allow, or a deny `ProcessingResult`.
async fn enrich_and_evaluate_surface_policies(
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    config_id: &str,
    method: &str,
    path: &str,
    body_bytes: bytes::Bytes,
    headers: Option<&serde_json::Map<String, Value>>,
    from_did: Option<String>,
    payment_context: Option<crate::surface_context::PaymentContext>,
    caller_identity: Option<&String>,
    caller_identity_verification: crate::surface_context::IdentityVerification,
    caller_issuer_did: Option<&String>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    variant_alias: Option<&str>,
    request_id: Option<&str>,
    mcp_binding: Option<&crate::surface_context::IdentityBindingContext>,
    peer_issuers: &crate::gateways::types::PeerIssuers,
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> Result<bytes::Bytes, ProcessingResult> {
    let mut body_bytes = body_bytes;
    // Caller-leg Trust Check stage runs further down (post-identity);
    // gateway OPA on GW2 already ran in `evaluate_gateway_policy_for_fabric`
    // and never sees caller-leg results.
    let mut trust_check_results: Option<crate::trust_registry_verification::TrustCheckResultsContext> = None;

    // Snapshot the caller's ORIGINAL body bytes before any GW2-side mutation
    // (custom metadata / trust-registry injection below). The caller-leg agent
    // context (esp. `provider_did`) is extracted from the caller's
    // trust-registry extension in `metadata`, which a later GW2 injection could
    // overwrite — so the caller Trust Check seam parses these pre-injection
    // bytes. `Bytes::clone` is a cheap refcount bump. Mirrors the direct-inbound
    // path, which builds the caller agent context from the pre-injection body.
    let original_caller_body = body_bytes.clone();

    // Inject custom metadata if enabled on THIS gateway (GW2)
    if let Some(custom_metadata) = surface.custom_metadata()
        && custom_metadata.enabled
        && method.to_uppercase() == "POST"
        && !body_bytes.is_empty()
    {
        channel_info!(config_id, "Attempting to inject custom metadata for channel {}", channel_id);
        match crate::a2a::inject_custom_metadata_extension(
            &body_bytes,
            custom_metadata,
            channel_id,
            &None,
            crate::protocols::MetadataRuntimeContext {
                request_id,
                surface_id: Some(config_id),
            },
        )
        .await
        {
            Ok(modified_bytes) => {
                channel_info!(
                    config_id,
                    "GW2: Custom metadata extension injected (original: {} bytes, new: {} bytes)",
                    body_bytes.len(),
                    modified_bytes.len()
                );
                body_bytes = modified_bytes;
            }
            Err(e) => {
                channel_warn!(config_id, "GW2: Failed to inject custom metadata extension, using original body: {}", e);
            }
        }
    }

    let is_agent_card_request = crate::proxy::paths::is_public_request(method, path);

    // ── Trust Check stage (caller leg) ──────────────────────────────────────
    // GW2 fabric-receive counterpart of the direct-inbound caller seam in
    // `proxy::handler`. Runs after the caller's verified identity is in hand
    // (so `extension_identity` is populated) and before surface OPA reads
    // `trust_check_results`. Gateway OPA on GW2 already ran above and never
    // sees these results. Caller-only by construction. No-op when the
    // caller-leg list is empty.
    //
    // Skipped on discovery requests (`.well-known/agent-card.json` etc., per
    // `is_public_path`) — surface OPA bypasses the same requests. Discovery is
    // unauthenticated by design so the caller-leg check has no caller to
    // verify; running it would only emit a spurious `TEMPLATE_RESOLUTION_FAILED`
    // and burn a trust-registry round-trip whose result nobody reads.
    {
        let caller_elements = &surface
            .access_point
            .trust_check_list;
        if !caller_elements.is_empty()
            && !is_agent_card_request
            && let Some(manager) = get_trust_registry_listener_manager()
        {
            let client = crate::trust_registry_verification::TrqpListenerClient::new(manager);
            let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);
            let mut probe_input = crate::surface_context::PolicyInput::new(
                method,
                path,
                http_headers,
                "inbound",
                from_did.clone(),
                None,
                surface
                    .config_id()
                    .map(str::to_string),
                &surface.name,
            );
            if let Some(ref mut ch) = probe_input.channel {
                ch.variant_alias = variant_alias.map(|s| s.to_string());
            }
            probe_input.extension_identity = caller_identity.map(|id| {
                let did = if id.starts_with("did:") {
                    Some(id.to_string())
                } else {
                    None
                };
                crate::surface_context::ExtensionIdentityContext {
                    verification: caller_identity_verification,
                    did,
                    identity_hash: Some(id.to_string()),
                }
            });
            probe_input.source_auth = source_auth_context.cloned();
            probe_input.payment = payment_context.clone();
            // Populate `input.mcp` for MCP surfaces so caller-leg Trust Check
            // templates referencing `{{ input.mcp.* }}` resolve on the fabric
            // path exactly as they do on the direct-inbound path.
            if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
                probe_input.mcp = mcp_context
                    .cloned()
                    .or_else(|| crate::mcp::build_mcp_context(&original_caller_body));
            }
            // Populate `input.agent` for caller-leg templates (esp.
            // `{{ input.agent.provider_did }}`). `provider_did`/`authority_did`
            // are extracted synchronously from the caller's trust-registry
            // extension — `tr_manager = None` skips the recognition queries the
            // template doesn't need, so this stays cheap. Without this the
            // fabric-receive path left `input.agent` empty and every
            // provider_did template failed with TEMPLATE_RESOLUTION_FAILED,
            // while the direct-inbound path worked (it sets `probe_input.agent`).
            let caller_body_json: Option<serde_json::Value> = serde_json::from_slice(&original_caller_body).ok();
            probe_input.agent = Some(
                crate::policies::build_agent_context_for_protocol(
                    surface.channel_protocol(),
                    caller_body_json.as_ref(),
                    None,
                    None,
                    // Caller leg: skip the TR-extension / identity-credential
                    // cross-check so a payload carrying a TR extension without a
                    // matching identity credential still surfaces `provider_did`
                    // to the caller-leg Trust Check template (matches the
                    // direct-inbound caller seam in `proxy::handler`).
                    false,
                )
                .await,
            );

            if let Some(issuer) = caller_issuer_did
                && let Some(agent) = probe_input.agent.as_mut()
            {
                agent.identity_issuer_did = Some(issuer.clone());
            }
            probe_input.normalize_caller_did();
            trust_check_results = crate::trust_registry_verification::run_caller_trust_check(
                surface.surface_id.as_str(),
                caller_elements,
                &probe_input,
                &client,
            )
            .await;
        }
    }

    // ── Trust Check stage (target leg, A2A Proxy target) ───────────────────
    // Mirror the direct-inbound A2A Proxy seam: there is no upstream A2A
    // agent-card endpoint behind Direct Line, so synthesize the target card and
    // expose target-leg results to surface OPA before adapter dispatch.
    {
        let target_elements = &surface
            .target
            .trust_check_list;
        if !target_elements.is_empty()
            && surface
                .target
                .endpoint
                .starts_with("a2a-proxy://")
        {
            let card_json = crate::a2a_proxies::resolve_prepared_agent_card_for_endpoint(
                GLOBAL_A2A_PROXY_STORE
                    .get()
                    .cloned(),
                &surface.target.endpoint,
                surface,
                &surface.name,
                GLOBAL_VC_ISSUER.get(),
            )
            .await
            .ok()
            .flatten()
            .map(|prepared| prepared.card);

            if let (Some(card_json), Some(manager)) = (card_json, get_trust_registry_listener_manager()) {
                let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
                let agent_ctx = crate::policies::build_agent_context(
                    body_json.as_ref(),
                    Some(&card_json),
                    Some(manager.as_ref()),
                    true,
                )
                .await;
                let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);
                let mut probe_input = crate::surface_context::PolicyInput::new(
                    method,
                    path,
                    http_headers,
                    "inbound",
                    from_did.clone(),
                    None,
                    surface
                        .config_id()
                        .map(str::to_string),
                    &surface.name,
                );
                if let Some(ref mut ch) = probe_input.channel {
                    ch.variant_alias = variant_alias.map(|s| s.to_string());
                }
                probe_input.extension_identity = caller_identity.map(|id| {
                    let did = if id.starts_with("did:") {
                        Some(id.to_string())
                    } else {
                        None
                    };
                    crate::surface_context::ExtensionIdentityContext {
                        verification: caller_identity_verification,
                        did,
                        identity_hash: Some(id.to_string()),
                    }
                });
                probe_input.source_auth = source_auth_context.cloned();
                probe_input.payment = payment_context.clone();
                probe_input.agent = Some(agent_ctx);
                if matches!(
                    surface.channel_protocol(),
                    crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
                ) && let Some(body) = body_json.as_ref()
                {
                    let a2a_method = body
                        .get("method")
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string());
                    let message = body
                        .get("params")
                        .and_then(|p| p.get("message"))
                        .or_else(|| body.get("message"))
                        .cloned();
                    probe_input.a2a = Some(crate::surface_context::A2aContext::new(a2a_method, message));
                }
                probe_input.normalize_caller_did();
                let probe_value = serde_json::to_value(&probe_input).unwrap_or_default();
                if let Some(target_results) = crate::trust_registry_verification::run_trust_check_stage(
                    surface.surface_id.as_str(),
                    crate::trust_registry_verification::TrustCheckLeg::Target,
                    target_elements,
                    &probe_value,
                    &crate::trust_registry_verification::TrqpListenerClient::new(manager),
                )
                .await
                {
                    let mut merged = trust_check_results
                        .take()
                        .unwrap_or_default();
                    merged.target = target_results.target;
                    trust_check_results = Some(merged);
                }
            } else {
                let mut merged = trust_check_results
                    .take()
                    .unwrap_or_default();
                merged.target = target_elements
                    .iter()
                    .map(|elem| {
                        crate::trust_registry_verification::synthesize_failure(
                            elem,
                            crate::trust_registry_verification::AGENT_CARD_UNAVAILABLE,
                            "A2A proxy target agent card could not be synthesized".to_string(),
                        )
                    })
                    .collect();
                trust_check_results = Some(merged);
            }
        }
    }

    let has_compiled_policy = GLOBAL_POLICY_MANAGER
        .get()
        .is_some_and(|pm| pm.has_policy_for_variant(config_id, variant_alias));
    channel_info!(config_id, "GW2: opa_enabled={} has_compiled_policy={}", surface.opa_enabled(), has_compiled_policy);
    if surface.opa_enabled() && !is_agent_card_request && has_compiled_policy {
        channel_info!(config_id, "GW2: Starting surface-level OPA policy evaluation");

        let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
        channel_info!(config_id, "GW2: Body parsed for OPA: {}", body_json.is_some());
        let body_ref = body_json.as_ref();
        let tr_manager = get_trust_registry_listener_manager();
        channel_info!(config_id, "GW2: Trust registry listener manager available: {}", tr_manager.is_some());

        // Fetch agent card from the backend target endpoint,
        // respecting override_agent_card_location if configured. A2A Proxy
        // targets are internal adapter references, so synthesize the same card
        // used by discovery and target-leg Trust Check instead of trying to
        // fetch `a2a-proxy://...` over HTTP.
        let card_json: Option<serde_json::Value> = if surface
            .target_endpoint()
            .starts_with("a2a-proxy://")
        {
            crate::a2a_proxies::resolve_prepared_agent_card_for_endpoint(
                GLOBAL_A2A_PROXY_STORE
                    .get()
                    .cloned(),
                surface.target_endpoint(),
                surface,
                &surface.name,
                GLOBAL_VC_ISSUER.get(),
            )
            .await
            .ok()
            .flatten()
            .map(|prepared| prepared.card)
        } else {
            let card_url = if surface.override_agent_card_location()
                && surface
                    .agent_card_location_path()
                    .is_some()
            {
                let custom_path = surface
                    .agent_card_location_path()
                    .unwrap();
                let target_endpoint = surface.target_endpoint();
                let origin = if let Some(scheme_end) = target_endpoint.find("://") {
                    let after_scheme = &target_endpoint[scheme_end + 3..];
                    let authority_end = after_scheme
                        .find('/')
                        .unwrap_or(after_scheme.len());
                    &target_endpoint[..scheme_end + 3 + authority_end]
                } else {
                    target_endpoint
                };
                if custom_path.starts_with('/') {
                    format!("{}{}", origin, custom_path)
                } else {
                    format!("{}/{}", origin, custom_path)
                }
            } else {
                format!(
                    "{}/.well-known/agent.json",
                    surface
                        .target_endpoint()
                        .trim_end_matches('/')
                )
            };
            channel_info!(config_id, "GW2: Fetching agent card from: {}", card_url);
            let timeout = GLOBAL_FORWARD_TIMEOUT
                .get()
                .copied()
                .unwrap_or(std::time::Duration::from_secs(30));
            fetch_agent_card(&card_url, timeout, fabric_body_limits(surface), config_id).await
        };
        channel_info!(config_id, "GW2: Agent card obtained: {}", card_json.is_some());
        let agent_ctx =
            crate::policies::build_agent_context(body_ref, card_json.as_ref(), tr_manager.as_deref(), true).await;
        channel_info!(config_id, "GW2: Agent context built: trust_verification={:?}", agent_ctx.trust_verification);

        // Build HTTP headers map (filter sensitive headers)
        let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);

        // Build extension identity from caller_identity (DID extracted from VP/credential extension)
        let ext_identity = caller_identity.map(|id| {
            let did = if id.starts_with("did:") {
                Some(id.to_string())
            } else {
                None
            };
            crate::surface_context::ExtensionIdentityContext {
                verification: caller_identity_verification,
                did,
                identity_hash: Some(id.to_string()),
            }
        });

        // Extract + verify the inbound identity binding VP (from the upstream
        // gateway) so `input.identity_binding` is available to surface OPA on
        // the fabric-receive path, mirroring the direct-inbound path in
        // `proxy::handler`. Verification uses the global VC issuer via a
        // permissive selector (the schema is irrelevant to VP verification).
        // The trust anchor for the binding issuer is the sending connection's
        // issuers (its attested issuer DID plus the issuers an operator trusts
        // for that connection). That connection is resolved from `from_did`,
        // which comes from the authcrypt envelope, so a peer cannot claim
        // another peer's DID. With no anchor the binding is surfaced to OPA as
        // unverified rather than trusted.
        // The binding VP lives in the caller's original (pre-injection) body.
        let identity_binding = if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
            mcp_binding.cloned()
        } else {
            let binding_selector = GLOBAL_VC_ISSUER
                .get()
                .and_then(|vc| {
                    crate::identity::IdentitySelector::new(&serde_json::json!({}), vc.clone())
                        .ok()
                        .map(Arc::new)
                });
            let binding_result = crate::protocols::extensions::extract_identity_binding_vp(
                &original_caller_body,
                &surface.channel_protocol(),
                &binding_selector,
                config_id,
                Some(peer_issuers),
            )
            .await;
            crate::observability::identity_binding_audit::audit_extraction(&surface.surface_id, None, &binding_result);
            // When an inbound identity-binding VP verified, also record it in the
            // delegation audit log so the *received* VP (carrying any
            // workloadBinding) surfaces as a `vp_injected` event on the Audit
            // page — the fabric-receive mirror of the GW1 injection sites. The
            // `audit_extraction` call above only emits a low-level tracing log
            // with no VP attached, so without this GW2 audits its own response
            // VP but never the request VP it received.
            if let Ok(Some(ref binding)) = binding_result
                && crate::delegation_vault::audit::identity_binding_vp_audit_enabled()
                && let Some(vp_jwt) = crate::protocols::extensions::extract_identity_binding_vp_jwt(
                    &original_caller_body,
                    &surface.channel_protocol(),
                )
            {
                let mut evt = crate::delegation_vault::audit::audit_event(
                    crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                    None,
                    None,
                    None,
                    surface.config_id(),
                );
                evt.agent_identity_did = Some(binding.agent_did.clone());
                evt.channel_name = Some(surface.name.clone());
                evt.target_endpoint = Some(
                    surface
                        .target
                        .endpoint
                        .clone(),
                );
                evt.protocol = Some(format!("{:?}", surface.channel_protocol()).to_lowercase());
                evt.vp_fingerprint = Some(crate::delegation_vault::audit::vp_fingerprint(&vp_jwt));
                evt.vp_jwt = Some(vp_jwt);
                evt.via_fabric = true;
                // Same trace id as this request's policy decisions so the Audit
                // "This request" filter + correlation work.
                evt.trace_id = crate::observability::policy_audit::current_span_trace_id();
                evt.detail = Some("request_path_fabric_received".to_string());
                crate::delegation_vault::audit::audit(evt);
            }
            match binding_result {
                Ok(binding) => binding,
                Err(e) => {
                    channel_warn!(config_id, "GW2: Identity binding VP present but invalid: {}", e);
                    None
                }
            }
        };

        let mut policy_input = crate::surface_context::PolicyInput::new(
            method,
            path,
            http_headers,
            "inbound",
            from_did.clone(),
            None,
            surface
                .config_id()
                .map(str::to_string),
            &surface.name,
        );
        if let Some(ref mut ch) = policy_input.channel {
            ch.variant_alias = variant_alias.map(|s| s.to_string());
        }
        policy_input.extension_identity = ext_identity;
        policy_input.source_auth = source_auth_context.cloned();
        policy_input.mcp = mcp_context.cloned();
        policy_input.agent = Some(agent_ctx);
        policy_input.payment = payment_context.clone();
        policy_input.identity_binding = identity_binding;
        policy_input.trust_check_results = trust_check_results.clone();
        if matches!(
            surface.channel_protocol(),
            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
        ) && let Some(body) = body_ref
        {
            let a2a_method = body
                .get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string());
            let message = body
                .get("params")
                .and_then(|p| p.get("message"))
                .or_else(|| body.get("message"))
                .cloned();
            policy_input.a2a = Some(crate::surface_context::A2aContext::new(a2a_method, message));
        }
        policy_input.normalize_caller_did();
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
        channel_info!(
            config_id,
            "GW2: surface OPA input (identity_binding present={}): {}",
            input_value
                .get("identity_binding")
                .is_some(),
            serde_json::to_string(&input_value).unwrap_or_default()
        );

        // Appliance-wide (global) surface policy — enforced deny-overrides ahead
        // of the per-surface policy, evaluated on every fabric request
        // regardless of the surface's own OPA configuration.
        if let Some(global_pm) = GLOBAL_APPLIANCE_POLICY_MANAGER.get()
            && global_pm.has_global(crate::policies::global_policy::PLANE_AGENT_SURFACE)
        {
            let gd = global_pm.evaluate_global(crate::policies::global_policy::PLANE_AGENT_SURFACE, &input_value);
            let global_policy_name = gd.policy_name.as_deref();
            crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                scope: crate::observability::PolicyScope::Surface,
                flow: crate::observability::PolicyFlow::Fabric,
                allow: gd.allow,
                reason: gd.reason.as_deref(),
                policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                policy_definition_id: gd.policy_id.as_deref(),
                policy_name: global_policy_name,
                surface_id: Some(config_id),
                http_method: Some(method),
                path: Some(path),
                identity: authenticated_identity,
                actor_did: caller_identity.map(String::as_str),
                policy_version: gd.version,
                policy_content_hash: gd.content_hash.as_deref(),
                ..Default::default()
            });
            if !gd.allow {
                channel_info!(config_id, "GW2: blocked by appliance-wide surface policy");
                return Err(ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: build_surface_policy_denied_forward_body(&body_bytes, gd.reason.as_deref()),
                });
            }
        }

        if let Some(policy_manager) = GLOBAL_POLICY_MANAGER.get() {
            let channel_opa_def_id = surface.opa_policy_definition_id();
            let (channel_opa_name, channel_opa_version, channel_opa_hash) = policy_manager
                .resolve_policy_decision_evidence(channel_opa_def_id)
                .await;
            match policy_manager.evaluate_policy_decision_for_variant(config_id, variant_alias, input_value) {
                Ok(decision) if decision.allow => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Surface,
                        flow: crate::observability::PolicyFlow::Fabric,
                        allow: true,
                        policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                        policy_definition_id: channel_opa_def_id,
                        policy_name: Some(channel_opa_name.as_str()),
                        surface_id: Some(config_id),
                        http_method: Some(method),
                        path: Some(path),
                        identity: authenticated_identity,
                        actor_did: caller_identity.map(String::as_str),
                        policy_version: channel_opa_version,
                        policy_content_hash: channel_opa_hash.as_deref(),
                        ..Default::default()
                    });
                }
                Ok(decision) => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Surface,
                        flow: crate::observability::PolicyFlow::Fabric,
                        allow: false,
                        reason: decision.reason.as_deref(),
                        policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                        policy_definition_id: channel_opa_def_id,
                        policy_name: Some(channel_opa_name.as_str()),
                        surface_id: Some(config_id),
                        http_method: Some(method),
                        path: Some(path),
                        identity: authenticated_identity,
                        actor_did: caller_identity.map(String::as_str),
                        policy_version: channel_opa_version,
                        policy_content_hash: channel_opa_hash.as_deref(),
                        ..Default::default()
                    });
                    return Err(ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: build_surface_policy_denied_forward_body(
                            &body_bytes,
                            decision.reason.as_deref(),
                        ),
                    });
                }
                Err(e) => {
                    let reason = format!("Policy evaluation error: {e}");
                    channel_warn!(config_id, "GW2: Surface-level OPA policy evaluation error (denying request): {}", e);
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Surface,
                        flow: crate::observability::PolicyFlow::Fabric,
                        allow: false,
                        reason: Some(reason.as_str()),
                        policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                        policy_definition_id: channel_opa_def_id,
                        policy_name: Some(channel_opa_name.as_str()),
                        surface_id: Some(config_id),
                        http_method: Some(method),
                        path: Some(path),
                        identity: authenticated_identity,
                        actor_did: caller_identity.map(String::as_str),
                        policy_version: channel_opa_version,
                        policy_content_hash: channel_opa_hash.as_deref(),
                        ..Default::default()
                    });
                    return Err(ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: build_surface_policy_denied_forward_body(&body_bytes, Some(reason.as_str())),
                    });
                }
            }
        }
    }

    Ok(body_bytes)
}

/// Collect `(name, value)` header pairs into a JSON headers object, preserving
/// every value of a header repeated more than once (e.g. MPP's per-method
/// `WWW-Authenticate` challenge) as a JSON array instead of collapsing to the
/// last value — mirrors `proxy::fabric_forward::parse_fabric_response_headers`,
/// which already accepts either shape.
fn multi_value_headers_json<'a, I>(pairs: I) -> serde_json::Value
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (k, v) in pairs {
        map.entry(k.to_string())
            .or_default()
            .push(v.to_string());
    }
    serde_json::Value::Object(
        map.into_iter()
            .map(|(k, mut vals)| {
                let value = if vals.len() == 1 {
                    serde_json::Value::String(vals.remove(0))
                } else {
                    serde_json::Value::Array(
                        vals.into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    )
                };
                (k, value)
            })
            .collect(),
    )
}

/// Convert an axum [`Response`] into a [`ProcessingResult::RequiresResponse`]
/// with the standard `ForwardResponse` envelope (`status` / `headers` / `body`).
/// Buffer a legacy Target response for the ForwardResponse, bounded by size and
/// idle time like the direct path; the forward client's own timeout still caps
/// the whole exchange. An SSE response is reduced to its final JSON-RPC
/// response. A failed read answers `502`/`504` rather than passing the Target's
/// status on with an empty body.
async fn read_forward_target_body(
    response: reqwest::Response,
    is_sse_response: bool,
    request: &[u8],
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
    config_id: &str,
) -> Result<String, ProcessingResult> {
    let body_error = if is_sse_response {
        channel_info!(config_id, "GW2: Upstream responded with SSE — consuming stream for final response");
        match crate::mcp::sse_transport::consume_sse_response(response, request, limits).await {
            Ok(json_response) => return Ok(json_response),
            Err(crate::mcp::sse_transport::SseConsumeError::NoResponse) => {
                channel_warn!(config_id, "GW2: SSE response carried no JSON-RPC response");
                return Ok(String::new());
            }
            Err(crate::mcp::sse_transport::SseConsumeError::Body(error)) => error,
        }
    } else {
        match crate::proxy::upstream_body::read_bounded(response, limits).await {
            Ok(body) => return Ok(String::from_utf8_lossy(&body).into_owned()),
            Err(error) => error,
        }
    };
    channel_warn!(config_id, "GW2: Failed to read upstream response: {}", body_error);
    let (status, message) = body_error.status_and_message();
    Err(axum_response_to_forward_result(crate::a2a::create_error_response(status, message)).await)
}

async fn axum_response_to_forward_result(response: axum::http::Response<axum::body::Body>) -> ProcessingResult {
    let (parts, body) = response.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let resp_headers = multi_value_headers_json(
        parts
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v_str| (k.as_str(), v_str))
            }),
    );
    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: serde_json::json!({
            "status": parts.status.as_u16(),
            "body": body_str,
            "headers": resp_headers,
        }),
    }
}

async fn process_modern_fabric_response<Process, ProcessFuture>(
    response: reqwest::Response,
    headers: axum::http::HeaderMap,
    request: crate::mcp::request_validation::ValidatedModernMessage,
    limits: crate::mcp::modern_sse::SseLimits,
    processing_headers: std::collections::HashMap<String, Vec<String>>,
    support: crate::mcp::modern::ForwardingSupport<'static>,
    continuation: Option<(
        Box<crate::proxy::credential_delegation::modern::PreparedDelegation>,
        Arc<crate::mcp::continuations::config::ContinuationRuntime>,
    )>,
    process: Process,
) -> Result<axum::response::Response, crate::mcp::modern_sse::SseReadError>
where
    Process: FnOnce(String, std::collections::HashMap<String, Vec<String>>) -> ProcessFuture + Send + 'static,
    ProcessFuture: std::future::Future<Output = ProcessingResult> + Send,
{
    use crate::mcp::modern_sse::{ProcessedResponse, SseReadError};
    let status = response.status();
    crate::mcp::modern_sse::forwarding_response_with_finalizer(
        response.bytes_stream(),
        status,
        &headers,
        request,
        limits,
        support,
        move |message| async move {
            let payload = serde_json::to_string(&message).map_err(|_| SseReadError::InvalidMessage)?;
            let ProcessingResult::RequiresResponse { response_type, response_body } =
                process(payload, processing_headers).await
            else {
                return Err(SseReadError::ResponseRejected);
            };
            if response_type != MessageType::ForwardResponse.to_string()
                || response_body
                    .get("status")
                    .and_then(Value::as_u64)
                    != Some(u64::from(status.as_u16()))
            {
                return Err(SseReadError::ResponseRejected);
            }
            let body = response_body
                .get("body")
                .and_then(Value::as_str)
                .ok_or(SseReadError::InvalidMessage)?;
            let headers = crate::proxy::fabric_stream::wire::headers_from_json(response_body.get("headers"))
                .map_err(|_| SseReadError::ResponseRejected)?;
            Ok(ProcessedResponse {
                message: serde_json::from_str(body).map_err(|_| SseReadError::InvalidMessage)?,
                headers: Some(headers),
            })
        },
        move |message| async move {
            let Some((prepared, runtime)) = continuation else {
                return Ok(message);
            };
            let now =
                crate::proxy::credential_delegation::modern::now_secs().map_err(|_| SseReadError::ResponseRejected)?;
            prepared
                .finish(&runtime.service, message, runtime.config.ttl_secs, now)
                .await
                .map_err(|_| SseReadError::ResponseRejected)
        },
    )
    .await
}

fn fabric_mcp_headers(headers: Option<&serde_json::Map<String, Value>>) -> Result<axum::http::HeaderMap, String> {
    let mut result = axum::http::HeaderMap::new();
    let Some(headers) = headers else {
        return Ok(result);
    };

    for (name, value) in headers {
        let is_mcp_header = name.eq_ignore_ascii_case("mcp-protocol-version")
            || name.eq_ignore_ascii_case("mcp-method")
            || name.eq_ignore_ascii_case("mcp-name");
        let Ok(header_name) = axum::http::HeaderName::from_bytes(name.as_bytes()) else {
            if is_mcp_header {
                return Err(format!("MCP header name '{name}' is invalid"));
            }
            continue;
        };
        let Some(value) = value.as_str() else {
            if is_mcp_header {
                return Err(format!("MCP header '{name}' must have a string value"));
            }
            continue;
        };
        let Ok(header_value) = axum::http::HeaderValue::from_str(value) else {
            if is_mcp_header {
                return Err(format!("MCP header '{name}' contains invalid characters"));
            }
            continue;
        };
        result.append(header_name, header_value);
    }

    Ok(result)
}

fn fabric_legacy_session_evidence(
    headers: Option<&serde_json::Map<String, Value>>
) -> crate::mcp::request_validation::LegacySessionEvidence {
    if headers.is_some_and(|headers| {
        headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("mcp-session-id"))
    }) {
        crate::mcp::request_validation::LegacySessionEvidence::Unknown
    } else {
        crate::mcp::request_validation::LegacySessionEvidence::Absent
    }
}

/// Reshape MCP `tools/call` denials into JSON-RPC `-32001` (HTTP 200) so the
/// MCP client sees a protocol error; non-MCP falls back to HTTP 403.
fn build_surface_policy_denied_forward_body(
    body_bytes: &[u8],
    deny_reason: Option<&str>,
) -> serde_json::Value {
    if crate::mcp::is_tools_call_request(body_bytes) {
        let envelope = crate::mcp::build_tools_call_policy_denied_envelope(body_bytes, deny_reason);
        let body_str = serde_json::to_string(&envelope).unwrap_or_else(|_| envelope.to_string());
        serde_json::json!({
            "status": 200,
            "body": body_str,
            "headers": { "content-type": "application/json" },
        })
    } else {
        let message = match deny_reason {
            Some(reason) if !reason.is_empty() => {
                format!("Agent trust policy denied the request: {reason}")
            }
            _ => "Agent trust policy denied the request".to_string(),
        };
        let body = serde_json::json!({
            "error": "Forbidden",
            "message": message,
        });
        let body_str = serde_json::to_string(&body).unwrap_or_else(|_| body.to_string());
        serde_json::json!({
            "status": 403,
            "body": body_str,
            "headers": { "content-type": "application/json" },
            "error": message,
        })
    }
}

/// A forward-request is honoured only when its authenticated sender is a
/// registered, active gateway on this appliance and the requested channel is
/// exposed to that gateway. The DIDComm signature proves possession of a key,
/// not that the key belongs to a federated peer.
/// The gateway the authenticated sender resolves to, when this appliance has
/// registered and approved it. `from_did` is authcrypt-bound, so a peer cannot
/// claim another peer's DID.
async fn active_sender_peer(message: &ReceivedMessage) -> Option<crate::gateways::types::Gateway> {
    let from_did = message.from_did.as_deref()?;
    let Some(storage_root) = storage_root_from_context(message) else {
        warn!("Refusing {} from {}: storage path not found in message context", message.message_type, from_did);
        return None;
    };
    match crate::gateways::FileSystemGatewayStore::new(storage_root.join("gateways"), None).await {
        Ok(store) => match store
            .get_by_did(from_did)
            .await
        {
            Ok(Some(gateway)) if gateway.status == crate::gateways::types::GatewayStatus::Active => Some(gateway),
            _ => None,
        },
        Err(e) => {
            warn!("Refusing {} from {}: gateway store unavailable: {}", message.message_type, from_did, e);
            None
        }
    }
}

/// Whether a Fabric peer may reach a surface. A tenant-owned peer reaches only
/// its own tenant's and appliance-wide surfaces, whatever its exposure lists
/// say, so an empty list ("every surface") never widens it to another
/// tenant's. An appliance-wide peer is unaffected.
pub(crate) fn fabric_peer_may_reach_surface(
    peer_tenant_id: Option<&str>,
    surface_tenant_id: Option<&str>,
) -> bool {
    peer_tenant_id.is_none() || crate::tenancy::can_reference(peer_tenant_id, surface_tenant_id)
}

/// `gateways` is a store to read instead of loading the directory from the
/// message's storage root; the authoritative check passes `None`.
async fn authorize_fabric_sender(
    message: &ReceivedMessage,
    channel_id: &str,
    gateways: Option<&crate::gateways::FileSystemGatewayStore>,
) -> Result<(), ProcessingResult> {
    let refuse = |error: &str| ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: serde_json::json!({
            "status": 403,
            "body": serde_json::json!({ "error": "Forbidden", "message": error }).to_string(),
            "error": error,
        }),
    };
    const UNREGISTERED: &str = "Sender is not a registered gateway";

    let Some(from_did) = message.from_did.as_deref() else {
        warn!("Refusing forward-request without a sender DID");
        return Err(refuse(UNREGISTERED));
    };
    let lookup = if let Some(gateways) = gateways {
        gateways
            .get_by_did(from_did)
            .await
    } else {
        let Some(storage_root) = storage_root_from_context(message) else {
            warn!("Refusing forward-request from {}: storage path not found in message context", from_did);
            return Err(refuse(UNREGISTERED));
        };
        match crate::gateways::FileSystemGatewayStore::new(storage_root.join("gateways"), None).await {
            Ok(store) => {
                store
                    .get_by_did(from_did)
                    .await
            }
            Err(e) => Err(e),
        }
    };
    match lookup {
        Ok(Some(gateway)) if gateway.status == crate::gateways::types::GatewayStatus::Active => {
            if !gateway
                .exposed_channels
                .is_empty()
                && !gateway
                    .exposed_channels
                    .iter()
                    .any(|exposed| exposed == channel_id)
            {
                warn!(
                    "Refusing forward-request from gateway {} ({}): channel {} is not exposed to it",
                    gateway.id, from_did, channel_id
                );
                return Err(refuse("Channel is not exposed to sender"));
            }
            // A tenant-owned peer must not reach another tenant's surface, even
            // through an empty ("every surface") exposure list. A surface that
            // does not exist is reported later, by channel resolution.
            if gateway.tenant_id.is_some() {
                let reachable = match lookup_channel(message, channel_id).await {
                    Ok(surface) => surface.is_none_or(|surface| {
                        fabric_peer_may_reach_surface(gateway.tenant_id.as_deref(), surface.tenant_id.as_deref())
                    }),
                    Err(e) => {
                        warn!("Refusing forward-request from {}: surface lookup failed: {}", from_did, e);
                        false
                    }
                };
                if !reachable {
                    warn!(
                        "Refusing forward-request from gateway {} ({}): channel {} belongs to another tenant",
                        gateway.id, from_did, channel_id
                    );
                    return Err(refuse("Channel is not exposed to sender"));
                }
            }
            Ok(())
        }
        Ok(Some(gateway)) => {
            warn!(
                "Refusing forward-request from gateway {} ({}): status is {:?}, not active",
                gateway.id, from_did, gateway.status
            );
            Err(refuse(UNREGISTERED))
        }
        Ok(None) => {
            warn!("Refusing forward-request from unregistered sender {}", from_did);
            Err(refuse(UNREGISTERED))
        }
        Err(e) => {
            warn!("Refusing forward-request from {}: gateway lookup failed: {}", from_did, e);
            Err(refuse(UNREGISTERED))
        }
    }
}

/// The answer to a Fabric forward whose Target egress policy blocks, matching the
/// direct path's `403`.
/// The client a Fabric receive forward dials `target_url` with.
///
/// An HTTP(S) Target gets a client pinned to the address it resolved to, with
/// redirects off, as on the direct path, so DNS cannot rebind it between
/// vetting and connect. A cloud-metadata Target is refused. Other Targets
/// (`proxy://`) keep the pooled client, which never follows redirects either.
async fn forward_client_for(
    target_url: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    if !(target_url.starts_with("http://") || target_url.starts_with("https://")) {
        return Ok(GLOBAL_HTTP_CLIENT
            .get()
            .cloned()
            .unwrap_or_else(reqwest::Client::new));
    }
    let candidate = target_url.to_string();
    match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&candidate, timeout)).await {
        Ok(Ok((client, _target))) => Ok(client),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(format!("egress validation failed: {error}")),
    }
}

/// `a2a.max_body_size`, the byte cap on what Fabric receive buffers from the
/// local Target.
fn fabric_max_response_bytes() -> usize {
    GLOBAL_MAX_RESPONSE_BYTES
        .get()
        .copied()
        .unwrap_or_else(|| crate::config::A2aConfig::default().max_body_size)
}

/// Bounds for a body buffered from the local Target on Fabric receive: the
/// surface's idle and request timeouts, defaulting to the forward timeout, and
/// `a2a.max_body_size`.
fn fabric_body_limits(
    surface: &crate::config::agent_surface::AgentSurface
) -> crate::proxy::upstream_body::UpstreamBodyLimits {
    crate::proxy::upstream_body::UpstreamBodyLimits::new(
        fabric_max_response_bytes(),
        surface.timeout(),
        GLOBAL_FORWARD_TIMEOUT
            .get()
            .map_or(30, std::time::Duration::as_secs),
    )
}

/// Fetch the local Target's agent card for the GW2 policy context, through the
/// same pinned, redirect-free client as the forward and within the buffered
/// response bounds. Any failure, including a blocked target or a redirect,
/// yields no card.
async fn fetch_agent_card(
    card_url: &str,
    timeout: std::time::Duration,
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
    config_id: &str,
) -> Option<serde_json::Value> {
    let client = match forward_client_for(card_url, timeout).await {
        Ok(client) => client,
        Err(error) => {
            channel_warn!(config_id, "GW2: Agent card target {} blocked by egress policy: {}", card_url, error);
            return None;
        }
    };
    let response = match client
        .get(card_url)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            channel_warn!(config_id, "GW2: Agent card fetch request failed (url={}): {}", card_url, e);
            return None;
        }
    };
    channel_info!(config_id, "GW2: Agent card fetch HTTP status: {}", response.status());
    if !response.status().is_success() {
        channel_warn!(config_id, "GW2: Agent card fetch returned non-success status: {}", response.status());
        return None;
    }
    let body = match crate::proxy::upstream_body::read_bounded(response, limits).await {
        Ok(body) => body,
        Err(e) => {
            channel_warn!(config_id, "GW2: Failed to read agent card: {}", e);
            return None;
        }
    };
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(card) => {
            channel_info!(
                config_id,
                "GW2: Agent card fetched successfully: name={:?} url={:?}",
                card.get("name"),
                card.get("url")
            );
            Some(card)
        }
        Err(e) => {
            channel_warn!(config_id, "GW2: Failed to parse agent card JSON: {}", e);
            None
        }
    }
}

fn egress_blocked_forward_response() -> ProcessingResult {
    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: refused_forward_response(403, "Forbidden", "Request blocked by egress policy"),
    }
}

pub(crate) async fn process_forward_request(message: &ReceivedMessage) -> ProcessingResult {
    process_forward_request_inner(message, None).await
}

pub(crate) struct FabricStreamRequest {
    pub headers: axum::http::HeaderMap,
    pub body: bytes::Bytes,
    pub surface: crate::config::agent_surface::AgentSurface,
    pub variant_id: Option<String>,
    pub capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities,
}

pub(crate) async fn resolve_stream_surface(
    message: &ReceivedMessage,
    request: &crate::proxy::fabric_stream::wire::OpenRequest,
) -> Result<(crate::config::agent_surface::AgentSurface, Option<String>), String> {
    let surface = lookup_channel(message, &request.channel_id)
        .await?
        .ok_or("Fabric stream surface is unavailable")?;
    let variant_id = match request
        .variant_alias
        .as_deref()
    {
        Some(alias) => Some(
            surface
                .variants
                .iter()
                .find(|variant| variant.alias == alias)
                .ok_or("Fabric stream variant is unavailable")?
                .id
                .clone(),
        ),
        None => surface
            .default_variant_id
            .clone(),
    };
    let surface = surface
        .resolve_variant(
            request
                .variant_alias
                .as_deref(),
        )
        .map_err(|error| error.to_string())?;
    if surface.status != crate::config::agent_surface::SurfaceStatus::Active
        || surface.channel_protocol() != crate::config::ChannelProtocol::Mcp
    {
        return Err("Fabric stream requires an active MCP surface".to_string());
    }
    Ok((surface, variant_id))
}

pub(crate) async fn process_stream_forward_request(
    message: &ReceivedMessage,
    request: FabricStreamRequest,
    versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
    continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
) -> ProcessingResult {
    Box::pin(process_forward_request_with_mcp_runtime(message, Some(request), versions, continuations)).await
}

async fn process_forward_request_inner(
    message: &ReceivedMessage,
    stream_request: Option<FabricStreamRequest>,
) -> ProcessingResult {
    let continuations = crate::mcp::continuations::config::global().map(|runtime| Arc::new(runtime.clone()));
    // Modern MCP crosses Fabric only as framed streams.
    Box::pin(process_forward_request_with_mcp_runtime(
        message,
        stream_request,
        crate::mcp::request_validation::LEGACY_ONLY_POLICY,
        continuations,
    ))
    .await
}

async fn process_forward_request_with_mcp_runtime(
    message: &ReceivedMessage,
    mut stream_request: Option<FabricStreamRequest>,
    mcp_versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
    mcp_continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
) -> ProcessingResult {
    use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
    use tracing::Instrument;

    let mut subscription_access =
        crate::mcp::subscriptions::SubscriptionLifetime::new(std::time::Duration::from_secs(86_400), None);
    // Extract channel_id early for span creation
    let channel_id = message
        .message_body
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Count receipt of the fabric forward before any policy or forwarding, so the metric is the
    // authoritative observation point for "this gateway received a fabric forward request".
    crate::metrics::backends::prometheus::track_fabric_forward_received(channel_id);

    let trace_id_field = message
        .message_body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract and parse OpenTelemetry parent context from GW1 BEFORE creating the span
    let parent_context = if let Some(otel_ctx) = message
        .message_body
        .get("otel_context")
    {
        info!("📊 GW2: Received otel_context from GW1: {:?}", otel_ctx);

        if let (Some(trace_id_str), Some(span_id_str), Some(trace_flags)) = (
            otel_ctx
                .get("trace_id")
                .and_then(|v| v.as_str()),
            otel_ctx
                .get("span_id")
                .and_then(|v| v.as_str()),
            otel_ctx
                .get("trace_flags")
                .and_then(|v| v.as_u64()),
        ) {
            info!(
                "📊 GW2: Parsing OTel context - trace_id: {}, span_id: {}, flags: {}",
                trace_id_str, span_id_str, trace_flags
            );

            if let (Ok(trace_id), Ok(span_id)) = (TraceId::from_hex(trace_id_str), SpanId::from_hex(span_id_str)) {
                let remote_context = SpanContext::new(
                    trace_id,
                    span_id,
                    TraceFlags::new(trace_flags as u8),
                    true,
                    TraceState::default(),
                );

                info!("📊 GW2: Created remote SpanContext for parent linkage");
                Some(opentelemetry::Context::current().with_remote_span_context(remote_context))
            } else {
                warn!("📊 GW2: Failed to parse trace_id or span_id from hex strings");
                None
            }
        } else {
            warn!("📊 GW2: otel_context missing required fields (trace_id, span_id, or trace_flags)");
            None
        }
    } else {
        info!("📊 GW2: No otel_context in message body");
        None
    };

    // Create span manually with parent context attached from the start
    let span = if let Some(ref parent_cx) = parent_context {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        info!("📊 GW2: Creating fabric.forward_request span with parent context");
        let span = tracing::info_span!(
            "fabric.forward_request",
            channel_id = channel_id,
            trace_id = trace_id_field,
            from_did = ?message.from_did,
            msg.id = %message.didcomm_message_id,
            otel.kind = "server",
            caller.auth_method = tracing::field::Empty,
            caller.principal = tracing::field::Empty,
            caller.did = tracing::field::Empty
        );
        let _ = span.set_parent(parent_cx.clone());

        // Log span details for debugging
        use opentelemetry::trace::TraceContextExt;
        let otel_context = span.context();
        let span_ref = otel_context.span();
        let span_ctx = span_ref.span_context();
        info!(
            "📊 GW2: Span created - trace_id: {}, span_id: {}, sampled: {}, service should be: agent-gateway-2",
            span_ctx.trace_id(),
            span_ctx.span_id(),
            span_ctx.is_sampled()
        );

        span
    } else {
        tracing::info_span!(
            "fabric.forward_request",
            channel_id = channel_id,
            trace_id = trace_id_field,
            from_did = ?message.from_did,
            msg.id = %message.didcomm_message_id,
            otel.kind = "server",
            caller.auth_method = tracing::field::Empty,
            caller.principal = tracing::field::Empty,
            caller.did = tracing::field::Empty
        )
    };

    // Execute the rest of the function within the span context
    async move {
        info!("📥 Received forward-request from {:?}", message.from_did);

    if channel_id.is_empty() {
        warn!("Invalid forward-request: Missing channel_id");
        let error_body = serde_json::json!({
            "error": "Missing channel_id in forward-request",
            "status": 400,
        });
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: error_body,
        };
    }

    if let Err(refused) = authorize_fabric_sender(message, channel_id, None).await {
        return refused;
    }
    if let Err(refused) = admit_forward_request_envelope(message) {
        return refused;
    }

    // Extract request details
    let method = message
        .message_body
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");
    let path = message
        .message_body
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let mut headers = message
        .message_body
        .get("headers")
        .and_then(|v| v.as_object())
        .cloned();

    // Extract body from DIDComm message - it's stored as a JSON value, not a string
    let mut body_bytes = match stream_request.as_ref() {
        Some(request) => request.body.clone(),
        None => match message.message_body.get("body") {
        Some(serde_json::Value::String(s)) => {
            // Legacy: body stored as string
            bytes::Bytes::from(s.clone())
        }
        Some(val) if !val.is_null() => {
            // New: body stored as JSON value, serialize it back to bytes
            bytes::Bytes::from(serde_json::to_vec(val).unwrap_or_default())
        }
        _ => bytes::Bytes::new(),
        },
    };

    info!(
        "📤 Forwarding {} {} to channel {} (headers: {}, body: {} bytes)",
        method,
        path,
        channel_id,
        headers.as_ref().map(|h| h.len()).unwrap_or(0),
        body_bytes.len()
    );

    debug!("  ↳ Received path from gateway 1: '{}'", path);

    // Debug: Log all received headers to diagnose payment propagation
    if let Some(ref h) = headers {
        info!("  ↳ Received headers: {:?}", h.keys().collect::<Vec<_>>());
        if let Some(payment_sig) = h.get("PAYMENT-SIGNATURE") {
            info!("  ↳ PAYMENT-SIGNATURE present: {:?}", payment_sig);
        } else {
            info!("  ↳ No PAYMENT-SIGNATURE header found");
        }
    }

    // Resolve the target channel from the cached store (no per-request disk reload).
    let resolved = match stream_request.as_ref() {
        Some(request) => Ok(Some(request.surface.clone())),
        None => lookup_channel(message, channel_id).await,
    };
    let surface = match resolved {
        Ok(Some(ch)) => ch,
        Ok(None) => {
            warn!("Channel {} not found", channel_id);
            let error_body = serde_json::json!({
                "error": format!("Channel {} not found", channel_id),
                "status": 404,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
        Err(e) => {
            warn!("Failed to resolve channel {}: {}", channel_id, e);
            let error_body = serde_json::json!({
                "error": format!("Failed to resolve channel {}: {}", channel_id, e),
                "status": 500,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
    };

    // The envelope sender is a paired Connection Point; identity presentations
    // may only come from that connection's issuers.
    let peer_issuers = match resolve_peer_issuers(message.from_did.as_deref()).await {
        Ok(issuers) => issuers,
        Err(reason) => {
            warn!("Rejecting forward-request from {:?}: {}", message.from_did, reason);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: forbidden_forward_response(&reason),
            };
        }
    };

    // Extract config_id for channel-specific logging
    let config_id = surface.config_id().unwrap_or("unknown");

    // Apply virtual channel variant override if specified by GW1
    let variant_alias = message
        .message_body
        .get("virtual_channel_alias")
        .or_else(|| message.message_body.get("active_variant_alias"))
        .and_then(|v| v.as_str());

    let active_variant_id = match stream_request.as_ref() {
        Some(request) => request.variant_id.clone(),
        None => match variant_alias {
            Some(alias) => surface.variants.iter().find(|variant| variant.enabled && variant.alias == alias)
                .map(|variant| variant.id.clone()),
            None => surface.default_variant_id.clone(),
        },
    };

    let surface = if stream_request.is_some() { surface.clone() } else { match surface.resolve_variant(variant_alias) {
        Ok(s) => {
            if let Some(alias) = variant_alias {
                channel_info!(config_id, "GW2: Applied variant '{}'", alias);
            }
            s
        }
        Err(e) => {
            channel_warn!(
                config_id,
                "GW2: Variant '{}' not found ({}), using default",
                variant_alias.unwrap_or(""),
                e
            );
            surface.resolve_variant(None).unwrap_or_else(|_| surface.clone())
        }
    }};

    // Check if channel is active
    if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
        channel_warn!(
            config_id,
            "Channel {} is not active (status: {:?})",
            channel_id,
            surface.status
        );
        let error_body = serde_json::json!({
            "error": format!("Channel {} is not active", channel_id),
            "status": 503,
        });
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: error_body,
        };
    }

    // ── Unified source authentication ──────────────────────────────────────────
    // Public paths (e.g. agent-card) bypass all authentication gates.
    // Caller-attributable failures are non-blocking: the outcome is handed to the
    // policy layer via `source_auth_context` below. Only server-side failures
    // (setup/config resolution, internal errors) still block here (now 500).
    let mut source_auth_failure: Option<crate::surface_context::SourceAuthContext> = None;
    let mut resource_authorization = None;
    let authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity> =
        if let Some(authorization) = surface.mcp_http.as_ref().and_then(|http| http.authorization.as_ref()) {
            use crate::mcp::resource_server::ResourceTokenError;

            let authorization = match authorization.for_variant(variant_alias) {
                Ok(authorization) => authorization,
                Err(_) => return axum_response_to_forward_result(authorization.challenge(ResourceTokenError::Unavailable)).await,
            };
            let Some(network) = GLOBAL_MCP_AUTH_NETWORK.get() else {
                return axum_response_to_forward_result(authorization.challenge(ResourceTokenError::Unavailable)).await;
            };
            let Some((profile, issuer, middleware)) = network.sts.mcp_issuer.as_ref()
                .zip(GLOBAL_VC_ISSUER.get()).zip(get_source_auth_middleware())
                .map(|((profile, issuer), middleware)| (profile, issuer, middleware)) else {
                return axum_response_to_forward_result(authorization.challenge(ResourceTokenError::Unavailable)).await;
            };
            let origins = network.map_url_to_port(&surface.access_point.listen_address)
                .and_then(|port| network.get_listener_by_port(port))
                .map(|listener| listener.external_urls.clone()).unwrap_or_default();
            let expected_path = match variant_alias {
                Some(alias) => format!("{}${alias}", surface.access_point.route),
                None => surface.access_point.route.clone(),
            };
            if surface.access_point.protocol != crate::config::agent_surface::SurfaceProtocol::Mcp
                || surface.source_auth().is_some()
                || authorization.validate_endpoint(&origins, &expected_path).is_err()
                || profile.validate_network(network).is_err()
            {
                return axum_response_to_forward_result(authorization.challenge(ResourceTokenError::Unavailable)).await;
            }
            let auth_headers = match stream_request.as_ref().map(|request| Ok(request.headers.clone())).unwrap_or_else(|| {
                crate::proxy::fabric_stream::wire::headers_from_json(headers.clone().map(Value::Object).as_ref())
            }) {
                Ok(headers) => headers,
                Err(_) => return axum_response_to_forward_result(authorization.challenge(ResourceTokenError::Invalid)).await,
            };
            let identity = match authorization.authenticate(&auth_headers, profile, issuer, middleware.jwks_client()).await {
                Ok(identity) => identity,
                Err(error) => return axum_response_to_forward_result(authorization.challenge(error)).await,
            };
            if let Some(headers) = headers.as_mut() {
                headers.retain(|name, _| !name.eq_ignore_ascii_case("authorization"));
            }
            if let Some(stream) = stream_request.as_mut() {
                stream.headers.remove(axum::http::header::AUTHORIZATION);
            }
            resource_authorization = Some(authorization);
            Some(identity)
        } else if !crate::proxy::paths::is_public_request(method, path) {
            // Rebuild an axum HeaderMap from the JSON headers map so the middleware
            // can use the same extract_bearer path as the direct handler.
            let to_header_option = |(k, v): (&String, &Value)| -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
                if let (Ok(name), Some(val)) = (
                    axum::http::HeaderName::from_bytes(k.as_bytes()),
                    v.as_str().and_then(|s| axum::http::HeaderValue::from_str(s).ok()),
                ) {
                    Some((name, val))
                } else {
                    None
                }
            };
            let to_header_iter = |headers: &serde_json::Map<String, Value>| -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
                headers.iter().filter_map(to_header_option).collect::<Vec<(axum::http::HeaderName, axum::http::HeaderValue)>>()
            };
            let axum_headers = stream_request.as_ref().map(|request| request.headers.clone()).unwrap_or_else(|| headers
                .as_ref()
                .map(to_header_iter)
                .map(axum::http::HeaderMap::from_iter).unwrap_or_else(axum::http::HeaderMap::new));

            if let (Some(auth_config), Some(sa_middleware)) =
                (surface.source_auth(), get_source_auth_middleware())
            {
                let resolved_auth_config = match resolve_fabric_surface_auth_config(
                    auth_config,
                    GLOBAL_VC_ISSUER.get().map(Arc::as_ref),
                    &surface.surface_id,
                )
                .await
                {
                    Ok(config) => config,
                    Err(e) => {
                        // Setup/config-resolution failure is a server-side
                        // problem, not a caller decision — keep blocking.
                        channel_warn!(config_id, "GW2: Source authentication setup failed (reason={}) — blocking", e);
                        let deny = crate::source_auth::errors::deny_response(
                            &surface.access_point.protocol,
                            auth_config,
                            &e,
                        );
                        return axum_response_to_forward_result(deny).await;
                    }
                };
                match sa_middleware
                    .authenticate(&resolved_auth_config, &axum_headers, &surface.name, &surface.surface_id, None)
                    .await
                {
                    Ok(identity) => Some(identity),
                    // Caller-attributable failure: record the outcome for the
                    // policy layer and continue with no asserted caller identity.
                    Err(e) if e.is_caller_attributable() => {
                        channel_warn!(config_id, "GW2: Source authentication failed (reason={}) — deferring to policy", e);
                        source_auth_failure = Some(crate::surface_context::SourceAuthContext::Failed {
                            attempted_method: resolved_auth_config.method_tag().to_string(),
                            reason: e.to_string(),
                        });
                        None
                    }
                    // Server-side failure — keep blocking (500).
                    Err(e) => {
                        channel_warn!(config_id, "GW2: Source authentication error (reason={}) — blocking", e);
                        let deny = crate::source_auth::errors::deny_response(
                            &surface.access_point.protocol,
                            &resolved_auth_config,
                            &e,
                        );
                        return axum_response_to_forward_result(deny).await;
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

    // Merged source-auth context for policy inputs: the verified identity on
    // success, or a `Failed` marker on a non-blocking caller-attributable
    // failure. `None` when no source auth is configured.
    let source_auth_context: Option<crate::surface_context::SourceAuthContext> =
        authenticated_identity
            .as_ref()
            .map(crate::surface_context::SourceAuthContext::from)
            .or(source_auth_failure);

    // Stamp the authenticated caller's identity onto the current span so the
    // connection-point trace can be attributed to a caller. No-op unless
    // opted in via `traces.record_caller_identity`.
    if let Some(identity) = authenticated_identity.as_ref() {
        crate::observability::record_caller_identity_on_current_span(identity);
    }

    let mut mcp_verified_binding = None;
    let (mcp_metadata_context, mcp_classification) = if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
        let http_policy = match crate::mcp::modern_http::EndpointHttpPolicy::with_versions(
            surface.mcp_http.as_ref(),
            std::slice::from_ref(&surface.access_point.listen_address),
            mcp_versions,
        ) {
            // The sending gateway already checked the caller's browser Origin
            // against its own surface, so a buffered ForwardRequest is not
            // checked again against this surface's allowlist.
            Ok(policy) if stream_request.is_none() => policy.without_origin_check(),
            Ok(policy) => policy,
            Err(error) => {
                channel_warn!(config_id, "Invalid MCP HTTP configuration: {}", error);
                return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid MCP HTTP configuration")).await;
            }
        };
        if stream_request.is_none() {
            for (name, value) in headers.iter().flat_map(|headers| headers.iter()) {
                if matches!(name.to_ascii_lowercase().as_str(), "accept" | "content-type")
                    && value.as_str().and_then(|value| axum::http::HeaderValue::from_str(value).ok()).is_none()
                {
                    let error = crate::mcp::modern_http::HttpAdmissionError {
                        status: axum::http::StatusCode::BAD_REQUEST,
                        message: "Malformed MCP HTTP header in Fabric request",
                    };
                    return axum_response_to_forward_result(error.into_response(None)).await;
                }
            }
        }
        let mcp_headers = match stream_request.as_ref().map(|request| Ok(request.headers.clone())).unwrap_or_else(|| fabric_mcp_headers(headers.as_ref())) {
            Ok(headers) => headers,
            Err(message) => {
                let error = crate::mcp::request_validation::malformed_transport_header(&body_bytes, message);
                return axum_response_to_forward_result((*error).into_response()).await;
            }
        };
        let classification = if method.eq_ignore_ascii_case("POST") {
            match http_policy.admit_post(&mcp_headers, &body_bytes, fabric_legacy_session_evidence(headers.as_ref())) {
                Ok(classification) => Some(classification),
                Err(validation_error) => {
                    channel_warn!(config_id, "Rejecting fabric MCP request at protocol boundary: code={} message={}", validation_error.code, validation_error.message);
                    return axum_response_to_forward_result((*validation_error).into_response()).await;
                }
            }
        } else {
            if let Err(error) = http_policy.validate_headers(&mcp_headers) {
                return axum_response_to_forward_result(error.into_response(None)).await;
            }
            if let Ok(http_method) = axum::http::Method::from_bytes(method.as_bytes())
                && let Some(response) = http_policy.non_post_response(&http_method, &mcp_headers)
            {
                return axum_response_to_forward_result(response).await;
            }
            None
        };
        if let Some(classification) = classification {
        let mcp_metadata_context = crate::mcp::meta::McpMetadataContext::from_classification(&classification, surface.mcp_legacy_metadata_output);
        if let Err(error) = surface.validate_mcp_metadata_base() {
            channel_warn!(config_id, "Invalid MCP metadata configuration: {}", error);
            return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid MCP metadata configuration")).await;
        }
        body_bytes = match crate::mcp::meta::normalize_bytes(&body_bytes, mcp_metadata_context) {
            Ok(body) => body,
            Err(error) => return axum_response_to_forward_result(error.into_response(&body_bytes, axum::http::StatusCode::BAD_REQUEST)).await,
        };
        if let Some(capped) = http_policy.cap_legacy_initialize(&body_bytes, &classification) {
            channel_info!(config_id, "Forwarding MCP initialize with protocolVersion {} in place of unsupported {}", capped.offered, capped.requested);
            body_bytes = capped.body;
        }
        mcp_verified_binding = match crate::protocols::extensions::verify_mcp_metadata_identity(
            &body_bytes, GLOBAL_VC_ISSUER.get(), config_id, Some(&peer_issuers),
        ).await {
            Ok(binding) => binding,
            Err(error) => {
                channel_warn!(config_id, "Invalid MCP identity presentation: {}", error);
                return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::UNPROCESSABLE_ENTITY, "Invalid MCP identity presentation")).await;
            }
        };
        (mcp_metadata_context, Some(classification))
        } else {
            (crate::mcp::meta::McpMetadataContext::legacy(surface.mcp_legacy_metadata_output), None)
        }
    } else {
        (crate::mcp::meta::McpMetadataContext::legacy(surface.mcp_legacy_metadata_output), None)
    };
    let modern_mcp_context = mcp_classification.as_ref().and_then(crate::mcp::modern_mcp_context);
    // Gateway and surface policies see the same `input.mcp` as the direct path:
    // the validated modern context, else the legacy request context.
    let policy_mcp_context = if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
        match mcp_classification.as_ref() {
            Some(classification) => crate::mcp::build_validated_mcp_context(&body_bytes, classification),
            None => crate::mcp::build_mcp_context(&body_bytes),
        }
    } else {
        None
    };
    let mut modern_request = match mcp_classification.as_ref() {
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => Some((**request).clone()),
        _ => None,
    };
    if let (Some(stream), Some(request)) = (stream_request.as_ref(), modern_request.as_ref())
        && !stream.capabilities.permits_mcp_method(&request.method)
    {
        let error = crate::mcp::request_validation::McpRequestValidationError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            id: request.id.clone(), code: crate::mcp::error_codes::INTERNAL_ERROR,
            message: "Fabric peer does not support this MCP message pattern".to_string(), data: None,
        };
        return axum_response_to_forward_result(error.into_response()).await;
    }
    if stream_request.is_some() && modern_request.is_none() {
        return axum_response_to_forward_result(crate::a2a::create_error_response(
            axum::http::StatusCode::BAD_REQUEST, "Fabric request streams require an admitted modern MCP request",
        )).await;
    }
    let subscription_lifetime = if let Some(request) = modern_request.as_ref().filter(|request| request.method == "subscriptions/listen") {
        let caller = crate::mcp::subscriptions::listen_caller(authenticated_identity.as_ref(), message.from_did.as_deref().unwrap_or_default());
        let Some(slot) = crate::mcp::subscriptions::ListenSlots::global().acquire(&crate::proxy::handler::listen_surface_key(&surface), &caller) else {
            return axum_response_to_forward_result(crate::mcp::subscriptions::listen_limit_error(request).into_response()).await;
        };
        subscription_access.hold(slot);
        subscription_access.record_owner(surface.surface_id.clone(), surface.tenant_id.as_deref());
        if let Some(vault) = get_delegation_vault_store()
            && subscription_access.watch_vault(vault).await.is_err()
        {
            return axum_response_to_forward_result(crate::mcp::request_validation::McpRequestValidationError {
                status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                id: request.id.clone(),
                code: crate::mcp::error_codes::INTERNAL_ERROR,
                message: "MCP subscription authorization unavailable".into(),
                data: None,
            }.into_response()).await;
        }
        subscription_access.restrict_lifetime(std::time::Duration::from_secs(surface.mcp_http.clone().unwrap_or_default().stream_max_lifetime_secs.get()));
        subscription_access.restrict_to_identity(authenticated_identity.as_ref());
        Some(subscription_access)
    } else {
        None
    };

    // Normalize configured transport headers into A2A metadata at the fabric
    // receiving Access Point before gateway/surface policy, identity, Trust
    // Check, and target forwarding evaluate the body.
    if method.eq_ignore_ascii_case("POST")
        && !body_bytes.is_empty()
        && matches!(
            surface.channel_protocol(),
            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
        )
        && let Some(mapping) = surface.access_point.header_metadata_mapping.as_ref()
    {
        let axum_headers = headers
            .as_ref()
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(k, v)| {
                        let name = axum::http::HeaderName::from_bytes(k.as_bytes()).ok()?;
                        let value = axum::http::HeaderValue::from_str(v.as_str()?).ok()?;
                        Some((name, value))
                    })
                    .collect::<Vec<_>>()
            })
            .map(axum::http::HeaderMap::from_iter)
            .unwrap_or_else(axum::http::HeaderMap::new);
        let diagnostics = mapping.diagnostics(&axum_headers);
        let identity_extraction_reads_mapped_extension = matches!(
            surface.inbound_identity(),
            Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg))
                if cfg.identity_extension_uri() == mapping.extension_uri.as_str()
        );
        match crate::a2a::inject_header_metadata_extension(&body_bytes, mapping, &axum_headers, &surface.name) {
            Ok((modified_body, mapped_count)) => {
                info!(
                    channel = %surface.name,
                    surface_id = %config_id,
                    extension_uri = %diagnostics.extension_uri,
                    mapped_count,
                    configured_fields = ?diagnostics.configured_fields,
                    mapped_fields = ?diagnostics.mapped_fields,
                    missing_headers = ?diagnostics.missing_headers,
                    strip_mapped_headers = diagnostics.strip_mapped_headers,
                    identity_extraction_reads_mapped_extension,
                    fabric_receive = true,
                    result = if mapped_count > 0 { "applied" } else { "skipped" },
                    "Header Metadata Mapping evaluated"
                );
                if mapped_count > 0 {
                    body_bytes = modified_body;
                }
            }
            Err(e) => {
                warn!(
                    channel = %surface.name,
                    surface_id = %config_id,
                    extension_uri = %diagnostics.extension_uri,
                    configured_fields = ?diagnostics.configured_fields,
                    mapped_fields = ?diagnostics.mapped_fields,
                    missing_headers = ?diagnostics.missing_headers,
                    strip_mapped_headers = diagnostics.strip_mapped_headers,
                    identity_extraction_reads_mapped_extension,
                    fabric_receive = true,
                    error = %e,
                    "Header Metadata Mapping failed"
                );
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 400,
                        "error": "Header Metadata Mapping failed",
                    }),
                };
            }
        }
    }

    if let Err(result) = evaluate_gateway_policy_for_fabric(
        GLOBAL_APPLIANCE_POLICY_MANAGER
            .get()
            .map(Arc::as_ref),
        &surface,
        config_id,
        method,
        path,
        headers.as_ref(),
        message.from_did.clone(),
        authenticated_identity.as_ref(),
        source_auth_context.as_ref(),
        policy_mcp_context.as_ref(),
    )
    .await
    {
        return result;
    }

    let payment_context = if modern_request.is_some() { None } else { match Box::pin(verify_payment_fabric(
        &surface,
        channel_id,
        config_id,
        headers.as_ref(),
        &body_bytes,
        path,
        &message.context,
    ))
    .await
    {
        Ok(ctx) => ctx,
        Err(result) => return result,
    }};

    let managed_id = surface.managed_identity();
    // Prefer an explicit `extension_rules`; otherwise synthesise one from the
    // slot-level `json_schema`. A protected-identity slot authored in the
    // dashboard writes `json_schema` (not `extension_rules`), so without this
    // fallback GW2's fabric path sees `has_identity_ext_rules: false` and never
    // extracts the backend agent identity or injects its VP — even though the
    // main proxy path (`compile_identity_engines_from_managed_identity`)
    // already builds the selector from `json_schema`.
    let synthesized_ext_rules = managed_id.as_ref().and_then(|mi| match mi {
        crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) if cfg.extension_rules.is_none() => cfg
            .json_schema
            .as_ref()
            .map(|schema| crate::config::types::ExtensionRules {
                json_schema: Some(schema.clone()),
                rules: vec![],
                filter_rules: vec![],
                default_action: None,
            }),
        _ => None,
    });
    let identity_ext_rules = managed_id
        .as_ref()
        .and_then(|mi| match mi {
            crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
            _ => None,
        })
        .or(synthesized_ext_rules.as_ref());
    // The CALLER identity (CA → AP request leg) must be extracted with the
    // INBOUND slot schema (`identity_slots.inbound`, e.g. `agentIdentity`), NOT
    // the protected/managed slot (`managed_identity`, MA → AP response leg,
    // e.g. `serverIdentity`) built above for the backend-agent VP. Using the
    // managed slot here made the fabric-receive path validate the caller's
    // `agentIdentity` body against the protected slot's `serverIdentity` schema
    // and always fall back to SHA256. Mirror the same `json_schema` synthesis
    // fallback the dashboard relies on.
    let caller_managed = surface.inbound_identity();
    let caller_synthesized_ext_rules = caller_managed.and_then(|mi| match mi {
        crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) if cfg.extension_rules.is_none() => cfg
            .json_schema
            .as_ref()
            .map(|schema| crate::config::types::ExtensionRules {
                json_schema: Some(schema.clone()),
                rules: vec![],
                filter_rules: vec![],
                default_action: None,
            }),
        _ => None,
    });
    let caller_ext_rules = caller_managed
        .and_then(|mi| match mi {
            crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
            _ => None,
        })
        .or(caller_synthesized_ext_rules.as_ref());
    let (caller_identity, caller_issuer_did, caller_identity_verification) =
        Box::pin(extract_caller_identity_inbound(
            &surface,
            channel_id,
            config_id,
            &body_bytes,
            caller_ext_rules,
            mcp_verified_binding.as_ref(),
            &peer_issuers,
            GLOBAL_VC_ISSUER.get(),
        ))
        .await;

    let audit_trace_id = message
        .message_body
        .get("otel_context")
        .and_then(|ctx| ctx.get("trace_id"))
        .and_then(|value| value.as_str())
        .or_else(|| (!trace_id_field.is_empty()).then_some(trace_id_field));

    if let Some(result) = evaluate_mcp_tool_policies_for_fabric(
        &surface,
        config_id,
        &body_bytes,
        headers.as_ref(),
        method,
        path,
        authenticated_identity.as_ref(),
        caller_identity.as_ref(),
        audit_trace_id,
        modern_mcp_context.as_ref(),
    )
    .await
    {
        return result;
    }

    let mut body_bytes = match Box::pin(enrich_and_evaluate_surface_policies(
        &surface,
        channel_id,
        config_id,
        method,
        path,
        body_bytes,
        headers.as_ref(),
        message.from_did.clone(),
        payment_context.clone(),
        caller_identity.as_ref(),
        caller_identity_verification,
        caller_issuer_did.as_ref(),
        authenticated_identity.as_ref(),
        source_auth_context.as_ref(),
        variant_alias,
        audit_trace_id,
        mcp_verified_binding.as_ref(),
        &peer_issuers,
        policy_mcp_context.as_ref(),
    ))
    .await
    {
        Ok(bytes) => bytes,
        Err(result) => return result,
    };

    // MCP Tool Gating — G2G `tools/call` gate. Runs after the surface OPA gate
    // (which may be disabled), so a tool the firewall denies is uncallable over
    // the fabric leg exactly as on the direct path.
    if let Some(result) = evaluate_mcp_tool_gating_call_for_fabric(
        &surface,
        config_id,
        variant_alias,
        &body_bytes,
        headers.as_ref(),
        method,
        path,
        message.from_did.clone(),
        authenticated_identity.as_ref(),
        source_auth_context.as_ref(),
        caller_identity.as_ref(),
        audit_trace_id,
        modern_mcp_context.as_ref(),
    )
    .await
    {
        return result;
    }

    let is_agent_card_request = crate::proxy::paths::is_public_request(method, path);

    let modern_payment = if modern_request.is_some() {
        let payment_headers = match stream_request.as_ref().map(|request| Ok(request.headers.clone()))
            .unwrap_or_else(|| crate::proxy::fabric_stream::wire::headers_from_json(headers.clone().map(Value::Object).as_ref()))
        {
            Ok(headers) => headers,
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::BAD_REQUEST, "Invalid payment transport headers",
            )).await,
        };
        let x402_headers = match message.context.get("x402_headers")
            .map(|value| serde_json::from_value::<crate::config::types::X402Headers>(value.clone())).transpose()
        {
            Ok(headers) => headers.unwrap_or_default(),
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid payment header configuration",
            )).await,
        };
        Some((payment_headers, x402_headers))
    } else { None };
    let mut modern_delegation = None;
    if let Some(request) = modern_request.as_ref()
        && !surface.outbound_credentials.is_empty()
    {
        use crate::mcp::continuations::{ContinuationError, protected::ContinuationRoute};
        use crate::proxy::credential_delegation::modern::{ModernDelegationContext, ModernDelegationError, ModernDelegationResult};
        use axum::response::IntoResponse;
        let result = Box::pin(async {
            let runtime = mcp_continuations.as_deref().ok_or(ContinuationError::Unavailable)?;
            let network = GLOBAL_MCP_AUTH_NETWORK.get().ok_or(ContinuationError::Unavailable)?;
            let vault = get_delegation_vault_store().ok_or(ContinuationError::Unavailable)?;
            let providers = get_credential_provider_store().ok_or(ContinuationError::Unavailable)?;
            let strategies = get_source_auth_middleware().ok_or(ContinuationError::Unavailable)?.provider_store();
            let secrets = get_secrets_store();
            if variant_alias.is_some() && active_variant_id.is_none() {
                return Err(ModernDelegationError::from(ContinuationError::BindingMismatch));
            }
            let variant_id = active_variant_id.clone();
            ModernDelegationContext {
                service: &runtime.service,
                deployment: &runtime.config.deployment,
                ttl_secs: runtime.config.ttl_secs,
                surface: &surface,
                variant_id,
                route: ContinuationRoute::Fabric { peer_did: message.from_did.clone().ok_or(ContinuationError::BindingMismatch)? },
                authorization: resource_authorization.as_ref().ok_or(ContinuationError::BindingMismatch)?,
                identity: authenticated_identity.as_ref().ok_or(ContinuationError::BindingMismatch)?,
                agent_did: caller_identity.as_deref().ok_or(ContinuationError::BindingMismatch)?,
                profile: network.sts.mcp_issuer.as_ref().ok_or(ContinuationError::Unavailable)?,
                vault: vault.as_ref(), providers: providers.as_ref(), strategies: strategies.as_ref(),
                secrets: secrets.as_ref(), provider_http: None,
            }.prepare_with_payment(request, crate::proxy::credential_delegation::modern::now_secs()?,
                modern_payment.as_ref().is_some_and(|(headers, config)| {
                    crate::proxy::handler::surface_payment::LocalPayment::inspect(
                        &surface, headers, &body_bytes, None, &config.payment_signature,
                    ).unpaid()
                }),
            ).await
        }).await;
        match result {
            Ok(ModernDelegationResult::InputRequired(response)) => {
                return axum_response_to_forward_result(
                    ([("cache-control", "no-store")], axum::Json(response)).into_response(),
                ).await;
            }
            Ok(ModernDelegationResult::Prepared(prepared)) => {
                body_bytes = match prepared.rewrite_body(&body_bytes) {
                    Ok(body) => body,
                    Err(error) => return axum_response_to_forward_result(ModernDelegationError::from(error).response(request)).await,
                };
                modern_request = Some(prepared.request.clone());
                modern_delegation = Some(prepared);
            }
            Err(ModernDelegationError::Unpaid) => {
                let Some((headers, config)) = modern_payment.as_ref() else {
                    return axum_response_to_forward_result(ModernDelegationError::Unpaid.response(request)).await;
                };
                return match Box::pin(process_modern_payment_fabric(&surface, config, headers, body_bytes, path, None)).await {
                    Err(result) => result,
                    Ok(_) => axum_response_to_forward_result(ModernDelegationError::Unpaid.response(request)).await,
                };
            }
            Err(error) => return axum_response_to_forward_result(error.response(request)).await,
        }
    }
    let modern_payment_receipt = if let Some((payment_headers, config)) = modern_payment.as_ref() {
        match Box::pin(process_modern_payment_fabric(
            &surface, config, payment_headers, body_bytes.clone(), path,
            modern_delegation.as_ref().and_then(|prepared| prepared.payment()),
        )).await {
            Ok(mut payment) => {
                if let Some(prepared) = modern_delegation.as_mut() {
                    let recorded = crate::proxy::credential_delegation::modern::now_secs().and_then(|now| {
                        prepared.record_local_payment(&payment, mcp_continuations.as_ref().map_or(300, |runtime| runtime.config.ttl_secs), now)
                    });
                    if let Err(error) = recorded {
                        return axum_response_to_forward_result(
                            crate::proxy::credential_delegation::modern::ModernDelegationError::from(error).response(&prepared.request),
                        ).await;
                    }
                }
                if payment.strip_consumed_mcp_argument().is_err() {
                    return axum_response_to_forward_result(crate::a2a::create_error_response(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid paid MCP request",
                    )).await;
                }
                if payment.consumed {
                    if let Some(headers) = headers.as_mut() {
                        headers.retain(|name, value| {
                            if payment.context.is_some() {
                                !name.eq_ignore_ascii_case(&config.payment_signature)
                            } else {
                                !name.eq_ignore_ascii_case("authorization")
                                    || !value.as_str().is_some_and(|value| value.starts_with("Payment "))
                            }
                        });
                    }
                    if let Some(stream) = stream_request.as_mut() {
                        payment.strip_consumed_headers(&mut stream.headers, &config.payment_signature);
                    }
                }
                let receipt = match payment.receipt_header(config) {
                    Ok(receipt) => receipt,
                    Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid payment receipt header",
                    )).await,
                };
                body_bytes = payment.body;
                receipt
            }
            Err(result) => return result,
        }
    } else { None };

    // Derived variables used by the forwarding and response-processing code below.
    let surface_protocol = surface.channel_protocol();
    let mut outbound_creds = surface.outbound_credentials();
    if let Some(prepared) = modern_delegation.as_ref() {
        outbound_creds.retain(|binding| !prepared.handled_provider_ids.contains(&binding.credential_provider_id));
    }
    let active_variant_alias = variant_alias.map(|s| s.to_string());
    let resolved_surface = surface.clone();
    let deadline_ms: Option<u64> = message
        .message_body
        .get("deadline_ms")
        .and_then(|v| v.as_u64());

    // Refuse an already-elapsed request before any dispatch branch. The proxy
    // branches below return before the per-request timeout is applied further
    // down, so without this an expired envelope replayed onto a proxy channel
    // would still reach the backend.
    if let Some(deadline) = deadline_ms {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if deadline <= now_ms {
            channel_warn!(config_id, "Caller deadline already elapsed on receive (now={now_ms}ms, deadline={deadline}ms) — 504");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: serde_json::json!({
                    "status": 504,
                    "error": "Caller deadline elapsed before GW2 processed the request",
                }),
            };
        }
    }

    // Forward the request to the channel's target endpoint
    channel_info!(
        config_id,
        "🎯 Forwarding to channel target: {}",
        surface.target_endpoint()
    );

    // Check if this channel uses a2a-proxy:// backend (A2A Proxy)
    if surface.target_endpoint().starts_with("a2a-proxy://") {
        let Some(proxy_id) = crate::a2a_proxies::A2aProxyTargetAdapter::proxy_id_from_endpoint(surface.target_endpoint())
        else {
            let response = crate::a2a_proxies::target_adapter::json_rpc_target_error(
                &body_bytes,
                crate::a2a_proxies::target_adapter::A2aProxyTargetError::InvalidEndpoint,
            );
            return axum_response_to_forward_result(response).await;
        };
        channel_info!(config_id, "🔌 Channel uses A2A proxy backend: {}", proxy_id);

        if is_agent_card_request {
            match crate::a2a_proxies::resolve_prepared_agent_card_for_endpoint(
                GLOBAL_A2A_PROXY_STORE
                    .get()
                    .cloned(),
                surface.target_endpoint(),
                &surface,
                &surface.name,
                GLOBAL_VC_ISSUER.get(),
            )
            .await
            {
                Ok(Some(prepared)) => {
                    let card = prepared.card;
                    // Trust Recorder — writes TrAdmin records to configured TRs
                    // on discovery (agent-card) fetches so a fresh surface
                    // populates its trust registry on the first
                    // `.well-known/agent-card.json` request instead of waiting
                    // for the first real message. Fire-and-forget; idempotent
                    // — duplicate records log at DEBUG (`apply_trust_recorder`).
                    if let Some(ProtectedAgentIdentity::Managed { did, .. }) = &prepared.identity {
                        crate::trust_registry_verification::spawn_trust_recorder(
                            &surface,
                            did,
                            get_trust_registry_listener_manager(),
                        );
                    }
                    return ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: serde_json::json!({
                            "status": 200,
                            "headers": {
                                "content-type": "application/json",
                            },
                            "body": card.to_string(),
                        }),
                    };
                }
                Ok(None) => {}
                Err(err) => {
                    channel_warn!(config_id, "A2A proxy agent-card synthesis failed on fabric receive: {}", err);
                    let status = match err {
                        crate::a2a_proxies::A2aProxyTargetError::NotFound
                        | crate::a2a_proxies::A2aProxyTargetError::Disabled => 502,
                        crate::a2a_proxies::A2aProxyTargetError::StoreUnavailable
                        | crate::a2a_proxies::A2aProxyTargetError::InvalidEndpoint
                        | crate::a2a_proxies::A2aProxyTargetError::LoadFailed
                        | crate::a2a_proxies::A2aProxyTargetError::AgentCardPreparationFailed => 500,
                    };
                    return ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: serde_json::json!({
                            "status": status,
                            "headers": {
                                "content-type": "application/problem+json",
                            },
                            "body": serde_json::json!({
                                "type": "https://a2a-protocol.org/errors/proxy-error",
                                "title": if status == 500 { "Internal Server Error" } else { "Bad Gateway" },
                                "status": status,
                                "detail": err.to_string(),
                            }).to_string(),
                        }),
                    };
                }
            }
        }

        return handle_a2a_proxy_forward(
            message,
            &surface,
            channel_id,
            proxy_id,
            body_bytes,
            caller_identity,
        )
        .await;
    }

    // Check if this channel uses a proxy:// backend (MCP proxy)
    if surface.target_endpoint().starts_with("proxy://") && modern_request.is_none() {
        let proxy_id = &surface.target_endpoint()[8..];
        channel_info!(config_id, "🔌 Channel uses MCP proxy backend: {}", proxy_id);

        // Route through MCP proxy handler
        return handle_mcp_proxy_forward(
            message,
            &surface,
            channel_id,
            proxy_id,
            method,
            path,
            headers,
            body_bytes,
            caller_identity,
        )
        .await;
    }

    // Build the target URL (path includes query params if present)
    // When override_agent_card_location is enabled and this is an agent card request,
    // use the custom path relative to the target's origin (scheme + host + port),
    // stripping any sub-path from target_endpoint.
    let target_url = if is_agent_card_request
        && surface.override_agent_card_location()
        && surface.agent_card_location_path().is_some()
    {
        let custom_path = surface.agent_card_location_path().unwrap();
        let target_endpoint = surface.target_endpoint();
        let origin = if let Some(scheme_end) = target_endpoint.find("://") {
            let after_scheme = &target_endpoint[scheme_end + 3..];
            let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            &target_endpoint[..scheme_end + 3 + authority_end]
        } else {
            target_endpoint
        };
        let url = if custom_path.starts_with('/') {
            format!("{}{}", origin, custom_path)
        } else {
            format!("{}/{}", origin, custom_path)
        };
        channel_info!(
            config_id,
            "Agent card location override applied: {} (origin={}, custom_path={})",
            url, origin, custom_path
        );
        url
    } else {
        join_endpoint_path(surface.target_endpoint(), path)
    };

    channel_info!(
        config_id,
        "🌐 Making HTTP request: {} {}",
        method.to_uppercase(),
        target_url
    );

    // Start timer for latency measurement
    let start_time = std::time::Instant::now();

    let timeout = GLOBAL_FORWARD_TIMEOUT
        .get()
        .copied()
        .unwrap_or(std::time::Duration::from_secs(30));
    let client = match forward_client_for(&target_url, timeout).await {
        Ok(client) => client,
        Err(error) => {
            channel_warn!(config_id, "GW2: target {} blocked by egress policy: {}", target_url, error);
            return egress_blocked_forward_response();
        }
    };

    // Build the request
    let http_method = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut req = client.request(http_method.clone(), &target_url);

    // Track if content-type was set
    let mut has_content_type = false;

    // Determine the source-auth credential header to strip (must not leak upstream).
    let source_cred_header = surface.source_auth().and_then(|sa| sa.credential_header_name());
    let header_metadata_mapping = surface.access_point.header_metadata_mapping.as_ref();

    // Add headers if provided
    if let Some(ref headers_map) = headers {
        channel_info!(config_id, "  ↳ Adding {} headers", headers_map.len());
        for (key, value) in headers_map {
            let key_lower = key.to_lowercase();
            if key_lower == "content-type" {
                has_content_type = true;
            }
            // Skip content-length - it will be set automatically by reqwest based on actual body size
            if key_lower == "content-length" {
                channel_info!(
                    config_id,
                    "    Skipping content-length header (will be set automatically)"
                );
                continue;
            }
            // Skip host - reqwest sets :authority from the URL in HTTP/2;
            // forwarding an explicit Host header causes PROTOCOL_ERROR resets
            // from strict HTTP/2 servers (e.g. Google Frontend).
            if key_lower == "host" {
                channel_info!(
                    config_id,
                    "    Skipping host header (will be derived from target URL)"
                );
                continue;
            }
            // Skip the source-auth credential header — it was consumed by the
            // gateway for authentication and must not be forwarded upstream.
            if let Some(cred) = source_cred_header
                && key.eq_ignore_ascii_case(cred) {
                    channel_info!(
                        config_id,
                        "    Skipping source auth credential header: {}",
                        key
                    );
                    continue;
                }
            if header_metadata_mapping.is_some_and(|mapping| {
                mapping.strip_mapped_headers
                    && mapping
                        .headers
                        .iter()
                        .any(|mapped| key.eq_ignore_ascii_case(mapped.header.trim()))
            }) {
                channel_info!(config_id, "    Skipping mapped header: {}", key);
                continue;
            }
            if modern_request.is_some() && matches!(key_lower.as_str(), "mcp-session-id" | "last-event-id") {
                continue;
            }
            let values = match stream_request.as_ref() {
                Some(request) => request.headers.get_all(key).iter().filter_map(|value| value.to_str().ok()).collect::<Vec<_>>(),
                None => value.as_str().into_iter().collect(),
            };
            for value_str in values {
                channel_info!(config_id, "    Header: {}: {}", key, value_str);
                req = req.header(key.as_str(), value_str);
            }
        }
    } else {
        channel_info!(config_id, "  ↳ No headers to add");
    }

    // Inject target authentication credentials (if configured on the channel)
    if let Some(target_auth) = surface.target_auth() {
        // Build a secrets store from the storage path passed via message context
        let secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>> = match message
            .context
            .get("secrets_storage_path")
            .and_then(|v| v.as_str())
        {
            Some(path) => match crate::secrets::FilesystemSecretsStore::new_async(path).await {
                Ok(store) => Some(Arc::new(store) as Arc<dyn crate::secrets::SecretsStore>),
                Err(e) => {
                    channel_warn!(config_id, "Failed to create secrets store for target auth: {}", e);
                    None
                }
            },
            None => {
                channel_warn!(config_id, "No secrets_storage_path in message context for target auth");
                None
            }
        };

        match crate::proxy::handler::inject_target_auth_header(
            target_auth,
            &secrets_store,
            &surface.name,
            crate::proxy::handler::CallerAssertion::Authenticated,
        )
        .await
        {
            Ok(Some((header_name, header_value))) => {
                req = req.header(&header_name, &header_value);
                channel_info!(config_id, "Injected target authentication header: {}", header_name);
            }
            Ok(None) => {
                // CredentialLookup method not implemented, skip
            }
            Err(e) => {
                channel_error!(config_id, "Failed to resolve target authentication: {}", e);
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: serde_json::json!({
                                "status": 502,
                                "headers": {
                                    "content-type": "application/problem+json",
                                },
                                "body": serde_json::json!({
                                    "type": "about:blank",
                                    "title": "Bad Gateway",
                                    "status": 502,
                                    "detail": "Target authentication configuration error",
                                }).to_string(),
                                "error": "Target authentication configuration error",
                            }),
                        };
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        channel_warn!(
                            config_id,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                    }
                }
            }
        }
    }

    // Inject custom metadata for MCP protocol
    if surface_protocol == crate::config::ChannelProtocol::Mcp
        && let Some(custom_metadata) = surface.custom_metadata()
        && custom_metadata.enabled
        && method.eq_ignore_ascii_case("POST")
        && !body_bytes.is_empty()
    {
        let injected = match crate::mcp::metadata::inject_custom_metadata_with_context(
            &body_bytes, custom_metadata, config_id, &get_secrets_store(),
            crate::protocols::MetadataRuntimeContext { request_id: audit_trace_id, surface_id: Some(config_id) },
            mcp_metadata_context, crate::mcp::meta::McpMetaTarget::Params,
        ).await {
            Ok(injected) => injected,
            Err(error) => {
                channel_warn!(config_id, "MCP metadata injection failed: {}", error);
                return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "MCP metadata injection failed")).await;
            }
        };
        body_bytes = injected.body;
        for (name, value) in injected.extra_headers {
            req = req.header(name, value);
        }
    }

    // ── Credential delegation: inject delegated OAuth tokens or signal consent ──
    if !outbound_creds.is_empty() {
        // Derive user identity hash from caller_identity (already a DID or identity hash from VP)
        // or fall back to authenticated_identity from source_auth
        let delegation_user_hash: Option<String> = caller_identity.clone().or_else(|| {
            authenticated_identity.as_ref().map(|id| {
                use sha2::{Digest, Sha256};
                let raw = match id {
                    crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, .. } => {
                        subject.clone()
                    }
                    crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => {
                        key_name.clone()
                    }
                    crate::source_auth::AuthenticatedIdentity::DidAuth { did } => did.clone(),
                    crate::source_auth::AuthenticatedIdentity::Mtls { principal, .. } => {
                        principal.clone()
                    }
                };
                format!("{:x}", Sha256::digest(raw.as_bytes()))
            })
        });

        if let (
            Some(user_hash),
            Some(vault_store),
            Some(provider_store),
            Some(secrets_store),
            Some(base_url),
        ) = (
            &delegation_user_hash,
            get_delegation_vault_store(),
            get_credential_provider_store(),
            get_secrets_store(),
            get_gateway_base_url(),
        ) {
            channel_info!(
                config_id,
                "GW2: Resolving credential delegation for {} bindings (user_hash={})",
                outbound_creds.len(),
                &user_hash[..8.min(user_hash.len())]
            );

            let delegation_results =
                crate::proxy::credential_delegation::resolve_delegation_credentials(
                    &outbound_creds,
                    user_hash,
                    surface.target_endpoint(),
                    config_id,
                    None, // MCP tool name not available in DIDComm path
                    &vault_store,
                    &provider_store,
                    &secrets_store,
                    &base_url,
                    true, // via_fabric = true (G2G path)
                    None, // audit context not yet available in G2G path
                    // The caller identity here is asserted by the peer gateway, not
                    // verified against the consenting issuer, so it can never unlock
                    // a modern consent record.
                    None,
                )
                .await;

            if delegation_results.iter().any(|resolution| matches!(
                &resolution.result,
                crate::proxy::credential_delegation::DelegationLookupResult::Unavailable
            )) {
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 503,
                        "headers": {"content-type": "text/plain", "cache-control": "no-store"},
                        "body": "Delegated credentials unavailable",
                    }),
                };
            }

            // Check for consent_required — if any binding needs consent, return immediately as ForwardResponse
            let mut consent_entries = Vec::new();
            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::ConsentRequired {
                    authorization_url,
                    provider_name,
                    scopes,
                } = &resolution.result
                {
                    consent_entries.push(serde_json::json!({
                        "provider_name": provider_name,
                        "authorization_url": authorization_url,
                        "scopes": scopes,
                    }));
                }
            }

            if !consent_entries.is_empty() {
                channel_info!(
                    config_id,
                    "GW2: Credential delegation requires consent for {} providers — returning consent_required via DIDComm",
                    consent_entries.len()
                );
                let consent_body = serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/consent-required",
                    "title": "Credential Delegation Consent Required",
                    "status": 401,
                    "detail": "This channel requires delegated credentials. The user must authorize access via the provided URLs.",
                    "consent_required": consent_entries,
                });
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 401,
                        "headers": {
                            "content-type": "application/problem+json",
                        },
                        "body": consent_body.to_string(),
                    }),
                };
            }

            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::Inject(
                    injections,
                ) = &resolution.result
                {
                    for injection in injections {
                        match injection {
                            crate::proxy::credential_delegation::ResolvedCredentialInjection::McpMeta { field, value } => {
                                match crate::proxy::credential_delegation::inject_delegated_credential_into_mcp_meta(
                                    &body_bytes,
                                    field,
                                    value,
                                ) {
                                    Ok(modified) => {
                                        body_bytes = modified.into();
                                        channel_info!(
                                            config_id,
                                            "GW2: Injected delegated credential into MCP metadata: {}",
                                            field
                                        );
                                    }
                                    Err(error) => {
                                        channel_warn!(
                                            config_id,
                                            "GW2: Failed to inject delegated credential into MCP metadata {}: {}",
                                            field,
                                            error
                                        );
                                        return ProcessingResult::RequiresResponse {
                                            response_type: MessageType::ForwardResponse.to_string(),
                                            response_body: serde_json::json!({
                                                "status": 500,
                                                "headers": {
                                                    "content-type": "application/problem+json",
                                                },
                                                "body": serde_json::json!({
                                                    "type": "https://affinidi.com/atg/errors/credential-delegation-injection-failed",
                                                    "title": "Credential Delegation Injection Failed",
                                                    "status": 500,
                                                    "detail": "Failed to inject delegated credential into MCP metadata",
                                                }).to_string(),
                                            }),
                                        };
                                    }
                                }
                            }
                            crate::proxy::credential_delegation::ResolvedCredentialInjection::Header { name, value } => {
                                req = req.header(name, value);
                                channel_info!(
                                    config_id,
                                    "GW2: Injected delegated credential header: {}",
                                    name
                                );
                            }
                        }
                    }
                }
            }
        } else {
            channel_warn!(
                config_id,
                "GW2: Credential delegation configured but stores or user identity not available — skipping"
            );
        }
    }

    if let Some(prepared) = modern_delegation.as_ref() {
        let injected = prepared.inject_body_credentials(&body_bytes)
            .and_then(|body| prepared.credential_headers().map(|headers| (body, headers)));
        match injected {
            Ok((body, headers)) => {
                body_bytes = body;
                req = req.headers(headers);
            }
            Err(error) => {
                let request = &prepared.request;
                return axum_response_to_forward_result(
                    crate::proxy::credential_delegation::modern::ModernDelegationError::from(error).response(request),
                ).await;
            }
        }
    }

    // Add body if provided and not empty
    let request_bytes = body_bytes.len() as u64;
    if !body_bytes.is_empty() {
        channel_info!(
            config_id,
            "  ↳ Adding request body: {} bytes",
            body_bytes.len()
        );
        // Ensure Content-Type is set BEFORE adding body
        if !has_content_type {
            req = req.header("Content-Type", "application/json");
        }

        // For MCP channels, advertise SSE support so upstream agents can stream
        if surface_protocol == crate::config::ChannelProtocol::Mcp && modern_request.is_none() {
            req = req.header("Accept", "text/event-stream, application/json");
        }

        req = req.body(body_bytes.clone());
    } else {
        channel_info!(config_id, "  ↳ No request body");
    }

    // Re-emit a trace id on the onward forward so a downstream hop (another gateway,
    // or an agent that re-transits back through a transit point) continues the
    // trace. Normally this is the request's own trace (`REQUEST_TRACE_ID`); when the
    // surface terminates traces we forward a FRESH id instead, so this gateway's own
    // VP/audit keep the incoming trace (past stays traceable) while the downstream
    // chain is isolated from it.
    let onward_trace_id = if surface.access_point.terminate_trace_id {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        crate::observability::policy_audit::current_span_trace_id()
    };
    if let Some(tid) = onward_trace_id {
        req = req.header("X-Gateway-Trace-Id", tid);
    }

    // Send the request
    channel_debug!(config_id, "Sending request to {}", target_url);

    let mut header_timeout = std::time::Duration::from_secs(surface.timeout().map(|timeout| timeout.request_secs).unwrap_or(30));
    if modern_request.is_some() {
        req = req.timeout(std::time::Duration::from_secs(surface.mcp_http.clone().unwrap_or_default().stream_max_lifetime_secs.get()));
    }

    // Apply the caller-deadline as a hard reqwest timeout so a hung upstream
    // cannot keep the dispatch task alive past the caller's wait window.
    if let Some(deadline) = deadline_ms {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        match deadline.checked_sub(now_ms) {
            Some(remaining) if remaining > 0 => {
                header_timeout = header_timeout.min(std::time::Duration::from_millis(remaining));
                req = req.timeout(std::time::Duration::from_millis(remaining));
            }
            _ => {
                channel_warn!(config_id, "Deadline already elapsed at reqwest dispatch (now={now_ms}ms, deadline={deadline}ms) — 504");
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 504,
                        "error": "Caller deadline elapsed before GW2 dispatched the upstream request",
                    }),
                };
            }
        }
    }

    // MCP shortcut: if we already have a persistent SSE session to this upstream
    // (established during a previous request that got 400), use it directly
    // instead of trying a plain POST that we know will fail.
    if surface_protocol == crate::config::ChannelProtocol::Mcp && modern_request.is_none() && !body_bytes.is_empty() {
        // Check if a persistent session already exists (cheap read lock check)
        let has_session = {
            let sessions = crate::mcp::sse_transport::UPSTREAM_SSE_SESSIONS
                .sessions
                .read()
                .await;
            sessions.contains_key(&target_url)
        };

        if has_session {
            channel_info!(config_id, "GW2: Reusing persistent SSE session for {}", target_url);
            let response_start = std::time::Instant::now();

            match crate::mcp::sse_transport::send_via_persistent_sse(
                &client,
                &target_url,
                &body_bytes,
                channel_id,
                fabric_max_response_bytes(),
            )
            .await
            {
                Ok(json_response) if !json_response.is_empty() => {
                    channel_info!(config_id, "GW2: Persistent SSE session succeeded (reuse)");
                    let response_time_ms = response_start.elapsed().as_millis() as u64;
                    let response_bytes = json_response.len() as u64;

                    return ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: serde_json::json!({
                            "status": 200,
                            "body": json_response,
                            "headers": {
                                "content-type": "application/json"
                            },
                            "metrics": {
                                "request_bytes": request_bytes,
                                "response_bytes": response_bytes,
                                "latency_ms": response_time_ms,
                            }
                        }),
                    };
                }
                Ok(_) => {
                    return ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: serde_json::json!({
                            "status": 202,
                            "body": "",
                        }),
                    };
                }
                Err(e) => {
                    channel_warn!(config_id, "GW2: Persistent SSE session (reuse) failed: {}", e);
                    // Fall through to try plain POST as the session may have expired
                }
            }
        }
    }

    let response = if let Some(request) = modern_request.as_ref()
        && let Some(proxy_id) = surface.target_endpoint().strip_prefix("proxy://")
    {
        use crate::mcp_proxies::McpProxyStore;
        let Some(store) = GLOBAL_MCP_PROXY_STORE.get() else {
            return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE, "MCP proxy storage is unavailable",
            )).await;
        };
        let proxy = match store.get(proxy_id).await {
            Ok(Some(proxy)) => proxy,
            Ok(None) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::NOT_FOUND, "MCP proxy was not found",
            )).await,
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE, "MCP proxy storage is unavailable",
            )).await,
        };
        let prepared = match req.build() {
            Ok(prepared) => prepared,
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare modern MCP proxy request",
            )).await,
        };
        let execute = crate::mcp_proxies::handlers::handle_modern_surface_http_request(
            &proxy, &surface, request, prepared, &client,
            crate::mcp::request_validation::runtime_policy_for(
                crate::mcp::request_validation::McpPathKind::FabricReceive,
            ),
        );
        let result = match tokio::time::timeout(header_timeout, Box::pin(execute)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => return axum_response_to_forward_result((*error).into_response()).await,
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::GATEWAY_TIMEOUT, "Modern MCP proxy execution timed out",
            )).await,
        };
        let (parts, body) = result.into_parts();
        let response = axum::http::Response::from_parts(parts, reqwest::Body::wrap_stream(body.into_data_stream()));
        Ok(reqwest::Response::from(response))
    } else if modern_request.is_some() {
        match tokio::time::timeout(header_timeout, req.send()).await {
            Ok(response) => response,
            Err(_) => return axum_response_to_forward_result(crate::a2a::create_error_response(
                axum::http::StatusCode::GATEWAY_TIMEOUT, "Modern MCP upstream response headers timed out",
            )).await,
        }
    } else { req.send().await };
    match response {
        Ok(response) => {
            // Start response timer (measures response processing time)
            let response_start = std::time::Instant::now();
            let status = response.status().as_u16();

            // MCP Legacy SSE fallback: if the upstream rejects a plain POST
            // (400/404/405), it likely only supports Legacy SSE transport.
            // Retry by connecting via GET /sse, obtaining a session endpoint,
            // and posting the JSON-RPC body to that endpoint.
            if surface_protocol == crate::config::ChannelProtocol::Mcp
                && modern_request.is_none()
                && !body_bytes.is_empty()
                && matches!(status, 400 | 404 | 405)
            {
                channel_info!(
                    config_id,
                    "GW2: Upstream returned {} for plain POST — trying Legacy SSE transport",
                    status
                );

                // Drop the failed response, try persistent Legacy SSE session
                drop(response);

                match crate::mcp::sse_transport::send_via_persistent_sse(
                    &client,
                    &target_url,
                    &body_bytes,
                    channel_id,
                    fabric_max_response_bytes(),
                )
                .await
                {
                    Ok(json_response) if !json_response.is_empty() => {
                        channel_info!(config_id, "GW2: Persistent SSE session succeeded");
                        let response_time_ms = response_start.elapsed().as_millis() as u64;
                        let response_bytes = json_response.len() as u64;

                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: serde_json::json!({
                                "status": 200,
                                "body": json_response,
                                "headers": {
                                    "content-type": "application/json"
                                },
                                "metrics": {
                                    "request_bytes": request_bytes,
                                    "response_bytes": response_bytes,
                                    "latency_ms": response_time_ms,
                                }
                            }),
                        };
                    }
                    Ok(_) => {
                        // Empty response (notification) — success with no body
                        channel_info!(config_id, "GW2: Persistent SSE session succeeded (notification, no response)");
                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: serde_json::json!({
                                "status": 202,
                                "body": "",
                            }),
                        };
                    }
                    Err(e) => {
                        channel_warn!(config_id, "GW2: Persistent SSE session also failed: {}", e);
                        // Fall through — the original error will be returned below
                        // Reconstruct a minimal error response since we dropped the original
                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: serde_json::json!({
                                "status": status,
                                "body": format!("{{\"error\":\"Upstream returned {} and Legacy SSE fallback failed: {}\"}}", status, e),
                            }),
                        };
                    }
                }
            }

            // Check if upstream responded with SSE (MCP Streamable HTTP)
            let is_sse_response = surface_protocol == crate::config::ChannelProtocol::Mcp
                && response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(crate::mcp::sse_transport::is_sse_content_type)
                    .unwrap_or(false);
                    let modern_limits = crate::mcp::modern_sse::SseLimits::from(&surface.mcp_http.clone().unwrap_or_default());
                    let mut modern_headers = response.headers().clone();
                    if let Some((name, receipt)) = modern_payment_receipt.as_ref() {
                        modern_headers.insert(name.clone(), receipt.clone());
                    }

            // Filter out hop-by-hop headers and content-length that should not be forwarded
            // content-length will be set automatically by the HTTP layer based on actual body.
            // Every value of a header repeated more than once (e.g. MPP's per-method
            // `WWW-Authenticate`) is preserved rather than collapsed to the last one.
            let mut response_headers: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for (k, v) in modern_headers.iter()
            {
                let key_lower = k.as_str().to_lowercase();

                // Skip hop-by-hop headers and content-length
                if matches!(
                    key_lower.as_str(),
                    "transfer-encoding"
                        | "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                        | "trailers"
                        | "upgrade"
                        | "content-length" // Skip content-length - will be set by HTTP layer
                ) {
                    continue;
                }
                if let Ok(v_str) = v.to_str() {
                    response_headers
                        .entry(k.as_str().to_string())
                        .or_default()
                        .push(v_str.to_string());
                }
            }

            // If the upstream returned SSE we have already consumed the stream
            // into a plain JSON payload below. Forwarding the original
            // `content-type: text/event-stream` (or the upstream's
            // `content-encoding`) would mis-frame the response on the GW1
            // side, so override the content-type and drop any encoding header.
            if is_sse_response {
                response_headers.remove("content-type");
                response_headers.remove("Content-Type");
                response_headers.remove("content-encoding");
                response_headers.remove("Content-Encoding");
                response_headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
            }

            let (modern_response, response_body) = if modern_request.is_some() {
                (Some(response), String::new())
            } else {
                match read_forward_target_body(response, is_sse_response, &body_bytes, fabric_body_limits(&surface), config_id).await {
                    Ok(body) => (None, body),
                    Err(result) => return result,
                }
            };
            let channel_id_owned = channel_id.to_string();
            let config_id_owned = config_id.to_string();
            let method_owned = method.to_string();
            let path_owned = path.to_string();
            let audit_trace_owned = audit_trace_id.map(str::to_string);
            let identity_rules_owned = identity_ext_rules.cloned();
            let discovery_support = crate::mcp::modern::ForwardingSupport::for_endpoint(
                false,
                crate::mcp::request_validation::McpPathKind::FabricReceive,
            )
            .restrict_to_fabric_peer(stream_request.as_ref().map(|request| &request.capabilities));
            let framed_response = stream_request.is_some();
            let is_modern_response = modern_request.is_some();
            let modern_completion = if is_modern_response {
                let tracked_task_id = ensure_task_registered(&resolved_surface).await;
                let monitor = GLOBAL_TASK_MONITOR.get().cloned();
                if let (Some(monitor), Some(task_id)) = (&monitor, &tracked_task_id) {
                    monitor.increment_connections(task_id).await;
                }
                let mut guard = crate::server::ConnectionGuard::new(monitor.clone(), tracked_task_id.clone());
                let metrics = GLOBAL_METRICS_STORE.get().cloned();
                let metric_surface = config_id.to_string();
                let metric_source = message.from_did.clone().unwrap_or_else(|| "unknown".to_string());
                let metric_target = target_url.clone();
                let metric_identity = caller_identity.clone();
                let metric_trace = audit_trace_id.map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let metric_variant = active_variant_alias.clone();
                Some(move |outcome: crate::mcp::modern_sse::ResponseOutcome| {
                    let latency = start_time.elapsed().as_millis() as u64;
                    tokio::spawn(async move {
                        guard.decrement().await;
                        if let (Some(monitor), Some(task_id)) = (monitor, tracked_task_id) {
                            monitor.record_bytes(&task_id, request_bytes, outcome.bytes).await;
                            if !outcome.completed || outcome.failed { monitor.increment_errors(&task_id).await; }
                        }
                        if let Some(metrics) = metrics {
                            let result = if outcome.completed && !outcome.failed && (200..300).contains(&status) {
                                crate::metrics::ConnectionStatus::Success
                            } else { crate::metrics::ConnectionStatus::Failed };
                            metrics.record_connection_with_bytes_and_ucp(
                                metric_surface.clone(), metric_source.clone(), metric_target.clone(), result,
                                Some(latency), metric_identity.clone(), crate::metrics::ConnectionDirection::Request,
                                metric_trace.clone(), request_bytes, 0, None, None, None, latency, metric_variant.clone(),
                            ).await;
                            metrics.record_connection_with_bytes(
                                metric_surface, metric_target, metric_source, result, Some(latency), metric_identity,
                                crate::metrics::ConnectionDirection::Response, metric_trace, 0, outcome.bytes, None, None,
                                latency, metric_variant,
                            ).await;
                        }
                    });
                })
            } else { None };
            let message = message.clone();
            let process_response = async move |mut response_body: String, mut response_headers: std::collections::HashMap<String, Vec<String>>| {
            let channel_id = channel_id_owned.as_str();
            let config_id = config_id_owned.as_str();
            let method = method_owned.as_str();
            let path = path_owned.as_str();
            let audit_trace_id = audit_trace_owned.as_deref();
            let identity_ext_rules = identity_rules_owned.as_ref();
            let mut body_modified = false;
            if surface_protocol == crate::config::ChannelProtocol::Mcp {
                response_body = match crate::mcp::meta::normalize_text(&response_body, mcp_metadata_context) {
                    Ok(body) => body,
                    Err(error) => return axum_response_to_forward_result(error.into_response(response_body.as_bytes(), axum::http::StatusCode::BAD_GATEWAY)).await,
                };
            }

            // GW2: Inject trust registry extension into agent card responses for fabric requests
            if is_agent_card_request && status == 200 && !response_body.is_empty() {
                info!(
                    config_id,
                    "GW2: Agent card response detected, checking for trust registry injection"
                );

                if let Ok(mut agent_card) = serde_json::from_str::<serde_json::Value>(&response_body) {
                    // Resolve protected agent identity from agent card (Step 12 for GW2)
                    let card_bytes = response_body.as_bytes();
                    // Compile the identity engines from `identity_slots.protected` so
                    // the agent-card identity extraction has a real selector — mirroring
                    // what `proxy/handler.rs` does on the direct AP path. Historically
                    // this was hard-coded to `None` (predates the `identity_slots`
                    // refactor), which forced every fabric-served card to inject
                    // without `agent_did`, and downstream target-leg Trust Check
                    // templates like `{{ input.agent.did }}` couldn't resolve.
                    let gw2_compiled_engines = GLOBAL_VC_ISSUER.get().and_then(|issuer| {
                        crate::proxy::compile_identity_engines_from_surface(&resolved_surface, Some(issuer))
                            .map_err(|e| {
                                channel_warn!(
                                    config_id,
                                    "GW2: Failed to compile identity engines for agent-card identity resolution: {} — falling back to Anonymous",
                                    e
                                );
                                e
                            })
                            .ok()
                    });
                    let gw2_identity_selector = gw2_compiled_engines
                        .as_ref()
                        .and_then(|c| c.protected_selector.as_ref());
                    let gw2_identity_rules = gw2_compiled_engines
                        .as_ref()
                        .and_then(|c| c.protected_rules_engine.as_ref());
                    let surface = &resolved_surface;
                    let resolved_identity = match crate::proxy::backend_identity::resolve_protected_agent_identity(
                        card_bytes,
                        surface,
                        gw2_identity_selector,
                        gw2_identity_rules,
                        channel_id,
                        true,
                        None, // agent-card response has no inbound caller token
                    )
                    .await
                    {
                        Ok(identity) => identity,
                        Err(e) => {
                            channel_warn!(
                                config_id,
                                "GW2: Protected agent identity resolution failed for agent card: {}",
                                e
                            );
                            ProtectedAgentIdentity::Anonymous
                        }
                    };

                    // Track whether any injection mutated the card so a single
                    // re-serialization at the end captures every change — even
                    // when trust-registry injection is disabled but the identity
                    // credential was injected.
                    let mut card_changed = false;

                    // GW2: inject the signed identity credential (agent-identity/v1
                    // → agent-identity-credential/v1 + VP + params.did), mirroring
                    // the direct inbound path (`proxy/handler.rs`). Without this the
                    // fabric-served card carried only the trust-registry extension,
                    // so a consuming gateway's `build_agent_context` saw the TR
                    // `agent_did` with no identity credential DID to cross-validate
                    // against. Skipped for an Anonymous identity; an injection error
                    // is logged and does not fail the fabric exchange.
                    if !matches!(resolved_identity, ProtectedAgentIdentity::Anonymous)
                        && let Some(vc_issuer) = GLOBAL_VC_ISSUER.get()
                    {
                        card_changed |=
                            crate::a2a::inject_credential_into_agent_card(&mut agent_card, &resolved_identity, vc_issuer, channel_id)
                                .await
                                .inspect_err(|e| {
                                    channel_warn!(config_id, "GW2: Failed to inject identity credential into agent card: {}", e)
                                })
                                .is_ok();
                    }

                    // Single re-serialization: fold whichever injections ran
                    // back into the response body exactly once.
                    if card_changed
                        && let Ok(new_body) = serde_json::to_string(&agent_card)
                    {
                        response_body = new_body;
                        body_modified = true;
                    }

                    // Trust Recorder — writes TrAdmin records to configured
                    // TRs on discovery (agent-card) fetches so a fresh
                    // surface populates its trust registry on the first
                    // `.well-known/agent-card.json` request instead of
                    // waiting for the first real message. Fire-and-forget;
                    // idempotent — duplicate records log at DEBUG
                    // (`apply_trust_recorder`).
                    if let ProtectedAgentIdentity::Managed { did, .. } = &resolved_identity {
                        crate::trust_registry_verification::spawn_trust_recorder(
                            &resolved_surface,
                            did,
                            get_trust_registry_listener_manager(),
                        );
                    }
                } else {
                    channel_warn!(
                        config_id,
                        "GW2: Failed to parse agent card response as JSON"
                    );
                }
            }

            // Inject response custom metadata if enabled (separate from request metadata)
            if !response_body.is_empty()
                && let Some(response_custom_metadata) = surface.response_custom_metadata()
                && response_custom_metadata.enabled
            {
                match surface_protocol {
                    crate::config::ChannelProtocol::A2a
                    | crate::config::ChannelProtocol::Ap2
                    | crate::config::ChannelProtocol::DIDComm => {
                        // For A2A/AP2 protocol, inject into message.metadata
                        channel_info!(config_id, "GW2: Injecting response custom metadata (A2A)");
                        match crate::a2a::inject_custom_metadata_extension(
                            &bytes::Bytes::from(response_body.clone()),
                            response_custom_metadata,
                            channel_id,
                            &None,
                            crate::protocols::MetadataRuntimeContext {
                                request_id: audit_trace_id,
                                surface_id: Some(config_id),
                            },
                        )
                        .await
                        {
                            Ok(modified_body) => {
                                response_body = String::from_utf8_lossy(&modified_body).to_string();
                                body_modified = true;
                                channel_info!(
                                    config_id,
                                    "GW2: Response custom metadata extension injected (A2A)"
                                );
                            }
                            Err(e) => {
                                channel_warn!(
                                    config_id,
                                    "GW2: Failed to inject response custom metadata extension: {}",
                                    e
                                );
                            }
                        }
                    }
                    crate::config::ChannelProtocol::Mcp => {
                        let injected = match crate::mcp::metadata::inject_custom_metadata_with_context(
                            &bytes::Bytes::from(response_body.clone()), response_custom_metadata, config_id, &get_secrets_store(),
                            crate::protocols::MetadataRuntimeContext { request_id: audit_trace_id, surface_id: Some(config_id) },
                            mcp_metadata_context, crate::mcp::meta::McpMetaTarget::Result,
                        ).await {
                            Ok(injected) => injected,
                            Err(error) => {
                                channel_warn!(config_id, "MCP response metadata injection failed: {}", error);
                                return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::BAD_GATEWAY, "MCP response metadata injection failed")).await;
                            }
                        };
                        response_body = String::from_utf8_lossy(&injected.body).into_owned();
                        body_modified = true;
                        for (name, value) in injected.extra_headers {
                            response_headers.insert(name.to_string(), vec![value.to_str().unwrap_or_default().to_string()]);
                        }
                    }
                }
            }

            // Inject responding gateway DID for fabric-to-fabric connections
            // This allows tracking gateway-to-gateway communication in metrics
            // Use the actual gateway DID (not connection point DID) to avoid information leakage
            if !response_body.is_empty() {
                // Get the local gateway DID from the global VC issuer (if available)
                let local_gateway_did = if let Some(vc_issuer) = GLOBAL_VC_ISSUER.get() {
                    vc_issuer.get_issuer_did().await.ok()
                } else {
                    None
                };

                if let Some(gateway_did) = local_gateway_did
                    && let Ok(mut json_body) =
                        serde_json::from_str::<serde_json::Value>(&response_body)
                    && (surface_protocol != crate::config::ChannelProtocol::Mcp || crate::mcp::meta::permits_result_enrichment(&json_body))
                    && let Some(obj) = json_body.as_object_mut()
                {
                    let gateway_did_field = "x-affinidi-fabric-gateway-did";

                    match surface_protocol {
                        crate::config::ChannelProtocol::Mcp => {
                            // For MCP, inject into result._meta field
                            if let Some(result) = obj.get_mut("result").and_then(|r| r.as_object_mut()) {
                                let meta = result.entry("_meta").or_insert(serde_json::json!({}));
                                if let Some(meta_obj) = meta.as_object_mut() {
                                    meta_obj.insert(
                                        gateway_did_field.to_string(),
                                        serde_json::json!(gateway_did),
                                    );
                                    channel_debug!(
                                        config_id,
                                        "GW2: Injected responding gateway DID into result._meta.{}: {}",
                                        gateway_did_field,
                                        gateway_did
                                    );
                                }
                            }
                        }
                        crate::config::ChannelProtocol::A2a
                        | crate::config::ChannelProtocol::Ap2
                        | crate::config::ChannelProtocol::DIDComm => {
                            // For A2A/AP2, inject into result.history[0].metadata if it exists
                            // Otherwise inject into top-level metadata
                            if let Some(result) = obj.get_mut("result") {
                                if let Some(history) =
                                    result.get_mut("history").and_then(|h| h.as_array_mut())
                                    && let Some(first_msg) = history.first_mut()
                                    && let Some(msg_obj) = first_msg.as_object_mut()
                                {
                                    let metadata =
                                        msg_obj.entry("metadata").or_insert(serde_json::json!({}));
                                    if let Some(metadata_obj) = metadata.as_object_mut() {
                                        let did_array = metadata_obj
                                            .entry(gateway_did_field.to_string())
                                            .or_insert_with(|| serde_json::json!([]));

                                        if let Some(arr) = did_array.as_array_mut() {
                                            arr.push(serde_json::json!(gateway_did));
                                            channel_debug!(
                                                config_id,
                                                "GW2: Appended responding gateway DID to result.history[0].metadata.{} array: {}",
                                                gateway_did_field,
                                                gateway_did
                                            );
                                        } else {
                                            // If it exists but is not an array, convert it to array
                                            let existing_value = did_array.clone();
                                            *did_array =
                                                serde_json::json!([existing_value, gateway_did]);
                                            channel_debug!(
                                                config_id,
                                                "GW2: Converted result.history[0].metadata.{} to array and appended DID: {}",
                                                gateway_did_field,
                                                gateway_did
                                            );
                                        }
                                    }
                                }
                            } else if let Some(message) =
                                obj.get_mut("message").and_then(|m| m.as_object_mut())
                            {
                                // Fallback: inject into message.metadata
                                let metadata =
                                    message.entry("metadata").or_insert(serde_json::json!({}));
                                if let Some(metadata_obj) = metadata.as_object_mut() {
                                    metadata_obj.insert(
                                        gateway_did_field.to_string(),
                                        serde_json::json!(gateway_did),
                                    );
                                    channel_debug!(
                                        config_id,
                                        "GW2: Injected responding gateway DID into message.metadata.{}: {}",
                                        gateway_did_field,
                                        gateway_did
                                    );
                                }
                            }
                        }
                    }

                    // Update response_body with modified JSON
                    if let Ok(new_body) = serde_json::to_string(&json_body) {
                        response_body = new_body;
                        body_modified = true;
                        channel_info!(
                            config_id,
                            "GW2: Responding gateway DID injected into fabric response"
                        );
                    }
                }
            }

            // Update Content-Length header if body was modified
            // This prevents hyper panics due to Content-Length mismatch
            // NOTE: We don't actually need to set this header in response_headers
            // because when we return the response through DIDComm, the HTTP layer
            // will set Content-Length automatically based on the actual JSON payload size.
            // Including it here causes mismatches when the response is serialized to JSON.
            if body_modified {
                channel_debug!(
                    config_id,
                    "GW2: Body was modified (new length: {} bytes), Content-Length will be set automatically by HTTP layer",
                    response_body.len()
                );
            }

            channel_info!(config_id, "✅ Forward completed with status {}", status);

            // Broadcast payload capture if enabled
            if let Some(ws_state) = GLOBAL_WS_STATE.get()
                && let Some(metrics_store) = GLOBAL_METRICS_STORE.get()
            {
                let config_id = surface
                    .config_id()
                    .map(str::to_string)
                    .unwrap_or_else(|| channel_id.to_string());

                // Prepare request payload as JSON
                let request_payload: serde_json::Value = if !body_bytes.is_empty() {
                    // Try to parse as JSON, otherwise create synthetic JSON
                    serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
                        serde_json::json!({
                            "_raw_body": String::from_utf8_lossy(&body_bytes).to_string(),
                            "method": method.to_uppercase()
                        })
                    })
                } else {
                    // Create synthetic JSON for empty bodies like handler.rs does
                    serde_json::json!({
                        "method": method.to_uppercase(),
                        "_no_body": true
                    })
                };

                // Response payload as JSON
                let response_payload: Option<serde_json::Value> = if !response_body.is_empty() {
                    serde_json::from_str(&response_body).ok()
                } else {
                    Some(serde_json::json!({
                        "status": status,
                        "_no_body": true
                    }))
                };

                // Determine validation status based on HTTP status code
                let validation_status = if (200..300).contains(&status) {
                    "success"
                } else if (400..500).contains(&status) {
                    "client_error"
                } else if status >= 500 {
                    "server_error"
                } else {
                    "unknown"
                };

                // Broadcast the payload capture
                crate::observability::payload_capture::broadcast_payload_capture_async(
                    &Some(ws_state.clone()),
                    &Some(metrics_store.clone()),
                    channel_id,
                    &config_id,
                    &request_payload,
                    response_payload,
                    validation_status,
                    None,                    // validation_error
                    caller_identity.clone(), // identity_hash
                    active_variant_alias.as_deref(),
                )
                .await;

                channel_info!(config_id, "📡 Broadcast payload capture for fabric flow");
            }

            // GW2: Extract agent identity from response extensions (before metrics recording)
            let mut agent_identity: Option<String> = None;
            channel_info!(
                config_id,
                "GW2: Checking for agent identity extraction - has_identity_ext_rules: {}, response_empty: {}",
                identity_ext_rules.is_some(),
                response_body.is_empty()
            );

            if !response_body.is_empty() {
                // Try to extract agent identity from response
                if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&response_body)
                {
                    channel_info!(config_id, "GW2: Successfully parsed response as JSON");

                    // Build identity selector from managed_identity.extension_rules
                    let identity_selector = match (identity_ext_rules, GLOBAL_VC_ISSUER.get()) {
                        (None, _) => {
                            channel_info!(
                                config_id,
                                "GW2: Identity selector unavailable - no managed_identity.extension_rules on channel"
                            );
                            None
                        }
                        (_, None) => {
                            channel_info!(
                                config_id,
                                "GW2: Identity selector unavailable - GLOBAL_VC_ISSUER not initialized"
                            );
                            None
                        }
                        (Some(ext_rules), Some(vc_issuer)) => {
                            match &ext_rules.json_schema {
                                None => {
                                    channel_info!(
                                        config_id,
                                        "GW2: Identity selector unavailable - managed_identity.extension_rules has no json_schema"
                                    );
                                    None
                                }
                                Some(json_schema) => {
                                    match crate::identity::IdentitySelector::new(
                                        json_schema,
                                        vc_issuer.clone(),
                                    ) {
                                        Ok(selector) if selector.has_identity_fields() => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector built from managed_identity.extension_rules"
                                            );
                                            Some(Arc::new(selector))
                                        }
                                        Ok(_) => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector unavailable - schema has no x-identity fields"
                                            );
                                            None
                                        }
                                        Err(e) => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector unavailable - schema compilation failed: {}",
                                                e
                                            );
                                            None
                                        }
                                    }
                                }
                            }
                        }
                    };

                    // Look for agent identity in response - extensions array contains URIs, data is in metadata
                    // Response structure can be either:
                    // - Multi-message: result.history[0].metadata[extension_uri]
                    // - Single message: result.metadata[extension_uri] (direct Message response)
                    let message_obj = response_json.get("result").and_then(|r| {
                        // Try history first (multi-message response)
                        if let Some(history) = r.get("history").and_then(|h| h.as_array()).and_then(|arr| arr.first()) {
                            info!("GW2: Found response in result.history[0]");
                            Some(history)
                        } else if r.get("metadata").is_some() || r.get("extensions").is_some() {
                            // Direct message response (single message completion)
                            info!("GW2: Found response directly in result");
                            Some(r)
                        } else {
                            warn!("GW2: Response has result but no history or metadata");
                            None
                        }
                    });

                    if let Some(message_msg) = message_obj {
                        if let Some(extensions) =
                            message_msg.get("extensions").and_then(|e| e.as_array())
                        {
                            channel_info!(
                                config_id,
                                "GW2: Found {} extension URIs in response",
                                extensions.len()
                            );

                            // Check if agent-identity extension is declared
                            let has_identity_ext = extensions.iter().any(|ext| {
                                ext.as_str()
                                    == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
                            });

                            if has_identity_ext {
                                channel_info!(
                                    config_id,
                                    "GW2: Agent identity extension is declared in response"
                                );

                                // Get the actual extension data from metadata
                                if let Some(metadata) = message_msg.get("metadata") {
                                    if let Some(identity_ext) = metadata
                                        .get(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
                                    {
                                        channel_info!(
                                            config_id,
                                            "GW2: Found identity extension in response metadata: {}",
                                            serde_json::to_string_pretty(identity_ext)
                                                .unwrap_or_default()
                                                .chars()
                                                .take(500)
                                                .collect::<String>()
                                        );

                                        // Check if agent already sent a DID
                                        if let Some(did) =
                                            identity_ext.get("did").and_then(|d| d.as_str())
                                        {
                                            agent_identity = Some(did.to_string());
                                            channel_info!(
                                                config_id,
                                                "GW2: Agent identity from DID: {}",
                                                did
                                            );
                                        } else {
                                            // Agent sent raw payload - compute identity using IdentitySelector
                                            if let Some(ref selector) = identity_selector {
                                                channel_info!(
                                                    config_id,
                                                    "GW2: Computing agent identity using IdentitySelector"
                                                );
                                                match selector
                                                    .compute_identity(
                                                        identity_ext,
                                                        channel_id,
                                                        surface.config_id().map(str::to_string),
                                                        surface.issuer_id.clone(),
                                                        crate::identity::filesystem::IdentityOrigin::Managed,
                                                    )
                                                    .await
                                                {
                                                    Ok(identity_result) => {
                                                        agent_identity =
                                                            Some(identity_result.did.clone());
                                                        crate::observability::record_caller_did_on_current_span(
                                                            &identity_result.did,
                                                        );
                                                        channel_info!(
                                                            config_id,
                                                            "GW2: Agent identity computed: {} (is_new: {})",
                                                            identity_result.did,
                                                            identity_result.is_new
                                                        );

                                                        // Trigger identity.appeared if this is a new identity appearing on the channel
                                                        if identity_result.is_new
                                                            && let Some(notif_store) =
                                                                GLOBAL_NOTIFICATION_STORE.get()
                                                        {
                                                            let did_clone =
                                                                identity_result.did.clone();
                                                            let channel_id_clone =
                                                                channel_id.to_string();
                                                            let notif = (*notif_store).clone();
                                                            tokio::spawn(async move {
                                                                crate::integrations::async_triggers::trigger_identity_appeared(
                                                                        Some(notif.clone()),
                                                                        &did_clone,
                                                                        &channel_id_clone,
                                                                    ).await;
                                                            });
                                                        }
                                                    }
                                                    Err(e) => {
                                                        channel_warn!(
                                                            config_id,
                                                            "GW2: Failed to compute agent identity: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }

                                            // Fallback: If no identity selector or computation failed, use SHA256
                                            if agent_identity.is_none() {
                                                channel_info!(
                                                    config_id,
                                                    "GW2: No IdentitySelector available for response, using SHA256 fallback"
                                                );
                                                let identity_value = identity_ext
                                                    .get("agentIdentity")
                                                    .or_else(|| identity_ext.get("agentId"))
                                                    .or_else(|| identity_ext.get("id"))
                                                    .or_else(|| identity_ext.get("agent_id"));

                                                let hash_input =
                                                    if let Some(id_val) = identity_value {
                                                        serde_json::to_string(id_val)
                                                            .unwrap_or_default()
                                                    } else {
                                                        serde_json::to_string(identity_ext)
                                                            .unwrap_or_default()
                                                    };

                                                use sha2::{Digest, Sha256};
                                                let mut hasher = Sha256::new();
                                                hasher.update(hash_input.as_bytes());
                                                let hash = hasher.finalize();
                                                let hash_str = format!("sha256:{:x}", hash);
                                                agent_identity = Some(hash_str.clone());
                                                channel_info!(
                                                    config_id,
                                                    "GW2: Agent identity computed from SHA256: {}",
                                                    hash_str
                                                );
                                            }
                                        }
                                    } else {
                                        channel_info!(
                                            config_id,
                                            "GW2: Identity extension declared but not found in response metadata"
                                        );
                                    }
                                } else {
                                    channel_info!(
                                        config_id,
                                        "GW2: No metadata found in response history message"
                                    );
                                }
                            } else {
                                channel_info!(
                                    config_id,
                                    "GW2: Agent identity extension not declared in response"
                                );
                            }
                        } else {
                            channel_info!(
                                config_id,
                                "GW2: No extensions array found in response history"
                            );
                        }
                    } else {
                        channel_info!(config_id, "GW2: No history found in response");
                    }
                } else {
                    channel_info!(config_id, "GW2: Failed to parse response as JSON");
                }

                channel_info!(
                    config_id,
                    "GW2: Response inspection - agent_identity: {:?}",
                    agent_identity
                );
            } else {
                channel_info!(
                    config_id,
                    "GW2: Response body is empty, cannot extract agent identity"
                );
            }

            // GW2: Record request and response metrics (after extracting agent identity)
            let request_latency_ms = start_time.elapsed().as_millis() as u64;
            let response_latency_ms = response_start.elapsed().as_millis() as u64;
            let response_bytes = response_body.len() as u64;

            // Detect UCP operation for fabric-forwarded requests (same two-pass logic as handler.rs)
            let method_result = Method::from_bytes(method.as_bytes());
            let ucp_operation = match method_result {
                Ok(ref m) => crate::proxy::handler::extract_ucp_operation(path, m),
                Err(_) => None,
            }
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in method: {}", op))
            .or_else(|| crate::proxy::handler::extract_ucp_operation_from_body(&body_bytes, config_id))
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in body: {}", op))
            // Fallback: if the request had no UCP data, inspect the upstream response body.
            // This handles the common A2A pattern where the client sends a plain text message/send
            // and the upstream returns UCP-structured data (e.g. a2a.ucp.checkout, a2a.product_results).
            .or_else(|| crate::proxy::handler::extract_ucp_operation_from_body(response_body.as_bytes(), config_id))
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in response: {}", op))
            .inspect(|op| channel_info!(config_id, "🛒 GW2 UCP operation detected: {}", op))
            .or_else(|| {
                channel_info!(config_id, "🛒 GW2: No UCP operation detected in request or response");
                None
            });

            if !is_modern_response && let Some(metrics_store) = GLOBAL_METRICS_STORE.get() {
                let request_status = if (200..300).contains(&status) {
                    crate::metrics::ConnectionStatus::Success
                } else if (400..500).contains(&status) {
                    crate::metrics::ConnectionStatus::Failed
                } else {
                    crate::metrics::ConnectionStatus::GatewayFault
                };

                // Record request metrics (GW1 -> GW2 -> target)
                let source = message.from_did.as_deref().unwrap_or("unknown").to_string();
                let dest = target_url.clone();

                metrics_store
                    .record_connection_with_bytes_and_ucp(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        source.clone(),
                        dest.clone(),
                        request_status,
                        Some(request_latency_ms),
                        caller_identity.clone(),
                        crate::metrics::ConnectionDirection::Request,
                        uuid::Uuid::new_v4().to_string(),
                        request_bytes,
                        0, // No bytes received in request direction
                        ucp_operation.clone(),
                        None,
                        None,
                        request_latency_ms,
                        None,
                    )
                    .await;

                channel_info!(
                    config_id,
                    "Recorded request metrics - status: {:?}, latency: {}ms, bytes: {}, caller: {:?}",
                    request_status,
                    request_latency_ms,
                    request_bytes,
                    caller_identity
                );

                // Record response metrics (target -> GW2 -> GW1)
                let response_status = request_status; // Use same status for both directions

                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        dest,
                        source,
                        response_status,
                        Some(response_latency_ms),
                        agent_identity.clone(),
                        crate::metrics::ConnectionDirection::Response,
                        uuid::Uuid::new_v4().to_string(),
                        0, // No bytes sent in response direction
                        response_bytes,
                        None,
                        None,
                        response_latency_ms,
                        None,
                    )
                    .await;

                channel_info!(
                    config_id,
                    "Recorded response metrics - status: {:?}, latency: {}ms, bytes: {}, agent: {:?}",
                    response_status,
                    response_latency_ms,
                    response_bytes,
                    agent_identity
                );

                // Ensure task is registered before tracking bytes
                let tracked_task_id = ensure_task_registered(&resolved_surface).await;

                // Track connection and bytes in TaskMonitor
                if let (Some(task_monitor), Some(task_id)) = (GLOBAL_TASK_MONITOR.get(), tracked_task_id.as_deref()) {
                    task_monitor.increment_connections(task_id).await;
                    task_monitor
                        .record_bytes(task_id, request_bytes, response_bytes)
                        .await;
                    task_monitor.decrement_active_connections(task_id).await;
                }
            }

            // GW2: Inject backend agent VP into response if identity was extracted
            // This mirrors the inbound VP injection pattern from handler.rs:2074-2132
            info!("GW2: VP injection check - agent_identity: {:?}", agent_identity);
            if let Some(ref agent_did) = agent_identity {
                info!(
                    "GW2: VP injection check - agent_did.starts_with('did:'): {}, has_identity_ext_rules: {}",
                    agent_did.starts_with("did:"),
                    identity_ext_rules.is_some()
                );
                if agent_did.starts_with("did:") && identity_ext_rules.is_some() {
                    info!("GW2: Backend agent DID found, injecting VP into response for DID: {}", agent_did);

                    // Get the VC issuer
                    if let Some(vc_issuer) = GLOBAL_VC_ISSUER.get() {
                        // Retrieve identity record from store
                        match vc_issuer.get_identity_store().find_by_did(agent_did).await {
                            Ok(Some(identity_record)) => {
                                // Extract identity fields from the record
                                let identity_fields: std::collections::HashMap<String, serde_json::Value> =
                                    identity_record
                                        .identity_fields
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect();

                                // Convert response_body String to Bytes for injection
                                let response_bytes = bytes::Bytes::from(response_body.clone());

                                // Bind the backend agent identity and the resolved caller
                                // (the CA→AP request-leg identity — e.g. the GW1-hosted
                                // surface DID `did:webvh:gw-1…`) into the backend-agent VP as
                                // `agentIdentity` + `userIdentity`/`delegated`, so the VP
                                // records both the backend agent and the caller it acted for.
                                // `traceId` (seeded from the inbound fabric message into
                                // `REQUEST_TRACE_ID`) correlates this response-leg VP with the
                                // request-leg VP GW1 injected.
                                // Only produced when the primary target has an
                                // enabled Workload Binding element; otherwise the
                                // response VP keeps the flat `identityFields` shape.
                                let gw2_workload_binding = if resolved_surface
                                    .target_workload_binding()
                                    .is_some()
                                {
                                    let mut binding = serde_json::json!({
                                        "agentIdentity": identity_fields,
                                    });
                                    if let (Some(caller), Some(obj)) =
                                        (caller_identity.as_ref(), binding.as_object_mut())
                                    {
                                        obj.insert(
                                            "userIdentity".to_string(),
                                            serde_json::json!({ "id": caller }),
                                        );
                                        obj.insert("delegated".to_string(), serde_json::Value::Bool(true));
                                    }
                                    if let (Some(tid), Some(obj)) = (
                                        crate::observability::policy_audit::current_span_trace_id(),
                                        binding.as_object_mut(),
                                    ) {
                                        obj.insert("traceId".to_string(), serde_json::Value::String(tid));
                                    }
                                    if let (Some(decisions), Some(obj)) = (
                                        crate::observability::policy_audit::current_policy_decisions(),
                                        binding.as_object_mut(),
                                    ) {
                                        obj.insert("policyDecisions".to_string(), decisions);
                                    }
                                    Some(binding)
                                } else {
                                    None
                                };

                                // Use protocol-specific injection (RESPONSE functions, not request functions!)
                                let inject_result = if surface_protocol == crate::config::ChannelProtocol::Mcp {
                                    let (gw2_meta_field, gw2_strip_raw) = resolved_surface
                                        .protected_identity()
                                        .and_then(|c| {
                                            if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                                                Some((cfg.meta_field.clone(), cfg.strip_raw_meta))
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or_else(|| ("serverIdentity".to_string(), false));
                                    // For MCP, use MCP-specific response injection
                                    crate::mcp::inject_vp_into_mcp_response(
                                        &response_bytes,
                                        agent_did,
                                        &identity_fields,
                                        gw2_workload_binding.clone(),
                                        vc_issuer,
                                        channel_id,
                                        Vec::new(),
                                        &gw2_meta_field,
                                        gw2_strip_raw,
                                        mcp_metadata_context,
                                    )
                                    .await
                                } else {
                                    // For A2A, use A2A-specific response injection
                                    crate::a2a::extensions::inject_vp_into_a2a_response(
                                        &response_bytes,
                                        agent_did,
                                        &identity_fields,
                                        gw2_workload_binding.clone(),
                                        vc_issuer,
                                        channel_id,
                                        Vec::new(),
                                    )
                                    .await
                                    .map(|(body, proof)| (body, Some(proof)))
                                };

                                match inject_result {
                                    Ok((modified_bytes, vp_jwt)) => {
                                        // Replace response_body with VP-injected version
                                        response_body = String::from_utf8_lossy(&modified_bytes).to_string();
                                        info!(
                                            "GW2: Successfully injected backend agent VP into response for DID: {}",
                                            agent_did
                                        );

                                        // Record the injection in the delegation audit log so it
                                        // surfaces as a `vp_injected` event on the Audit page —
                                        // mirroring the GW1 injection sites in `proxy/handler.rs`.
                                        // Without this the GW2 backend-agent VP is injected but
                                        // never audited (the response leg of the fabric flow).
                                        if let Some(vp_jwt) = vp_jwt
                                            && crate::delegation_vault::audit::identity_binding_vp_audit_enabled() {
                                            let mut evt = crate::delegation_vault::audit::audit_event(
                                                crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                                                None,
                                                None,
                                                None,
                                                resolved_surface.config_id(),
                                            );
                                            evt.agent_identity_did = Some(agent_did.to_string());
                                            evt.channel_name = Some(resolved_surface.name.clone());
                                            evt.target_endpoint = Some(resolved_surface.target.endpoint.clone());
                                            evt.protocol = Some(format!("{:?}", surface_protocol).to_lowercase());
                                            evt.vp_jwt = Some(vp_jwt.clone());
                                            evt.via_fabric = true;
                                            // Same trace id as this request's policy decisions so
                                            // the Audit "This request" filter + correlation work.
                                            evt.trace_id = crate::observability::policy_audit::current_span_trace_id();
                                            evt.detail = Some("response_path_fabric_backend_agent".to_string());
                                            crate::delegation_vault::audit::audit(evt);
                                        }
                                    }
                                    Err(e) => {
                                        if surface_protocol == crate::config::ChannelProtocol::Mcp {
                                            channel_warn!(config_id, "MCP response identity injection failed: {}", e);
                                            return axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::BAD_GATEWAY, "MCP response identity injection failed")).await;
                                        }
                                        warn!(
                                            "GW2: Failed to inject backend agent VP into response: {}, using original body",
                                            e
                                        );
                                        // Keep original response_body
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!(
                                    "GW2: Identity record not found for backend agent DID: {}, skipping VP injection",
                                    agent_did
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "GW2: Error retrieving identity record for DID {}: {}, skipping VP injection",
                                    agent_did, e
                                );
                            }
                        }
                    } else {
                        warn!("GW2: VC issuer not available, cannot inject backend agent VP");
                    }
                } else if !agent_did.starts_with("did:") {
                    debug!("GW2: Backend agent identity is not a DID (SHA256 hash), skipping VP injection");
                } else {
                    debug!("GW2: No managed_identity.extension_rules configured, skipping backend agent VP injection");
                }
            }

            // Trust Recorder — writes TrAdmin records to configured TRs on
            // the MA→AP response leg. Fire-and-forget; idempotent — duplicate
            // records log at DEBUG (`apply_trust_recorder`).
            if let Some(agent_did) = agent_identity.as_deref() {
                crate::trust_registry_verification::spawn_trust_recorder(
                    &resolved_surface,
                    agent_did,
                    get_trust_registry_listener_manager(),
                );
            }

            // MCP Tool Gating — G2G `tools/list` filter. Hides denied tools
            // from the list GW1 receives (parity with the direct-path filter).
            // `response_body` is already de-SSE'd above, so this covers MCP
            // targets that answer over SSE too.
            if let Some(filtered) = filter_mcp_tools_list_for_fabric(
                &resolved_surface,
                config_id,
                active_variant_alias.as_deref(),
                &body_bytes,
                &response_body,
                headers.as_ref(),
                method,
                path,
                message.from_did.clone(),
                source_auth_context.as_ref(),
                modern_mcp_context.as_ref(),
                mcp_metadata_context,
            ) {
                response_body = filtered;
            }

            if surface_protocol == crate::config::ChannelProtocol::Mcp {
                response_body = match crate::mcp::meta::normalize_text(&response_body, mcp_metadata_context) {
                    Ok(body) => body,
                    Err(error) => return axum_response_to_forward_result(error.into_response(response_body.as_bytes(), axum::http::StatusCode::BAD_GATEWAY)).await,
                };
            }

            let response_json = serde_json::json!({
                "status": status,
                "headers": multi_value_headers_json(
                    response_headers
                        .iter()
                        .flat_map(|(k, vals)| vals.iter().map(move |v| (k.as_str(), v.as_str())))
                ),
                "body": response_body,
            });

            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: response_json,
            }
            };
            if let (Some(response), Some(request), Some(complete)) = (modern_response, modern_request, modern_completion) {
                let continuation = modern_delegation.zip(
                    mcp_continuations,
                );
                let result = Box::pin(process_modern_fabric_response(
                    response, modern_headers, request, modern_limits, response_headers, discovery_support,
                    continuation,
                    move |payload, headers| Box::pin(async move { process_response(payload, headers).await }),
                )).await;
                return match result {
                    Ok(response) => {
                        let response = match subscription_lifetime {
                            Some(lifetime) => lifetime.wrap(response),
                            None => response,
                        };
                        let response = if framed_response {
                            crate::proxy::fabric_stream::transport::observe_delivery(response, complete)
                        } else {
                            crate::mcp::modern_sse::observe_response(response, complete)
                        };
                        ProcessingResult::StreamingResponse { response }
                    }
                    Err(error) => {
                        complete(crate::mcp::modern_sse::ResponseOutcome { failed: true, ..Default::default() });
                        warn!(error = %error, "Invalid modern Fabric upstream response");
                        axum_response_to_forward_result(crate::a2a::create_error_response(axum::http::StatusCode::BAD_GATEWAY, "Invalid modern MCP upstream response")).await
                    }
                };
            }
            Box::pin(process_response(response_body, response_headers)).await
        }
        Err(e) => {
            channel_error!(
                config_id,
                "❌ Forward failed: {} {} - {}",
                http_method,
                target_url,
                e
            );

            // Provide detailed error information
            let mut error_details = vec![format!("Error: {}", e)];

            // Check error type and add specific details
            if e.is_timeout() {
                error_details.push("Type: Request timeout".to_string());
            } else if e.is_connect() {
                error_details.push("Type: Connection failed".to_string());
                error_details.push(
                    "Possible causes: Service not running, firewall blocking, wrong port"
                        .to_string(),
                );
            } else if e.is_request() {
                error_details.push("Type: Request build error".to_string());
            } else if e.is_body() {
                error_details.push("Type: Body error".to_string());
            } else if e.is_decode() {
                error_details.push("Type: Response decode error".to_string());
            }

            // Add source error if available
            if let Some(source) = e.source() {
                error_details.push(format!("Source: {}", source));
                // Walk the full error chain for deeper diagnostics
                let mut current: &dyn std::error::Error = source;
                while let Some(inner) = current.source() {
                    error_details.push(format!("  Caused by: {}", inner));
                    current = inner;
                }
            }
            // Full debug representation
            error_details.push(format!("Debug: {:?}", e));

            // Log all error details
            for detail in &error_details {
                channel_warn!(config_id, "  ↳ {}", detail);
            }

            // Provide more specific error messages based on error type
            let (error_msg, status_code) = if e.is_timeout() {
                ("Request timed out after 30 seconds".to_string(), 504)
            } else if e.is_connect() {
                (
                    format!(
                        "Failed to connect to target endpoint: {}. Service may not be running on port {}",
                        surface.target_endpoint(),
                        surface
                            .target_endpoint()
                            .split(':')
                            .next_back()
                            .unwrap_or("unknown")
                    ),
                    502,
                )
            } else {
                (format!("Failed to forward request: {}", e), 502)
            };

            let error_body = serde_json::json!({
                "error": error_msg,
                "status": status_code,
                "target": surface.target_endpoint(),
                "method": http_method.as_str(),
                "url": target_url,
                "error_details": error_details,
            });
            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            }
        }
    }
    }.instrument(span).await
}

async fn evaluate_mcp_tool_policies_for_fabric(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    body_bytes: &bytes::Bytes,
    headers: Option<&serde_json::Map<String, Value>>,
    method: &str,
    path: &str,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    caller_identity: Option<&String>,
    trace_id: Option<&str>,
    modern_mcp_context: Option<&crate::surface_context::McpContext>,
) -> Option<ProcessingResult> {
    if surface.channel_protocol() != crate::config::ChannelProtocol::Mcp
        || modern_mcp_context.is_some_and(|context| context.method != "tools/call")
        || surface
            .target
            .mcp_tool_policies
            .is_empty()
    {
        return None;
    }

    let tool_request = match crate::mcp::McpToolRequest::from_json_rpc(body_bytes) {
        Ok(request) => request,
        Err(error) => {
            channel_warn!(config_id, "GW2: Failed to parse MCP request for tool policy: {}", error);
            return Some(mcp_forward_error_response(
                None,
                crate::mcp::error_codes::INVALID_REQUEST,
                "Invalid MCP request",
            ));
        }
    };

    let requested_tool_name = tool_request.tool_name();
    if tool_request.method == "tools/call" && requested_tool_name.is_none() {
        return Some(mcp_forward_error_response(
            Some(tool_request.id.clone()),
            crate::mcp::error_codes::INVALID_REQUEST,
            "Invalid MCP tools/call request: missing params.name",
        ));
    }

    if tool_request.method != "tools/call" {
        return None;
    }

    let Some(policy_manager) = GLOBAL_POLICY_MANAGER.get() else {
        channel_error!(config_id, "GW2: MCP tool policies configured but policy manager is not initialized");
        return Some(mcp_forward_error_response(
            Some(tool_request.id.clone()),
            crate::mcp::error_codes::INTERNAL_ERROR,
            "Internal error: policy evaluation failed",
        ));
    };

    let Some(store) = policy_manager.policy_definition_store() else {
        channel_error!(config_id, "GW2: MCP tool policies configured but no policy definition store is available");
        return Some(mcp_forward_error_response(
            Some(tool_request.id.clone()),
            crate::mcp::error_codes::INTERNAL_ERROR,
            "Internal error: policy evaluation failed",
        ));
    };

    // Rebuild the caller's (unverified) JWT claims from the forwarded
    // Authorization header so target-surface tool policies evaluate `input.jwt`
    // exactly like the direct path. GW1 forwards request headers uppercased, so
    // match the header name case-insensitively.
    let jwt_claims = headers.and_then(|h| {
        h.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, value)| value.as_str())
            .and_then(crate::proxy::handler::decode_bearer_jwt_claims)
    });

    let context = crate::mcp::McpPolicyContext::new(
        tool_request.method.clone(),
        tool_request.params.clone(),
        jwt_claims,
        surface.name.clone(),
        surface
            .config_id()
            .map(str::to_string),
        "mcp".to_string(),
        "fabric".to_string(),
        method.to_string(),
        path.to_string(),
    )
    .with_modern_request(modern_mcp_context);

    let entries: Vec<_> = surface
        .target
        .mcp_tool_policies
        .iter()
        .filter(|entry| Some(entry.tool_name.as_str()) == requested_tool_name)
        .collect();

    if entries.is_empty() {
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            flow: crate::observability::PolicyFlow::Fabric,
            allow: false,
            reason: Some("Access denied: insufficient permissions for this tool"),
            surface_id: Some(config_id),
            http_method: Some(method),
            path: Some(path),
            identity: authenticated_identity,
            actor_did: caller_identity.map(String::as_str),
            trace_id,
            ..Default::default()
        });
        return Some(mcp_forward_error_response(
            Some(tool_request.id.clone()),
            -32000,
            "Access denied: insufficient permissions for this tool",
        ));
    }

    for entry in entries {
        let policy_id = &entry.policy_definition_id;
        let Some(definition) = store.get(policy_id).await else {
            channel_error!(config_id, "GW2: MCP tool policy references unknown policy definition: {}", policy_id);
            return Some(mcp_forward_error_response(
                Some(tool_request.id.clone()),
                crate::mcp::error_codes::INTERNAL_ERROR,
                "Internal error: policy evaluation failed",
            ));
        };
        if !definition.enabled {
            continue;
        }
        let engine = crate::policies::OpaEngine::new();
        if let Err(error) = engine.load_policy(policy_id, &definition.policy) {
            channel_error!(config_id, "GW2: Failed to load MCP tool policy {}: {}", policy_id, error);
            return Some(mcp_forward_error_response(
                Some(tool_request.id.clone()),
                crate::mcp::error_codes::INTERNAL_ERROR,
                "Internal error: policy evaluation failed",
            ));
        }
        let decision = match engine.evaluate_mcp_tool_policy(&context) {
            Ok(decision) => decision,
            Err(error) => {
                channel_error!(config_id, "GW2: Failed to evaluate MCP tool policy {}: {}", policy_id, error);
                return Some(mcp_forward_error_response(
                    Some(tool_request.id.clone()),
                    crate::mcp::error_codes::INTERNAL_ERROR,
                    "Internal error: policy evaluation failed",
                ));
            }
        };
        let (allow, reason) = if decision.allow {
            (true, None)
        } else {
            (false, decision.reason.as_deref())
        };
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            flow: crate::observability::PolicyFlow::Fabric,
            allow,
            reason,
            policy_id: Some(policy_id.as_str()),
            policy_definition_id: Some(policy_id.as_str()),
            policy_name: Some(definition.name.as_str()),
            policy_version: definition.version,
            policy_content_hash: definition
                .content_hash
                .as_deref(),
            surface_id: Some(config_id),
            http_method: Some(method),
            path: Some(path),
            identity: authenticated_identity,
            actor_did: caller_identity.map(String::as_str),
            trace_id,
            ..Default::default()
        });
        if !allow {
            return Some(mcp_forward_error_response(
                Some(tool_request.id.clone()),
                -32000,
                "Access denied: insufficient permissions for this tool",
            ));
        }
    }

    None
}

/// Build the gating `PolicyInput` for the G2G (`fabric://`) leg, mirroring the
/// direct-path inbound input so a gate condition decides identically here. The
/// caller supplies the request-scoped `mcp` context (`tools/call` with a tool
/// name, or `tools/list`).
fn build_fabric_gating_input(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    variant_alias: Option<&str>,
    headers: Option<&serde_json::Map<String, Value>>,
    method: &str,
    path: &str,
    from_did: Option<String>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    mcp: crate::surface_context::McpContext,
    modern_mcp_context: Option<&crate::surface_context::McpContext>,
) -> Value {
    let filtered_headers = headers
        .map(|h| {
            h.iter()
                .filter_map(|(k, v)| {
                    v.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                })
                .collect::<std::collections::HashMap<String, String>>()
        })
        .unwrap_or_default();
    let mut policy_input = crate::surface_context::PolicyInput::new(
        method,
        path,
        filtered_headers,
        "inbound",
        from_did,
        None,
        Some(config_id.to_string()),
        &surface.name,
    );
    if let Some(ref mut ch) = policy_input.channel {
        ch.variant_alias = variant_alias.map(|s| s.to_string());
    }
    policy_input.source_auth = source_auth_context.cloned();
    policy_input.mcp = Some(
        modern_mcp_context
            .cloned()
            .unwrap_or(mcp),
    );
    policy_input.normalize_caller_did();
    serde_json::to_value(&policy_input).unwrap_or_default()
}

/// MCP Tool Gating — G2G (`fabric://`) `tools/call` enforcement. A tool the
/// firewall hides from `tools/list` must be uncallable when reached over the
/// fabric leg too (parity with the direct-path gate in `proxy::handler`).
/// Returns `Some(deny)` when the call is blocked; `None` to continue.
#[allow(clippy::too_many_arguments)]
async fn evaluate_mcp_tool_gating_call_for_fabric(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    variant_alias: Option<&str>,
    body_bytes: &bytes::Bytes,
    headers: Option<&serde_json::Map<String, Value>>,
    method: &str,
    path: &str,
    from_did: Option<String>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    caller_identity: Option<&String>,
    trace_id: Option<&str>,
    modern_mcp_context: Option<&crate::surface_context::McpContext>,
) -> Option<ProcessingResult> {
    if surface.channel_protocol() != crate::config::ChannelProtocol::Mcp
        || !crate::mcp::is_tools_call_request(body_bytes)
    {
        return None;
    }
    let policy_manager = GLOBAL_POLICY_MANAGER.get()?;
    let gating = policy_manager
        .compiled_mcp_tool_gating(config_id, variant_alias)
        .filter(|g| !g.is_empty())?;
    let tool_request = crate::mcp::McpToolRequest::from_json_rpc(body_bytes).ok()?;
    let tool_name = tool_request
        .tool_name()?
        .to_string();

    let input_value = if gating.has_policy_conditions() {
        build_fabric_gating_input(
            surface,
            config_id,
            variant_alias,
            headers,
            method,
            path,
            from_did,
            source_auth_context,
            crate::surface_context::McpContext {
                method: tool_request.method.clone(),
                tool_name: Some(tool_name.clone()),
                resource_uri: None,
                prompt_name: None,
                params: tool_request.params.clone(),
                ..Default::default()
            },
            modern_mcp_context,
        )
    } else {
        Value::Null
    };

    let allowed = gating.is_tool_call_allowed(&tool_name, &input_value);
    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
        scope: crate::observability::PolicyScope::McpTool,
        flow: crate::observability::PolicyFlow::Fabric,
        allow: allowed,
        reason: if allowed {
            None
        } else {
            Some("blocked by MCP tool gating")
        },
        policy_id: Some("mcp_tool_gating"),
        surface_id: Some(config_id),
        http_method: Some(method),
        path: Some(path),
        identity: authenticated_identity,
        actor_did: caller_identity.map(String::as_str),
        trace_id,
        ..Default::default()
    });
    if allowed {
        return None;
    }
    channel_warn!(config_id, "GW2: MCP tool gating blocked tools/call for tool '{}'", tool_name);
    Some(mcp_forward_error_response(Some(tool_request.id.clone()), -32001, "Tool is not available"))
}

/// MCP Tool Gating — G2G (`fabric://`) `tools/list` response filter. Hides
/// tools the firewall denies from the list GW1 receives, so a tool the managed
/// agent can't call is also one it can't see. `request_body` is the original
/// forwarded request (to confirm the method); `response_body` is the target's
/// JSON-RPC response, already de-SSE'd by the caller. Returns the rewritten
/// JSON string when it filtered anything, else `None`.
#[allow(clippy::too_many_arguments)]
fn filter_mcp_tools_list_for_fabric(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    variant_alias: Option<&str>,
    request_body: &bytes::Bytes,
    response_body: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    method: &str,
    path: &str,
    from_did: Option<String>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    modern_mcp_context: Option<&crate::surface_context::McpContext>,
    context: crate::mcp::meta::McpMetadataContext,
) -> Option<String> {
    if surface.channel_protocol() != crate::config::ChannelProtocol::Mcp
        || !crate::mcp::is_tools_list_request(request_body)
    {
        return None;
    }
    let policy_manager = GLOBAL_POLICY_MANAGER.get()?;
    let gating = policy_manager
        .compiled_mcp_tool_gating(config_id, variant_alias)
        .filter(|g| !g.is_empty())?;
    let mut json: Value = match serde_json::from_str(response_body) {
        Ok(v) => v,
        // Un-inspectable tools/list response: fail closed once gating is
        // installed (return an empty tool list) instead of passing it through.
        Err(_) => {
            channel_warn!(
                config_id,
                "GW2: MCP tools/list response unparsable under gating; failing closed (empty tool list)"
            );
            return Some(crate::mcp::fail_closed_tools_list(request_body, context));
        }
    };
    let input_value = if gating.has_policy_conditions() {
        build_fabric_gating_input(
            surface,
            config_id,
            variant_alias,
            headers,
            method,
            path,
            from_did,
            source_auth_context,
            crate::surface_context::McpContext {
                method: "tools/list".to_string(),
                tool_name: None,
                resource_uri: None,
                prompt_name: None,
                params: None,
                ..Default::default()
            },
            modern_mcp_context,
        )
    } else {
        Value::Null
    };
    let (before, after) = gating.filter_tools_list_value(&mut json, &input_value)?;
    // A caller-scoped gate makes the list authorization-dependent even when it
    // removes nothing, so the modern result must not stay publicly cacheable.
    let privatize = context.requires_private_result_cache();
    if after == before && !privatize {
        return None;
    }
    if privatize {
        crate::mcp::meta::protect_enriched_result_cache(&mut json, context);
    }
    if after < before {
        channel_info!(config_id, "GW2: MCP tool gating filtered tools/list before={} after={}", before, after);
    }
    serde_json::to_string(&json).ok()
}

fn mcp_forward_error_response(
    id: Option<serde_json::Value>,
    code: i32,
    message: &str,
) -> ProcessingResult {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    });
    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: serde_json::json!({
            "status": 200,
            "headers": {
                "content-type": "application/json",
            },
            "body": body.to_string(),
        }),
    }
}

async fn handle_a2a_proxy_forward(
    message: &ReceivedMessage,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    proxy_id: &str,
    body_bytes: bytes::Bytes,
    caller_identity: Option<String>,
) -> ProcessingResult {
    let config_id = surface
        .config_id()
        .unwrap_or("unknown");
    let request_bytes = body_bytes.len() as u64;
    let start_time = std::time::Instant::now();

    if let Some(policy_manager) = GLOBAL_POLICY_MANAGER.get()
        && let Some(config_id) = surface.config_id()
    {
        match policy_manager
            .check_rate_limit(config_id)
            .await
        {
            Ok(_) => channel_debug!(config_id, "Rate limit check passed for fabric A2A proxy request"),
            Err(e) => {
                channel_warn!(config_id, "Rate limit exceeded on fabric A2A proxy request: {}", e);
                let id = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                    .ok()
                    .and_then(|body| body.get("id").cloned())
                    .unwrap_or(serde_json::Value::Null);
                let error_response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32000,
                        "message": "Rate limit exceeded",
                        "data": { "retry_after": e.to_string() }
                    }
                });
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 429,
                        "headers": {
                            "content-type": "application/json",
                            "retry-after": e.to_string(),
                        },
                        "body": error_response.to_string(),
                    }),
                };
            }
        }
    }

    let adapter = match crate::a2a_proxies::A2aProxyTargetAdapter::from_optional_store(
        GLOBAL_A2A_PROXY_STORE
            .get()
            .cloned(),
    ) {
        Ok(adapter) => adapter,
        Err(err) => {
            channel_warn!(config_id, "A2A proxy store unavailable on fabric receive: {}", err);
            let response = crate::a2a_proxies::target_adapter::json_rpc_target_error(&body_bytes, err);
            return axum_response_to_forward_result(response).await;
        }
    };

    let secrets_store = get_secrets_store();
    let response = adapter
        .dispatch_message_send(proxy_id, &body_bytes, secrets_store.as_ref(), &surface.name)
        .await;

    let request_body_bytes = body_bytes;
    let (parts, body) = response.into_parts();
    let response_body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    let response_body = String::from_utf8_lossy(&response_body_bytes).to_string();
    let response_bytes = response_body_bytes.len() as u64;
    let latency_ms = start_time
        .elapsed()
        .as_millis() as u64;
    let status = parts.status;
    let response_headers: std::collections::HashMap<String, String> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();
    let connection_status = crate::proxy::handler::a2a_proxy_connection_status(status, &response_body_bytes);

    if let Some(metrics_store) = GLOBAL_METRICS_STORE.get() {
        let source = message
            .from_did
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let dest = format!("a2a-proxy:{proxy_id}");
        let surface_id = surface
            .config_id()
            .map(str::to_string)
            .unwrap_or_else(|| channel_id.to_string());
        let active_variant_alias = message
            .message_body
            .get("active_variant_alias")
            .and_then(|v| v.as_str())
            .or_else(|| {
                message
                    .message_body
                    .get("virtual_channel_alias")
                    .and_then(|v| v.as_str())
            })
            .map(str::to_string);

        metrics_store
            .record_connection_with_bytes(
                surface_id.clone(),
                source.clone(),
                dest.clone(),
                connection_status,
                Some(latency_ms),
                caller_identity.clone(),
                crate::metrics::ConnectionDirection::Request,
                uuid::Uuid::new_v4().to_string(),
                request_bytes,
                0,
                None,
                None,
                latency_ms,
                active_variant_alias.clone(),
            )
            .await;
        metrics_store
            .record_connection_with_bytes(
                surface_id,
                dest,
                source,
                connection_status,
                Some(latency_ms),
                None,
                crate::metrics::ConnectionDirection::Response,
                uuid::Uuid::new_v4().to_string(),
                0,
                response_bytes,
                None,
                None,
                latency_ms,
                active_variant_alias,
            )
            .await;
    }

    if let Some(ws_state) = GLOBAL_WS_STATE.get()
        && let Some(metrics_store) = GLOBAL_METRICS_STORE.get()
    {
        let request_payload = serde_json::from_slice(&request_body_bytes).unwrap_or_else(|_| {
            serde_json::json!({
                "_raw_body": String::from_utf8_lossy(&request_body_bytes).to_string(),
            })
        });
        let response_payload = serde_json::from_str(&response_body).ok();
        let validation_status = if connection_status == crate::metrics::ConnectionStatus::Success {
            "success"
        } else {
            "a2a_proxy_error"
        };
        crate::observability::payload_capture::broadcast_payload_capture_async(
            &Some(ws_state.clone()),
            &Some(metrics_store.clone()),
            channel_id,
            config_id,
            &request_payload,
            response_payload,
            validation_status,
            None,
            caller_identity,
            None,
        )
        .await;
    }

    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: serde_json::json!({
            "status": status.as_u16(),
            "headers": response_headers,
            "body": response_body,
            "metrics": {
                "request_bytes": request_bytes,
                "response_bytes": response_bytes,
                "latency_ms": latency_ms,
            }
        }),
    }
}

async fn process_forward_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received forward-response from {:?}", message.from_did);
    if crate::proxy::fabric_response_waiter::complete_forward_response_waiter(message) {
        debug!(
            thid = ?message.didcomm_thid,
            "Completed pending fabric ForwardResponse waiter"
        );
    } else {
        // Either no waiter is pending for this thread, or one is pending for a
        // different gateway and the waiter refused this sender — that refusal is
        // logged at the waiter with both DIDs.
        warn!(
            thid = ?message.didcomm_thid,
            from = ?message.from_did,
            "Fabric ForwardResponse did not complete a pending waiter"
        );
    }
    ProcessingResult::ProcessedNoResponse
}

/// Resolve the backend agent identity from an MCP proxy response and delegate
/// to `spawn_trust_recorder`. Runs on the fabric MCP-proxy response leg, which
/// short-circuits before the generic recorder seam in
/// `process_forward_request`. Fire-and-forget; idempotent — duplicate records
/// log at DEBUG (`apply_trust_recorder`). No-op when the surface has no
/// recorder entries or the response carries no DID-shaped managed identity.
async fn spawn_mcp_proxy_trust_recorder(
    surface: &crate::config::agent_surface::AgentSurface,
    mcp_response: &serde_json::Value,
) {
    let Some(recorder_cfg) = surface.trust_recorder() else {
        return;
    };
    if recorder_cfg
        .entries
        .is_empty()
    {
        return;
    }

    let response_bytes_json = serde_json::to_vec(mcp_response).unwrap_or_default();
    if response_bytes_json.is_empty() {
        return;
    }

    let gw2_engines = GLOBAL_VC_ISSUER
        .get()
        .and_then(|issuer| crate::proxy::compile_identity_engines_from_surface(surface, Some(issuer)).ok());
    let selector = gw2_engines
        .as_ref()
        .and_then(|c| c.protected_selector.as_ref());
    let rules = gw2_engines
        .as_ref()
        .and_then(|c| {
            c.protected_rules_engine
                .as_ref()
        });

    let resolved = crate::proxy::backend_identity::resolve_protected_agent_identity(
        &response_bytes_json,
        surface,
        selector,
        rules,
        &surface.name,
        false,
        None,
    )
    .await
    .ok();

    if let Some(ProtectedAgentIdentity::Managed { did, .. }) = resolved {
        crate::trust_registry_verification::spawn_trust_recorder(surface, &did, get_trust_registry_listener_manager());
    }
}

/// Handle MCP proxy forwarding for fabric gateway requests
#[instrument(name = "fabric.mcp_proxy_forward", skip(message, surface, body_bytes), fields(channel_id, proxy_id, msg.id = %message.didcomm_message_id))]
async fn handle_mcp_proxy_forward(
    message: &ReceivedMessage,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    proxy_id: &str,
    _method: &str,
    _path: &str,
    _headers: Option<serde_json::Map<String, serde_json::Value>>,
    body_bytes: bytes::Bytes,
    caller_identity: Option<String>,
) -> ProcessingResult {
    // Record fields in the span
    tracing::Span::current().record("channel_id", channel_id);
    tracing::Span::current().record("proxy_id", proxy_id);

    let config_id = surface
        .config_id()
        .unwrap_or("unknown");
    channel_info!(
        config_id,
        "🔌 Handling MCP proxy forward - proxy_id: {}, body: {} bytes",
        proxy_id,
        body_bytes.len()
    );

    // Track request bytes for metrics
    let request_bytes = body_bytes.len() as u64;

    // Start timer for latency measurement
    let start_time = std::time::Instant::now();

    // Check rate limit for this channel (same as direct access path)
    if let Some(policy_manager) = GLOBAL_POLICY_MANAGER.get()
        && let Some(config_id) = surface.config_id()
    {
        match policy_manager
            .check_rate_limit(config_id)
            .await
        {
            Ok(_) => {
                channel_debug!(config_id, "Rate limit check passed");
            }
            Err(e) => {
                channel_warn!(config_id, "Rate limit exceeded on fabric-forwarded request: {}", e);

                // Return JSON-RPC error for rate limiting with HTTP 429 status
                let error_response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Rate limit exceeded",
                        "data": {
                            "retry_after": e.to_string()
                        }
                    },
                    "id": null
                });

                // Serialize the JSON-RPC error as the response body
                let error_body = serde_json::json!({
                    "status": 429,  // HTTP 429 Too Many Requests
                    "headers": {
                        "Content-Type": "application/json",
                        "Retry-After": e.to_string()
                    },
                    "body": serde_json::to_string(&error_response).unwrap_or_else(|_| error_response.to_string())
                });

                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: error_body,
                };
            }
        }
    }

    // Load MCP proxy configuration
    let mcp_proxy_store = match GLOBAL_MCP_PROXY_STORE.get() {
        Some(store) => store,
        None => {
            channel_warn!(config_id, "MCP proxy store not initialized");
            let error_body = serde_json::json!({
                "error": "MCP proxy store not initialized",
                "status": 500,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
    };

    use crate::mcp_proxies::filesystem::McpProxyStore;
    let proxy = match mcp_proxy_store
        .as_ref()
        .get(proxy_id)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            channel_warn!(config_id, "MCP proxy not found: {}", proxy_id);
            let error_body = serde_json::json!({
                "error": format!("MCP proxy not found: {}", proxy_id),
                "status": 404,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
        Err(e) => {
            channel_warn!(config_id, "Failed to load MCP proxy {}: {}", proxy_id, e);
            let error_body = serde_json::json!({
                "error": format!("Failed to load MCP proxy: {}", e),
                "status": 500,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
    };

    // Check if proxy is active
    if proxy.status != crate::mcp_proxies::types::McpProxyStatus::Active {
        channel_warn!(config_id, "MCP proxy '{}' is disabled", proxy.name);
        let error_body = serde_json::json!({
            "error": format!("MCP proxy '{}' is disabled", proxy.name),
            "status": 503,
        });
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: error_body,
        };
    }

    // Parse MCP request from body
    let mcp_request = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            channel_warn!(config_id, "Failed to parse MCP request: {}", e);
            let error_body = serde_json::json!({
                "error": format!("Invalid MCP request: {}", e),
                "status": 400,
            });
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            };
        }
    };

    channel_info!(config_id, "📨 Handling MCP request via proxy '{}' (ID: {})", proxy.name, proxy.id);

    // Get global HTTP client for policy-aware requests (timeout, retry, circuit breaker, mirroring)
    let fallback_client = reqwest::Client::new();
    let http_client = GLOBAL_HTTP_CLIENT
        .get()
        .unwrap_or(&fallback_client);

    // Get policy manager for circuit breaker support
    let policy_manager = GLOBAL_POLICY_MANAGER.get();

    // Resolve target auth header if configured on the channel
    let target_auth_header = if let Some(target_auth) = surface.target_auth() {
        let secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>> = match message
            .context
            .get("secrets_storage_path")
            .and_then(|v| v.as_str())
        {
            Some(path) => match crate::secrets::FilesystemSecretsStore::new_async(path).await {
                Ok(store) => Some(Arc::new(store) as Arc<dyn crate::secrets::SecretsStore>),
                Err(e) => {
                    channel_warn!(config_id, "Failed to create secrets store for MCP proxy target auth: {}", e);
                    None
                }
            },
            None => {
                channel_warn!(config_id, "No secrets_storage_path in message context for MCP proxy target auth");
                None
            }
        };

        match crate::proxy::handler::inject_target_auth_header(
            target_auth,
            &secrets_store,
            &surface.name,
            crate::proxy::handler::CallerAssertion::Authenticated,
        )
        .await
        {
            Ok(header) => header,
            Err(e) => {
                channel_error!(config_id, "Failed to resolve target auth for MCP proxy: {}", e);
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        let error_body = serde_json::json!({
                            "error": "Target authentication configuration error",
                            "status": 502,
                        });
                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: error_body,
                        };
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        channel_warn!(
                            config_id,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                        None
                    }
                }
            }
        }
    } else {
        None
    };

    // Use handle_mcp_request_with_policies to apply all surface policies
    // This ensures MCP channels have feature parity with A2A (timeout, retry, circuit breaker, mirroring)
    match crate::mcp_proxies::handlers::handle_mcp_request_with_policies(
        &proxy,
        mcp_request.clone(),
        surface,
        policy_manager,
        http_client,
        &surface.name,
        target_auth_header,
    )
    .await
    {
        Ok(mcp_response) => {
            // Broadcast payload capture for successful MCP proxy request
            if let (Some(ws_state), Some(metrics_store)) = (GLOBAL_WS_STATE.get(), GLOBAL_METRICS_STORE.get()) {
                let config_id = surface
                    .config_id()
                    .unwrap_or("unknown");
                let active_variant_alias = message
                    .message_body
                    .get("active_variant_alias")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        message
                            .message_body
                            .get("virtual_channel_alias")
                            .and_then(|v| v.as_str())
                    });
                crate::observability::payload_capture::broadcast_payload_capture_async(
                    &Some(ws_state.clone()),
                    &Some(metrics_store.clone()),
                    &surface.name,
                    config_id,
                    &mcp_request,
                    Some(mcp_response.clone()),
                    "success", // MCP protocol doesn't have A2A extension validation
                    None,
                    None, // identity_hash
                    active_variant_alias,
                )
                .await;
            }

            // Trust Recorder — writes TrAdmin records to configured TRs on the
            // fabric MCP-proxy response leg. This path short-circuits before the
            // generic recorder seam in `process_forward_request`, so run it here.
            // Fire-and-forget; never blocks the response.
            spawn_mcp_proxy_trust_recorder(surface, &mcp_response).await;

            // Record success metrics with latency
            let latency_ms = start_time
                .elapsed()
                .as_millis() as u64;

            // Convert MCP response to JSON string for metrics and ForwardResponse
            let response_body = match serde_json::to_string(&mcp_response) {
                Ok(json_str) => json_str,
                Err(e) => {
                    channel_warn!(config_id, "Failed to serialize MCP response: {}", e);
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32603,\"message\":\"Failed to serialize response: {}\"}}}}",
                        e
                    )
                }
            };

            // Calculate response bytes from serialized response
            let response_bytes = response_body.len() as u64;

            if let Some(metrics_store) = GLOBAL_METRICS_STORE.get() {
                let source = message
                    .from_did
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                let dest = format!("proxy://{}", proxy_id);

                // Record request metrics (GW1 -> GW2 -> MCP Proxy)
                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        source.clone(),
                        dest.clone(),
                        crate::metrics::ConnectionStatus::Success,
                        Some(latency_ms),
                        caller_identity.clone(),
                        crate::metrics::ConnectionDirection::Request,
                        uuid::Uuid::new_v4().to_string(),
                        request_bytes,
                        0, // No bytes received in request direction
                        None,
                        None,
                        latency_ms,
                        None,
                    )
                    .await;

                // Record response metrics (MCP Proxy -> GW2 -> GW1)
                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        dest,
                        source,
                        crate::metrics::ConnectionStatus::Success,
                        Some(latency_ms),
                        None, // No agent identity for MCP responses
                        crate::metrics::ConnectionDirection::Response,
                        uuid::Uuid::new_v4().to_string(),
                        0, // No bytes sent in response direction
                        response_bytes,
                        None,
                        None,
                        latency_ms,
                        None,
                    )
                    .await;

                // Ensure task is registered before tracking bytes
                let tracked_task_id = ensure_task_registered(surface).await;

                // Track connection and bytes in TaskMonitor
                if let (Some(task_monitor), Some(task_id)) = (GLOBAL_TASK_MONITOR.get(), tracked_task_id.as_deref()) {
                    task_monitor
                        .increment_connections(task_id)
                        .await;
                    task_monitor
                        .record_bytes(task_id, request_bytes, response_bytes)
                        .await;
                    task_monitor
                        .decrement_active_connections(task_id)
                        .await;
                }
            }

            let response_headers: std::collections::HashMap<String, String> =
                std::collections::HashMap::from([("Content-Type".to_string(), "application/json".to_string())]);

            channel_info!(config_id, "✓ MCP proxy request succeeded");

            let response_body_json = serde_json::json!({
                "status": 200,
                "headers": response_headers,
                "body": response_body,
            });

            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: response_body_json,
            }
        }
        Err(error_msg) => {
            let config_id = surface
                .config_id()
                .unwrap_or("unknown");
            channel_warn!(config_id, "❌ MCP proxy request failed: {}", error_msg);

            // Broadcast payload capture for failed MCP proxy request
            if let (Some(ws_state), Some(metrics_store)) = (GLOBAL_WS_STATE.get(), GLOBAL_METRICS_STORE.get()) {
                let active_variant_alias = message
                    .message_body
                    .get("active_variant_alias")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        message
                            .message_body
                            .get("virtual_channel_alias")
                            .and_then(|v| v.as_str())
                    });
                crate::observability::payload_capture::broadcast_payload_capture_async(
                    &Some(ws_state.clone()),
                    &Some(metrics_store.clone()),
                    &surface.name,
                    config_id,
                    &mcp_request,
                    None,
                    "mcp_error", // Custom status for MCP errors
                    Some(format!("MCP Proxy Error: {}", error_msg)),
                    None,
                    active_variant_alias,
                )
                .await;
            }

            // Record failure metrics with latency
            let latency_ms = start_time
                .elapsed()
                .as_millis() as u64;
            if let Some(metrics_store) = GLOBAL_METRICS_STORE.get() {
                let source = message
                    .from_did
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                let dest = format!("proxy://{}", proxy_id);

                // Error response bytes (approximate from error message)
                let error_response_bytes = error_msg.len() as u64 + 100; // JSON-RPC error wrapper overhead

                // Record request metrics (GW1 -> GW2 -> MCP Proxy)
                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        source.clone(),
                        dest.clone(),
                        crate::metrics::ConnectionStatus::Failed,
                        Some(latency_ms),
                        caller_identity.clone(),
                        crate::metrics::ConnectionDirection::Request,
                        uuid::Uuid::new_v4().to_string(),
                        request_bytes,
                        0, // No bytes received in request direction
                        None,
                        None,
                        latency_ms,
                        None,
                    )
                    .await;

                // Record response metrics (MCP Proxy -> GW2 -> GW1)
                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        dest,
                        source,
                        crate::metrics::ConnectionStatus::Failed,
                        Some(latency_ms),
                        None, // No identity for failed requests
                        crate::metrics::ConnectionDirection::Response,
                        uuid::Uuid::new_v4().to_string(),
                        0, // No bytes sent in response direction
                        error_response_bytes,
                        None,
                        None,
                        latency_ms,
                        None,
                    )
                    .await;

                // Ensure task is registered before tracking bytes
                let tracked_task_id = ensure_task_registered(surface).await;

                // Track connection and bytes in TaskMonitor
                if let (Some(task_monitor), Some(task_id)) = (GLOBAL_TASK_MONITOR.get(), tracked_task_id.as_deref()) {
                    task_monitor
                        .increment_connections(task_id)
                        .await;
                    task_monitor
                        .record_bytes(task_id, request_bytes, error_response_bytes)
                        .await;
                    task_monitor
                        .decrement_active_connections(task_id)
                        .await;
                }
            }

            // Create a proper MCP JSON-RPC error response
            let request_id = mcp_request
                .get("id")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let mcp_error_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": error_msg
                }
            });

            let error_response_body = match serde_json::to_string(&mcp_error_response) {
                Ok(json_str) => json_str,
                Err(e) => {
                    channel_warn!(config_id, "Failed to serialize MCP error response: {}", e);
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32603,\"message\":\"{}\" }}}}",
                        request_id,
                        error_msg.replace('"', "\\\"")
                    )
                }
            };

            let response_headers: std::collections::HashMap<String, String> =
                std::collections::HashMap::from([("Content-Type".to_string(), "application/json".to_string())]);

            // Return as HTTP 200 with MCP error in body (JSON-RPC errors are application-level, not HTTP-level)
            let error_body = serde_json::json!({
                "status": 200,
                "headers": response_headers,
                "body": error_response_body,
            });

            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_body,
            }
        }
    }
}

/// Process x402 verify-request message
/// When acting as a facilitator, verify payment for another gateway
#[instrument(skip(message), fields(message_id = %message.id))]
async fn process_x402_verify_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Processing x402 verify-request from {:?}", message.from_did);

    // Get x402 configuration from context
    let config = match message
        .context
        .get("x402_config")
    {
        Some(config_value) => match serde_json::from_value::<crate::config::types::X402Config>(config_value.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to parse x402 config from context: {}", e);
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402VerifyResponse.to_string(),
                    response_body: serde_json::json!({
                        "valid": false,
                        "error": "x402 not configured on this gateway"
                    }),
                };
            }
        },
        None => {
            warn!("x402 config not available in message context");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402VerifyResponse.to_string(),
                response_body: serde_json::json!({
                    "valid": false,
                    "error": "x402 not configured on this gateway"
                }),
            };
        }
    };

    // Check if fabric facilitator is enabled at gateway level
    if let Some(facilitator_mode) = GLOBAL_FACILITATOR_MODE.get() {
        if !facilitator_mode.facilitator_via_fabric {
            warn!("Fabric facilitator not enabled on this gateway, rejecting verification request");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402VerifyResponse.to_string(),
                response_body: serde_json::json!({
                    "valid": false,
                    "error": "Fabric facilitator not enabled on this gateway"
                }),
            };
        }
    } else {
        warn!("Facilitator mode not initialized, rejecting verification request");
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::X402VerifyResponse.to_string(),
            response_body: serde_json::json!({
                "valid": false,
                "error": "Facilitator mode not configured on this gateway"
            }),
        };
    }

    // Extract request fields from message body
    let body = &message.message_body;

    // Extract verification_id from the request (GW1 sends this)
    let verification_id = body
        .get("verification_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let payment_signature = match body
        .get("payment_signature")
        .and_then(|v| v.as_str())
    {
        Some(sig) => sig.to_string(),
        None => {
            error!("Missing payment_signature in verify-request");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402VerifyResponse.to_string(),
                response_body: serde_json::json!({
                    "valid": false,
                    "error": "Missing payment_signature field"
                }),
            };
        }
    };

    let network = body
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();

    let channel_id = body
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("remote-gateway")
        .to_string();

    let resource = body
        .get("resource")
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();

    if let Some(ref vid) = verification_id {
        info!("   Verification ID: {}", vid);
    }
    info!(
        "   Payment signature: {}...",
        &payment_signature
            .chars()
            .take(20)
            .collect::<String>()
    );
    info!("   Network: {}", network);
    info!("   Channel: {}", channel_id);
    info!("   Resource: {}", resource);

    // Perform payment verification using deterministic correlation_id (tx_hash)
    // This ensures both GW1 and GW2 use the same correlation_id for the same transaction
    match crate::x402::verification::verify_payment(
        &payment_signature,
        &config,
        &channel_id,
        &channel_id,
        &resource,
        None,                    // No listener manager - verify locally
        get_transaction_store(), // Creates transaction with correlation_id=tx_hash
        None,                    // No existing correlation_id - will use tx_hash from payment
    )
    .await
    {
        Ok((verified_payment, correlation_id)) => {
            info!("✅ Payment verification successful - correlation_id={}", correlation_id);

            // Update transaction to set facilitator_gateway_id to the requesting gateway (message sender)
            // This allows GW2 to send settlement-complete notification back to GW1 after settling
            if let Some(store) = get_transaction_store() {
                // Set facilitator_gateway_id to the requesting gateway's ID
                let requesting_gateway_id = message.gateway_id.clone();
                info!("Setting requesting_gateway_id={} for transaction {}", requesting_gateway_id, correlation_id);

                // Update the transaction with requesting gateway ID
                if let Err(e) = store
                    .set_facilitator_gateway_id(&correlation_id, requesting_gateway_id)
                    .await
                {
                    warn!("Failed to set facilitator_gateway_id: {}", e);
                }
            }

            // GW2 should create settlement stage after successful verification
            // Settlement mode determines whether to settle immediately or defer
            if let Some(store) = get_transaction_store() {
                let settlement_mode_str = format!("{:?}", config.settlement_mode).to_lowercase();

                match config.settlement_mode {
                    crate::config::types::X402SettlementMode::Immediate => {
                        info!("GW2: Immediate settlement mode - will settle before responding");

                        // Initialize settlement stage
                        if let Err(e) = store
                            .init_settlement(
                                &correlation_id,
                                settlement_mode_str.clone(),
                                "local".to_string(),
                                verified_payment.tx_hash(),
                                None,
                            )
                            .await
                        {
                            warn!("Failed to init settlement: {}", e);
                        }

                        // Execute settlement
                        match crate::x402::settlement::settle_payment(
                            &verified_payment,
                            &config,
                            &channel_id,
                            &channel_id,
                            Some(&store),
                            None,
                            Some(correlation_id.clone()),
                        )
                        .await
                        {
                            Ok(()) => {
                                info!("✅ GW2 immediate settlement completed");
                                // Transaction store is already updated by settle_payment
                            }
                            Err(e) => {
                                warn!("❌ GW2 immediate settlement failed: {}", e);
                            }
                        }
                    }
                    crate::config::types::X402SettlementMode::Deferred => {
                        info!("GW2: Deferred settlement mode - creating pending settlement for worker");

                        // Create pending settlement stage for worker to pick up
                        if let Err(e) = store
                            .init_settlement(
                                &correlation_id,
                                settlement_mode_str,
                                "local".to_string(),
                                verified_payment.tx_hash(),
                                None,
                            )
                            .await
                        {
                            warn!("Failed to create deferred settlement stage: {}", e);
                        } else {
                            info!("✅ GW2 pending settlement created - worker will process");
                        }
                    }
                    crate::config::types::X402SettlementMode::None => {
                        info!("GW2: No settlement mode - verification only");
                    }
                }
            }

            // Return success response with payment details
            ProcessingResult::RequiresResponse {
                response_type: MessageType::X402VerifyResponse.to_string(),
                response_body: serde_json::json!({
                    "valid": true,
                    "payment": verified_payment
                }),
            }
        }
        Err(e) => {
            warn!("❌ Payment verification failed for {}: {}", channel_id, e);

            // Return failure response
            ProcessingResult::RequiresResponse {
                response_type: MessageType::X402VerifyResponse.to_string(),
                response_body: serde_json::json!({
                    "valid": false,
                    "error": e
                }),
            }
        }
    }
}

/// Process x402 verify-response message
/// Received when we requested verification from another gateway
#[instrument(skip(message), fields(message_id = %message.id))]
async fn process_x402_verify_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Processing x402 verify-response");

    let body = &message.message_body;
    let valid = body
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let error = body
        .get("error")
        .and_then(|v| v.as_str());

    // Get correlation ID from DIDComm thread ID (thid)
    // The response should have thid matching our original request message ID
    let correlation_id = message
        .didcomm_message_id
        .clone();

    // Get transaction store (GW2 should record this verification)
    let transaction_store = get_transaction_store();

    if valid {
        info!("✅ Payment verification successful");
        info!("   Correlation ID (thid): {}", correlation_id);

        if let Some(payment) = body.get("payment") {
            info!("   Payment details: {}", payment);

            // CRITICAL: GW2 must record the verification to its TransactionStore
            // This ensures both GW1 and GW2 have transaction records for traceability
            if let Some(txn_store) = transaction_store
                && let Ok(payment_payload) = serde_json::from_value::<crate::x402::PaymentPayload>(payment.clone())
            {
                // Get channel info from body if available
                let channel_id = body
                    .get("channel_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let channel_name = body
                    .get("channel_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let resource_path = body
                    .get("resource_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");

                // Check if transaction already exists, if not create it
                if txn_store
                    .get(&correlation_id)
                    .await
                    .is_none()
                {
                    // Create transaction on GW2
                    if let Err(e) = txn_store
                        .create_transaction(
                            correlation_id.clone(),
                            channel_id.to_string(),
                            channel_name.to_string(),
                            resource_path.to_string(),
                            payment_payload,
                            "fabric_gateway".to_string(), // verification_mode
                            None,                         // facilitator_gateway_id
                        )
                        .await
                    {
                        warn!("Failed to create transaction in GW2 TransactionStore: {}", e);
                    } else {
                        info!("✅ GW2 created transaction in TransactionStore: {}", correlation_id);
                    }
                }

                // Mark verification as complete
                if let Err(e) = txn_store
                    .complete_verification(&correlation_id)
                    .await
                {
                    warn!("Failed to mark verification complete in GW2 TransactionStore: {}", e);
                } else {
                    info!("✅ GW2 marked verification complete: {}", correlation_id);
                }
            }
        }
    } else {
        warn!("❌ Payment verification failed");
        warn!("   Correlation ID (thid): {}", correlation_id);

        if let Some(err) = error {
            warn!("   Error: {}", err);
            // TODO: Record verification failure in TransactionStore
            // This would require adding a fail_verification method
        }
    }

    ProcessingResult::ProcessedNoResponse
}

/// Process x402 settle-request message
/// When acting as a facilitator, execute on-chain settlement for another gateway
/// OR record a deferred settlement if action="record"
#[instrument(skip(message), fields(message_id = %message.id))]
async fn process_x402_settle_request(message: &ReceivedMessage) -> ProcessingResult {
    // Extract request fields
    let body = &message.message_body;

    // Check if this is a recording request (not execution)
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("settle");

    if action == "record" {
        // This is a settlement recording request for deferred settlements
        info!("📥 Processing x402 settle-request - recording deferred settlement");

        // CRITICAL: GW2 must record the settlement to its TransactionStore
        // This ensures both GW1 and GW2 have transaction records for traceability

        // Extract payment and correlation_id from request
        let payment: crate::x402::PaymentPayload = match body.get("payment") {
            Some(payment_val) => match serde_json::from_value(payment_val.clone()) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to parse payment payload for record action: {}", e);
                    return ProcessingResult::ProcessedNoResponse;
                }
            },
            None => {
                warn!("Missing payment field in settle-request (record action)");
                return ProcessingResult::ProcessedNoResponse;
            }
        };

        let correlation_id = body
            .get("correlation_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&message.didcomm_message_id)
            .to_string();

        // Get transaction store (GW2 records settlement)
        if let Some(txn_store) = get_transaction_store() {
            let channel_id = body
                .get("channel_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let channel_name = body
                .get("channel_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let resource_path = body
                .get("resource_path")
                .and_then(|v| v.as_str())
                .unwrap_or("/");

            // Check if transaction exists, if not create it
            if txn_store
                .get(&correlation_id)
                .await
                .is_none()
                && let Err(e) = txn_store
                    .create_transaction(
                        correlation_id.clone(),
                        channel_id.to_string(),
                        channel_name.to_string(),
                        resource_path.to_string(),
                        payment.clone(),
                        "fabric_gateway".to_string(),
                        None,
                    )
                    .await
            {
                warn!("GW2 failed to create transaction for deferred settlement: {}", e);
                return ProcessingResult::ProcessedNoResponse;
            }

            // Initialize settlement stage in GW2's TransactionStore
            let tx_hash = payment
                .tx_hash()
                .unwrap_or_default();
            if let Err(e) = txn_store
                .init_settlement(
                    &correlation_id,
                    "deferred".to_string(),       // settlement_mode
                    "fabric_gateway".to_string(), // settlement_method
                    Some(tx_hash),
                    None, // confirmations
                )
                .await
            {
                warn!("GW2 failed to record deferred settlement: {}", e);
            } else {
                info!("✅ GW2 recorded deferred settlement to TransactionStore: {}", correlation_id);
            }
        }

        return ProcessingResult::ProcessedNoResponse; // Fire-and-forget, no response expected
    }

    // Otherwise, this is a settlement execution request
    info!("📥 Processing x402 settle-request - executing on-chain settlement");

    // Get x402 config from message context (same pattern as verify-request)
    let config = match message
        .context
        .get("x402_config")
    {
        Some(config_value) => match serde_json::from_value::<crate::config::types::X402Config>(config_value.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to parse x402 config from context: {}", e);
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402SettleResponse.to_string(),
                    response_body: serde_json::json!({
                        "success": false,
                        "errorReason": "x402 config parse error",
                        "transaction": "",
                    }),
                };
            }
        },
        None => {
            warn!("x402 config not available in message context");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "success": false,
                    "errorReason": "x402 not configured on this gateway",
                    "transaction": "",
                }),
            };
        }
    };

    // Check if facilitator mode is enabled
    if let Some(facilitator_mode) = GLOBAL_FACILITATOR_MODE.get() {
        if !facilitator_mode.facilitator_via_fabric {
            warn!("Fabric facilitator not enabled, rejecting settlement request");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "success": false,
                    "errorReason": "Fabric facilitator not enabled on this gateway",
                    "transaction": "",
                }),
            };
        }
    } else {
        warn!("Facilitator mode not initialized");
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::X402SettleResponse.to_string(),
            response_body: serde_json::json!({
                "success": false,
                "errorReason": "Facilitator mode not configured",
                "transaction": "",
            }),
        };
    }

    // Extract request fields
    let body = &message.message_body;

    // Parse payment payload
    let payment: crate::x402::PaymentPayload = match body.get("payment") {
        Some(payment_val) => match serde_json::from_value(payment_val.clone()) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse payment payload: {}", e);
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402SettleResponse.to_string(),
                    response_body: serde_json::json!({
                        "success": false,
                        "errorReason": format!("Invalid payment payload: {}", e),
                        "transaction": "",
                    }),
                };
            }
        },
        None => {
            error!("Missing payment field in settle-request");
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "success": false,
                    "errorReason": "Missing payment field",
                    "transaction": "",
                }),
            };
        }
    };

    let channel_id = body
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("remote-gateway")
        .to_string();

    let asset_transfer_method = body
        .get("asset_transfer_method")
        .and_then(|v| v.as_str())
        .unwrap_or("transaction")
        .to_string();

    let network = body
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or(payment.network())
        .to_string();

    info!("   Channel: {}", channel_id);
    info!("   Method: {}", asset_transfer_method);
    info!("   Network: {}", network);
    info!("   Amount: {}", payment.amount());
    info!("   PayTo: {}", payment.pay_to());

    // Load facilitator_private_keys from global x402.json for settlement execution
    let merged_config = match crate::x402::config_cache::get_or_load_x402_config().await {
        Ok(global_config) => {
            let mut merged = config.clone();
            if let Some(global_keys) = &global_config.facilitator_private_keys {
                merged.facilitator_private_keys = Some(global_keys.clone());
                info!("Loaded {} facilitator_private_keys from global x402.json for settlement", global_keys.len());
            } else {
                error!("Global x402.json config has no facilitator_private_keys");
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402SettleResponse.to_string(),
                    response_body: serde_json::json!({
                        "settled": false,
                        "error": "Global x402.json config missing facilitator_private_keys",
                        "payer": payment.payload.get("authorization")
                            .and_then(|a| a.get("from"))
                            .and_then(|f| f.as_str())
                            .unwrap_or("unknown"),
                        "network": network,
                    }),
                };
            }
            merged
        }
        Err(e) => {
            error!("Failed to load global x402.json config for settlement: {}", e);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "settled": false,
                    "error": format!("Failed to load global x402.json config: {}", e),
                    "payer": payment.payload.get("authorization")
                        .and_then(|a| a.get("from"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("unknown"),
                    "network": network,
                }),
            };
        }
    };

    // Initialize embedded facilitator with merged config
    info!("Initializing embedded facilitator for settlement execution");
    let facilitator = match crate::x402::embedded_facilitator::get_embedded_facilitator(&merged_config).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to initialize embedded facilitator for settlement: {}", e);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "settled": false,
                    "error": format!("Failed to initialize embedded facilitator: {}", e),
                    "payer": payment.payload.get("authorization")
                        .and_then(|a| a.get("from"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("unknown"),
                    "network": network,
                }),
            };
        }
    };

    // Convert payment to x402 SettleRequest
    let settle_request = match crate::x402::x402rs_adapter::to_settle_request(&payment) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to convert payment to settle request: {}", e);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "settled": false,
                    "error": format!("Failed to convert payment to x402 format: {}", e),
                    "payer": payment.payload.get("authorization")
                        .and_then(|a| a.get("from"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("unknown"),
                    "network": network,
                }),
            };
        }
    };

    // Get facilitator address for this network for error reporting
    let facilitator_address = merged_config
        .facilitator_private_keys
        .as_ref()
        .and_then(|keys| keys.get(&network))
        .map(|key_config| key_config.address.as_str())
        .unwrap_or("unknown");

    // Execute on-chain settlement via embedded facilitator with retry logic
    info!(
        "Executing on-chain settlement via embedded facilitator network={} facilitator={} method={}",
        network, facilitator_address, asset_transfer_method
    );

    // Retry configuration (from x402.json facilitator section)
    let max_retries = merged_config
        .facilitator
        .as_ref()
        .map(|f| f.max_retries)
        .unwrap_or(3);
    let retry_backoff_ms = merged_config
        .facilitator
        .as_ref()
        .map(|f| f.retry_backoff_ms)
        .unwrap_or(1000);

    let mut settlement_result = None;
    let mut last_error = String::new();

    for attempt in 1..=max_retries {
        info!("Settlement attempt {}/{}", attempt, max_retries);

        match facilitator
            .settle(settle_request.clone())
            .await
        {
            Ok(response) => {
                settlement_result = Some(Ok(response));
                break;
            }
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();

                // Check if this is an "already settled" error (signature already used)
                if error_msg.contains("already used")
                    || error_msg.contains("already spent")
                    || error_msg.contains("invalid nonce")
                    || error_msg.contains("nonce too low")
                    || error_msg.contains("authorization used")
                    || error_msg.contains("transfer already executed")
                {
                    info!("✅ Settlement already completed (signature reused): {}", e);
                    // Treat as success - create a successful response from JSON
                    match serde_json::from_value::<x402_types::proto::SettleResponse>(serde_json::json!({
                        "success": true,
                        "transaction": "already_settled",
                        "message": format!("Payment already settled: {}", e)
                    })) {
                        Ok(response) => {
                            settlement_result = Some(Ok(response));
                            break;
                        }
                        Err(parse_err) => {
                            warn!("Failed to create already-settled response: {}", parse_err);
                            // Error will be captured below
                        }
                    }
                }

                last_error = e.to_string();
                warn!("Settlement attempt {}/{} failed: {}", attempt, max_retries, last_error);

                if attempt < max_retries {
                    // Exponential backoff: attempt 1 = 1x, attempt 2 = 2x, attempt 3 = 4x
                    let delay_ms = retry_backoff_ms * (1u64 << (attempt - 1));
                    info!("Retrying in {}ms...", delay_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    let settlement_result = settlement_result
        .unwrap_or_else(|| Err(format!("Settlement failed after {} attempts: {}", max_retries, last_error)));

    // Process settlement result and return response
    match settlement_result {
        Ok(settle_response) => {
            // Check if settlement was successful and extract transaction hash
            let is_successful = crate::x402::x402rs_adapter::is_settlement_successful(&settle_response);
            let tx_hash = crate::x402::x402rs_adapter::extract_transaction(&settle_response);

            if is_successful {
                let tx_hash_str = tx_hash.unwrap_or_else(|| "unknown".to_string());
                info!(
                    "✅ Settlement successful tx_hash={} network={} facilitator={}",
                    tx_hash_str, network, facilitator_address
                );
                ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402SettleResponse.to_string(),
                    response_body: serde_json::json!({
                        "settled": true,
                        "payer": payment.payload.get("authorization")
                            .and_then(|a| a.get("from"))
                            .and_then(|f| f.as_str())
                            .unwrap_or("unknown"),
                        "transaction_id": tx_hash_str,
                        "network": network,
                        "facilitator": facilitator_address,
                    }),
                }
            } else {
                let error_msg = crate::x402::x402rs_adapter::extract_settle_error(&settle_response)
                    .unwrap_or_else(|| "Unknown settlement error".to_string());
                let detailed_error =
                    format!("{} [network={}, facilitator={}]", error_msg, network, facilitator_address);
                error!("❌ Settlement failed: {}", detailed_error);
                ProcessingResult::RequiresResponse {
                    response_type: MessageType::X402SettleResponse.to_string(),
                    response_body: serde_json::json!({
                        "settled": false,
                        "error": detailed_error,
                        "payer": payment.payload.get("authorization")
                            .and_then(|a| a.get("from"))
                            .and_then(|f| f.as_str())
                            .unwrap_or("unknown"),
                        "network": network,
                        "facilitator": facilitator_address,
                    }),
                }
            }
        }
        Err(e) => {
            let detailed_error = format!("{} [network={}, facilitator={}]", e, network, facilitator_address);
            error!("❌ Settlement execution failed: {}", detailed_error);
            ProcessingResult::RequiresResponse {
                response_type: MessageType::X402SettleResponse.to_string(),
                response_body: serde_json::json!({
                    "settled": false,
                    "error": detailed_error,
                    "payer": payment.payload.get("authorization")
                        .and_then(|a| a.get("from"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("unknown"),
                    "network": network,
                    "facilitator": facilitator_address,
                }),
            }
        }
    }
}

#[instrument(skip(message), fields(message_id = %message.id))]
async fn process_x402_settle_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing settlement response");

    let body = &message.message_body;
    let settled = body
        .get("settled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let transaction_id = body
        .get("transaction_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let error_msg = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("Settlement failed");
    let network = body
        .get("network")
        .and_then(|v| v.as_str());
    let facilitator = body
        .get("facilitator")
        .and_then(|v| v.as_str());

    // Get correlation_id from DIDComm thid field
    // The response should have thid matching our original request message ID
    let correlation_id = match &message.didcomm_thid {
        Some(id) => id.clone(),
        None => {
            warn!("Settlement response missing thid - cannot match to request");
            return ProcessingResult::Failed {
                reason: "Missing thid (thread ID) in settlement response".to_string(),
            };
        }
    };

    if settled {
        info!(
            "✅ Settlement successful - txn: {} network: {} facilitator: {} correlation_id: {}",
            transaction_id,
            network.unwrap_or("unknown"),
            facilitator.unwrap_or("unknown"),
            correlation_id
        );
    } else {
        warn!(
            "❌ Settlement failed - error: {} network: {} facilitator: {} correlation_id: {}",
            error_msg,
            network.unwrap_or("unknown"),
            facilitator.unwrap_or("unknown"),
            correlation_id
        );
    }

    // Create settlement response
    let response = crate::x402::gateway_facilitator_service::SettlementResponse {
        settled,
        tx_hash: transaction_id.to_string(),
        error: error_msg.to_string(),
    };

    // Try to signal any waiting immediate mode request (event-driven, NO POLLING!)
    let signaled =
        crate::x402::gateway_facilitator_service::signal_settlement_response(&correlation_id, response.clone()).await;

    if signaled {
        info!("✅ Signaled waiting immediate mode settlement request: {}", correlation_id);
    } else {
        // No immediate request waiting - this is deferred mode, update payment record
        info!("No immediate request waiting, updating payment record for deferred settlement: {}", correlation_id);
    }

    ProcessingResult::ProcessedNoResponse
}

/// Process x402 settlement-complete message
/// Received when a remote gateway has completed settlement (GW2 → GW1 sync)
#[instrument(skip(message), fields(message_id = %message.id))]
async fn process_x402_settlement_complete(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Processing x402 settlement-complete");

    let body = &message.message_body;

    // Extract settlement completion details
    let correlation_id = body
        .get("correlation_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&message.didcomm_message_id)
        .to_string();

    let tx_hash = body
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("completed");

    info!(
        "✅ Settlement completion notification received: correlation_id={} tx_hash={} status={}",
        correlation_id, tx_hash, status
    );

    // Update local transaction record with settlement completion from remote gateway
    if let Some(txn_store) = get_transaction_store() {
        // First set the transaction hash
        if !tx_hash.is_empty() {
            if let Err(e) = txn_store
                .set_settlement_tx_hash(&correlation_id, tx_hash.clone())
                .await
            {
                warn!("Failed to set settlement tx_hash for {}: {}", correlation_id, e);
            } else {
                info!("✅ Updated transaction {} with tx_hash: {}", correlation_id, tx_hash);
            }
        }

        // Then mark settlement as complete
        if status == "completed" {
            if let Err(e) = txn_store
                .complete_settlement(&correlation_id)
                .await
            {
                warn!("Failed to complete settlement for {}: {}", correlation_id, e);
            } else {
                info!("✅ Marked settlement as complete for: {}", correlation_id);
            }
        }
    } else {
        warn!("Transaction store not available - cannot update settlement completion");
    }

    ProcessingResult::ProcessedNoResponse
}

#[cfg(test)]
mod mcp_receive_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
    use axum::body::Body;
    use axum::http::{Response, StatusCode};

    #[test]
    fn fabric_mcp_headers_preserve_case_insensitive_duplicates() {
        let headers = serde_json::json!({
            "MCP-METHOD": "tools/list",
            "mcp-method": "tools/call"
        });
        let result = fabric_mcp_headers(headers.as_object()).unwrap();
        assert_eq!(
            result
                .get_all("mcp-method")
                .iter()
                .count(),
            2
        );
    }

    #[test]
    fn fabric_mcp_headers_reject_non_string_standard_value() {
        let headers = serde_json::json!({"MCP-PROTOCOL-VERSION": 20260728});
        let error = fabric_mcp_headers(headers.as_object()).unwrap_err();
        assert!(error.contains("must have a string value"));
    }

    #[test]
    fn fabric_mcp_headers_ignore_malformed_unrelated_values() {
        let headers = serde_json::json!({
            "MCP-METHOD": "tools/list",
            "x-unrelated": {"nested": true}
        });
        let result = fabric_mcp_headers(headers.as_object()).unwrap();
        assert_eq!(
            result
                .get("mcp-method")
                .unwrap(),
            "tools/list"
        );
        assert!(!result.contains_key("x-unrelated"));
    }

    #[test]
    fn fabric_session_headers_are_always_untrusted() {
        use crate::mcp::request_validation::LegacySessionEvidence;

        assert_eq!(fabric_legacy_session_evidence(None), LegacySessionEvidence::Absent);
        let headers = serde_json::json!({"MCP-SESSION-ID": "forwarded-session"});
        assert_eq!(fabric_legacy_session_evidence(headers.as_object()), LegacySessionEvidence::Unknown);
    }

    #[tokio::test]
    async fn fabric_mcp_headers_feed_legacy_only_version_rejection() {
        let headers = serde_json::json!({
            "MCP-PROTOCOL-VERSION": "2026-07-28",
            "MCP-METHOD": "tools/list"
        });
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fabric-modern",
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .unwrap();

        let headers = fabric_mcp_headers(headers.as_object()).unwrap();
        let error = crate::mcp::request_validation::validate_mcp_post(
            &headers,
            &body,
            crate::mcp::request_validation::LegacySessionEvidence::Absent,
            crate::mcp::request_validation::LEGACY_ONLY_POLICY,
        )
        .unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(error.id, Some(serde_json::json!("fabric-modern")));
        assert_eq!(
            error.data,
            Some(serde_json::json!({
                "requested": "2026-07-28",
                "supported": ["2024-11-05"]
            }))
        );

        let result = axum_response_to_forward_result((*error).into_response()).await;
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected ForwardResponse");
        };
        assert_eq!(response_body["status"], 400);
        assert_eq!(response_body["headers"]["content-type"], "application/json");
        let error_body: serde_json::Value = serde_json::from_str(
            response_body["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error_body["id"], "fabric-modern");
        assert_eq!(error_body["error"]["code"], crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn fabric_request_resolves_surface_agent_did_audience_with_receiver_issuer() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        vc_issuer
            .get_identity_store()
            .create(crate::identity::test_helpers::test_surface_identity_record(
                "did:webvh:gw2-agent",
                "fabric-surface",
            ))
            .await
            .expect("store fabric surface identity");
        let config = crate::source_auth::SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig {
            audiences: vec![crate::source_auth::middleware::SURFACE_AGENT_DID_AUDIENCE.to_string()],
            ..Default::default()
        });

        let resolved = resolve_fabric_surface_auth_config(&config, Some(&vc_issuer), "fabric-surface")
            .await
            .expect("resolve fabric surface audience");

        let crate::source_auth::SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["did:webvh:gw2-agent"]);
    }

    fn make_connection_accepted_msg(
        authenticated: bool,
        from_did: Option<&str>,
        channel_did: Option<&str>,
    ) -> ReceivedMessage {
        let body = match channel_did {
            Some(did) => serde_json::json!({ "channel_did": did }),
            None => serde_json::json!({}),
        };
        ReceivedMessage::new(
            "cp-test".to_string(),
            "gw-test".to_string(),
            "https://affinidi.com/atm/client-actions/connection-accepted".to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            from_did.map(str::to_string),
            vec!["did:web:acceptor.example:us".to_string()],
            None,
            None,
            body,
            MessageMetadata {
                encrypted: true,
                authenticated,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    fn make_handshake_msg(
        message_type: &str,
        thid: Option<&str>,
        body: serde_json::Value,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-test".to_string(),
            "gw-test".to_string(),
            message_type.to_string(),
            uuid::Uuid::new_v4().to_string(),
            thid.map(str::to_string),
            Some("did:web:peer.example:tmp".to_string()),
            vec!["did:web:us.example:tmp".to_string()],
            None,
            None,
            body,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    #[tokio::test]
    async fn connection_setup_surfaces_issuer_attestation_and_thread_nonce() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point =
            store_invitation(temp.path(), Some(chrono::Utc::now() + chrono::Duration::hours(1))).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let mut body = setup_body(&did, Some(&proof));
        body["issuer_attestation"] = serde_json::json!("header.payload.signature");
        let msg = make_connection_setup_msg_with_thid(temp.path(), &connection_point.id, body, Some("thid-setup"));

        let result = process_connection_setup(&msg).await;

        match result {
            ProcessingResult::OOBConnectionSetup(setup) => {
                assert_eq!(setup.acceptor_temporary_did, ACCEPTOR_TMP_DID);
                assert_eq!(setup.acceptor_secure_did, did);
                assert_eq!(setup.secret, "s3cret");
                assert_eq!(
                    setup
                        .issuer_attestation
                        .as_deref(),
                    Some("header.payload.signature")
                );
                assert_eq!(setup.nonce.as_deref(), Some("thid-setup"));
            }
            other => panic!("expected OOBConnectionSetup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_setup_without_attestation_surfaces_none() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point =
            store_invitation(temp.path(), Some(chrono::Utc::now() + chrono::Duration::hours(1))).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        match result {
            ProcessingResult::OOBConnectionSetup(setup) => {
                assert_eq!(setup.issuer_attestation, None);
                assert_eq!(setup.nonce, None);
            }
            other => panic!("expected OOBConnectionSetup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_accepted_surfaces_issuer_attestation_and_thread_nonce() {
        let msg = make_handshake_msg(
            "https://affinidi.com/atm/client-actions/connection-accepted",
            Some("thid-accepted"),
            serde_json::json!({
                "channel_did": "did:web:peer.example:cp",
                "issuer_attestation": "header.payload.signature",
            }),
        );

        let result = process_connection_accepted(&msg).await;

        match result {
            ProcessingResult::OOBConnectionAccepted(accepted) => {
                assert_eq!(accepted.inviter_temporary_did, "did:web:peer.example:tmp");
                assert_eq!(accepted.inviter_secure_did, "did:web:peer.example:cp");
                assert_eq!(
                    accepted
                        .issuer_attestation
                        .as_deref(),
                    Some("header.payload.signature")
                );
                assert_eq!(accepted.nonce.as_deref(), Some("thid-accepted"));
            }
            other => panic!("expected OOBConnectionAccepted, got {other:?}"),
        }
    }

    const ISSUER_REQUEST_TYPE: &str = "https://affinidi.com/atm/client-actions/gateway-issuer-request";
    const ISSUER_RESPONSE_TYPE: &str = "https://affinidi.com/atm/client-actions/gateway-issuer-response";
    const OUR_CP_DID: &str = "did:web:us.example:connection-points:9999";
    const PEER_CP_DID: &str = "did:web:peer.example:connection-points:1111";

    fn issuer_request_msg(
        body: serde_json::Value,
        with_context: bool,
    ) -> ReceivedMessage {
        let mut msg = ReceivedMessage::new(
            "cp-test".to_string(),
            "gw-test".to_string(),
            ISSUER_REQUEST_TYPE.to_string(),
            "issuer-req-1".to_string(),
            None,
            Some(PEER_CP_DID.to_string()),
            vec![OUR_CP_DID.to_string()],
            None,
            None,
            body,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        );
        if with_context {
            msg.context.insert(
                CONNECTION_POINT_DID_CONTEXT_KEY.to_string(),
                serde_json::Value::String(OUR_CP_DID.to_string()),
            );
        }
        msg
    }

    /// The document a peer would obtain by resolving the issuer DID. The test
    /// issuer's DID is `did:webvh`, whose resolved document carries that DID as
    /// `id`, while `get_did_document()` returns the `did:web` fallback copy.
    async fn resolved_issuer_document(issuer: &crate::identity::VCIssuer) -> serde_json::Value {
        let mut document = issuer
            .get_did_document()
            .await
            .expect("did document");
        document["id"] = serde_json::Value::String(
            issuer
                .get_issuer_did()
                .await
                .expect("issuer did"),
        );
        document
    }

    #[tokio::test]
    async fn issuer_request_without_nonce_is_rejected() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let msg = issuer_request_msg(serde_json::json!({}), true);

        let result = build_gateway_issuer_response(&issuer, &msg).await;

        match result {
            ProcessingResult::Failed { reason } => assert_eq!(reason, "Missing nonce in gateway-issuer-request"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issuer_request_returns_attestation_for_own_connection_point() {
        use crate::gateways::issuer_attestation::{ExpectedAttestation, verify_issuer_attestation_with_document};
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let msg = issuer_request_msg(serde_json::json!({ "nonce": "nonce-42" }), true);

        let result = build_gateway_issuer_response(&issuer, &msg).await;

        let ProcessingResult::RequiresResponse { response_type, response_body } = result else {
            panic!("expected RequiresResponse, got {result:?}");
        };
        assert_eq!(response_type, ISSUER_RESPONSE_TYPE);
        let jwt = response_body["issuer_attestation"]
            .as_str()
            .expect("issuer_attestation string");
        let document = resolved_issuer_document(&issuer).await;
        let verified = verify_issuer_attestation_with_document(
            jwt,
            ExpectedAttestation {
                sub: OUR_CP_DID,
                aud: PEER_CP_DID,
                nonce: "nonce-42",
            },
            &document,
        );
        assert_eq!(
            verified,
            Ok(issuer
                .get_issuer_did()
                .await
                .unwrap())
        );
    }

    #[tokio::test]
    async fn issuer_request_falls_back_to_envelope_recipient_as_connection_point() {
        use crate::gateways::issuer_attestation::{ExpectedAttestation, verify_issuer_attestation_with_document};
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let msg = issuer_request_msg(serde_json::json!({ "nonce": "nonce-7" }), false);

        let result = build_gateway_issuer_response(&issuer, &msg).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse, got {result:?}");
        };
        let jwt = response_body["issuer_attestation"]
            .as_str()
            .unwrap();
        let document = resolved_issuer_document(&issuer).await;
        let verified = verify_issuer_attestation_with_document(
            jwt,
            ExpectedAttestation {
                sub: OUR_CP_DID,
                aud: PEER_CP_DID,
                nonce: "nonce-7",
            },
            &document,
        );
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[tokio::test]
    async fn issuer_response_is_processed_without_reply() {
        let msg = make_handshake_msg(ISSUER_RESPONSE_TYPE, Some("issuer-req-unwaited"), serde_json::json!({}));

        let result = process_gateway_issuer_response(&msg).await;

        assert!(matches!(result, ProcessingResult::ProcessedNoResponse), "{result:?}");
    }

    #[tokio::test]
    async fn issuer_response_completes_the_waiter_registered_for_its_thread() {
        let thid = uuid::Uuid::new_v4().to_string();
        let rx =
            crate::proxy::fabric_response_waiter::register_forward_response_waiter(&thid, "did:web:peer.example:tmp")
                .unwrap();
        let msg =
            make_handshake_msg(ISSUER_RESPONSE_TYPE, Some(&thid), serde_json::json!({ "issuer_attestation": "a.b.c" }));

        let result = process_gateway_issuer_response(&msg).await;
        let delivered = crate::proxy::fabric_response_waiter::wait_for_forward_response(
            &thid,
            rx,
            std::time::Duration::from_millis(50),
        )
        .await
        .expect("waiter completed");

        assert!(matches!(result, ProcessingResult::ProcessedNoResponse), "{result:?}");
        assert_eq!(delivered.message_body["issuer_attestation"], "a.b.c");
        assert_eq!(
            delivered
                .didcomm_thid
                .as_deref(),
            Some(thid.as_str())
        );
    }

    const PEER_ISSUER: &str = "did:web:peer.example";

    fn peer_issuers(trusted: &[&str]) -> crate::gateways::types::PeerIssuers {
        crate::gateways::types::PeerIssuers {
            attested: Some(PEER_ISSUER.to_string()),
            trusted: trusted
                .iter()
                .map(|did| did.to_string())
                .collect(),
        }
    }

    const CLAIMED_DID: &str = "did:web:victim.example";

    fn a2a_surface() -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "surf-inbound-identity",
            "name": "inbound identity",
            "access_point": { "listen_address": "127.0.0.1:8080", "route": "/a2a", "protocol": "a2a" },
            "target": { "endpoint": "http://127.0.0.1:9/" }
        }))
        .unwrap()
    }

    use crate::surface_context::IdentityVerification;

    const CREDENTIAL_EXT: &str = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    const RAW_IDENTITY_EXT: &str = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;

    async fn inbound_caller_identity(
        extensions: &[&str],
        metadata: serde_json::Value,
        peer_issuers: &crate::gateways::types::PeerIssuers,
        vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
    ) -> (Option<String>, Option<String>, IdentityVerification) {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "message/send",
            "params": { "message": { "role": "user", "parts": [], "extensions": extensions, "metadata": metadata } }
        });
        extract_caller_identity_inbound(
            &a2a_surface(),
            "channel-1",
            "cfg-1",
            &serde_json::to_vec(&body).unwrap(),
            None,
            None,
            peer_issuers,
            vc_issuer,
        )
        .await
    }

    async fn audit_record(
        issuer: &crate::identity::VCIssuer,
        did: &str,
    ) -> crate::identity::filesystem::AgentIdentityRecord {
        issuer
            .get_identity_store()
            .find_by_did(did)
            .await
            .unwrap()
            .expect("audit record for the DID")
    }

    #[tokio::test]
    async fn credential_extension_did_without_presentation_yields_no_caller_identity() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let (identity, issuer_did, verification) = inbound_caller_identity(
            &[CREDENTIAL_EXT],
            serde_json::json!({ CREDENTIAL_EXT: { "did": CLAIMED_DID } }),
            &peer_issuers(&[]),
            Some(&issuer),
        )
        .await;
        assert_eq!(identity, None, "a bare did claim must not become the caller identity");
        assert_eq!(issuer_did, None);
        assert_eq!(verification, IdentityVerification::Unverified);
        assert!(
            !audit_record(&issuer, CLAIMED_DID)
                .await
                .verified,
            "the claimed DID is audited as unverified"
        );
    }

    #[tokio::test]
    async fn credential_extension_with_unverifiable_presentation_yields_no_caller_identity() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let (identity, issuer_did, verification) = inbound_caller_identity(
            &[CREDENTIAL_EXT, RAW_IDENTITY_EXT],
            serde_json::json!({
                CREDENTIAL_EXT: { "did": CLAIMED_DID, "verifiablePresentation": "not-a-jwt" },
                RAW_IDENTITY_EXT: { "agentId": "agent-7" },
            }),
            &peer_issuers(&[]),
            Some(&issuer),
        )
        .await;
        assert_eq!(identity, None, "a failed presentation yields no identity and no payload-derived fallback");
        assert_eq!(issuer_did, None);
        assert_eq!(verification, IdentityVerification::Unverified);
        assert!(
            !audit_record(&issuer, CLAIMED_DID)
                .await
                .verified,
            "the claimed DID is audited as unverified"
        );
    }

    #[tokio::test]
    async fn presentation_from_a_connection_issuer_is_attributed_as_verified() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let connection = crate::gateways::types::PeerIssuers {
            attested: Some(signed.issuer_did.clone()),
            trusted: Vec::new(),
        };
        let (identity, issuer_did, verification) = inbound_caller_identity(
            &[CREDENTIAL_EXT],
            serde_json::json!({
                CREDENTIAL_EXT: { "did": signed.holder_did, "verifiablePresentation": signed.presentation.to_string() },
            }),
            &connection,
            Some(&signed.issuer),
        )
        .await;
        assert_eq!(identity.as_deref(), Some(signed.holder_did.as_str()));
        assert_eq!(issuer_did.as_deref(), Some(signed.issuer_did.as_str()));
        assert_eq!(verification, IdentityVerification::Vp);
        assert!(
            audit_record(&signed.issuer, &signed.holder_did)
                .await
                .verified
        );
    }

    #[tokio::test]
    async fn presentation_from_a_foreign_issuer_yields_no_identity_and_no_fallback() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let (identity, issuer_did, verification) = inbound_caller_identity(
            &[CREDENTIAL_EXT, RAW_IDENTITY_EXT],
            serde_json::json!({
                CREDENTIAL_EXT: { "did": signed.holder_did, "verifiablePresentation": signed.presentation.to_string() },
                RAW_IDENTITY_EXT: { "agentId": "agent-7" },
            }),
            &peer_issuers(&[]),
            Some(&signed.issuer),
        )
        .await;
        assert_eq!(identity, None, "an issuer outside the connection is neither attributed nor replaced by a fallback");
        assert_eq!(issuer_did, None);
        assert_eq!(verification, IdentityVerification::Unverified);
        assert!(
            !audit_record(&signed.issuer, &signed.holder_did)
                .await
                .verified
        );
    }

    #[tokio::test]
    async fn raw_identity_extension_did_is_ignored_and_identity_is_payload_derived() {
        use sha2::{Digest, Sha256};
        let (identity, issuer_did, verification) = inbound_caller_identity(
            &[RAW_IDENTITY_EXT],
            serde_json::json!({ RAW_IDENTITY_EXT: { "did": CLAIMED_DID, "agentId": "agent-7" } }),
            &peer_issuers(&[]),
            None,
        )
        .await;
        let expected =
            format!("sha256:{:x}", Sha256::digest(serde_json::to_string(&serde_json::json!("agent-7")).unwrap()));
        assert_eq!(identity.as_deref(), Some(expected.as_str()), "identity must be computed from the payload");
        assert_ne!(identity.as_deref(), Some(CLAIMED_DID));
        assert_eq!(issuer_did, None);
        assert_eq!(verification, IdentityVerification::Unverified);
    }

    #[tokio::test]
    async fn raw_identity_extension_did_does_not_influence_whole_object_identity() {
        let raw_identity = |did: &str| serde_json::json!({ RAW_IDENTITY_EXT: { "did": did, "name": "agent-7" } });
        let (claimed, _, claimed_verification) =
            inbound_caller_identity(&[RAW_IDENTITY_EXT], raw_identity(CLAIMED_DID), &peer_issuers(&[]), None).await;
        let (other, _, _) = inbound_caller_identity(
            &[RAW_IDENTITY_EXT],
            raw_identity("did:web:other.example"),
            &peer_issuers(&[]),
            None,
        )
        .await;
        let (without_did, _, _) = inbound_caller_identity(
            &[RAW_IDENTITY_EXT],
            serde_json::json!({ RAW_IDENTITY_EXT: { "name": "agent-7" } }),
            &peer_issuers(&[]),
            None,
        )
        .await;
        let (other_name, _, _) = inbound_caller_identity(
            &[RAW_IDENTITY_EXT],
            serde_json::json!({ RAW_IDENTITY_EXT: { "did": CLAIMED_DID, "name": "agent-8" } }),
            &peer_issuers(&[]),
            None,
        )
        .await;
        assert!(
            claimed
                .as_deref()
                .is_some_and(|id| id.starts_with("sha256:")),
            "{claimed:?}"
        );
        assert_eq!(claimed, other, "a different did must not yield a different identity");
        assert_eq!(claimed, without_did, "the did must not be part of the hashed payload");
        assert_ne!(claimed, other_name, "the remaining payload still determines the identity");
        assert_eq!(claimed_verification, IdentityVerification::Unverified);
    }

    #[test]
    fn identity_issued_by_the_sending_gateway_matches() {
        assert!(issuer_matches_peer(Some(PEER_ISSUER), &peer_issuers(&[])));
    }

    #[test]
    fn identity_without_issuer_does_not_match() {
        assert!(!issuer_matches_peer(None, &peer_issuers(&[])));
        assert!(!issuer_matches_peer(None, &peer_issuers(&["did:web:other.example"])));
    }

    #[test]
    fn identity_issued_by_another_gateway_does_not_match() {
        assert!(!issuer_matches_peer(Some("did:web:other.example"), &peer_issuers(&[])));
    }

    #[test]
    fn identity_issued_by_an_issuer_trusted_for_the_connection_matches() {
        let issuers = peer_issuers(&["did:web:other.example"]);

        assert!(issuer_matches_peer(Some("did:web:other.example"), &issuers));
        assert!(!issuer_matches_peer(Some("did:web:third.example"), &issuers));
    }

    #[test]
    fn operator_trusted_issuer_matches_without_an_attested_issuer() {
        let issuers = crate::gateways::types::PeerIssuers {
            attested: None,
            trusted: vec!["did:web:legacy.example".to_string()],
        };

        assert!(issuer_matches_peer(Some("did:web:legacy.example"), &issuers));
        assert!(!issuer_matches_peer(Some(PEER_ISSUER), &issuers));
    }

    #[tokio::test]
    async fn forward_request_without_sender_cannot_resolve_peer_issuers() {
        let err = resolve_peer_issuers(None)
            .await
            .unwrap_err();

        assert_eq!(err, "forward-request has no sender DID");
    }

    #[tokio::test]
    async fn peer_issuer_resolution_fails_closed_for_an_unknown_sender() {
        let err = resolve_peer_issuers(Some(PEER_CP_DID))
            .await
            .unwrap_err();

        // Other tests in this process may have installed a listener manager;
        // either way an unpaired sender must be rejected.
        assert!(
            err == "listener manager not available" || err == format!("unknown peer gateway {PEER_CP_DID}"),
            "{err}"
        );
    }

    #[test]
    fn forbidden_forward_response_carries_status_error_and_json_body() {
        let response = forbidden_forward_response("unknown peer gateway did:web:x");

        assert_eq!(response["status"], 403);
        assert_eq!(response["error"], "unknown peer gateway did:web:x");
        assert_eq!(response["headers"]["content-type"], "application/json");
        let body: serde_json::Value = serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "Forbidden");
        assert_eq!(body["message"], "unknown peer gateway did:web:x");
    }

    // A valid connection-accepted must be accepted and surface the correct DIDs
    // from the message. (Sender authentication is now enforced by the SDK's
    // authcrypt-only UnpackPolicy before the handler runs, so the handler no
    // longer rejects on metadata.authenticated.)
    #[tokio::test]
    async fn authcrypt_connection_accepted_succeeds() {
        let msg = make_connection_accepted_msg(
            true,
            Some("did:web:inviter.example:tmp"),
            Some("did:web:inviter.example:secure"),
        );
        let result = process_connection_accepted(&msg).await;
        assert!(
            matches!(result, ProcessingResult::OOBConnectionAccepted(_)),
            "expected OOBConnectionAccepted for authcrypt message, got {:?}",
            result
        );
        if let ProcessingResult::OOBConnectionAccepted(accepted) = result {
            assert_eq!(accepted.inviter_temporary_did, "did:web:inviter.example:tmp");
            assert_eq!(accepted.inviter_secure_did, "did:web:inviter.example:secure");
        }
    }

    // Authcrypt message with no `from` DID must still fail.
    #[tokio::test]
    async fn authcrypt_connection_accepted_missing_from_fails() {
        let msg = make_connection_accepted_msg(true, None, Some("did:web:inviter.example:secure"));
        let result = process_connection_accepted(&msg).await;
        assert!(
            matches!(result, ProcessingResult::Failed { .. }),
            "expected Failed when from_did is absent, got {:?}",
            result
        );
    }

    // Authcrypt message with no `channel_did` body field must fail.
    #[tokio::test]
    async fn authcrypt_connection_accepted_missing_channel_did_fails() {
        let msg = make_connection_accepted_msg(true, Some("did:web:inviter.example:tmp"), None);
        let result = process_connection_accepted(&msg).await;
        assert!(
            matches!(result, ProcessingResult::Failed { .. }),
            "expected Failed when channel_did is absent, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn forward_result_preserves_status_code() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("{}"))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_type, response_body } = result else {
            panic!("expected RequiresResponse");
        };
        assert_eq!(response_type, MessageType::ForwardResponse.to_string());
        assert_eq!(response_body["status"], 401);
    }

    #[tokio::test]
    async fn forward_result_preserves_headers() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Bearer realm=\"agent-gateway\"")
            .header("content-type", "application/problem+json")
            .body(Body::from("{}"))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse");
        };
        let headers = response_body["headers"]
            .as_object()
            .expect("headers should be an object");
        assert_eq!(
            headers["www-authenticate"]
                .as_str()
                .unwrap(),
            "Bearer realm=\"agent-gateway\""
        );
        assert_eq!(
            headers["content-type"]
                .as_str()
                .unwrap(),
            "application/problem+json"
        );
    }

    #[tokio::test]
    async fn forward_result_preserves_repeated_www_authenticate_values() {
        // Combined x402+MPP (or MPP with multiple payment methods) issues one
        // `WWW-Authenticate` challenge per method — none may be dropped.
        let response = Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("www-authenticate", "Payment realm=\"tg\", method=\"tempo\"")
            .header("www-authenticate", "Payment realm=\"tg\", method=\"stripe\"")
            .body(Body::from("{}"))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse");
        };
        let headers = response_body["headers"]
            .as_object()
            .expect("headers should be an object");
        let values = headers["www-authenticate"]
            .as_array()
            .expect("repeated header should serialize as a JSON array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"Payment realm=\"tg\", method=\"tempo\""));
        assert!(values.contains(&"Payment realm=\"tg\", method=\"stripe\""));
    }

    #[tokio::test]
    async fn forward_result_preserves_body() {
        let body_json = serde_json::json!({
            "type": "about:blank",
            "title": "Unauthorized",
            "status": 401,
            "detail": "Missing credential: Missing bearer token",
        });
        let body_str = serde_json::to_string(&body_json).unwrap();

        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/problem+json")
            .body(Body::from(body_str.clone()))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse");
        };
        assert_eq!(
            response_body["body"]
                .as_str()
                .unwrap(),
            body_str
        );
    }

    #[tokio::test]
    async fn forward_result_envelope_has_no_error_field() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("{}"))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse");
        };
        assert!(
            response_body
                .get("error")
                .is_none(),
            "envelope must not contain an 'error' field so GW1 uses the transparent pass-through path"
        );
    }

    #[tokio::test]
    async fn forward_result_handles_empty_body() {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected RequiresResponse");
        };
        assert_eq!(response_body["status"], 403);
        assert_eq!(
            response_body["body"]
                .as_str()
                .unwrap(),
            ""
        );
    }

    fn forward_error_of(result: Result<String, ProcessingResult>) -> (u64, String) {
        match result {
            Err(ProcessingResult::RequiresResponse { response_type, response_body }) => {
                assert_eq!(response_type, MessageType::ForwardResponse.to_string());
                (
                    response_body["status"]
                        .as_u64()
                        .unwrap(),
                    response_body["body"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            }
            other => panic!("expected an error ForwardResponse, got {other:?}"),
        }
    }

    const JSON_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n";
    const SSE_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";

    #[tokio::test]
    async fn forward_target_body_within_the_limit_is_returned() {
        use crate::proxy::upstream_body::tests::{PATIENT, chunk, limits, upstream};
        use std::time::Duration;
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let response =
            upstream(JSON_HEAD.to_string(), vec![(Duration::ZERO, chunk(body)), (Duration::ZERO, chunk(b""))]).await;

        let read =
            read_forward_target_body(response, false, b"", limits(body.len(), Some(PATIENT), PATIENT), "surface-1")
                .await
                .unwrap();

        assert_eq!(read.as_bytes(), body);
    }

    #[tokio::test]
    async fn forward_target_body_over_the_limit_answers_502() {
        use crate::proxy::upstream_body::tests::{PATIENT, chunk, limits, upstream};
        use std::time::Duration;
        let response = upstream(
            JSON_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(&[b'x'; 64])), (Duration::ZERO, chunk(&[b'x'; 64]))],
        )
        .await;

        let result =
            read_forward_target_body(response, false, b"", limits(100, Some(PATIENT), PATIENT), "surface-1").await;

        let (status, body) = forward_error_of(result);
        assert_eq!(status, 502);
        assert!(body.contains("Upstream response too large"), "{body}");
    }

    #[tokio::test]
    async fn stalled_forward_target_body_answers_504() {
        use crate::proxy::upstream_body::tests::{PATIENT, chunk, limits, upstream};
        use std::time::Duration;
        let response = upstream(JSON_HEAD.to_string(), vec![(Duration::ZERO, chunk(br#"{"jsonrpc":"#))]).await;

        let result = read_forward_target_body(
            response,
            false,
            b"",
            limits(1024, Some(Duration::from_millis(200)), PATIENT),
            "surface-1",
        )
        .await;

        let (status, body) = forward_error_of(result);
        assert_eq!(status, 504);
        assert!(body.contains("Upstream response timed out"), "{body}");
    }

    #[tokio::test]
    async fn forward_target_sse_body_is_reduced_to_its_response_and_bounded() {
        use crate::proxy::upstream_body::tests::{PATIENT, chunk, limits, upstream};
        use std::time::Duration;
        let event = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let response =
            upstream(SSE_HEAD.to_string(), vec![(Duration::ZERO, chunk(event)), (Duration::ZERO, chunk(b""))]).await;
        let read = read_forward_target_body(response, true, b"", limits(1024, Some(PATIENT), PATIENT), "surface-1")
            .await
            .unwrap();
        assert_eq!(read, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);

        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(event)), (Duration::ZERO, chunk(event)), (Duration::ZERO, chunk(b""))],
        )
        .await;
        let result =
            read_forward_target_body(response, true, b"", limits(event.len(), Some(PATIENT), PATIENT), "surface-1")
                .await;
        let (status, body) = forward_error_of(result);
        assert_eq!(status, 502);
        assert!(body.contains("Upstream response too large"), "{body}");
    }

    /// The GW2 agent-card hop uses the forward's pinned, redirect-free client
    /// and its body bounds: a redirect or an oversized card yields no card.
    #[tokio::test]
    async fn agent_card_fetch_is_bounded_and_does_not_follow_redirects() {
        use crate::proxy::upstream_body::tests::{PATIENT, limits};
        let app = axum::Router::new()
            .route("/card", axum::routing::get(|| async { r#"{"name":"card"}"# }))
            .route("/big", axum::routing::get(|| async { format!(r#"{{"name":"{}"}}"#, "x".repeat(4096)) }))
            .route(
                "/redirect",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, "/card")])
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let fetch = |path: &str| {
            let url = format!("http://{address}{path}");
            async move { fetch_agent_card(&url, PATIENT, limits(1024, Some(PATIENT), PATIENT), "surface-1").await }
        };

        assert_eq!(fetch("/card").await, Some(serde_json::json!({"name": "card"})));
        assert_eq!(fetch("/big").await, None, "an oversized card was read");
        assert_eq!(fetch("/redirect").await, None, "the redirect was followed");
    }

    #[tokio::test]
    async fn forward_result_uses_forward_response_type() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("ok"))
            .unwrap();

        let result = axum_response_to_forward_result(response).await;

        let ProcessingResult::RequiresResponse { response_type, .. } = result else {
            panic!("expected RequiresResponse");
        };
        assert_eq!(response_type, "https://affinidi.com/atm/client-actions/forward-response");
    }

    #[test]
    fn surface_policy_denied_body_is_mcp_envelope_for_tools_call() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": { "name": "delete_account" },
        });
        let body_bytes = serde_json::to_vec(&req).unwrap();
        let result = build_surface_policy_denied_forward_body(&body_bytes, Some("admin only"));

        assert_eq!(result["status"], 200);
        assert_eq!(result["headers"]["content-type"], "application/json");
        let inner: serde_json::Value = serde_json::from_str(
            result["body"]
                .as_str()
                .expect("body string"),
        )
        .expect("valid JSON-RPC body");
        assert_eq!(inner["jsonrpc"], "2.0");
        assert_eq!(inner["id"], 42);
        assert_eq!(inner["error"]["code"], -32001);
        assert_eq!(inner["error"]["message"], "Tool 'delete_account' is not allowed by policy: admin only");
    }

    #[test]
    fn surface_policy_denied_body_is_403_for_non_mcp() {
        let body_bytes = br#"{"hello":"world"}"#;
        let result = build_surface_policy_denied_forward_body(body_bytes, Some("missing scope"));

        assert_eq!(result["status"], 403);
        assert_eq!(result["headers"]["content-type"], "application/json");
        assert_eq!(result["error"], "Agent trust policy denied the request: missing scope");
        let inner: serde_json::Value = serde_json::from_str(
            result["body"]
                .as_str()
                .expect("body string"),
        )
        .expect("valid JSON body");
        assert_eq!(inner["error"], "Forbidden");
        assert_eq!(inner["message"], "Agent trust policy denied the request: missing scope");
    }

    #[test]
    fn surface_policy_denied_body_omits_empty_reason_suffix() {
        let body_bytes = br#"{}"#;
        let result = build_surface_policy_denied_forward_body(body_bytes, None);

        assert_eq!(result["status"], 403);
        assert_eq!(result["error"], "Agent trust policy denied the request");
    }

    const ACCEPTOR_TMP_DID: &str = "did:web:acceptor.example:tmp";
    const INVITER_TMP_DID: &str = "did:web:inviter.example:tmp";

    fn storage_context(storage_root: &std::path::Path) -> serde_json::Value {
        serde_json::json!(storage_root.join("agent_surfaces"))
    }

    fn authcrypt_metadata() -> MessageMetadata {
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: serde_json::Value::Null,
        }
    }

    fn make_forward_request_msg(
        storage_root: &std::path::Path,
        from_did: Option<&str>,
        channel_id: &str,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-test".to_string(),
            "gw-test".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            from_did.map(str::to_string),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::json!({ "channel_id": channel_id, "method": "GET", "path": "/" }),
            authcrypt_metadata(),
        )
        .with_context("agent_surface_storage_path", storage_context(storage_root))
    }

    #[test]
    fn redelivered_forward_request_is_dropped_without_a_response() {
        let temp = tempfile::tempdir().unwrap();
        let msg = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");

        assert!(admit_forward_request_envelope(&msg).is_ok());
        assert!(
            matches!(admit_forward_request_envelope(&msg), Err(ProcessingResult::ProcessedNoResponse)),
            "a duplicate must produce no ForwardResponse"
        );

        let mut expired = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");
        expired.expires_time = Some(crate::gateways::connection_points::envelope_replay::now_secs() - 1);
        match admit_forward_request_envelope(&expired) {
            Err(ProcessingResult::RequiresResponse { response_body, .. }) => {
                assert_eq!(response_body["status"], 504, "{response_body}");
            }
            other => panic!("expected a 504 ForwardResponse, got {other:?}"),
        }
    }

    /// The appliance-wide policy also covers public discovery reads over Fabric,
    /// as on the direct path; only the per-gateway policy skips them.
    #[tokio::test]
    async fn the_appliance_wide_policy_covers_public_fabric_reads() {
        use crate::policies::global_policy::tests::{gw_def, store_with};
        use crate::policies::global_policy::{GlobalAssignment, GlobalPolicyAssignments, PLANE_GATEWAY};
        let manager = crate::policies::GlobalPolicyManager::new();
        manager.set_policy_definition_store(
            store_with(vec![gw_def("deny", "package gateway.policy\ndefault allow = false")]).await,
        );
        let mut assignments = GlobalPolicyAssignments::default();
        assignments
            .assignments
            .insert(
                PLANE_GATEWAY.to_string(),
                vec![GlobalAssignment {
                    policy_id: "deny".to_string(),
                    monitor_only: false,
                }],
            );
        manager
            .refresh(&assignments)
            .await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "card", "name": "card",
            "access_point": {"listen_address": "https://gateway.example", "route": "/card", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example"}
        }))
        .unwrap();
        for (method, path) in [("GET", "/.well-known/agent-card.json"), ("POST", "/rpc")] {
            let result = evaluate_gateway_policy_for_fabric(
                Some(&manager),
                &surface,
                "card",
                method,
                path,
                None,
                Some("did:web:peer.example".into()),
                None,
                None,
                None,
            )
            .await;
            match result {
                Err(ProcessingResult::RequiresResponse { response_body, .. }) => {
                    assert_eq!(response_body["status"], 403, "{method} {path}")
                }
                other => panic!("{method} {path}: expected the appliance-wide deny, got {other:?}"),
            }
        }
    }

    /// A Fabric receive forward refuses a cloud-metadata Target, and dials an
    /// HTTP Target through a pinned client that returns a redirect instead of
    /// following it.
    #[tokio::test]
    async fn fabric_receive_forwards_dial_a_pinned_target_and_refuse_metadata() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let timeout = std::time::Duration::from_secs(5);
        assert!(
            forward_client_for("http://169.254.169.254/latest/meta-data/", timeout)
                .await
                .is_err(),
            "a cloud-metadata Target was dialled"
        );

        let followed = Arc::new(AtomicUsize::new(0));
        let hits = followed.clone();
        let app = axum::Router::new()
            .route(
                "/start",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, "/internal")])
                }),
            )
            .route(
                "/internal",
                axum::routing::get(move || {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async { "internal" }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let target = format!("http://{address}/start");
        let response = forward_client_for(&target, timeout)
            .await
            .expect("a loopback Target is allowed")
            .get(&target)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(followed.load(Ordering::SeqCst), 0, "the redirect target was fetched");
    }

    /// A forward request that finds every dispatch slot busy is checked as the
    /// task checks it, without being remembered: only one the task would admit
    /// is shed with a 503.
    #[tokio::test]
    async fn saturation_sheds_only_forward_requests_the_task_would_admit() {
        let temp = tempfile::tempdir().unwrap();
        register_gateway(
            temp.path(),
            "did:web:peer.example",
            crate::gateways::types::GatewayStatus::Active,
            Vec::new(),
        )
        .await;
        // The listener's long-lived store.
        let gateways = crate::gateways::FileSystemGatewayStore::new(temp.path().join("gateways"), None)
            .await
            .unwrap();
        let refusal = |message: ReceivedMessage| {
            let gateways = &gateways;
            async move { forward_request_refusal_before_dispatch(&message, Some(gateways)).await }
        };
        let status_of = |refusal: Option<ProcessingResult>| match refusal {
            Some(ProcessingResult::RequiresResponse { response_body, .. }) => response_body["status"].clone(),
            other => panic!("expected a ForwardResponse, got {other:?}"),
        };

        // Admissible, so it is shed; the check does not remember it, so the
        // task still admits it afterwards.
        let fresh = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");
        assert!(
            refusal(fresh.clone())
                .await
                .is_none()
        );
        assert!(admit_forward_request_envelope(&fresh).is_ok());
        // A redelivery of an admitted request gets no reply at all.
        assert!(matches!(refusal(fresh).await, Some(ProcessingResult::ProcessedNoResponse)));

        let mut expired = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");
        expired.expires_time = Some(crate::gateways::connection_points::envelope_replay::now_secs() - 1);
        assert_eq!(status_of(refusal(expired).await), 504);

        let stranger = make_forward_request_msg(temp.path(), Some("did:web:stranger.example"), "surface-1");
        assert_eq!(status_of(refusal(stranger).await), 403);

        let unrouted = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "");
        assert_eq!(status_of(refusal(unrouted).await), 400);
    }

    /// The reader answers a shed request from the listener's store in memory,
    /// never by loading the gateway directory from disk.
    #[tokio::test]
    async fn the_shed_check_reads_the_listeners_store_not_the_disk() {
        let temp = tempfile::tempdir().unwrap();
        register_gateway(
            temp.path(),
            "did:web:peer.example",
            crate::gateways::types::GatewayStatus::Active,
            Vec::new(),
        )
        .await;
        let gateways = crate::gateways::FileSystemGatewayStore::new(temp.path().join("gateways"), None)
            .await
            .unwrap();
        std::fs::remove_dir_all(temp.path().join("gateways")).unwrap();

        let message = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");
        assert!(
            forward_request_refusal_before_dispatch(&message, Some(&gateways))
                .await
                .is_none(),
            "the peer is found in memory"
        );
        // Loading from disk no longer finds the peer.
        match forward_request_refusal_before_dispatch(&message, None).await {
            Some(ProcessingResult::RequiresResponse { response_body, .. }) => assert_eq!(response_body["status"], 403),
            other => panic!("expected a 403 ForwardResponse, got {other:?}"),
        }
    }

    async fn register_gateway(
        storage_root: &std::path::Path,
        did: &str,
        status: crate::gateways::types::GatewayStatus,
        exposed_channels: Vec<String>,
    ) {
        let store = crate::gateways::FileSystemGatewayStore::new(storage_root.join("gateways"), None)
            .await
            .unwrap();
        let mut gateway = crate::gateways::types::Gateway::new(
            "Peer".to_string(),
            String::new(),
            did.to_string(),
            crate::gateways::types::GatewayType::Remote,
        );
        gateway.status = status;
        gateway.exposed_channels = exposed_channels;
        store
            .create(&gateway)
            .await
            .unwrap();
    }

    #[test]
    fn only_a_tenant_owned_peer_is_held_to_its_own_tenant() {
        for (peer, surface, reachable) in [
            (None, None, true),
            (None, Some("tenant-a"), true),
            (Some("tenant-a"), None, true),
            (Some("tenant-a"), Some("tenant-a"), true),
            (Some("tenant-a"), Some("tenant-b"), false),
        ] {
            assert_eq!(fabric_peer_may_reach_surface(peer, surface), reachable, "peer {peer:?}, surface {surface:?}");
        }
    }

    /// An empty exposure list ("every surface") never lets a tenant-owned peer
    /// reach or list another tenant's surface; an appliance-wide peer is
    /// unaffected.
    #[tokio::test]
    async fn a_tenant_peer_with_empty_exposure_reaches_only_its_own_tenants_surfaces() {
        use crate::surfaces::AgentSurfaceStore;
        // Surface lookup prefers the process-global surface store, which other
        // tests in this binary can initialise; run in a child process where it
        // is unset, so the lookup reads this test's storage root.
        if std::env::var_os("ATG_FABRIC_TENANT_REACH_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_FABRIC_TENANT_REACH_CHILD", "1")
                .env("RUST_MIN_STACK", "8388608")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated tenant reach check failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let surfaces = crate::surfaces::FileSystemAgentSurfaceStore::new(
            temp.path()
                .join("agent_surfaces"),
        )
        .await
        .unwrap();
        for (id, tenant) in
            [("own-surface", Some("tenant-a")), ("other-surface", Some("tenant-b")), ("shared-surface", None)]
        {
            let mut surface = crate::component_tests::helpers::build_minimal_mcp_surface();
            surface.surface_id = id.to_string();
            surface.tenant_id = tenant.map(str::to_string);
            surfaces
                .save(&surface)
                .await
                .unwrap();
        }
        let gateways = crate::gateways::FileSystemGatewayStore::new(temp.path().join("gateways"), None)
            .await
            .unwrap();
        for (did, tenant) in
            [("did:web:tenant-peer.example", Some("tenant-a")), ("did:web:appliance-peer.example", None)]
        {
            let mut gateway = crate::gateways::types::Gateway::new(
                "Peer".to_string(),
                String::new(),
                did.to_string(),
                crate::gateways::types::GatewayType::Remote,
            );
            gateway.status = crate::gateways::types::GatewayStatus::Active;
            gateway.tenant_id = tenant.map(str::to_string);
            gateways
                .create(&gateway)
                .await
                .unwrap();
        }

        for (did, channel, admitted) in [
            ("did:web:tenant-peer.example", "own-surface", true),
            ("did:web:tenant-peer.example", "shared-surface", true),
            ("did:web:tenant-peer.example", "other-surface", false),
            ("did:web:appliance-peer.example", "other-surface", true),
        ] {
            let message = make_forward_request_msg(temp.path(), Some(did), channel);
            match authorize_fabric_sender(&message, channel, None).await {
                Ok(()) => assert!(admitted, "{did} reached {channel}"),
                Err(ProcessingResult::RequiresResponse { response_body, .. }) => {
                    assert!(!admitted, "{did} was refused {channel}: {response_body}");
                    assert_eq!(response_body["status"], 403);
                    assert_eq!(response_body["error"], "Channel is not exposed to sender");
                }
                Err(other) => panic!("expected a 403 ForwardResponse, got {other:?}"),
            }
        }

        let mut listing = make_forward_request_msg(temp.path(), Some("did:web:tenant-peer.example"), "");
        listing.message_type = MessageType::GetSurfaces.to_string();
        let ProcessingResult::RequiresResponse { response_body, .. } = process_get_surfaces(&listing).await else {
            panic!("expected a get-channels response");
        };
        let mut listed: Vec<&str> = response_body["channels"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|channel| channel["config_id"].as_str())
            .collect();
        listed.sort_unstable();
        assert_eq!(listed, ["own-surface", "shared-surface"]);
    }

    async fn forward_response(message: &ReceivedMessage) -> serde_json::Value {
        match Box::pin(process_forward_request(message)).await {
            ProcessingResult::RequiresResponse { response_type, response_body } => {
                assert_eq!(response_type, MessageType::ForwardResponse.to_string());
                response_body
            }
            other => panic!("expected ForwardResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forward_request_from_unregistered_sender_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let msg = make_forward_request_msg(temp.path(), Some("did:web:stranger.example"), "surface-1");

        let response = forward_response(&msg).await;

        assert_eq!(response["status"], 403);
        assert_eq!(response["error"], "Sender is not a registered gateway");
    }

    #[tokio::test]
    async fn forward_request_without_sender_did_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let msg = make_forward_request_msg(temp.path(), None, "surface-1");

        let response = forward_response(&msg).await;

        assert_eq!(response["status"], 403);
        assert_eq!(response["error"], "Sender is not a registered gateway");
    }

    #[tokio::test]
    async fn forward_request_from_gateway_awaiting_approval_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        register_gateway(
            temp.path(),
            "did:web:peer.example",
            crate::gateways::types::GatewayStatus::AwaitingApproval,
            vec![],
        )
        .await;
        let msg = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");

        let response = forward_response(&msg).await;

        assert_eq!(response["status"], 403);
        assert_eq!(response["error"], "Sender is not a registered gateway");
    }

    #[tokio::test]
    async fn forward_request_to_channel_not_exposed_to_sender_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        register_gateway(
            temp.path(),
            "did:web:peer.example",
            crate::gateways::types::GatewayStatus::Active,
            vec!["surface-2".to_string()],
        )
        .await;
        let msg = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");

        let response = forward_response(&msg).await;

        assert_eq!(response["status"], 403);
        assert_eq!(response["error"], "Channel is not exposed to sender");
    }

    // The sender check passes and processing reaches channel resolution, which
    // is where an unknown channel is reported.
    #[tokio::test]
    async fn forward_request_from_active_gateway_passes_sender_check() {
        let temp = tempfile::tempdir().unwrap();
        register_gateway(temp.path(), "did:web:peer.example", crate::gateways::types::GatewayStatus::Active, vec![])
            .await;
        let msg = make_forward_request_msg(temp.path(), Some("did:web:peer.example"), "surface-1");

        let response = forward_response(&msg).await;

        // Past the sender gate. What happens next is channel resolution, which depends on
        // process-global surface-store state this test does not own, so assert only that the
        // sender was not refused.
        assert_ne!(response["status"], 403, "an Active registered peer must pass the sender check");
    }

    async fn store_invitation(
        storage_root: &std::path::Path,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> crate::gateways::connection_points::types::GatewayConnectionPoint {
        let store = crate::gateways::connection_points::FileSystemConnectionPointStore::new(
            storage_root.join("connection_points"),
        )
        .await
        .unwrap();
        let connection_point = crate::gateways::connection_points::types::GatewayConnectionPoint::new(
            "gw-test".to_string(),
            "mediator-test".to_string(),
            INVITER_TMP_DID.to_string(),
            "Invitation".to_string(),
            String::new(),
            "oob-123".to_string(),
            "https://mediator.example/oob?_oobid=oob-123".to_string(),
            serde_json::json!({}),
            expires_at,
            crate::gateways::connection_points::ConnectionPointType::User,
            "s3cret".to_string(),
        );
        store
            .create(&connection_point)
            .await
            .unwrap();
        connection_point
    }

    fn did_key_identity() -> (String, affinidi_tdk_common::secrets_resolver::secrets::Secret) {
        let mut key = affinidi_tdk_common::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let multibase = key
            .get_public_keymultibase()
            .unwrap();
        let did = format!("did:key:{multibase}");
        key.id = format!("{did}#{multibase}");
        (did, key)
    }

    fn setup_body(
        channel_did: &str,
        proof: Option<&str>,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({ "channel_did": channel_did, "secret": "s3cret" });
        if let Some(proof) = proof {
            body["channel_did_proof"] = serde_json::json!(proof);
        }
        body
    }

    fn make_connection_setup_msg(
        storage_root: &std::path::Path,
        connection_point_id: &str,
        body: serde_json::Value,
    ) -> ReceivedMessage {
        make_connection_setup_msg_with_thid(storage_root, connection_point_id, body, None)
    }

    fn make_connection_setup_msg_with_thid(
        storage_root: &std::path::Path,
        connection_point_id: &str,
        body: serde_json::Value,
        thid: Option<&str>,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            connection_point_id.to_string(),
            "gw-test".to_string(),
            MessageType::ConnectionSetup.to_string(),
            uuid::Uuid::new_v4().to_string(),
            thid.map(str::to_string),
            Some(ACCEPTOR_TMP_DID.to_string()),
            vec![INVITER_TMP_DID.to_string()],
            None,
            None,
            body,
            authcrypt_metadata(),
        )
        .with_context("agent_surface_storage_path", storage_context(storage_root))
    }

    async fn init_resolver() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("shared DID resolver");
    }

    fn failure_reason(result: &ProcessingResult) -> &str {
        match result {
            ProcessingResult::Failed { reason } => reason,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn channel_did_proof_verifies_against_the_signing_key_document() {
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let doc = serde_json::json!({
            "id": did,
            "verificationMethod": [
                { "id": key.id, "type": "Multikey", "publicKeyMultibase": key.get_public_keymultibase().unwrap() }
            ]
        });

        let verified = crate::didauth::verify::verify_challenge_response_with_doc(
            &did,
            &proof,
            &challenge,
            &channel_did_proof_config(),
            &doc,
        )
        .unwrap();

        assert_eq!(verified.did, did);
        assert_eq!(verified.kid, key.id);
        assert_eq!(verified.alg, "EdDSA");
    }

    #[tokio::test]
    async fn connection_setup_without_channel_did_proof_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let connection_point = store_invitation(temp.path(), None).await;
        let (did, _) = did_key_identity();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, None));

        let result = process_connection_setup(&msg).await;

        assert!(failure_reason(&result).contains("channel_did_proof"), "{result:?}");
    }

    #[tokio::test]
    async fn connection_setup_envelope_is_processed_once() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point = store_invitation(temp.path(), None).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));

        let first = process_connection_setup(&msg).await;
        assert!(matches!(first, ProcessingResult::OOBConnectionSetup(_)), "{first:?}");

        let replayed = process_connection_setup(&msg).await;
        assert!(failure_reason(&replayed).contains("already processed"), "{replayed:?}");
    }

    // The seen set is populated only once the sender has proven control of its
    // channel_did, so a refused envelope does not block a later valid one and
    // an unauthenticated sender cannot fill the set.
    #[tokio::test]
    async fn connection_setup_refused_before_verification_is_not_remembered() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point = store_invitation(temp.path(), None).await;
        let (did, key) = did_key_identity();
        let unproven = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, None));
        let refused = process_connection_setup(&unproven).await;
        assert!(failure_reason(&refused).contains("channel_did_proof"), "{refused:?}");

        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let mut proven = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));
        proven.didcomm_message_id = unproven
            .didcomm_message_id
            .clone();

        let result = process_connection_setup(&proven).await;
        assert!(matches!(result, ProcessingResult::OOBConnectionSetup(_)), "{result:?}");
    }

    // An attacker names a victim DID and its real key id but can only sign with
    // their own key.
    #[tokio::test]
    async fn connection_setup_with_proof_from_another_key_is_refused() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point = store_invitation(temp.path(), None).await;
        let (victim_did, victim_key) = did_key_identity();
        let (_, mut attacker_key) = did_key_identity();
        attacker_key.id = victim_key.id.clone();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &victim_did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&attacker_key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&victim_did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        assert!(failure_reason(&result).starts_with("Invalid channel_did_proof"), "{result:?}");
    }

    #[tokio::test]
    async fn connection_setup_with_proof_bound_to_another_sender_is_refused() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point = store_invitation(temp.path(), None).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge("did:web:someone.else:tmp", INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        assert!(failure_reason(&result).starts_with("Invalid channel_did_proof"), "{result:?}");
    }

    #[tokio::test]
    async fn connection_setup_on_expired_invitation_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let connection_point =
            store_invitation(temp.path(), Some(chrono::Utc::now() - chrono::Duration::minutes(1))).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        assert_eq!(failure_reason(&result), "invitation has expired");
    }

    #[tokio::test]
    async fn connection_setup_on_unknown_connection_point_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        store_invitation(temp.path(), None).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), "cp-missing", setup_body(&did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        assert_eq!(failure_reason(&result), "connection point not found");
    }

    #[tokio::test]
    async fn connection_setup_with_valid_proof_succeeds() {
        init_resolver().await;
        let temp = tempfile::tempdir().unwrap();
        let connection_point =
            store_invitation(temp.path(), Some(chrono::Utc::now() + chrono::Duration::hours(1))).await;
        let (did, key) = did_key_identity();
        let challenge = channel_did_proof_challenge(ACCEPTOR_TMP_DID, INVITER_TMP_DID, &did);
        let proof = sign_channel_did_proof(std::slice::from_ref(&key), &challenge).unwrap();
        let msg = make_connection_setup_msg(temp.path(), &connection_point.id, setup_body(&did, Some(&proof)));

        let result = process_connection_setup(&msg).await;

        match result {
            ProcessingResult::OOBConnectionSetup(setup) => {
                assert_eq!(setup.acceptor_temporary_did, ACCEPTOR_TMP_DID);
                assert_eq!(setup.acceptor_secure_did, did);
                assert_eq!(setup.invitation_id, "oob-123");
                assert_eq!(setup.secret, "s3cret");
            }
            other => panic!("expected OOBConnectionSetup, got {other:?}"),
        }
    }
}
