//! Gateway approval handler for human-in-the-loop OOB connections

use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use crate::auth_manager::pat::PatResourceScope;
use crate::gateways::connection_points::{ConnectionPointListenerManager, ConnectionPointStore};
use crate::gateways::{GatewayStore, types::Gateway};
use crate::tenancy::{PatTenantContext, ResourceKind, can_reference, scope_allows_resource};
/// Request body for approving a gateway connection
#[derive(Debug, Deserialize)]
pub struct ApproveGatewayRequest {
    pub name: String,
    pub description: String,
}

/// Load a gateway awaiting approval that this caller may change. Approving
/// activates the peer, so it needs write access, not read access: a tenant token
/// cannot activate an appliance-wide peer that would then reach every tenant.
async fn load_pending_gateway<S: GatewayStore>(
    store: &S,
    gateway_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Gateway, (StatusCode, String)> {
    let gateway = store
        .get(gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !crate::gateways::handlers::gateway_writable(&gateway, context, scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }
    if gateway.status != crate::gateways::types::GatewayStatus::AwaitingApproval {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Gateway is not awaiting approval (status: {:?})", gateway.status),
        ));
    }
    Ok(gateway)
}

/// Approve a pending gateway connection
/// This completes the OOB handshake by sending connection-accepted to the acceptor
pub async fn approve_gateway<
    S: GatewayStore + 'static,
    P: ConnectionPointStore + 'static,
    M: crate::mediators::MediatorStore,
>(
    Extension(store): Extension<Arc<S>>,
    Extension(cp_store): Extension<Arc<P>>,
    Extension(mediator_store): Extension<Arc<M>>,
    Extension(vc_issuer): Extension<Arc<crate::identity::VCIssuer>>,
    Extension(pending_store): Extension<Arc<crate::gateways::PendingConnectionStore>>,
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(network_config): Extension<Arc<crate::config::NetworkConfig>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    #[cfg(feature = "didwebvh")] Extension(log_storage): Extension<
        Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    >,
    #[cfg(feature = "didwebvh")] Extension(identity_store): Extension<
        Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    >,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<ApproveGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Approving gateway connection");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  Gateway ID: {}", gateway_id);
    info!("  New Name: {}", req.name);
    info!("  New Description: {}", req.description);

    // Step 1: Get the pending gateway
    let mut gateway = load_pending_gateway(store.as_ref(), &gateway_id, &context, &scope).await?;

    info!("✓ Found gateway awaiting approval");

    // Step 2: Get the pending connection context
    let pending_conn = pending_store
        .get_approval_by_gateway_id(&gateway_id)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Pending connection context not found".to_string()))?;

    info!("✓ Retrieved pending connection context");
    info!("  Our temporary DID: {}", pending_conn.our_temporary_did);
    info!("  Our secure DID: {}", pending_conn.our_secure_did);
    info!("  Their temporary DID: {}", pending_conn.their_temporary_did);
    info!("  Their secure DID: {:?}", pending_conn.their_secure_did);

    // Step 4: Get the connection point to retrieve mediator information
    let connection_point = cp_store
        .get(&pending_conn.invitation_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get connection point: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Connection point not found".to_string()))?;

    // Get mediator details
    let mediator = mediator_store
        .get(&connection_point.mediator_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    let tenant_context = context
        .as_ref()
        .map(|Extension(context)| context);
    let resource_scope = scope
        .as_ref()
        .map(|Extension(scope)| scope);
    if !can_reference(gateway.tenant_id.as_deref(), mediator.tenant_id.as_deref())
        || !scope_allows_resource(resource_scope, tenant_context, ResourceKind::Mediators, &mediator.id)
    {
        return Err((StatusCode::BAD_REQUEST, "Mediator reference is not accessible".to_string()));
    }

    // Step 3: Activate the gateway with the provided name and description.
    // Every lookup above can fail without a write; a later step that fails
    // restores the record, so a failed approval leaves the peer awaiting
    // approval.
    let previous = gateway.clone();
    gateway.name = req.name;
    gateway.description = req.description;
    gateway.status = crate::gateways::types::GatewayStatus::Active;
    if gateway.issuer_did.is_none()
        && let Some(their_issuer_did) = pending_conn
            .their_issuer_did
            .clone()
    {
        gateway.issuer_did = Some(their_issuer_did);
        gateway.issuer_did_source = Some(crate::gateways::types::IssuerDidSource::Handshake);
    }
    gateway.updated_at = chrono::Utc::now();

    activate_then_complete(store.as_ref(), &previous, &gateway, async {
        let mediator_did = mediator.did.clone();
        info!("Using mediator: {}", mediator_did);

        // Step 5: Send connection-accepted message to acceptor
        info!("📤 Sending connection-accepted message to acceptor...");

        // Load the temporary DID's secrets from storage
        let storage_path = std::path::Path::new(
            &bootstrap_config
                .storage_paths
                .connection_points,
        );
        let temp_secrets = crate::gateways::connection_points::handlers::load_connection_point_secrets(
            &pending_conn.invitation_id,
            storage_path,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load temporary DID secrets: {}", e)))?;

        info!("✓ Loaded {} secrets for temporary DID", temp_secrets.len());

        // Initialize DIDComm client for sending the message
        let mut client = crate::comm::didcomm::client::DIDCommClient::new_with_mediator_document(
            pending_conn
                .our_temporary_did
                .clone(),
            temp_secrets,
            Some(mediator_did.clone()),
            mediator.did_document.clone(),
            Some("oob-inviter-approval".to_string()),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        client
            .register_profile()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        info!("✓ Temporary DID profile registered with mediator");

        // Step 4.5: Create connection points for bidirectional communication BEFORE sending connection-accepted
        // We need to send the gateway CP DID in the connection-accepted message
        info!("📝 Creating connection points for gateway communication...");

        // IMPORTANT: Use the SAME mediator as the OOB connection point (already retrieved above)
        // Both sides of the connection MUST use the same mediator for the handshake to work!
        let gw_mediator_did = mediator_did.clone();
        let gw_mediator_id = connection_point
            .mediator_id
            .clone();

        // Extract mediator URL from DID
        use crate::gateways::connection_points::handlers::extract_mediator_url;
        let gw_mediator_url = extract_mediator_url(&gw_mediator_did)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to extract mediator URL: {}", e)))?;

        info!("  Using mediator from OOB connection point: {}", gw_mediator_did);

        // Create gateway connection point (for receiving from acceptor)
        let gateway_cp_id = uuid::Uuid::new_v4().to_string();
        if !scope_allows_resource(resource_scope, tenant_context, ResourceKind::ConnectionPoints, &gateway_cp_id) {
            return Err((
                StatusCode::FORBIDDEN,
                "Connection point is outside this token's permitted scope".to_string(),
            ));
        }

        let (gateway_cp_did, _gateway_cp_secrets, _gateway_cp_doc) =
            crate::gateways::connection_points::handlers::generate_connection_point_identity(
                &gateway_cp_id,
                &network_config.did.domain,
                std::path::Path::new(
                    &bootstrap_config
                        .storage_paths
                        .connection_points,
                ),
                &gw_mediator_url,
                &connection_point.did_method,
                #[cfg(feature = "didwebvh")]
                log_storage.clone(),
                #[cfg(feature = "didwebvh")]
                identity_store.clone(),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to generate gateway connection point identity: {}", e),
                )
            })?;

        // Store acceptor's secure DID in oob_message for ACL setup when listener starts
        let acceptor_secure_did = pending_conn
            .their_secure_did
            .as_ref()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Acceptor secure DID not found in pending connection".to_string())
            })?;

        let mut gateway_connection_point = super::connection_points::types::GatewayConnectionPoint::new(
            gateway.id.clone(),
            gw_mediator_id.clone(),
            gateway_cp_did.clone(),
            format!("Connection Point for {}", gateway.name),
            "Auto-created for OOB connection (inviter side, for receiving from acceptor)".to_string(),
            String::new(),
            String::new(),
            serde_json::json!({"acceptor_secure_did": acceptor_secure_did}), // Store for ACL setup
            None,
            super::connection_points::types::ConnectionPointType::OobResponder,
            String::new(),
        );

        gateway_connection_point.id = gateway_cp_id.clone();
        gateway_connection_point.last_used_at = Some(chrono::Utc::now());
        gateway_connection_point.did_method = connection_point
            .did_method
            .clone();

        cp_store
            .create(&gateway_connection_point)
            .await
            .map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create gateway connection point: {}", e))
            })?;

        info!("  ✓ Gateway connection point {} created", gateway_cp_id);

        // Step 4.5: Start listener for the gateway connection point BEFORE sending connection-accepted
        // This ensures the DID is authenticated with the mediator before the other side tries to reach us
        info!("🎧 Starting WebSocket listener for gateway connection point...");

        let manager = listener_manager
            .as_ref()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Listener manager not available".to_string()))?;

        // Use request_start_listener for event-driven completion notification
        match manager.request_start_listener(
            gateway_connection_point.clone(),
            gw_mediator_did.clone(),
            gw_mediator_url.clone(),
        ) {
            Ok(completion_rx) => {
                info!("  ✓ Gateway listener startup requested");

                // Wait for the listener to actually start (event-driven, no polling)
                info!("  ⏳ Waiting for listener to start...");
                match completion_rx.await {
                    Ok(Ok(())) => {
                        info!("  ✓ Listener started successfully");
                    }
                    Ok(Err(e)) => {
                        // Listener failed to start - this is a critical error
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to start gateway listener: {}", e),
                        ));
                    }
                    Err(_) => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Listener start notification channel closed".to_string(),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to request gateway listener startup: {}", e),
                ));
            }
        }

        info!("✓ Gateway connection point listener started and authenticated with mediator");

        // Step 5: NOW send connection-accepted with the gateway CP DID (not the OOB secure DID!)
        // The thread id doubles as the attestation nonce so the acceptor can bind
        // the attestation to this exact message.
        use serde_json::json;

        let accepted_thid = uuid::Uuid::new_v4().to_string();
        let issuer_attestation = crate::gateways::issuer_attestation::build_issuer_attestation(
            &vc_issuer,
            &gateway_cp_did,
            &pending_conn.their_temporary_did,
            &accepted_thid,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build issuer attestation: {}", e)))?;

        crate::comm::didcomm::gateway::send_connection_accepted(
            &client,
            &pending_conn.our_temporary_did,
            &pending_conn.their_temporary_did,
            json!({"channel_did": gateway_cp_did.clone(), "issuer_attestation": issuer_attestation}),
            &accepted_thid,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        info!("✓ Connection-accepted sent successfully with gateway CP DID: {}", gateway_cp_did);

        // Note: Temporary connection point is intentionally NOT cleaned up here
        // It must remain available for DID resolution so the acceptor can decrypt the message
        // Cleanup happens at server startup (see cleanup_expired_connection_points in server initialization)

        // Remove pending connection context (this can be cleaned up now)
        pending_store
            .remove_approval(&gateway_id)
            .await;
        info!("✓ Pending connection context removed");

        Ok(())
    })
    .await?;

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Gateway connection approved successfully");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(Json(gateway))
}

/// Saves the approved gateway, then runs the rest of the approval. When that
/// fails, the gateway's previous record is restored, so the peer is never left
/// active, or renamed, by an approval that did not complete.
async fn activate_then_complete<S: GatewayStore>(
    store: &S,
    previous: &Gateway,
    approved: &Gateway,
    complete: impl std::future::Future<Output = Result<(), (StatusCode, String)>>,
) -> Result<(), (StatusCode, String)> {
    store
        .update(approved)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;
    info!("✓ Gateway updated with new name and Active status");
    let outcome = complete.await;
    if outcome.is_err()
        && let Err(error) = store.update(previous).await
    {
        tracing::error!(gateway_id = %previous.id, %error, "Failed to restore a gateway whose approval failed");
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::types::{Gateway, GatewayCreationType, GatewayStatus, GatewayType};
    use crate::gateways::{FileSystemGatewayStore, GatewayStore};
    use crate::tenancy::PatTenantContext;
    use axum::{Extension, http::StatusCode};

    fn pending_gateway(
        id: &str,
        tenant_id: Option<&str>,
    ) -> Gateway {
        let mut gateway = Gateway::new_with_creation_type(
            "Pending".to_string(),
            "Pending peer".to_string(),
            format!("did:web:{id}.example"),
            GatewayType::Remote,
            GatewayCreationType::User,
        );
        gateway.id = id.to_string();
        gateway.status = GatewayStatus::AwaitingApproval;
        gateway.tenant_id = tenant_id.map(str::to_string);
        gateway
    }

    fn tenant(tenant_id: &str) -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: tenant_id.into(),
        }))
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_approve_an_appliance_wide_peer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemGatewayStore::new(dir.path().to_path_buf(), Some("did:web:self.example".to_string()))
            .await
            .expect("gateway store");
        for gateway in [pending_gateway("appliance-peer", None), pending_gateway("tenant-peer", Some("tenant-a"))] {
            store
                .create(&gateway)
                .await
                .expect("create gateway");
        }

        let err = load_pending_gateway(&store, "appliance-peer", &tenant("tenant-a"), &None)
            .await
            .expect_err("a tenant token cannot activate an appliance-wide peer");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            load_pending_gateway(&store, "tenant-peer", &tenant("tenant-a"), &None)
                .await
                .is_ok(),
            "a tenant approves its own peer"
        );
        assert_eq!(
            load_pending_gateway(&store, "tenant-peer", &tenant("tenant-b"), &None)
                .await
                .expect_err("another tenant's peer is out of reach")
                .0,
            StatusCode::FORBIDDEN
        );
        assert!(
            load_pending_gateway(&store, "appliance-peer", &None, &None)
                .await
                .is_ok(),
            "an appliance-wide caller approves any pending peer"
        );
    }

    #[tokio::test]
    async fn a_failed_approval_leaves_the_peer_awaiting_approval() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemGatewayStore::new(dir.path().to_path_buf(), Some("did:web:self.example".to_string()))
            .await
            .expect("gateway store");
        let previous = pending_gateway("pending-peer", None);
        store
            .create(&previous)
            .await
            .expect("create gateway");
        let mut approved = previous.clone();
        approved.name = "Approved".to_string();
        approved.status = GatewayStatus::Active;

        let err = activate_then_complete(&store, &previous, &approved, async {
            Err((StatusCode::NOT_FOUND, "Connection point not found".to_string()))
        })
        .await
        .expect_err("a later step failed");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        let kept = store
            .get("pending-peer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.status, GatewayStatus::AwaitingApproval);
        assert_eq!(kept.name, previous.name);

        activate_then_complete(&store, &previous, &approved, async { Ok(()) })
            .await
            .expect("the approval completed");
        let active = store
            .get("pending-peer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.status, GatewayStatus::Active);
        assert_eq!(active.name, "Approved");
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_approve_an_appliance_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(root.join("gateways"), Some("did:web:self.example".into()))
                .await
                .unwrap(),
        );
        let appliance = Gateway::new("Peer".into(), String::new(), "did:web:peer.example".into(), GatewayType::Remote);
        store
            .create(&appliance)
            .await
            .unwrap();
        let cp_store = Arc::new(
            crate::gateways::connection_points::FileSystemConnectionPointStore::new(root.join("cps"))
                .await
                .unwrap(),
        );
        let mediator_store = Arc::new(
            crate::mediators::FileSystemMediatorStore::new(root.join("mediators"))
                .await
                .unwrap(),
        );
        let (vc_issuer, _issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let pending = Arc::new(
            crate::gateways::PendingConnectionStore::new(root.join("pending"))
                .await
                .unwrap(),
        );
        let bootstrap: crate::config::BootstrapConfig =
            toml::from_str(include_str!("../../config/examples/config.example.toml")).unwrap();
        let network: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {}
        }))
        .unwrap();
        let tenant = Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let result = approve_gateway(
            Extension(store),
            Extension(cp_store),
            Extension(mediator_store),
            Extension(Arc::new(vc_issuer)),
            Extension(pending),
            Extension(Arc::new(bootstrap)),
            Extension(Arc::new(network)),
            Extension(None),
            #[cfg(feature = "didwebvh")]
            Extension(None),
            #[cfg(feature = "didwebvh")]
            Extension(None),
            Path(appliance.id.clone()),
            tenant,
            None,
            Json(ApproveGatewayRequest {
                name: "Renamed".into(),
                description: String::new(),
            }),
        )
        .await;
        let (status, body) = result.expect_err("a tenant must not approve an appliance-wide gateway");
        assert_eq!(status, StatusCode::FORBIDDEN, "passed the tenant guard and reached: {body}");
    }
}
