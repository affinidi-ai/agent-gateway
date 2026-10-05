//! Utility functions for mediators

use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::egress::{EgressError, EgressPolicy, bdd_egress_allowlist, guarded_send_inner};
use crate::http_client::EXTERNAL_TIMEOUT_SECS;
use trust_tasks_rs::specs::messaging::account::update::v0_1::{MediatorAcl, MediatorAclAccessListMode};

/// well-known DID document response structure
#[derive(Debug, Deserialize)]
struct WellKnownDidResponse {
    id: String,
}

impl std::fmt::Display for WellKnownDidResponse {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

// 0x0000000000000000000000000000000000000000000001111111111111111011
// from: https://github.com/affinidi/affinidi-tdk-rs/blob/8cf1feda035f1e96ede65dc3f0d7fe49a780631a/crates/affinidi-messaging/affinidi-messaging-sdk/src/protocols/mediator/acls.rs#L40
// ✅ 0: access_list_mode (0 = explicit_allow, 1 = explicit_deny)
// ✅ 1: access_list_mode_change (0 = admin_only, 1 = self)
// ❌ 2: did_blocked (0 = allow, 1 = blocked)
// ✅ 3: did_local (0 = false, 1 = true/local)
// ✅ 4: send_messages (0 = false, 1 = true)
// ✅ 5: send_messages_change (0 = admin_only, 1 = self)
// ✅ 6: receive_messages (0 = false, 1 = true)
// ✅ 7: receive_messages_change (0 = admin_only, 1 = self)
// ✅ 8: send_forwarded (0 = no, 1 = yes)
// ✅ 9: send_forwarded_change (0 = admin_only, 1 = self)
// ✅ 10: receive_forwarded (0 = no, 1 = yes)
// ✅ 11: receive_forwarded_change (0 = admin_only, 1 = self)
// ✅ 12: create_invites (0 = no, 1 = yes)
// ✅ 13: create_invites_change (0 = admin_only, 1 = self)
// ✅ 14: anon_receive (0 = no, 1 = yes)
// ✅ 15: anon_receive_change (0 = admin_only, 1 = self)
// ✅ 16: self_manage_list (0 = admin_only, 1 = self)
// ✅ 17: self_manage_send_queue_limit
// ✅ 18: self_manage_receive_queue_limit

/// Construct a `MediatorAcl` that allows everything.
fn allow_all_acl() -> Result<MediatorAcl, String> {
    MediatorAcl::builder()
        .access_list_mode(MediatorAclAccessListMode::ExplicitDeny)
        .anon_receive(true)
        .blocked(false)
        .create_invites(true)
        .local(true)
        .receive_forwarded(true)
        .receive_messages(true)
        .self_manage_list(true)
        .self_manage_receive_queue_limit(true)
        .self_manage_send_queue_limit(true)
        .send_forwarded(true)
        .send_messages(true)
        .try_into()
        .map_err(|e| format!("Failed to build ALLOW_ALL ACL: {}", e))
}

/// GET `url` through the shared SSRF egress guard (Strict policy): the target
/// host is validated, resolved once, pinned to its vetted address, and every
/// redirect hop is re-validated. A loopback/private/metadata target (or a
/// redirect to one) fails closed instead of being fetched.
async fn guarded_get(
    url: &str,
    exact_allowlist: Option<&str>,
) -> Result<reqwest::Response, EgressError> {
    guarded_send_inner(
        Method::GET,
        url,
        HeaderMap::new(),
        None,
        EgressPolicy::Strict,
        Duration::from_secs(EXTERNAL_TIMEOUT_SECS),
        exact_allowlist,
    )
    .await
}

/// Try to fetch and parse a `did.jsonl` (webvh) from the given URL.
///
/// Returns `Ok(Some(did))` on success, `Ok(None)` when this location has no
/// usable document (fall through to the next probe), and `Err` when the egress
/// guard blocks the URL as an SSRF target — a fail-closed hard stop, not a
/// silent fallthrough.
async fn try_fetch_did_jsonl(
    url: &str,
    exact_allowlist: Option<&str>,
) -> Result<Option<String>, String> {
    info!("Trying mediator did.jsonl at {}", url);
    let response = match guarded_get(url, exact_allowlist).await {
        Ok(response) => response,
        Err(EgressError::Blocked(reason)) => {
            // Log the detailed reason (incl. the resolved internal IP) server-side
            // only; the client body gets a generic message so it can't be used as
            // a DNS-rebind / SSRF oracle.
            tracing::warn!("mediator DID fetch blocked by egress policy for {}: {}", url, reason);
            return Err("mediator URL blocked by egress policy".to_string());
        }
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let Ok(body) = response.text().await else {
        return Ok(None);
    };
    let Some(last_line) = body
        .lines()
        .rfind(|l| !l.trim().is_empty())
    else {
        return Ok(None);
    };
    let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) else {
        return Ok(None);
    };
    let did = entry
        .get("state")
        .and_then(|state| state.get("id"))
        .and_then(|id| id.as_str());
    match did {
        Some(did) => {
            info!("Successfully fetched mediator DID from did.jsonl: {}", did);
            Ok(Some(did.to_string()))
        }
        None => Ok(None),
    }
}

/// Try to fetch and parse a `did.json` from the given URL.
///
/// Same fail-closed contract as [`try_fetch_did_jsonl`]: `Ok(None)` means try
/// the next probe, `Err` means the egress guard blocked the URL.
async fn try_fetch_did_json(
    url: &str,
    exact_allowlist: Option<&str>,
) -> Result<Option<String>, String> {
    info!("Trying mediator did.json at {}", url);
    let response = match guarded_get(url, exact_allowlist).await {
        Ok(response) => response,
        Err(EgressError::Blocked(reason)) => {
            // Log the detailed reason (incl. the resolved internal IP) server-side
            // only; the client body gets a generic message so it can't be used as
            // a DNS-rebind / SSRF oracle.
            tracing::warn!("mediator DID fetch blocked by egress policy for {}: {}", url, reason);
            return Err("mediator URL blocked by egress policy".to_string());
        }
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let Ok(doc) = response
        .json::<WellKnownDidResponse>()
        .await
    else {
        return Ok(None);
    };
    info!("Successfully fetched mediator DID from did.json: {}", doc);
    Ok(Some(doc.id))
}

/// Return mediator DID for a specified mediator URL by resolving its DID.
///
/// Probes the origin-scoped `.well-known` location first (per RFC 8615,
/// well-known URIs always live at the origin root regardless of any path in
/// the input URL), then falls back to path-scoped locations for `did:web`
/// mediators hosted under a sub-path. Within each scope, tries `did.jsonl`
/// (did:webvh DID log) before `did.json` (did:web DID document).
///
/// Probe order for `https://host/mediator/v1`:
///   1. `https://host/.well-known/did.jsonl`
///   2. `https://host/.well-known/did.json`
///   3. `https://host/mediator/v1/did.jsonl`
///   4. `https://host/mediator/v1/did.json`
pub async fn fetch_mediator_did_from_url(mediator_url: &str) -> Result<String, String> {
    fetch_mediator_did_from_url_inner(mediator_url, bdd_egress_allowlist().as_deref()).await
}

async fn fetch_mediator_did_from_url_inner(
    mediator_url: &str,
    exact_allowlist: Option<&str>,
) -> Result<String, String> {
    let parsed = url::Url::parse(mediator_url).map_err(|e| format!("Invalid mediator URL: {}", e))?;

    let origin = parsed
        .origin()
        .ascii_serialization();
    let path = parsed
        .path()
        .trim_end_matches('/');
    let has_path = !path.is_empty() && path != "/";

    // Origin-scoped .well-known probes first (root did:web / did:webvh — common case)
    if let Some(did) = try_fetch_did_jsonl(&format!("{}/.well-known/did.jsonl", origin), exact_allowlist).await? {
        return Ok(did);
    }
    if let Some(did) = try_fetch_did_json(&format!("{}/.well-known/did.json", origin), exact_allowlist).await? {
        return Ok(did);
    }

    // Path-scoped fallback (did:web with sub-paths serve did.json{l} under the path)
    if has_path {
        let base = format!("{}{}", origin, path);
        if let Some(did) = try_fetch_did_jsonl(&format!("{}/did.jsonl", base), exact_allowlist).await? {
            return Ok(did);
        }
        if let Some(did) = try_fetch_did_json(&format!("{}/did.json", base), exact_allowlist).await? {
            return Ok(did);
        }
    }

    let tried = if has_path {
        format!(
            "{}/.well-known/did.jsonl, {}/.well-known/did.json, {}{}/did.jsonl, {}{}/did.json",
            origin, origin, origin, path, origin, path
        )
    } else {
        format!("{}/.well-known/did.jsonl, {}/.well-known/did.json", origin, origin)
    };
    Err(format!("Failed to fetch mediator DID document from {} (tried: {})", mediator_url, tried))
}

pub async fn set_acl_to_allow_everything_and_more(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> Result<(), String> {
    let did = profile.inner.did.to_string();
    info!("set_acl_to_allow_everything_and_more called for did: {}", did);

    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let did_hash = format!("{:x}", hasher.finalize());
    atm.trust_tasks()
        .account_update(&profile, Some(did_hash), None, Some(allow_all_acl()?), None)
        .await
        .map_err(|e| format!("Failed to update ACL to ALLOW_ALL_ACL_FLAGS: {}", e))?;

    // Ensure all DIDs are removed from access list
    atm.trust_tasks()
        .access_list_update(&profile, None, true, vec![], vec![])
        .await
        .map_err(|e| format!("Failed to clear ACL: {}", e))?;

    info!("profile Access Lists set to Allow Everything and More");
    Ok(())
}

pub async fn _set_acl_to_explicit_deny(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> Result<(), String> {
    let did = profile.inner.did.to_string();
    info!("set_acl_to_explicit_deny called for did: {}", did);

    let profile_info = atm
        .trust_tasks()
        .account_get(&profile, None)
        .await
        .map_err(|e| format!("profile account not found on mediator: {}", e))?;
    info!("profile active: {:?}", profile_info);

    // Convert account::get MediatorAcl → account::update MediatorAcl via serde (structurally identical)
    let mut acl: MediatorAcl = serde_json::from_value(
        serde_json::to_value(&profile_info.acl).map_err(|e| format!("Failed to serialize ACL: {}", e))?,
    )
    .map_err(|e| format!("Failed to deserialize ACL: {}", e))?;
    acl.access_list_mode = Some(MediatorAclAccessListMode::ExplicitDeny);

    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let did_hash = format!("{:x}", hasher.finalize());
    atm.trust_tasks()
        .account_update(&profile, Some(did_hash), None, Some(acl), None)
        .await
        .map_err(|e| format!("Failed to update ACL: {}", e))?;

    // Ensure their DID is removed from our temp did explicit deny list
    atm.trust_tasks()
        .access_list_update(&profile, None, true, vec![], vec![])
        .await
        .map_err(|e| format!("Failed to clear ACL: {}", e))?;

    info!("profile Access Lists set to Explicit Deny");
    Ok(())
}

pub async fn _update_acls(
    atm: &affinidi_messaging_sdk::ATM,
    our_profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
    their_did: &str,
) -> Result<(), String> {
    info!("update_acls called for did: {}", their_did);

    // Step 5.1: Update our temp DID's access lists for their temporary DID
    let our_profile_info = atm
        .trust_tasks()
        .account_get(&our_profile, None)
        .await
        .map_err(|e| format!("our profile account not found on mediator: {}", e))?;

    info!("our profile active: {:?}", our_profile_info);
    let is_explicit_allow = our_profile_info
        .acl
        .access_list_mode
        .as_ref()
        .is_some_and(|m| m.to_string() == "explicitAllow");
    info!(
        "our profile ACL Mode Type: {:?}",
        our_profile_info
            .acl
            .access_list_mode
    );

    let mut hasher = Sha256::new();
    hasher.update(their_did.as_bytes());
    let their_did_hash = format!("{:x}", hasher.finalize());
    if is_explicit_allow {
        // Ensure their DID is added to our temp did explicit allow list
        atm.trust_tasks()
            .access_list_update(&our_profile, None, false, vec![their_did_hash], vec![])
            .await
            .map_err(|e| format!("Failed to update ACL: {}", e))?;
    } else {
        // Ensure their DID is removed from our temp did explicit deny list
        atm.trust_tasks()
            .access_list_update(&our_profile, None, false, vec![], vec![their_did_hash])
            .await
            .map_err(|e| format!("Failed to update ACL: {}", e))?;
    }
    info!("our profile Access Lists reset");
    Ok(())
}

fn _get_didcomm_service_endpoint(did_document: &serde_json::Value) -> Result<&serde_json::Value, String> {
    let services = did_document
        .get("service")
        .and_then(|s| s.as_array())
        .ok_or_else(|| "No services found in DID document".to_string())?;

    let didcomm_service = services
        .iter()
        .find(|service| {
            service
                .get("type")
                .map(|service_type| {
                    (service_type.as_str() == Some("DIDCommMessaging"))
                        || service_type
                            .as_array()
                            .is_some_and(|arr| {
                                arr.iter()
                                    .any(|v| v.as_str() == Some("DIDCommMessaging"))
                            })
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| "No DIDCommMessaging service found in DID document".to_string())?;

    tracing::debug!(
        "Found DIDCommMessaging service: {}",
        serde_json::to_string_pretty(didcomm_service).unwrap_or_default()
    );

    // Extract serviceEndpoint
    didcomm_service
        .get("serviceEndpoint")
        .ok_or_else(|| "DIDCommMessaging service missing serviceEndpoint".to_string())
}

/// Extract mediator information from a DID document.
/// Handles two scenarios:
/// 1. DIDCommMessaging service endpoint is a URL - extract directly
/// 2. DIDCommMessaging service endpoint is a DID - resolve it first, then extract URL
///
/// Returns: (mediator_url, final_did_document)
pub async fn extract_mediator_info(did_document: &serde_json::Value) -> Result<(String, serde_json::Value), String> {
    let endpoint_value = _get_didcomm_service_endpoint(did_document).and_then(extract_endpoint_value)?;

    tracing::info!("Extracted endpoint value: {}", endpoint_value);

    // Check if the endpoint is a DID or a URL
    if endpoint_value.starts_with("did:") {
        tracing::info!("Endpoint is a DID ({}), resolving to get actual URL...", endpoint_value);

        // Resolve the DID to get the actual service endpoint
        let resolved_doc = &resolve_did(&endpoint_value).await?;

        // Extract URL from the resolved DID document
        let mediator_url = _get_didcomm_service_endpoint(resolved_doc).and_then(extract_endpoint_value)?;

        if mediator_url.starts_with("did:") {
            return Err("Resolved endpoint is still a DID, expected a URL".to_string());
        }

        tracing::info!("Resolved DID {} to URL: {}", endpoint_value, mediator_url);

        // Return the URL and the original DID document (not the resolved one)
        Ok((mediator_url, did_document.clone()))
    } else if endpoint_value.starts_with("http://")
        || endpoint_value.starts_with("https://")
        || endpoint_value.starts_with("ws://")
        || endpoint_value.starts_with("wss://")
    {
        // Endpoint is already a URL
        tracing::info!("Endpoint is a URL: {}", endpoint_value);

        // Extract base URL (protocol + host) without path
        let base_url = extract_base_url(&endpoint_value)?;

        Ok((base_url, did_document.clone()))
    } else {
        Err(format!("Service endpoint is neither a DID nor a valid URL: {}", endpoint_value))
    }
}

/// Extract the endpoint value from a serviceEndpoint field.
/// Handles: string, object with uri/url field, or array of endpoint objects.
fn extract_endpoint_value(service_endpoint: &serde_json::Value) -> Result<String, String> {
    if let Some(url_str) = service_endpoint.as_str() {
        // Simple string endpoint
        return Ok(url_str.to_string());
    }

    if let Some(uri) = service_endpoint
        .get("uri")
        .and_then(|v| v.as_str())
    {
        // Object with uri field
        return Ok(uri.to_string());
    }

    if let Some(url) = service_endpoint
        .get("url")
        .and_then(|v| v.as_str())
    {
        // Object with url field
        return Ok(url.to_string());
    }

    if let Some(endpoint_array) = service_endpoint.as_array() {
        // Array of endpoint objects - find the first HTTP/HTTPS endpoint
        for ep in endpoint_array {
            if let Some(uri) = ep
                .get("uri")
                .and_then(|v| v.as_str())
                && (uri.starts_with("http://") || uri.starts_with("https://") || uri.starts_with("did:"))
            {
                return Ok(uri.to_string());
            }
        }

        // If no HTTP/HTTPS found, try the first URI
        if let Some(first_ep) = endpoint_array.first()
            && let Some(uri) = first_ep
                .get("uri")
                .and_then(|v| v.as_str())
        {
            return Ok(uri.to_string());
        }
    }

    Err(format!("Could not extract endpoint value from: {:?}", service_endpoint))
}

/// Extract base URL (protocol + host) from a full URL
fn extract_base_url(url: &str) -> Result<String, String> {
    url::Url::parse(url)
        .map_err(|e| format!("Failed to parse URL '{}': {}", url, e))
        .and_then(|parsed| {
            parsed
                .host_str()
                .map(|host| {
                    if let Some(port) = parsed.port() {
                        format!("{}://{}:{}", parsed.scheme(), host, port)
                    } else {
                        format!("{}://{}", parsed.scheme(), host)
                    }
                })
                .ok_or_else(|| format!("Could not extract host from URL: {}", url))
        })
}

/// Resolve a DID to get its DID document
async fn resolve_did(did: &str) -> Result<serde_json::Value, String> {
    tracing::info!("Resolving DID: {}", did);

    let client = crate::gateways::did_cache::shared_resolver();

    let resolution_result = client
        .resolve(did)
        .await
        .map_err(|e| format!("Failed to resolve DID {}: {}", did, e))?;

    let did_document = resolution_result.doc;

    // Convert to JSON for easier manipulation
    serde_json::to_value(&did_document).map_err(|e| format!("Failed to serialize resolved DID document: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allow_all_acl_grants_every_capability_in_explicit_deny_mode() {
        let acl = serde_json::to_value(allow_all_acl().unwrap()).unwrap();
        assert_eq!(
            acl,
            json!({
                "accessListMode": "explicitDeny",
                "anonReceive": true,
                "blocked": false,
                "createInvites": true,
                "local": true,
                "receiveForwarded": true,
                "receiveMessages": true,
                "selfManageList": true,
                "selfManageReceiveQueueLimit": true,
                "selfManageSendQueueLimit": true,
                "sendForwarded": true,
                "sendMessages": true,
            })
        );
    }

    // ── extract_endpoint_value ────────────────────────────────────────────────

    #[test]
    fn test_extract_endpoint_value_string() {
        let endpoint = json!("https://mediator.example.com/didcomm");
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_object_uri() {
        let endpoint = json!({ "uri": "https://mediator.example.com/didcomm" });
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_object_url() {
        let endpoint = json!({ "url": "https://mediator.example.com/didcomm" });
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_array_http_uri() {
        let endpoint = json!([
            { "uri": "https://mediator.example.com/didcomm" },
            { "uri": "wss://mediator.example.com/ws" }
        ]);
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_array_did_uri() {
        let endpoint = json!([{ "uri": "did:web:mediator.example.com" }]);
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "did:web:mediator.example.com");
    }

    #[test]
    fn test_extract_endpoint_value_unsupported_returns_error() {
        let endpoint = json!(42);
        assert!(extract_endpoint_value(&endpoint).is_err());
    }

    // ── extract_base_url ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_base_url_https_no_port() {
        assert_eq!(extract_base_url("https://mediator.example.com/path").unwrap(), "https://mediator.example.com");
    }

    #[test]
    fn test_extract_base_url_https_with_port() {
        assert_eq!(
            extract_base_url("https://mediator.example.com:8443/path").unwrap(),
            "https://mediator.example.com:8443"
        );
    }

    #[test]
    fn test_extract_base_url_http() {
        assert_eq!(extract_base_url("http://localhost:8080/agents").unwrap(), "http://localhost:8080");
    }

    #[test]
    fn test_extract_base_url_wss_for_ssl() {
        assert_eq!(extract_base_url("wss://mediator.example.com:443/ws").unwrap(), "wss://mediator.example.com");
    }

    #[test]
    fn test_extract_base_url_wss() {
        assert_eq!(extract_base_url("wss://mediator.example.com:1234/ws").unwrap(), "wss://mediator.example.com:1234");
    }

    #[test]
    fn test_extract_base_url_invalid_returns_error() {
        assert!(extract_base_url("not a url").is_err());
    }

    // ── fetch_mediator_did_from_url egress guard (SSRF) ─────────────────────────

    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Loopback mediator that serves `did_jsonl` on `/.well-known/did.jsonl` and
    /// 404s everything else. Loops so repeated probes are handled.
    async fn spawn_mediator_server(did_jsonl: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let n = sock
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("");
                let response = if path.ends_with("/.well-known/did.jsonl") {
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", did_jsonl.len(), did_jsonl)
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                };
                let _ = sock
                    .write_all(response.as_bytes())
                    .await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn fetch_rejects_loopback_oob_url_fail_closed() {
        // No allow-list entry: a loopback oob_url must be blocked before any
        // connection is attempted.
        let result = fetch_mediator_did_from_url_inner("http://127.0.0.1:1/mediator/v1", None).await;
        let err = result.expect_err("loopback mediator URL must be rejected");
        assert!(
            err.to_lowercase()
                .contains("blocked"),
            "expected an egress-blocked error, got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_private_oob_url_fail_closed() {
        let result = fetch_mediator_did_from_url_inner("http://10.0.0.1/mediator/v1", None).await;
        let err = result.expect_err("private RFC1918 mediator URL must be rejected");
        assert!(
            err.to_lowercase()
                .contains("blocked"),
            "expected an egress-blocked error, got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_does_not_follow_redirect_to_internal_target() {
        // Entry server redirects the .well-known probe to the cloud-metadata IP.
        // The guard must re-validate the hop and block it, never fetching the
        // internal target to completion.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let response = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n";
                let _ = sock
                    .write_all(response.as_bytes())
                    .await;
                let _ = sock.flush().await;
            }
        });

        let mediator_url = format!("http://{addr}/mediator/v1");
        let allow = format!("http://{addr}/.well-known/did.jsonl");
        let result = fetch_mediator_did_from_url_inner(&mediator_url, Some(&allow)).await;
        let err = result.expect_err("redirect to an internal target must be blocked");
        assert!(
            err.to_lowercase()
                .contains("blocked"),
            "expected the internal redirect hop to be blocked, got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_resolves_legitimate_mediator_via_allowlisted_loopback() {
        let body = r#"{"state":{"id":"did:web:mediator.example.com"}}"#;
        let addr = spawn_mediator_server(body).await;
        let mediator_url = format!("http://{addr}/mediator/v1");
        // Exact allow-list of the origin-scoped did.jsonl probe URL only.
        let allow = format!("http://{addr}/.well-known/did.jsonl");

        let result = fetch_mediator_did_from_url_inner(&mediator_url, Some(&allow)).await;
        assert_eq!(result.expect("allow-listed loopback mediator must resolve"), "did:web:mediator.example.com");
    }
}
