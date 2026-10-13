//! Gateway configuration for modern MCP consent: the STS MCP issuer behind a
//! public HTTPS origin, protected continuations, an STS client for token
//! exchange, a JWT verification strategy for the identity provider and an
//! OAuth credential provider that proves the consenting user.

use std::path::Path;

use chrono::Utc;
use serde_json::{Value, json};

use crate::bdd_support::config::secrets::write_secret_fixture;
use crate::bdd_support::jwt::now_secs;

/// The public origin the gateway's inbound listener advertises. The MCP
/// issuer and Access Point resources must be HTTPS; requests still reach the
/// listener over loopback HTTP.
pub const PUBLIC_ORIGIN: &str = "https://gateway.example";
pub const MCP_SCOPE: &str = "read";
pub const STS_CLIENT_ID: &str = "bdd-mcp-client";
pub const STS_CLIENT_SECRET: &str = "bdd-mcp-client-secret-value";
pub const CALLER_AGENT_DID: &str = "did:web:caller.example";
const STS_CLIENT_SECRET_ID: &str = "bdd-mcp-client-secret";
const CONTINUATION_KEY_SECRET_ID: &str = "bdd-mcp-continuation-key";
const CONSENT_IDENTITY_STRATEGY_ID: &str = "bdd-consent-identity";

#[derive(Debug, Clone)]
pub struct ModernConsentFixture {
    pub provider_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub identity_issuer: String,
    pub identity_client_id: String,
    pub identity_client_secret: String,
    pub identity_jwk: Value,
    /// The route of the Access Point that accepts MCP access tokens.
    pub route: String,
}

pub fn mcp_issuer() -> String {
    format!("{PUBLIC_ORIGIN}/api/oauth2/mcp")
}

pub fn access_point_resource(route: &str) -> String {
    format!("{PUBLIC_ORIGIN}{route}")
}

pub fn provider_resource(provider_id: &str) -> String {
    format!("https://{provider_id}.example/api")
}

/// The `mcp_http.authorization` of an Access Point on `route`.
pub fn access_point_authorization(route: &str) -> Value {
    json!({ "resource": access_point_resource(route), "scopes": [MCP_SCOPE] })
}

pub fn outbound_credential(provider_id: &str) -> Value {
    json!({ "credential_provider_id": provider_id, "scopes": [MCP_SCOPE] })
}

/// The exact OAuth endpoints a test-mode gateway may reach over loopback.
pub fn oauth_endpoint_allowlist(fixture: &ModernConsentFixture) -> String {
    [&fixture.authorization_endpoint, &fixture.token_endpoint]
        .map(String::as_str)
        .join(",")
}

/// Add modern consent to a config tree already written under `base_dir`.
pub fn write_modern_consent_config(
    base_dir: &Path,
    fixture: &ModernConsentFixture,
) {
    let storage_dir = base_dir.join("_storage");
    patch_network_config(&base_dir.join("gateway.json"));
    append_continuations(&base_dir.join("config.toml"));

    let secrets_dir = storage_dir.join("secrets");
    let continuation_key = hex::encode(rand::random::<[u8; 32]>());
    write_secret_fixture(&secrets_dir, CONTINUATION_KEY_SECRET_ID, &continuation_key);
    write_secret_fixture(&secrets_dir, STS_CLIENT_SECRET_ID, STS_CLIENT_SECRET);
    let client_id_secret = format!("bdd-{}-client-id", fixture.provider_id);
    let client_secret_secret = format!("bdd-{}-client-secret", fixture.provider_id);
    write_secret_fixture(&secrets_dir, &client_id_secret, &fixture.identity_client_id);
    write_secret_fixture(&secrets_dir, &client_secret_secret, &fixture.identity_client_secret);

    let now = Utc::now().to_rfc3339();
    write_record(
        &storage_dir.join("sts_clients"),
        STS_CLIENT_ID,
        &json!({
            "id": STS_CLIENT_ID,
            "client_id": STS_CLIENT_ID,
            "name": "BDD MCP client",
            "client_secret_ref": STS_CLIENT_SECRET_ID,
            "allowed_audiences": [access_point_resource(&fixture.route)],
            "allowed_scopes": [MCP_SCOPE],
            "allowed_subject_audiences": [fixture.identity_client_id],
            "created_at": now,
            "updated_at": now,
        }),
    );
    write_record(
        &storage_dir.join("jwt_verification_strategies"),
        CONSENT_IDENTITY_STRATEGY_ID,
        &json!({
            "id": CONSENT_IDENTITY_STRATEGY_ID,
            "name": "BDD identity provider",
            "expected_issuer": fixture.identity_issuer,
            "jwks_source": { "type": "static", "jwks": [fixture.identity_jwk] },
            "created_at": now,
            "updated_at": now,
        }),
    );
    write_record(
        &storage_dir.join("credential_providers"),
        &fixture.provider_id,
        &json!({
            "id": fixture.provider_id,
            "name": fixture.provider_id,
            "provider_id": fixture.provider_id,
            "provider_type": "oauth2_authorization_code",
            "authorization_endpoint": fixture.authorization_endpoint,
            "token_endpoint": fixture.token_endpoint,
            "client_id_secret_ref": client_id_secret,
            "client_secret_secret_ref": client_secret_secret,
            "default_scopes": [MCP_SCOPE],
            "callback_path": format!("/v1/identity/oauth/callback/{}", fixture.provider_id),
            "resource": provider_resource(&fixture.provider_id),
            "consent_identity_strategy_id": CONSENT_IDENTITY_STRATEGY_ID,
            "token_refresh_enabled": true,
            "created_at": now,
            "updated_at": now,
        }),
    );
}

fn patch_network_config(path: &Path) {
    let mut network: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    network["listeners"][0]["external_urls"]
        .as_array_mut()
        .expect("inbound listener external_urls")
        .push(json!(PUBLIC_ORIGIN));
    network["sts"] = json!({ "mcp_issuer": { "issuer": mcp_issuer() } });
    std::fs::write(path, serde_json::to_string_pretty(&network).unwrap()).unwrap();
}

fn append_continuations(path: &Path) {
    let now = now_secs();
    let seal_until = now + 3600;
    let section = format!(
        r#"
[mcp.continuations]
deployment = "bdd-gateway"
ttl_secs = 300
active_key = "bdd-key"

[[mcp.continuations.keys]]
id = "bdd-key"
secret_id = "{CONTINUATION_KEY_SECRET_ID}"
not_before = {not_before}
seal_until = {seal_until}
open_until = {open_until}

[mcp.continuations.storage]
backend = "embedded"
capacity = 128
"#,
        not_before = now - 60,
        open_until = seal_until + 900,
    );
    let mut toml = std::fs::read_to_string(path).unwrap();
    toml.push_str(&section);
    std::fs::write(path, toml).unwrap();
}

fn write_record(
    dir: &Path,
    id: &str,
    record: &Value,
) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(format!("{id}.json")), serde_json::to_string_pretty(record).unwrap()).unwrap();
}
