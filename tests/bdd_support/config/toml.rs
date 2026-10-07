use std::path::Path;

use crate::bdd_support::config::config_tree::G2G_BDD_GATEWAY_LOG_LEVEL_ENV;

pub fn write_config_toml(
    config_dir: &Path,
    storage_dir: &Path,
) {
    let certs_dir = crate::bdd_support::config::dev_certs::dev_cert_dir();
    let log_level = std::env::var(G2G_BDD_GATEWAY_LOG_LEVEL_ENV).unwrap_or_else(|_| "error".to_string());
    // Backup key is required at startup; a deterministic literal hex test key.
    let backup_key = "00".repeat(32);
    let config_toml = format!(
        r#"channel_config_source = "local"
secrets_backend = "filesystem"
auth_mode = "passkey"
session_timeout_minutes = 20
websocket_require_auth = false
metrics_retention_minutes = 360
metrics_cache_ttl_seconds = 1
backup_encryption_key = "{backup_key}"

[a2a]
fabric_gateway_timeout_ms = 5000
message_expires_seconds = 15

[config_files]
gateway = "{gateway_json_path}"

[storage_paths]
config_cache = "{storage}/cache"
settings = "{storage}/settings"
notifications = "{storage}/notifications/messages"
notification_templates = "{storage}/notifications/templates"
connection_points = "{storage}/connection_points"
agent_surfaces = "{storage}/agent_surfaces"
secrets = "{storage}/secrets"
apikeys = "{storage}/apikeys"
certificates = "{storage}/certificates"
mcp_proxies = "{storage}/mcp_proxies"
a2a_proxies = "{storage}/a2a_proxies"
credential_providers = "{storage}/credential_providers"
delegation_vault = "{storage}/delegation_vault"
pipes = "{storage}/pipes"
integrations = "{storage}/integrations/definitions"
integration_triggers = "{storage}/integrations/triggers"
webhooks = "{storage}/webhooks"
vc_keys = "{storage}/vc_keys"
metrics = "{storage}/metrics"
passkeys = "{storage}/passkeys"
avatars = "{storage}/avatars"
identities = "{storage}/identities"
gateways = "{storage}/gateways"
mediators = "{storage}/mediators"
trust_registries = "{storage}/trust_registries"
messages = "{storage}/messages"
x402_transactions = "{storage}/x402_transactions"
sessions = "{storage}/sessions"
policy_definitions = "{storage}/policies"
issuers = "{storage}/issuers"
backup_restore = "{storage}/backup_restore"
system_metrics = "{storage}/system_metrics"
mpp_transactions = "{storage}/mpp_transactions"

[did_cache]
ttl_seconds = 3600
max_entries = 100
stale_threshold_percent = 80
storage_path = "{storage}/cache/did"
allow_private_hosts = true

[tls]
cert_path = "{cert}"
key_path = "{key}"
verify_upstream = false

[logging]
level = "{log_level}"
json = false
"#,
        gateway_json_path = config_dir
            .join("gateway.json")
            .display(),
        storage = storage_dir.display(),
        cert = certs_dir
            .join("cert.pem")
            .display(),
        key = certs_dir
            .join("key.pem")
            .display(),
        log_level = log_level,
    );
    std::fs::write(config_dir.join("config.toml"), config_toml).unwrap();
}
