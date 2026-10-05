use std::path::Path;

pub fn create_storage_dirs(storage_dir: &Path) {
    let subdirs = [
        "cache",
        "settings",
        "agent_surfaces",
        "notifications/messages",
        "notifications/templates",
        "connection_points",
        "secrets",
        "apikeys",
        "certificates",
        "mcp_proxies",
        "a2a_proxies",
        "credential_providers",
        "delegation_vault",
        "audit",
        "pipes",
        "integrations/definitions",
        "integrations/triggers",
        "webhooks",
        "vc_keys",
        "metrics",
        "passkeys",
        "avatars",
        "identities",
        "gateways",
        "mediators",
        "trust_registries",
        "messages",
        "x402_transactions",
        "sessions",
        "policies",
        "issuers",
        "backup_restore",
        "system_metrics",
        "mpp_transactions",
        "cache/did",
    ];
    for subdir in &subdirs {
        std::fs::create_dir_all(storage_dir.join(subdir)).unwrap();
    }
}
