use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};

/// SHA-256 hex of an API key secret, matching the gateway's `hash_secret`.
fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn write_api_key_provider_fixture(
    api_keys_dir: &Path,
    agent_id: &str,
    key_id: &str,
    client_id: &str,
    secret: &str,
    created_at: DateTime<Utc>,
) {
    let agent_dir = api_keys_dir.join(agent_id);
    std::fs::create_dir_all(&agent_dir).unwrap();

    let key_json = json!({
        "key_id": key_id,
        "agent_id": agent_id,
        "client_id": client_id,
        "secret_hash": hash_secret(secret),
        "status": "active",
        "created_at": created_at.to_rfc3339(),
        "revoked_at": null,
        "last_used_at": null,
        "labels": { "source": "bdd" },
        "issuer": {
            "actor": "bdd",
            "method": "fixture",
        },
        "rotated_from": null,
    });

    std::fs::write(agent_dir.join(format!("{key_id}.json")), serde_json::to_string_pretty(&key_json).unwrap()).unwrap();
}

/// Writes a key record of `agent_id` and makes that agent's key folder unreadable, so the
/// gateway cannot load its keys; returns the folder.
pub fn write_unloadable_api_key_fixture(
    api_keys_dir: &Path,
    agent_id: &str,
    key_id: &str,
) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    write_api_key_provider_fixture(api_keys_dir, agent_id, key_id, "bdd-client", "bdd-secret", Utc::now());
    let agent_dir = api_keys_dir.join(agent_id);
    std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    agent_dir
}

/// Key folders made unreadable for a scenario, readable again when dropped so the scenario's
/// directory can be removed.
#[derive(Debug, Default)]
pub struct UnreadableKeyFolders(pub Vec<PathBuf>);

impl Drop for UnreadableKeyFolders {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        for folder in &self.0 {
            let _ = std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn api_key_provider_fixture_writer_creates_expected_storage_record() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let api_keys_dir = temp_dir
            .path()
            .join("api_keys");

        let created_at = chrono::Utc::now() - chrono::Duration::days(1);
        super::write_api_key_provider_fixture(&api_keys_dir, "agent", "key", "client", "valid", created_at);

        let api_key_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(api_keys_dir.join("agent/key.json")).unwrap()).unwrap();
        assert_eq!(api_key_json["key_id"], "key");
        assert_eq!(api_key_json["agent_id"], "agent");
        assert_eq!(api_key_json["client_id"], "client");
        // The raw secret is never persisted — only its SHA-256 hash.
        assert!(api_key_json["secret"].is_null());
        assert_eq!(api_key_json["secret_hash"], super::hash_secret("valid"));
        assert_eq!(api_key_json["created_at"], created_at.to_rfc3339());
    }
}
