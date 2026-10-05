use std::path::Path;

use chrono::Utc;

pub fn write_secret_fixture(
    secrets_dir: &Path,
    secret_id: &str,
    value: &str,
) {
    let path = secrets_dir.join(format!("{secret_id}.json"));
    if path.exists() {
        return;
    }

    let now = Utc::now().to_rfc3339();
    let secret_json = serde_json::json!({
        "id": secret_id,
        "name": format!("BDD {secret_id}"),
        "secret_id": secret_id,
        "description": "BDD fixture secret",
        "value": value,
        "secret_type": "ApiKey",
        "tags": ["bdd"],
        "created_at": now,
        "updated_at": now,
    });
    std::fs::write(path, serde_json::to_string_pretty(&secret_json).unwrap()).unwrap();
}
