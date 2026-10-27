//! A surface stored with the surface-wide target Trust Check list is migrated
//! once when the surface store loads it: the file is re-persisted with the
//! list on its Transit Points, and later loads leave it unchanged.

use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};
use serde_json::json;

fn legacy_surface() -> serde_json::Value {
    json!({
        "surface_id": "legacy-store",
        "name": "legacy-store",
        "access_point": {"listen_address": "0.0.0.0:8443", "route": "/legacy-store", "protocol": "a2a"},
        "target": {
            "endpoint": "https://managed.example/a2a",
            "trust_check_list": [{
                "id": "target-recognition",
                "trust_registry_id": "tr-1",
                "query_type": "recognition",
                "query": {"authority_id": "did:example:authority", "entity_id": "{{ input.agent.did }}"}
            }]
        },
        "transit": {"points": [
            {"id": "tp-a2a", "alias": "partner-a", "target_endpoint": "https://a.example/a2a", "protocol": "a2a"},
            {"id": "tp-mcp", "alias": "tools", "target_endpoint": "https://t.example/mcp", "protocol": "mcp"}
        ]}
    })
}

async fn load(dir: &std::path::Path) -> serde_json::Value {
    let store = FileSystemAgentSurfaceStore::new(dir.to_path_buf())
        .await
        .expect("store opens");
    let surface = store
        .get("legacy-store")
        .await
        .expect("get")
        .expect("surface loads");
    serde_json::to_value(surface).expect("serialize surface")
}

#[tokio::test]
async fn a_legacy_surface_file_is_migrated_and_persisted_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("legacy-store.json");
    std::fs::write(&path, serde_json::to_string_pretty(&legacy_surface()).unwrap()).unwrap();

    let first = load(dir.path()).await;

    let persisted = std::fs::read_to_string(&path).expect("read migrated file");
    let on_disk: serde_json::Value = serde_json::from_str(&persisted).expect("parse migrated file");
    assert!(
        on_disk
            .get("trust_check_split")
            .is_none(),
        "no target list remains, so no marker: {on_disk}"
    );
    assert!(
        on_disk["target"]
            .get("trust_check_list")
            .is_none(),
        "{on_disk}"
    );
    let points = &on_disk["transit"]["points"];
    assert_eq!(points[0]["trust_check_list"][0]["id"], "target-recognition");
    assert_eq!(points[0]["trust_check_migrated"], json!(true));
    assert_eq!(points[1]["trust_check_list"][0]["id"], "target-recognition", "MCP Transit Points get a copy too");
    assert_eq!(points[1]["trust_check_migrated"], json!(true));
    assert_eq!(first, on_disk, "the loaded surface is the persisted one");

    let store = FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
        .await
        .expect("store reopens");
    store
        .refresh_from_disk()
        .await
        .expect("refresh");
    let refreshed = store
        .get("legacy-store")
        .await
        .expect("get")
        .expect("surface");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), persisted, "a second load must not rewrite the file");
    assert_eq!(serde_json::to_value(refreshed).unwrap(), first);
    assert_eq!(load(dir.path()).await, first);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), persisted);
}
