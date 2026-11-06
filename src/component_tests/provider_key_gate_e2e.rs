//! A surface stored naming an API Key Provider key it may not use goes live without the save
//! check, at boot or on a configuration reload. Under `tenant_credential_isolation: warn` it keeps
//! serving and the gateway logs the key id and rule; under `enforce`, or while the API key store
//! is unavailable, its Access Point is not ready: every request is refused with `503`. A surface
//! names only its own keys: one naming its own key serves in both modes, one naming another
//! surface's key of its own tenant is held back like one naming another tenant's. Revoking a
//! surface's own key takes it out of service on the next request in both modes.

use serde_json::{Value, json};
use std::sync::atomic::Ordering;

use super::helpers::{GatewayHarness, MockServer, configure_admin_api};
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};
use crate::source_auth::errors::ACCESS_POINT_UNAVAILABLE;

const KEY_A: &str = "atgk_0000000000000000000000000000ga01";
const KEY_B: &str = "atgk_0000000000000000000000000000gb01";
const NAMES_CROSS: &str = "names-cross";
const NAMES_OWN: &str = "owner-a";
const NAMES_SAME_TENANT: &str = "names-same-tenant";
const LEGACY_CALLER: &str = "legacy-caller";

struct Gate {
    h: GatewayHarness,
    admin: reqwest::Client,
    surfaces_dir: std::path::PathBuf,
}

fn api_keys_dir(bootstrap: &crate::config::BootstrapConfig) -> std::path::PathBuf {
    std::path::Path::new(
        &bootstrap
            .storage_paths
            .secrets,
    )
    .parent()
    .unwrap()
    .join("api_keys")
}

fn stored_surface(
    listen_address: &str,
    target: &str,
    surface_id: &str,
    tenant: &str,
    extra: Value,
) -> Value {
    let mut surface = json!({
        "surface_id": surface_id, "name": surface_id, "status": "active", "tenant_id": tenant,
        "access_point": {
            "listen_address": listen_address, "route": format!("/smoke/gate/{surface_id}"),
            "protocol": "a2a", "public": true
        },
        "target": {"endpoint": target}
    });
    for (key, value) in extra.as_object().unwrap() {
        if key == "access_point" {
            surface["access_point"]
                .as_object_mut()
                .unwrap()
                .extend(
                    value
                        .as_object()
                        .unwrap()
                        .clone(),
                );
        } else {
            surface[key] = value.clone();
        }
    }
    surface
}

fn names(key_id: &str) -> Value {
    json!({"identity_slots": {"external": {"type": "from_api_key", "api_key_id": key_id}}})
}

impl Gate {
    /// Boots a gateway whose store holds two key-owning surfaces, of tenants `a` and `b`, the
    /// first naming its own key, a tenant `a` surface naming tenant `b`'s key, one naming the
    /// tenant `a` owner's key, and one whose Caller Context API Key secret id is tenant `b`'s key. Without `key_store`, the API key store
    /// cannot start.
    async fn start(
        isolation: RuleMode,
        key_store: bool,
    ) -> Self {
        Self::start_with(isolation, key_store, 0).await
    }

    /// [`Self::start`] with the stores' `cache_refresh_interval_secs`.
    async fn start_with(
        isolation: RuleMode,
        key_store: bool,
        cache_refresh_interval_secs: u64,
    ) -> Self {
        let mock = MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "a2a-1", "result": {"kind": "message", "messageId": "r-1", "role": "agent",
                "parts": []}})
            .to_string(),
        )
        .await;
        let target = mock.url();
        let mut admin = None;
        let mut surfaces_dir = None;
        let h = GatewayHarness::start_with_mock(mock, |temp_dir, _, bootstrap| {
            bootstrap.credential_policy = CredentialPolicyConfig {
                tenant_credential_isolation: isolation,
                ..Default::default()
            };
            bootstrap.cache_refresh_interval_secs = cache_refresh_interval_secs;
            admin = Some(configure_admin_api(bootstrap));
            let gateway: Value =
                serde_json::from_slice(&std::fs::read(temp_dir.join("gateway.json")).unwrap()).unwrap();
            let listen_address = gateway["listeners"][0]["external_urls"][0]
                .as_str()
                .unwrap()
                .to_string();
            let directory = std::path::PathBuf::from(
                &bootstrap
                    .storage_paths
                    .agent_surfaces,
            );
            std::fs::create_dir_all(&directory).unwrap();
            let legacy = json!({
                "identity_slots": {"inbound": {"type": "from_api_key"}},
                "access_point": {"caller_authentication": {"methods": [{
                    "type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": KEY_B
                }]}}
            });
            for (id, tenant, extra) in [
                (NAMES_OWN, "tenant-a", names(KEY_A)),
                ("owner-b", "tenant-b", json!({})),
                (NAMES_CROSS, "tenant-a", names(KEY_B)),
                (NAMES_SAME_TENANT, "tenant-a", names(KEY_A)),
                (LEGACY_CALLER, "tenant-a", legacy),
            ] {
                std::fs::write(
                    directory.join(format!("{id}.json")),
                    stored_surface(&listen_address, &target, id, tenant, extra).to_string(),
                )
                .unwrap();
            }
            surfaces_dir = Some(directory);
            let api_keys = api_keys_dir(bootstrap);
            if !key_store {
                std::fs::create_dir_all(api_keys.parent().unwrap()).unwrap();
                std::fs::write(&api_keys, b"not a directory").unwrap();
                return;
            }
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    use crate::api_keys::store::ApiKeyStore as _;
                    let store = crate::api_keys::FileSystemApiKeyStore::new(&api_keys.to_string_lossy())
                        .await
                        .unwrap();
                    for (owner, key_id) in [(NAMES_OWN, KEY_A), ("owner-b", KEY_B)] {
                        store
                            .create_with_material(
                                owner,
                                key_id.to_string(),
                                format!("atgs_{key_id}"),
                                "client",
                                None,
                                "component-test",
                            )
                            .await
                            .unwrap();
                    }
                })
            });
        })
        .await;
        let gate = Self {
            h,
            admin: admin.unwrap(),
            surfaces_dir: surfaces_dir.unwrap(),
        };
        gate.reload().await;
        gate
    }

    async fn reload(&self) {
        let response = self
            .admin
            .post(format!("{}/api/v1/config/reload", self.h.gateway_base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    async fn call(
        &self,
        surface_id: &str,
    ) -> (u16, Value) {
        let response = reqwest::Client::new()
            .post(format!("{}/smoke/gate/{surface_id}", self.h.gateway_base))
            .header("content-type", "application/json")
            .body(
                json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send",
                    "params": {"message": {"role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hi"}]}}})
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (
            status,
            response
                .json()
                .await
                .unwrap_or(Value::Null),
        )
    }

    /// Rewrites the stored file of `surface_id` as another node or an operator would, and reloads
    /// the gateway's configuration.
    async fn rewrite_and_reload(
        &self,
        surface_id: &str,
        edit: impl FnOnce(&mut Value),
    ) {
        self.rewrite(surface_id, edit);
        self.reload().await;
    }

    /// The stored file of `surface_id`.
    fn stored_path(
        &self,
        surface_id: &str,
    ) -> std::path::PathBuf {
        let paths: Vec<_> = std::fs::read_dir(&self.surfaces_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                std::fs::read_to_string(path).is_ok_and(|content| content.contains(&format!("\"{surface_id}\"")))
            })
            .collect();
        assert_eq!(paths.len(), 1, "{paths:?}");
        paths[0].clone()
    }

    /// Rewrites the stored file of `surface_id` as another node sharing the store would.
    fn rewrite(
        &self,
        surface_id: &str,
        edit: impl FnOnce(&mut Value),
    ) {
        let path = self.stored_path(surface_id);
        let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edit(&mut stored);
        std::fs::write(&path, stored.to_string()).unwrap();
    }

    /// Calls `surface_id` until it answers `status`, as a change read from storage is applied
    /// after the reload that read it answers.
    async fn call_until(
        &self,
        surface_id: &str,
        status: u16,
    ) -> (u16, Value) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let answer = self.call(surface_id).await;
            if answer.0 == status || std::time::Instant::now() > deadline {
                return answer;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    fn reached(&self) -> usize {
        self.h
            .mock
            .request_count
            .load(Ordering::SeqCst)
    }
}

fn assert_not_ready(
    (status, body): (u16, Value),
    context: &str,
) {
    assert_eq!(status, 503, "{context}: {body}");
    assert_eq!(body["detail"], ACCESS_POINT_UNAVAILABLE, "{context}: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn under_warn_a_surface_naming_another_tenants_key_serves_and_is_logged() {
    let gate = Gate::start(RuleMode::Warn, true).await;

    let (status, body) = gate.call(NAMES_CROSS).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = gate
        .call(NAMES_SAME_TENANT)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(gate.reached(), 3);

    let warnings = gate.h.startup_warnings();
    let line = warnings
        .lines()
        .find(|line| line.contains("provider_key_tenant") && line.contains(NAMES_CROSS))
        .unwrap_or_else(|| panic!("a provider key warning for {NAMES_CROSS}: {warnings}"));
    assert!(line.contains(&format!("{KEY_B}:other_tenant")) && line.contains("tenant-a"), "{line}");
    let line = warnings
        .lines()
        .find(|line| line.contains("provider_key_tenant") && line.contains(NAMES_SAME_TENANT))
        .unwrap_or_else(|| panic!("a provider key warning for {NAMES_SAME_TENANT}: {warnings}"));
    assert!(line.contains(&format!("{KEY_A}:other_surface")) && line.contains("not_ready=false"), "{line}");
    assert!(!warnings.contains("atgs_"), "no key secret is logged: {warnings}");
    assert!(
        !warnings
            .lines()
            .any(|line| line.contains("provider_key_tenant") && line.contains(NAMES_OWN)),
        "{warnings}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn under_enforce_a_surface_naming_another_tenants_key_is_not_ready() {
    let gate = Gate::start(RuleMode::Enforce, true).await;

    assert_not_ready(gate.call(NAMES_CROSS).await, "another tenant's key");
    assert_not_ready(
        gate.call(NAMES_SAME_TENANT)
            .await,
        "another surface's key of the same tenant",
    );
    assert_not_ready(gate.call(LEGACY_CALLER).await, "a legacy caller secret shaped like another tenant's key");
    assert_eq!(gate.reached(), 0, "a not-ready Access Point never reaches the Target");
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(gate.reached(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_makes_a_serving_surface_name_another_tenants_key_takes_it_out_of_service_when_enforced() {
    let gate = Gate::start(RuleMode::Enforce, true).await;
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "{body}");

    gate.rewrite_and_reload(NAMES_OWN, |stored| {
        stored["identity_slots"]["external"]["api_key_id"] = json!(KEY_B);
    })
    .await;
    assert_not_ready(
        gate.call_until(NAMES_OWN, 503)
            .await,
        "rewritten to another tenant's key",
    );
    let reached = gate.reached();
    assert_not_ready(gate.call(NAMES_OWN).await, "rewritten to another tenant's key");
    assert_eq!(gate.reached(), reached, "a not-ready Access Point never reaches the Target");

    gate.rewrite_and_reload(NAMES_OWN, |stored| {
        stored["identity_slots"]["external"]["api_key_id"] = json!(KEY_A);
    })
    .await;
    let (status, body) = gate
        .call_until(NAMES_OWN, 200)
        .await;
    assert_eq!(status, 200, "rewritten back to its own key: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_api_key_store_a_surface_naming_a_key_is_not_ready() {
    let gate = Gate::start(RuleMode::Warn, false).await;

    assert_not_ready(gate.call(NAMES_OWN).await, "its own key, no store");
    assert_not_ready(gate.call(NAMES_CROSS).await, "another tenant's key, no store");
    let (status, body) = gate.call("owner-b").await;
    assert_eq!(status, 200, "a surface naming no key is served: {body}");
}

/// Runs `flow` in a child test process, since the cache refresh interval it sets is
/// process-wide and would make every other gateway in this process poll its storage.
fn run_in_own_process<F: std::future::Future<Output = ()>>(flow: impl FnOnce() -> F) {
    if std::env::var_os("ATG_PROVIDER_KEY_GATE_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_PROVIDER_KEY_GATE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated test {test_name} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(flow()));
}

#[test]
fn a_change_another_node_writes_is_applied_through_the_refresh_scan_and_a_deleted_surface_forgotten() {
    run_in_own_process(refresh_scan_flow);
}

async fn refresh_scan_flow() {
    crate::storage::filesystem::set_cache_refresh_interval_secs(1);
    let gate = Gate::start_with(RuleMode::Enforce, true, 1).await;
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "{body}");

    gate.rewrite(NAMES_OWN, |stored| {
        stored["identity_slots"]["external"]["api_key_id"] = json!(KEY_B);
    });
    assert_not_ready(
        gate.call_until(NAMES_OWN, 503)
            .await,
        "rewritten to another tenant's key by another node",
    );
    let verdicts = gate.h.provider_key_gate();
    assert!(verdicts.has_verdict(NAMES_OWN));

    std::fs::remove_file(gate.stored_path(NAMES_OWN)).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while verdicts.has_verdict(NAMES_OWN) && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!verdicts.has_verdict(NAMES_OWN), "a deleted surface's verdict is dropped");
}

#[test]
fn a_key_owner_moved_to_another_tenant_by_another_node_keeps_serving_its_own_key() {
    run_in_own_process(owner_tenant_change_flow);
}

async fn owner_tenant_change_flow() {
    crate::storage::filesystem::set_cache_refresh_interval_secs(1);
    let gate = Gate::start_with(RuleMode::Enforce, true, 1).await;
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "{body}");

    let verdicts = gate.h.provider_key_gate();
    assert_not_ready(
        gate.call(NAMES_SAME_TENANT)
            .await,
        "another surface's key",
    );
    assert!(verdicts.has_verdict(NAMES_SAME_TENANT));

    gate.rewrite(NAMES_OWN, |stored| {
        stored["tenant_id"] = json!("tenant-b");
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while verdicts.has_verdict(NAMES_SAME_TENANT) && std::time::Instant::now() < deadline {
        let (status, body) = gate.call(NAMES_OWN).await;
        assert_eq!(status, 200, "a surface moved with its own key keeps serving it: {body}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        !verdicts.has_verdict(NAMES_SAME_TENANT),
        "the refresh scan applies the owner's move and drops the verdicts that read it"
    );
    let (status, body) = gate.call(NAMES_OWN).await;
    assert_eq!(status, 200, "a surface moved with its own key keeps serving it: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_surfaces_own_key_takes_it_out_of_service_at_once_in_both_modes() {
    for mode in [RuleMode::Warn, RuleMode::Enforce] {
        let gate = Gate::start(mode, true).await;
        let (status, body) = gate.call(NAMES_OWN).await;
        assert_eq!(status, 200, "{mode:?}: an active own key serves: {body}");

        let response = gate
            .admin
            .post(format!("{}/api/v1/api-keys/{NAMES_OWN}/{KEY_A}/revoke", gate.h.gateway_base))
            .json(&json!({"actor": "component-test"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204, "{mode:?}");

        let reached = gate.reached();
        assert_not_ready(gate.call(NAMES_OWN).await, "its own key revoked, the next request");
        assert_eq!(gate.reached(), reached, "{mode:?}: a surface naming a revoked key never reaches the Target");
        let (status, body) = gate.call("owner-b").await;
        assert_eq!(status, 200, "{mode:?}: a surface naming no revoked key serves: {body}");
    }
}
