//! Stored records without the MCP HTTP and consent settings load and re-save
//! byte-identically, records that still carry the retired `mcp_protocol_mode`
//! load and re-save without it, and bootstrap configs without the Fabric
//! stream envelope limit still validate.
//!
//! Each fixture under `tests/fixtures/records/` is the exact file the
//! filesystem store writes for a release without those settings
//! (`serde_json::to_string_pretty`, no trailing newline).

use crate::config::agent_surface::AgentSurface;
use crate::storage::filesystem::{StorableEntity, StorageConfig, cached_storage_with_config};

const MCP_SURFACE: &str = include_str!("../../tests/fixtures/records/agent_surface_mcp.json");
const A2A_PARENT_SURFACE: &str = include_str!("../../tests/fixtures/records/agent_surface_a2a_parent.json");
const MCP_PROXY: &str = include_str!("../../tests/fixtures/records/mcp_proxy.json");
const DELEGATION_TOKEN: &str = include_str!("../../tests/fixtures/records/delegation_token.json");
const CREDENTIAL_PROVIDER: &str = include_str!("../../tests/fixtures/records/credential_provider.json");
const BOOTSTRAP_EXAMPLE: &str = include_str!("../../config/examples/config.example.toml");

const MCP_ENDPOINT_KEYS: [&str; 2] = ["mcp_protocol_mode", "mcp_http"];

/// Loads `fixture` through the filesystem store, saves it back, and asserts the
/// file is unchanged and none of `absent_pointers` was written.
async fn assert_stable_round_trip<T: StorableEntity>(
    fixture: &str,
    absent_pointers: &[String],
) -> T {
    assert_round_trip(fixture, fixture, absent_pointers).await
}

/// Loads `stored` through the filesystem store, saves it back, and asserts the
/// file then holds `expected` and none of `absent_pointers`.
async fn assert_round_trip<T: StorableEntity>(
    stored: &str,
    expected: &str,
    absent_pointers: &[String],
) -> T {
    let id = serde_json::from_str::<T>(stored)
        .expect("record must deserialize")
        .id()
        .to_string();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join(format!("{id}.json"));
    std::fs::write(&path, stored).unwrap();

    let storage = cached_storage_with_config::<T>(dir.path().to_path_buf(), "record", StorageConfig::new())
        .await
        .expect("store must open");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), stored, "loading must not rewrite the record");
    let record = crate::storage::filesystem::StorageBackend::get(&storage, &id)
        .await
        .unwrap()
        .expect("stored record must load");
    crate::storage::filesystem::StorageBackend::save(&storage, &record)
        .await
        .unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(written, expected, "saving must write the expected bytes");
    let written: serde_json::Value = serde_json::from_str(&written).unwrap();
    for pointer in absent_pointers {
        assert!(
            written
                .pointer(pointer)
                .is_none(),
            "{pointer} must not be written"
        );
    }
    record
}

fn endpoint_pointers(prefixes: &[&str]) -> Vec<String> {
    prefixes
        .iter()
        .flat_map(|prefix| {
            MCP_ENDPOINT_KEYS
                .iter()
                .map(move |key| format!("{prefix}/{key}"))
        })
        .collect()
}

/// `fixture` as an older release stored it, with `mode` set at every pointer.
fn with_retired_protocol_mode(
    fixture: &str,
    pointers: &[&str],
    mode: &str,
) -> String {
    let mut record: serde_json::Value = serde_json::from_str(fixture).unwrap();
    for pointer in pointers {
        record
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| panic!("{pointer} must be an object"))
            .insert("mcp_protocol_mode".into(), mode.into());
    }
    serde_json::to_string_pretty(&record).unwrap()
}

#[tokio::test]
async fn mcp_surface_with_base_and_variant_transit_points_round_trips() {
    let surface: AgentSurface = assert_stable_round_trip(
        MCP_SURFACE,
        &endpoint_pointers(&["", "/transit/points/0", "/transit/points/1", "/variants/0/overrides/transit/points/0"]),
    )
    .await;

    assert!(surface.mcp_http.is_none());
    assert_eq!(surface.validate_mcp_metadata(), Ok(()));
    surface
        .resolve_variant(Some("staging"))
        .expect("variant must resolve");
}

#[tokio::test]
async fn records_with_the_retired_protocol_mode_load_and_save_without_it() {
    let surface_pointers = ["", "/transit/points/0", "/transit/points/1", "/variants/0/overrides/transit/points/0"];
    for mode in ["legacy", "dual"] {
        let stored = with_retired_protocol_mode(MCP_SURFACE, &surface_pointers, mode);
        let surface: AgentSurface =
            assert_round_trip(&stored, MCP_SURFACE, &endpoint_pointers(&surface_pointers)).await;
        assert_eq!(surface.validate_mcp_metadata(), Ok(()), "{mode}");

        let stored = with_retired_protocol_mode(A2A_PARENT_SURFACE, &["/transit/points/0"], mode);
        let _: AgentSurface =
            assert_round_trip(&stored, A2A_PARENT_SURFACE, &endpoint_pointers(&["/transit/points/0"])).await;

        let stored = with_retired_protocol_mode(MCP_PROXY, &[""], mode);
        let _: crate::mcp_proxies::types::McpProxy =
            assert_round_trip(&stored, MCP_PROXY, &endpoint_pointers(&[""])).await;
    }
}

#[tokio::test]
async fn a2a_surface_with_an_mcp_transit_point_round_trips() {
    let surface: AgentSurface =
        assert_stable_round_trip(A2A_PARENT_SURFACE, &endpoint_pointers(&["", "/transit/points/0"])).await;

    assert_eq!(surface.validate_mcp_metadata(), Ok(()));
}

#[tokio::test]
async fn mcp_proxy_round_trips() {
    let proxy: crate::mcp_proxies::types::McpProxy =
        assert_stable_round_trip(MCP_PROXY, &endpoint_pointers(&[""])).await;

    assert!(proxy.mcp_http.is_none());
}

#[tokio::test]
async fn delegation_token_round_trips_without_consent_identity() {
    let token: crate::delegation_vault::DelegationToken =
        assert_stable_round_trip(DELEGATION_TOKEN, &["/consent_identity".to_string()]).await;

    assert!(
        token
            .consent_identity
            .is_none()
    );
}

#[tokio::test]
async fn credential_provider_round_trips_without_resource_or_consent_strategy() {
    let provider: crate::credential_providers::CredentialProvider = assert_stable_round_trip(
        CREDENTIAL_PROVIDER,
        &["/resource".to_string(), "/consent_identity_strategy_id".to_string()],
    )
    .await;

    assert_eq!(provider.resource, None);
    assert_eq!(provider.consent_identity_strategy_id, None);
}

/// Every stored surface admits `2026-07-28` alongside `2024-11-05`, whatever
/// retired `mcp_protocol_mode` it still carries, and an unmodelled revision is
/// refused with `-32022` before it reaches the Target.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "fails in the full test run: its gateway refuses connections after other tests change the process-wide server mode"]
async fn every_stored_surface_admits_modern_and_legacy_mcp() {
    use std::sync::atomic::Ordering;

    for mode in [None, Some("legacy"), Some("dual")] {
        let harness = super::helpers::GatewayHarness::start(|_, config, _| {
            let mut surface = serde_json::to_value(super::helpers::build_minimal_mcp_surface()).unwrap();
            if let Some(mode) = mode {
                surface["mcp_protocol_mode"] = mode.into();
            }
            config.surfaces = vec![serde_json::from_value(surface).unwrap()];
        })
        .await;
        let client = reqwest::Client::new();
        let send = |version: &'static str| {
            let mut request = client
                .post(&harness.gateway_url)
                .header("accept", "application/json, text/event-stream");
            let body = if version == crate::mcp::MCP_LEGACY_VERSION {
                serde_json::json!({"jsonrpc": "2.0", "id": "compat", "method": "tools/list"})
            } else {
                request = request
                    .header("mcp-protocol-version", version)
                    .header("mcp-method", "tools/list");
                serde_json::json!({"jsonrpc": "2.0", "id": "compat", "method": "tools/list", "params": {"_meta": {
                    "io.modelcontextprotocol/protocolVersion": version,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }}})
            };
            request.json(&body).send()
        };
        let forwarded = || {
            harness
                .mock
                .request_count
                .load(Ordering::SeqCst)
        };

        send(crate::mcp::MCP_MODERN_VERSION)
            .await
            .unwrap();
        assert_eq!(forwarded(), 1, "{mode:?}: 2026-07-28 must reach the Target");
        send(crate::mcp::MCP_LEGACY_VERSION)
            .await
            .unwrap();
        assert_eq!(forwarded(), 2, "{mode:?}: 2024-11-05 must reach the Target");

        let refused = send("2025-11-25")
            .await
            .unwrap();
        assert_eq!(refused.status(), 400, "{mode:?}");
        let refused: serde_json::Value = refused.json().await.unwrap();
        assert_eq!(refused["error"]["code"], crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION, "{mode:?}");
        assert_eq!(
            refused["error"]["data"]["supported"],
            serde_json::json!([crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION])
        );
        assert_eq!(forwarded(), 2, "{mode:?}: 2025-11-25 must not reach the Target");
    }
}

fn bootstrap_example_with_sdk_cache(
    sdk_inbound_cache_bytes: i64,
    fabric_stream_max_envelope_bytes: Option<i64>,
) -> crate::config::BootstrapConfig {
    let mut example: toml::Table = toml::from_str(BOOTSTRAP_EXAMPLE).expect("example must parse");
    let a2a = example["a2a"]
        .as_table_mut()
        .expect("example must have [a2a]");
    assert!(!a2a.contains_key("fabric_stream_max_envelope_bytes"), "the example must leave the envelope limit unset");
    a2a.insert("sdk_inbound_cache_bytes".into(), sdk_inbound_cache_bytes.into());
    if let Some(limit) = fabric_stream_max_envelope_bytes {
        a2a.insert("fabric_stream_max_envelope_bytes".into(), limit.into());
    }
    toml::from_str(&toml::to_string(&example).unwrap()).expect("example must deserialize")
}

#[test]
fn bootstrap_example_without_the_envelope_limit_validates_with_a_small_sdk_cache() {
    let config = bootstrap_example_with_sdk_cache(64 * 1024, None);

    assert_eq!(config.a2a.validate(), Ok(()));
    assert_eq!(
        config
            .a2a
            .stream_envelope_limit(),
        64 * 1024
    );
}

#[test]
fn bootstrap_example_with_an_explicit_envelope_limit_keeps_the_sdk_cache_check() {
    let config = bootstrap_example_with_sdk_cache(64 * 1024, Some(128 * 1024));

    assert!(
        config
            .a2a
            .validate()
            .unwrap_err()
            .contains("fabric_stream_max_envelope_bytes")
    );
    let config = bootstrap_example_with_sdk_cache(128 * 1024, Some(128 * 1024));
    assert_eq!(config.a2a.validate(), Ok(()));
}
