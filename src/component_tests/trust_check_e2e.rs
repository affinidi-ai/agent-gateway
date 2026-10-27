//! Trust Check stage → surface OPA end-to-end.
//!
//! Proves the Trust Check stage results actually reach surface OPA on the live
//! proxy path: the stage writes `input.trust_check_results.caller` and a Rego
//! rule that denies on `ok=false` produces an HTTP 403 with the standard
//! agent-trust-policy denial body. Two scenarios:
//!
//! 1. **caller element + missing registry → deny.** A configured
//!    `trust_check_list` entry referencing an unknown `trust_registry_id`
//!    produces a stage failure (`ok=false`, `error.code=TRUST_REGISTRY_UNREACHABLE`)
//!    at the single post-identity caller seam which
//!    the surface policy sees and denies.
//! 2. **no `trust_check_list` configured → allow.** Same policy, no caller
//!    entries: `input.trust_check_results` is absent and the policy allows,
//!    confirming the deny in (1) is driven by the stage output (not by a
//!    default-deny side effect of compiling the policy).

use super::helpers::GatewayHarness;
use serde_json::json;

const TR_CHECK_DENY_ON_ERROR_POLICY_ID: &str = "tr-check-deny-on-error";

/// Rego that denies when any caller- or target-leg trust check result has
/// `ok == false`, and allows otherwise (including when the stage produced no
/// results at all). Uses comprehensions instead of `every` for regorus
/// compatibility, matching the style already in `surface_manager.rs` tests.
const TR_CHECK_DENY_ON_ERROR_REGO: &str = r#"package surface.policy

default allow := false

# No trust check results → nothing to verify against → allow.
allow if {
    not input.trust_check_results
}

# Trust check ran → allow iff no failing caller or target result.
allow if {
    input.trust_check_results
    count([r | r := input.trust_check_results.caller[_]; r.ok == false]) == 0
    count([r | r := input.trust_check_results.target[_]; r.ok == false]) == 0
}
"#;

fn write_deny_on_error_policy_definition(temp_dir: &std::path::Path) {
    let definition = json!({
        "id": TR_CHECK_DENY_ON_ERROR_POLICY_ID,
        "name": "Trust Check: deny on error",
        "description": "Denies the request when any trust_check_results entry has ok=false.",
        "policy_type": "agent_surface",
        "policy": TR_CHECK_DENY_ON_ERROR_REGO,
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{}.json", TR_CHECK_DENY_ON_ERROR_POLICY_ID)),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write tr-check-deny-on-error policy definition fixture");
}

/// Build an A2A surface that references the `tr-check-deny-on-error` policy.
/// `with_caller_check = true` configures one caller-leg trust check element
/// pointing at an unreachable registry; `false` omits the `trust_check_list`
/// altogether.
fn surface_with_trust_check(
    surface_id: &str,
    with_caller_check: bool,
) -> crate::config::agent_surface::AgentSurface {
    let mut access_point = json!({
        "listen_address": "inbound_port_placeholder",
        "route": "/smoke",
        "protocol": "a2a"
    });
    if with_caller_check {
        access_point["trust_check_list"] = json!([{
            "id": "caller-recognition",
            "trust_registry_id": "tr-unreachable",
            "query_type": "recognition",
            "query": {
                "authority_id": "did:example:authority",
                "entity_id": "did:example:caller"
            }
        }]);
    }

    serde_json::from_value(json!({
        "surface_id": surface_id,
        "name": surface_id,
        "description": "Trust Check → OPA e2e",
        "access_point": access_point,
        "target": {
            "endpoint": "inbound_target_placeholder",
            "policy": { "policy_definition_id": TR_CHECK_DENY_ON_ERROR_POLICY_ID }
        }
    }))
    .expect("build trust-check surface")
}

fn a2a_request_body() -> String {
    json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "hello" }]
            }
        }
    })
    .to_string()
}

/// Caller-leg element pointing at a registry that has no live connection →
/// stage records `ok=false` at the single post-identity caller seam → surface
/// policy denies → HTTP 403 with the canonical "Agent trust policy denied the
/// request" body.
#[tokio::test(flavor = "multi_thread")]
async fn caller_trust_check_failure_denies_via_surface_opa() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        write_deny_on_error_policy_definition(temp_dir);
        gw_config.surfaces = vec![surface_with_trust_check("tc-deny", true)];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(a2a_request_body())
        .send()
        .await
        .expect("POST tc-deny failed");

    assert_eq!(resp.status(), 403, "caller trust check failure must deny via surface OPA, got {}", resp.status());
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("parse 403 body");
    assert_eq!(body["error"], "Forbidden");
    assert_eq!(body["message"], "Agent trust policy denied the request");
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "denied request must not reach the mock"
    );
}

/// No `trust_check_list` on the access point → stage produces no results →
/// `input.trust_check_results` is absent → the same Rego allows → request is
/// forwarded to the mock upstream. Pins that the deny in the scenario above
/// is driven by the trust check stage output, not by an unrelated side effect
/// of compiling the policy.
#[tokio::test(flavor = "multi_thread")]
async fn no_trust_check_list_allows_through_surface_opa() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        write_deny_on_error_policy_definition(temp_dir);
        gw_config.surfaces = vec![surface_with_trust_check("tc-empty-allow", false)];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(a2a_request_body())
        .send()
        .await
        .expect("POST tc-empty-allow failed");

    assert_eq!(
        resp.status(),
        200,
        "request must be allowed when no trust_check_list is configured, got {}",
        resp.status()
    );
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "allowed request must reach the mock exactly once"
    );
}

const API_TRUST_REGISTRY_ID: &str = "tr-api";

fn write_trust_registry_fixture(temp_dir: &std::path::Path) {
    let registry = json!({
        "id": API_TRUST_REGISTRY_ID,
        "name": "API registry",
        "description": "",
        "oob_url": "https://registry.example/oob",
        "connection_status": "failed",
        "status": "disabled",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("trust_registries");
    std::fs::create_dir_all(&dir).expect("create trust_registries dir");
    std::fs::write(
        dir.join(format!("{API_TRUST_REGISTRY_ID}.json")),
        serde_json::to_string_pretty(&registry).expect("serialize trust registry"),
    )
    .expect("write trust registry fixture");
}

fn api_trust_check(id: &str) -> serde_json::Value {
    json!({
        "id": id,
        "trust_registry_id": API_TRUST_REGISTRY_ID,
        "query_type": "recognition",
        "query": { "authority_id": "did:example:authority", "entity_id": "{{ target.did }}" }
    })
}

/// The management API stores every written surface with `trust_check_split`,
/// keeps per-Transit-Point lists, and refuses a surface-wide target list on an
/// HTTP(S) Managed Agent target (base or variant) without persisting it.
#[tokio::test(flavor = "multi_thread")]
async fn surface_api_writes_per_transit_point_trust_checks() {
    let mut client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_trust_registry_fixture(temp_dir);
        client = Some(super::helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("admin client");
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let send = |request: reqwest::RequestBuilder| async move {
        let response = request
            .send()
            .await
            .expect("admin API request");
        let status = response.status().as_u16();
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(json!(null));
        (status, body)
    };
    let surface = |surface_id: &str,
                   split: bool,
                   target_list: Vec<serde_json::Value>,
                   tp_list: Vec<serde_json::Value>| {
        let mut body = json!({
            "surface_id": surface_id,
            "name": surface_id,
            "status": "disabled",
            "access_point": {"listen_address": h.gateway_base, "route": format!("/{surface_id}"), "protocol": "a2a"},
            "target": {"endpoint": h.mock.url(), "trust_check_list": target_list},
            "transit": {"points": [{
                "alias": "partner-a",
                "target_endpoint": "https://partner.example/a2a",
                "protocol": "a2a",
                "trust_check_list": tp_list
            }]}
        });
        if split {
            body["trust_check_split"] = json!(true);
        }
        body
    };
    let partner = || vec![api_trust_check("partner-recognition")];
    let rejection = "transit.points[].trust_check_list";

    let (status, created) = send(
        client
            .post(&collection)
            .json(&surface("tc-api-split", true, Vec::new(), partner())),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert!(
        created
            .get("trust_check_split")
            .is_none(),
        "no target list, so no marker: {created}"
    );
    assert_eq!(created["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");
    assert!(
        created["transit"]["points"][0]
            .get("trust_check_migrated")
            .is_none(),
        "{created}"
    );
    assert!(
        created["target"]
            .get("trust_check_list")
            .is_none(),
        "{created}"
    );

    let surface_url = format!("{collection}/tc-api-split");
    let (status, updated) = send(
        client
            .put(&surface_url)
            .json(&surface("tc-api-split", true, Vec::new(), partner())),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert!(
        updated
            .get("trust_check_split")
            .is_none(),
        "{updated}"
    );

    let (status, patched) = send(
        client
            .patch(&surface_url)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"description": "patched", "trust_check_split": false})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert!(
        patched
            .get("trust_check_split")
            .is_none(),
        "{patched}"
    );
    assert_eq!(patched["description"], "patched");
    assert_eq!(patched["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");

    let (status, body) = send(
        client
            .post(&collection)
            .json(&surface("tc-api-declared", true, vec![api_trust_check("declared-target")], Vec::new())),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );
    let (status, _) = send(client.get(format!("{collection}/tc-api-declared"))).await;
    assert_eq!(status, 404, "a rejected create must not persist the surface");

    let (status, body) = send(
        client
            .put(&surface_url)
            .json(&surface("tc-api-split", true, vec![api_trust_check("declared-target")], partner())),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );

    let (status, body) = send(
        client
            .patch(&surface_url)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"trust_check_split": true, "variants": [{
                "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": {"target": {"trust_check_list": [api_trust_check("dev-target")]}}
            }]})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains("Variant 'dev'"),
        "{body}"
    );
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );

    let (status, stored) = send(client.get(&surface_url)).await;
    assert_eq!(status, 200, "{stored}");
    assert_eq!(stored["description"], "patched");
    assert!(
        stored["target"]
            .get("trust_check_list")
            .is_none(),
        "{stored}"
    );
    assert!(
        stored
            .get("variants")
            .is_none(),
        "{stored}"
    );

    let (status, legacy) = send(
        client
            .post(&collection)
            .json(&surface("tc-api-legacy", false, vec![api_trust_check("legacy-target")], Vec::new())),
    )
    .await;
    assert_eq!(status, 201, "an old-shape create is migrated, not rejected: {legacy}");
    assert!(
        legacy["target"]
            .get("trust_check_list")
            .is_none(),
        "{legacy}"
    );
    assert_eq!(legacy["transit"]["points"][0]["trust_check_list"][0]["id"], "legacy-target");
    assert_eq!(legacy["transit"]["points"][0]["trust_check_migrated"], json!(true));
    assert!(
        legacy
            .get("trust_check_split")
            .is_none(),
        "{legacy}"
    );

    let (status, patched) = send(
        client
            .patch(&surface_url)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"variants": [{
                "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": {
                    "target": {"trust_check_list": [api_trust_check("dev-target")]},
                    "transit": {"points": [{
                        "alias": "dev-partner", "target_endpoint": "https://dev-partner.example/a2a", "protocol": "a2a"
                    }]}
                }
            }]})),
    )
    .await;
    assert_eq!(status, 200, "an old-shape PATCH is migrated, not rejected: {patched}");
    let overrides = &patched["variants"][0]["overrides"];
    assert!(
        overrides["target"]
            .get("trust_check_list")
            .is_none(),
        "{patched}"
    );
    assert_eq!(overrides["transit"]["points"][0]["trust_check_list"][0]["id"], "dev-target");
    assert_eq!(overrides["transit"]["points"][0]["trust_check_migrated"], json!(true));
    assert_eq!(patched["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");
    assert!(
        patched["transit"]["points"][0]
            .get("trust_check_migrated")
            .is_none(),
        "{patched}"
    );
}

/// Variant writes follow the same declared shape as surface writes: without
/// `trust_check_split: true` a variant target list is converted onto the
/// variant's Transit Points; with it, the 400 rule applies.
#[tokio::test(flavor = "multi_thread")]
async fn surface_api_variant_writes_follow_the_declared_shape() {
    let mut client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_trust_registry_fixture(temp_dir);
        client = Some(super::helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("admin client");
    let send = |request: reqwest::RequestBuilder| async move {
        let response = request
            .send()
            .await
            .expect("admin API request");
        let status = response.status().as_u16();
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(json!(null));
        (status, body)
    };
    let dev_point =
        || json!({"alias": "dev-partner", "target_endpoint": "https://dev-partner.example/a2a", "protocol": "a2a"});
    let surface_url = format!("{}/api/v1/surfaces/tc-api-variant", h.gateway_base);
    let (status, created) = send(
        client
            .post(format!("{}/api/v1/surfaces", h.gateway_base))
            .json(&json!({
                "surface_id": "tc-api-variant",
                "name": "tc-api-variant",
                "status": "disabled",
                "trust_check_split": true,
                "access_point": {"listen_address": h.gateway_base, "route": "/tc-api-variant", "protocol": "a2a"},
                "target": {"endpoint": h.mock.url()},
                "variants": [{
                    "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                    "overrides": {"transit": {"points": [dev_point()]}}
                }]
            })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let variant_url = format!("{surface_url}/variants/variant-dev");
    let rejection = "transit.points[].trust_check_list";
    let overrides = |list_id: &str| json!({"target": {"trust_check_list": [api_trust_check(list_id)]}, "transit": {"points": [dev_point()]}});
    let assert_converted = |overrides: &serde_json::Value, list_id: &str| {
        assert!(
            overrides["target"]
                .get("trust_check_list")
                .is_none(),
            "{overrides}"
        );
        assert_eq!(overrides["transit"]["points"][0]["trust_check_list"][0]["id"], list_id, "{overrides}");
        assert_eq!(overrides["transit"]["points"][0]["trust_check_migrated"], json!(true), "{overrides}");
    };

    let (status, body) = send(
        client
            .put(&variant_url)
            .json(&json!({"trust_check_split": true, "overrides": overrides("put-declared")})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains("Variant 'dev'"),
        "{body}"
    );
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );

    let (status, updated) = send(
        client
            .put(&variant_url)
            .json(&json!({"overrides": overrides("put-legacy")})),
    )
    .await;
    assert_eq!(status, 200, "an old-shape variant PUT is converted: {updated}");
    assert_converted(&updated["overrides"], "put-legacy");

    let (status, body) = send(
        client
            .patch(&variant_url)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"trust_check_split": true, "overrides": overrides("patch-declared")})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );

    let (status, patched) = send(
        client
            .patch(&variant_url)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"overrides": overrides("patch-legacy")})),
    )
    .await;
    assert_eq!(status, 200, "an old-shape variant PATCH is converted: {patched}");
    assert_converted(&patched["variants"][0]["overrides"], "patch-legacy");
    assert!(
        patched
            .get("trust_check_split")
            .is_none(),
        "{patched}"
    );

    for (alias, body) in [
        ("copy-a", json!({"alias": "copy-a", "name": "copy-a", "source_alias": "dev"})),
        ("copy-b", json!({"alias": "copy-b", "name": "copy-b", "source_alias": "dev", "trust_check_split": true})),
    ] {
        let (status, variant) = send(
            client
                .post(format!("{surface_url}/variants"))
                .json(&body),
        )
        .await;
        assert_eq!(status, 201, "{alias}: {variant}");
        assert_converted(&variant["overrides"], "patch-legacy");
    }
}

/// An MCP Transit Point receives the converted copy of an old-shape write, may
/// keep that exact list or remove it, and may never gain or change one.
#[tokio::test(flavor = "multi_thread")]
async fn surface_api_mcp_transit_points_keep_or_remove_migrated_copies_only() {
    let mut client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_trust_registry_fixture(temp_dir);
        client = Some(super::helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("admin client");
    let send = |request: reqwest::RequestBuilder| async move {
        let response = request
            .send()
            .await
            .expect("admin API request");
        let status = response.status().as_u16();
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(json!(null));
        (status, body)
    };
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let surface = |split: bool, target_list: Vec<serde_json::Value>, tools_list: Vec<serde_json::Value>| {
        let mut body = json!({
            "surface_id": "tc-api-mcp",
            "name": "tc-api-mcp",
            "status": "disabled",
            "access_point": {"listen_address": h.gateway_base, "route": "/tc-api-mcp", "protocol": "a2a"},
            "target": {"endpoint": h.mock.url(), "trust_check_list": target_list},
            "transit": {"points": [{
                "id": "tp-tools",
                "alias": "tools",
                "target_endpoint": "https://tools.example/mcp",
                "protocol": "mcp",
                "trust_check_list": tools_list
            }]}
        });
        if split {
            body["trust_check_split"] = json!(true);
        }
        body
    };
    let rejection = "Trust Checks can't be added or changed on an MCP or HTTP Transit Point";

    let (status, body) = send(
        client
            .post(&collection)
            .json(&surface(true, Vec::new(), vec![api_trust_check("new")])),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );
    assert!(
        body.to_string()
            .contains("tools"),
        "{body}"
    );

    let (status, created) = send(
        client
            .post(&collection)
            .json(&surface(false, vec![api_trust_check("legacy-target")], Vec::new())),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let tools = &created["transit"]["points"][0];
    assert_eq!(tools["trust_check_list"], json!([api_trust_check("legacy-target")]));
    assert_eq!(tools["trust_check_migrated"], json!(true));

    let surface_url = format!("{collection}/tc-api-mcp");
    let (status, kept) = send(
        client
            .put(&surface_url)
            .json(&surface(true, Vec::new(), vec![api_trust_check("legacy-target")])),
    )
    .await;
    assert_eq!(status, 200, "keeping the migrated copy is accepted: {kept}");
    assert_eq!(kept["transit"]["points"][0]["trust_check_list"][0]["id"], "legacy-target");

    let (status, body) = send(
        client
            .put(&surface_url)
            .json(&surface(true, Vec::new(), vec![api_trust_check("legacy-target"), api_trust_check("extra")])),
    )
    .await;
    assert_eq!(status, 400, "changing the migrated copy is rejected: {body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );

    let (status, removed) = send(
        client
            .put(&surface_url)
            .json(&surface(true, Vec::new(), Vec::new())),
    )
    .await;
    assert_eq!(status, 200, "removing the migrated copy is accepted: {removed}");
    assert!(
        removed["transit"]["points"][0]
            .get("trust_check_list")
            .is_none(),
        "{removed}"
    );

    let (status, body) = send(
        client
            .put(&surface_url)
            .json(&surface(true, Vec::new(), vec![api_trust_check("legacy-target")])),
    )
    .await;
    assert_eq!(status, 400, "a removed copy cannot be added back: {body}");
    assert!(
        body.to_string()
            .contains(rejection),
        "{body}"
    );
}
