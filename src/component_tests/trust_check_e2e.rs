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

pub(super) fn write_trust_registry_fixture(temp_dir: &std::path::Path) {
    write_tenant_trust_registry_fixture(temp_dir, API_TRUST_REGISTRY_ID, None);
}

fn write_tenant_trust_registry_fixture(
    temp_dir: &std::path::Path,
    id: &str,
    tenant_id: Option<&str>,
) {
    let mut registry = json!({
        "id": id,
        "name": format!("Registry {id}"),
        "description": "",
        "oob_url": "https://registry.example/oob",
        "connection_status": "failed",
        "status": "disabled",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    if let Some(tenant_id) = tenant_id {
        registry["tenant_id"] = json!(tenant_id);
    }
    let dir = temp_dir.join("trust_registries");
    std::fs::create_dir_all(&dir).expect("create trust_registries dir");
    std::fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_string_pretty(&registry).expect("serialize trust registry"),
    )
    .expect("write trust registry fixture");
}

pub(super) fn api_trust_check(id: &str) -> serde_json::Value {
    registry_trust_check(id, API_TRUST_REGISTRY_ID)
}

fn registry_trust_check(
    id: &str,
    trust_registry_id: &str,
) -> serde_json::Value {
    json!({
        "id": id,
        "trust_registry_id": trust_registry_id,
        "query_type": "recognition",
        "query": { "authority_id": "did:example:authority", "entity_id": "{{ target.did }}" }
    })
}

async fn send(request: reqwest::RequestBuilder) -> (u16, serde_json::Value) {
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
}

const PER_TRANSIT_POINT_REQUIRED: &str = "this surface stores Trust Checks per Transit Point; send trust_check_split: \
                                          true and set transit.points[].trust_check_list";
const TARGET_LIST_REJECTED: &str = "target.trust_check_list is only allowed for a2a-proxy:// and fabric:// Managed \
                                    Agent targets";

/// Surface writes through the management API: a declared write is stored as
/// sent, a full undeclared write is converted and keeps stored copies, and a
/// partial undeclared write that touches Trust Check lists is refused while
/// the surface keeps them per Transit Point.
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
    let surface = |id: &str, split: bool, target_list: Vec<serde_json::Value>, tp_list: Vec<serde_json::Value>| {
        let mut body = json!({
            "surface_id": id,
            "name": id,
            "status": "disabled",
            "access_point": {"listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a"},
            "target": {"endpoint": h.mock.url(), "trust_check_list": target_list},
            "transit": {"points": [{
                "id": "tp-partner",
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
    let patch = |url: &str, body: serde_json::Value| {
        client
            .patch(url)
            .header("content-type", "application/merge-patch+json")
            .json(&body)
    };

    let (status, created) = send(
        client
            .post(&collection)
            .json(&surface("tc-api-split", true, Vec::new(), partner())),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["trust_check_split"], json!(true), "a Transit Point list is stored with the marker");
    assert_eq!(created["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");
    assert!(
        created["target"]
            .get("trust_check_list")
            .is_none(),
        "{created}"
    );
    let split_url = format!("{collection}/tc-api-split");

    let (status, patched) = send(patch(&split_url, json!({"description": "patched"}))).await;
    assert_eq!(status, 200, "an undeclared PATCH that does not touch Trust Checks is a normal write: {patched}");
    assert_eq!(patched["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");

    for touching in [
        json!({"transit": {"points": [{"alias": "partner-a", "target_endpoint": "https://partner.example/a2a"}]}}),
        json!({"target": {"trust_check_list": [api_trust_check("legacy")]}}),
        json!({"transit": null}),
        json!({"target": null}),
        json!({"variants": [{"id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"transit": {"points": []}}}]}),
    ] {
        let (status, body) = send(patch(&split_url, touching.clone())).await;
        assert_eq!(status, 400, "{touching}: {body}");
        assert!(
            body.to_string()
                .contains(PER_TRANSIT_POINT_REQUIRED),
            "{body}"
        );
    }

    let (status, body) = send(patch(
        &split_url,
        json!({"trust_check_split": true, "target": {"trust_check_list": [api_trust_check("declared")]}}),
    ))
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(TARGET_LIST_REJECTED),
        "{body}"
    );

    let (status, stored) = send(client.get(&split_url)).await;
    assert_eq!(status, 200, "{stored}");
    assert_eq!(stored["description"], "patched");
    assert_eq!(stored["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");
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
    assert_eq!(status, 201, "an undeclared create is converted, not rejected: {legacy}");
    assert!(
        legacy["target"]
            .get("trust_check_list")
            .is_none(),
        "{legacy}"
    );
    assert_eq!(legacy["transit"]["points"][0]["trust_check_list"][0]["id"], "legacy-target");
    assert_eq!(legacy["transit"]["points"][0]["trust_check_migrated"], json!(true));
    assert_eq!(legacy["trust_check_split"], json!(true));
    let legacy_url = format!("{collection}/tc-api-legacy");

    let (status, kept) = send(
        client
            .put(&legacy_url)
            .json(&surface("tc-api-legacy", false, Vec::new(), Vec::new())),
    )
    .await;
    assert_eq!(status, 200, "{kept}");
    assert_eq!(
        kept["transit"]["points"][0]["trust_check_list"][0]["id"], "legacy-target",
        "an undeclared PUT keeps the converted copy"
    );
    assert_eq!(kept["transit"]["points"][0]["trust_check_migrated"], json!(true));

    let (status, removed) = send(
        client
            .put(&legacy_url)
            .json(&surface("tc-api-legacy", true, Vec::new(), Vec::new())),
    )
    .await;
    assert_eq!(status, 200, "{removed}");
    assert!(
        removed["transit"]["points"][0]
            .get("trust_check_list")
            .is_none(),
        "a declared PUT removes it"
    );
    assert!(
        removed
            .get("trust_check_split")
            .is_none(),
        "no list remains, so no marker: {removed}"
    );

    let (status, body) =
        send(patch(&legacy_url, json!({"target": {"trust_check_list": [api_trust_check("late")]}}))).await;
    assert_eq!(status, 400, "an undeclared PATCH is not converted: {body}");
    assert!(
        body.to_string()
            .contains(TARGET_LIST_REJECTED),
        "{body}"
    );
}

/// Variant writes without `trust_check_split: true` are refused when they
/// touch Trust Check lists of a surface that keeps them per Transit Point, and
/// are never converted; declared variant writes are stored as sent.
#[tokio::test(flavor = "multi_thread")]
async fn surface_api_variant_writes_follow_the_declared_shape() {
    let mut client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_trust_registry_fixture(temp_dir);
        client = Some(super::helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("admin client");
    let dev_point = |list: Vec<serde_json::Value>| {
        json!({"id": "tp-dev", "alias": "dev-partner", "target_endpoint": "https://dev-partner.example/a2a",
               "protocol": "a2a", "trust_check_list": list})
    };
    let create = |id: &str, points_list: Vec<serde_json::Value>| {
        json!({
            "surface_id": id,
            "name": id,
            "status": "disabled",
            "trust_check_split": true,
            "access_point": {"listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a"},
            "target": {"endpoint": h.mock.url()},
            "variants": [{
                "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": {"transit": {"points": [dev_point(points_list)]}}
            }]
        })
    };
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let (status, created) = send(
        client
            .post(&collection)
            .json(&create("tc-api-variant", vec![api_trust_check("dev-check")])),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let variant_url = format!("{collection}/tc-api-variant/variants/variant-dev");
    let patch = |body: serde_json::Value| {
        client
            .patch(&variant_url)
            .header("content-type", "application/merge-patch+json")
            .json(&body)
    };

    let (status, body) = send(
        client
            .put(&variant_url)
            .json(&json!({"overrides": {"transit": {"points": [dev_point(Vec::new())]}}})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(PER_TRANSIT_POINT_REQUIRED),
        "{body}"
    );

    for touching in [json!({"overrides": {"transit": null}}), json!({"overrides": null})] {
        let (status, body) = send(patch(touching.clone())).await;
        assert_eq!(status, 400, "{touching}: {body}");
        assert!(
            body.to_string()
                .contains(PER_TRANSIT_POINT_REQUIRED),
            "{body}"
        );
    }
    let (status, body) = send(
        client
            .put(&variant_url)
            .json(&json!({"overrides": {}})),
    )
    .await;
    assert_eq!(status, 400, "replacing overrides drops the stored variant lists: {body}");
    assert!(
        body.to_string()
            .contains(PER_TRANSIT_POINT_REQUIRED),
        "{body}"
    );

    let (status, renamed) = send(
        client
            .put(&variant_url)
            .json(&json!({"name": "Development"})),
    )
    .await;
    assert_eq!(status, 200, "an undeclared PUT that does not touch Trust Checks is a normal write: {renamed}");
    assert_eq!(renamed["overrides"]["transit"]["points"][0]["trust_check_list"][0]["id"], "dev-check");

    let (status, body) =
        send(patch(json!({"overrides": {"target": {"trust_check_list": [api_trust_check("x")]}}}))).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains(PER_TRANSIT_POINT_REQUIRED),
        "{body}"
    );

    let (status, patched) = send(patch(json!({
        "trust_check_split": true,
        "overrides": {"transit": {"points": [dev_point(vec![api_trust_check("dev-new")])]}}
    })))
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["variants"][0]["overrides"]["transit"]["points"][0]["trust_check_list"][0]["id"], "dev-new");

    let (status, updated) = send(
        client
            .put(&variant_url)
            .json(&json!({
                "trust_check_split": true,
                "overrides": {"transit": {"points": [dev_point(Vec::new())]}}
            })),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert!(
        updated["overrides"]["transit"]["points"][0]
            .get("trust_check_list")
            .is_none(),
        "{updated}"
    );

    let (status, body) = send(
        client
            .put(&variant_url)
            .json(&json!({
                "overrides": {"target": {"trust_check_list": [api_trust_check("undeclared")]},
                              "transit": {"points": [dev_point(Vec::new())]}}
            })),
    )
    .await;
    assert_eq!(status, 400, "no stored lists remain, so the write proceeds and meets the target rule: {body}");
    assert!(
        body.to_string()
            .contains(TARGET_LIST_REJECTED),
        "{body}"
    );
}

/// Transit Points of every protocol may carry a list through the API.
#[tokio::test(flavor = "multi_thread")]
async fn surface_api_accepts_trust_check_lists_on_mcp_transit_points() {
    let mut client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_trust_registry_fixture(temp_dir);
        client = Some(super::helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("admin client");
    let (status, created) = send(
        client
            .post(format!("{}/api/v1/surfaces", h.gateway_base))
            .json(&json!({
                "surface_id": "tc-api-mcp",
                "name": "tc-api-mcp",
                "status": "disabled",
                "trust_check_split": true,
                "access_point": {"listen_address": h.gateway_base, "route": "/tc-api-mcp", "protocol": "a2a"},
                "target": {"endpoint": h.mock.url()},
                "transit": {"points": [{
                    "alias": "tools", "target_endpoint": "https://tools.example/mcp", "protocol": "mcp",
                    "trust_check_list": [api_trust_check("tools-check")]
                }]}
            })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["transit"]["points"][0]["trust_check_list"][0]["id"], "tools-check");
}

/// A tenant access token can reference only its own or appliance-wide trust
/// registries from Transit Point lists, on the base and in variant overrides.
#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_token_references_only_its_own_trust_registries_from_transit_points() {
    let mut tenant = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_tenant_trust_registry_fixture(temp_dir, "tr-tenant-a", Some("tenant-a"));
        write_tenant_trust_registry_fixture(temp_dir, "tr-tenant-b", Some("tenant-b"));
        write_tenant_trust_registry_fixture(temp_dir, "tr-global", None);
        super::helpers::configure_admin_api(bootstrap);
        tenant = Some(super::a2a_flow_e2e::seed_scoped_access_token(
            bootstrap,
            Some("TENANT:${x-external-account}:(?:surfaces:.*|trust-registries:.*)"),
        ));
    })
    .await;
    let tenant = tenant.expect("tenant client");
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let surface = |id: &str, base_registry: &str, variant_registry: &str| {
        let point = |alias: &str, registry: &str| {
            json!({"alias": alias, "target_endpoint": "https://partner.example/a2a", "protocol": "a2a",
                   "trust_check_list": [registry_trust_check(&format!("{alias}-check"), registry)]})
        };
        json!({
            "surface_id": id,
            "name": id,
            "status": "disabled",
            "trust_check_split": true,
            "access_point": {"listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a"},
            "target": {"endpoint": h.mock.url()},
            "transit": {"points": [point("base-partner", base_registry)]},
            "variants": [{"id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": {"transit": {"points": [point("dev-partner", variant_registry)]}}}]
        })
    };

    for (id, base, variant) in
        [("tc-tenant-base-b", "tr-tenant-b", "tr-tenant-a"), ("tc-tenant-variant-b", "tr-tenant-a", "tr-tenant-b")]
    {
        let (status, body) = send(
            tenant
                .post(&collection)
                .json(&surface(id, base, variant)),
        )
        .await;
        assert_eq!(status, 400, "{id}: another tenant's registry must be refused: {body}");
        assert!(
            body.to_string()
                .contains("Trust Registry"),
            "{id}: {body}"
        );
    }

    for (id, base, variant) in
        [("tc-tenant-own", "tr-tenant-a", "tr-tenant-a"), ("tc-tenant-global", "tr-global", "tr-global")]
    {
        let (status, body) = send(
            tenant
                .post(&collection)
                .json(&surface(id, base, variant)),
        )
        .await;
        assert_eq!(status, 201, "{id}: {body}");
        assert_eq!(body["tenant_id"], "tenant-a", "{id}: {body}");
    }
}
