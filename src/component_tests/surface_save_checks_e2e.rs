//! Surface saves report fail-open policies and declaration outcomes per Surface
//! Variant, accept a save response sent back, refuse any other unknown field, and
//! recompute the report on read after a policy changes. A caller of a surface whose
//! strategy is gone gets a server error that names no strategy.

use serde_json::{Value, json};

use super::helpers::admin_api::{AdminApi, listener_origin};
use super::helpers::card_security::{
    ISSUER, PUBLIC_ORIGIN, REQUIRED_SCOPE, STRATEGY_ID, advertise_public_origin, jwt_bearer_caller_authentication,
    write_strategy,
};
use super::helpers::{GatewayHarness, configure_admin_api};

const SEND_ONLY: &str = "deny-send-only";
const UNDEFINED: &str = "undefined-allow";
const DENY_SEND_ONLY: &str = "package surface.policy\n\ndefault allow := true\n\nallow := false if {\n  input.source_auth.method == \"failed\"\n  input.a2a.method == \"SendMessage\"\n}\n";
const DENY_FAILED: &str =
    "package surface.policy\n\ndefault allow := true\n\nallow := false if input.source_auth.method == \"failed\"\n";
const NO_DEFAULT: &str = "package surface.policy\n\nallow if input.source_auth.method == \"api_key\"\n";
const DELETED_STRATEGY: &str = "deleted-strategy-7f3a";

fn write_policy(
    temp_dir: &std::path::Path,
    id: &str,
    rego: &str,
) {
    let definition = json!({
        "id": id, "name": id, "description": "", "policy_type": "agent_surface",
        "policy": rego, "enabled": true, "created_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("policy_definitions dir");
    std::fs::write(dir.join(format!("{id}.json")), definition.to_string()).expect("policy definition fixture");
}

impl AdminApi {
    /// The status and body of the answer.
    async fn body_of(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, Value) {
        let (status, body, _) = self.send(request).await;
        (status, body)
    }

    async fn put(
        &self,
        path: &str,
        body: &Value,
    ) -> (u16, Value) {
        self.body_of(
            self.client
                .put(self.url(path))
                .json(body),
        )
        .await
    }

    async fn merge_patch(
        &self,
        path: &str,
        body: &Value,
    ) -> (u16, Value) {
        self.body_of(
            self.client
                .patch(self.url(path))
                .header("Content-Type", "application/merge-patch+json")
                .body(body.to_string()),
        )
        .await
    }

    async fn get(
        &self,
        path: &str,
    ) -> (u16, Value) {
        self.body_of(
            self.client
                .get(self.url(path)),
        )
        .await
    }

    /// Issue a tenant PAT bound to `tenant` and `resource_pattern`; returns its secret.
    async fn tenant_pat(
        &self,
        tenant: &str,
        resource_pattern: &str,
    ) -> String {
        let (status, body) = self
            .post(
                "access-tokens",
                &json!({
                    "name": format!("{tenant} surfaces"),
                    "resource_pattern": resource_pattern,
                    "required_headers": [{"name": "x-external-account", "pattern": tenant}]
                }),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body["token"]
            .as_str()
            .expect("token secret")
            .to_string()
    }

    async fn get_as_tenant(
        &self,
        path: &str,
        secret: &str,
        tenant: &str,
    ) -> (u16, Value) {
        self.body_of(
            reqwest::Client::new()
                .get(self.url(path))
                .bearer_auth(secret)
                .header("x-external-account", tenant),
        )
        .await
    }
}

fn warning_codes(body: &Value) -> Vec<(String, Value)> {
    body["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .map(|warning| {
            (
                warning["code"]
                    .as_str()
                    .expect("code")
                    .to_string(),
                warning["variant"].clone(),
            )
        })
        .collect()
}

fn warning<'a>(
    body: &'a Value,
    code: &str,
) -> &'a Value {
    body["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .find(|warning| warning["code"] == code)
        .unwrap_or_else(|| panic!("no {code} warning: {body}"))
}

/// A gateway with the admin API whose listener advertises [`PUBLIC_ORIGIN`], with
/// the pinned strategy [`STRATEGY_ID`] trusting [`ISSUER`].
async fn declaring_admin() -> (GatewayHarness, AdminApi) {
    let mut admin_client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        advertise_public_origin(bootstrap);
        write_strategy(temp_dir, ISSUER, true);
        admin_client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = AdminApi::new(admin_client.expect("admin client"), &h);
    (h, admin)
}

fn surface_on(
    h: &GatewayHarness,
    route: &str,
    protocol: &str,
    caller_authentication: Value,
) -> Value {
    json!({
        "name": route.trim_start_matches('/').replace('/', "-"), "status": "active",
        "access_point": {"listen_address": listener_origin(h), "route": route, "protocol": protocol,
            "caller_authentication": caller_authentication},
        "target": {"endpoint": h.mock.url()}
    })
}

fn forwarding_caller_authentication(route: &str) -> Value {
    let mut authentication = jwt_bearer_caller_authentication(Some(&format!("{PUBLIC_ORIGIN}{route}")));
    authentication["methods"][0]["forward_header"] = json!(true);
    authentication
}

#[tokio::test(flavor = "multi_thread")]
async fn surface_saves_report_fail_open_policies_per_variant_and_recompute_on_read() {
    let mut admin_client = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_policy(temp_dir, SEND_ONLY, DENY_SEND_ONLY);
        write_policy(temp_dir, "deny-failed", DENY_FAILED);
        write_policy(temp_dir, UNDEFINED, NO_DEFAULT);
        admin_client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = AdminApi::new(admin_client.expect("admin client"), &h);
    let listener = listener_origin(&h);

    let (status, body) = admin
        .post("secrets/new", &json!({"name": "CALLER_KEYS", "secret_id": "CALLER_KEYS", "value": "key"}))
        .await;
    assert_eq!(status, 201, "{body}");

    let surface = json!({
        "name": "save-checks", "status": "active",
        "access_point": {
            "listen_address": listener, "route": "/save-checks", "protocol": "a2a",
            "caller_authentication": {"methods": [{
                "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"},
                "secret_id": "CALLER_KEYS"
            }]},
            "inbound_policy": {"policy_definition_id": SEND_ONLY}
        },
        "target": {"endpoint": "https://agent.example.invalid/a2a"},
        "variants": [
            {"id": "v-strict", "alias": "strict", "name": "strict", "description": "", "enabled": true,
             "overrides": {"access_point": {"inbound_policy": {"policy_definition_id": "deny-failed"}}}},
            {"id": "v-off", "alias": "off", "name": "off", "description": "", "enabled": false,
             "overrides": {"access_point": {"inbound_policy": {"policy_definition_id": UNDEFINED}}}}
        ]
    });
    let (status, created) = admin
        .post("surfaces", &surface)
        .await;
    assert_eq!(status, 201, "{created}");
    let surface_id = created["surface_id"]
        .as_str()
        .expect("surface_id")
        .to_string();
    let fail_open = |variant: Value| ("fail_open_policy".to_string(), variant);
    assert_eq!(warning_codes(&created), vec![fail_open(Value::Null), fail_open(json!("strict"))]);
    let message = created["warnings"][0]["message"]
        .as_str()
        .expect("message");
    assert!(message.contains("kind missing on message/send; 22 of 24 checked cases"), "{message}");
    assert_eq!(created["warnings"][0]["path"], "access_point.inbound_policy");
    let over_fabric = created["warnings"][1]["message"]
        .as_str()
        .expect("message");
    assert!(
        over_fabric.contains("over Fabric") && over_fabric.contains("24 of 24 checked cases"),
        "an inbound policy alone does not deny failed callers arriving over Fabric: {over_fabric}"
    );
    assert_eq!(created["warnings"][1]["path"], "target.policy");
    let variants: Vec<&Value> = created["declarations"]
        .as_array()
        .expect("declarations")
        .iter()
        .map(|declaration| &declaration["variant"])
        .collect();
    assert_eq!(variants, vec![&Value::Null, &json!("strict")]);
    assert_eq!(created["declarations"][0]["outcome"], "strip");
    assert_eq!(created["declarations"][0]["reason"], "not_declared");

    let (status, updated) = admin
        .put(&format!("surfaces/{surface_id}"), &created)
        .await;
    assert_eq!(status, 200, "a save response sent back is accepted: {updated}");
    assert_eq!(warning_codes(&updated), warning_codes(&created));

    let mut unknown = updated.clone();
    unknown["unexpected_field"] = json!(true);
    let (status, body) = admin
        .put(&format!("surfaces/{surface_id}"), &unknown)
        .await;
    assert_eq!(status, 422, "any other unknown field is still refused: {body}");
    let (status, body) = admin
        .merge_patch(&format!("surfaces/{surface_id}"), &json!({"unexpected_field": true}))
        .await;
    assert!(matches!(status, 400 | 422), "a merge patch with an unknown field is refused: {status} {body}");

    let mut copy = created.clone();
    copy.as_object_mut()
        .expect("surface object")
        .remove("surface_id");
    copy["name"] = json!("save-checks-copy");
    copy["access_point"]["route"] = json!("/save-checks-copy");
    let (status, copied) = admin
        .post("surfaces", &copy)
        .await;
    assert_eq!(status, 201, "a create carrying a save report is accepted: {copied}");
    assert_eq!(warning_codes(&copied), warning_codes(&created));
    copy["unexpected_field"] = json!(true);
    copy["access_point"]["route"] = json!("/save-checks-unknown");
    let (status, body) = admin
        .post("surfaces", &copy)
        .await;
    assert_eq!(status, 422, "a create with any other unknown field is refused: {body}");

    let (status, patched) = admin
        .merge_patch(
            &format!("surfaces/{surface_id}"),
            &json!({"description": "patched", "warnings": [], "declarations": []}),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["description"], "patched");
    assert_eq!(warning_codes(&patched), warning_codes(&created));

    let (status, read) = admin
        .get(&format!("surfaces/{surface_id}/declarations"))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(warning_codes(&read), warning_codes(&created));
    assert_eq!(read["declarations"], created["declarations"]);
    assert!(
        read.get("surface_id")
            .is_none(),
        "the read returns only the report: {read}"
    );
    let (status, stored) = admin
        .get(&format!("surfaces/{surface_id}"))
        .await;
    assert_eq!(status, 200, "{stored}");
    assert!(
        stored
            .get("warnings")
            .is_none()
            && stored
                .get("declarations")
                .is_none(),
        "the stored surface carries no report: {stored}"
    );

    let (status, policy) = admin
        .get(&format!("policy-definitions/{SEND_ONLY}"))
        .await;
    assert_eq!(status, 200, "{policy}");
    let mut policy = policy;
    policy["policy"] = json!(DENY_FAILED);
    let (status, body) = admin
        .put(&format!("policy-definitions/{SEND_ONLY}"), &policy)
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, read) = admin
        .get(&format!("surfaces/{surface_id}/declarations"))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(
        warning_codes(&read),
        vec![fail_open(Value::Null), fail_open(json!("strict"))],
        "the read sees the changed policy: {read}"
    );
    assert!(
        read["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .all(|warning| warning["path"] == "target.policy"),
        "the base route now denies every direct failed caller and admits them only over Fabric: {read}"
    );

    let (status, enabled) = admin
        .merge_patch(&format!("surfaces/{surface_id}/variants/v-off"), &json!({"enabled": true, "warnings": []}))
        .await;
    assert_eq!(status, 200, "{enabled}");
    assert_eq!(
        warning_codes(&enabled),
        vec![fail_open(Value::Null), fail_open(json!("strict")), ("fail_open_undetermined".to_string(), json!("off"))]
    );

    let (status, created_variant) = admin
        .post(
            &format!("surfaces/{surface_id}/variants"),
            &json!({"alias": "copy", "name": "copy", "source_alias": "off"}),
        )
        .await;
    assert_eq!(status, 201, "{created_variant}");
    assert_eq!(created_variant["alias"], "copy");
    assert_eq!(
        warning_codes(&created_variant),
        vec![
            fail_open(Value::Null),
            fail_open(json!("strict")),
            ("fail_open_undetermined".to_string(), json!("off")),
            ("fail_open_undetermined".to_string(), json!("copy")),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_point_reports_its_declaration_and_no_fail_open_policy() {
    let (h, admin) = declaring_admin().await;
    let route = "/smoke/declaring";
    let resource = format!("{PUBLIC_ORIGIN}{route}");

    let (status, created) = admin
        .post("surfaces", &surface_on(&h, route, "a2a", jwt_bearer_caller_authentication(Some(&resource))))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(
        created["declarations"],
        json!([{"variant": null, "outcome": "declare", "reason": null, "resource": resource,
            "authorization_servers": [ISSUER], "required_scopes": [REQUIRED_SCOPE],
            "scopes_supported": [REQUIRED_SCOPE],
            "metadata_url": format!("{PUBLIC_ORIGIN}/.well-known/oauth-protected-resource{route}")}])
    );
    assert!(
        warning_codes(&created).is_empty(),
        "the source-auth refusal protects a declaring Access Point without a policy: {created}"
    );

    let route = "/smoke/forwarding";
    let mut forwarding_authentication = jwt_bearer_caller_authentication(None);
    forwarding_authentication["methods"][0]["forward_header"] = json!(true);
    let (status, forwarding) = admin
        .post("surfaces", &surface_on(&h, route, "a2a", forwarding_authentication))
        .await;
    assert_eq!(status, 201, "{forwarding}");
    assert_eq!(
        warning_codes(&forwarding),
        vec![("fail_open_policy".to_string(), Value::Null)],
        "an Access Point that does not declare is still checked for failed callers"
    );
    let fail_open = warning(&forwarding, "fail_open_policy")["message"]
        .as_str()
        .expect("message");
    assert!(fail_open.contains("36 of 36 checked cases"), "{fail_open}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scoped_access_point_that_forwards_the_callers_token_is_saved_without_declaring() {
    let (h, admin) = declaring_admin().await;
    for (protocol, route) in [("a2a", "/smoke/forward-a2a"), ("mcp", "/smoke/forward-mcp")] {
        let mut without_setting = jwt_bearer_caller_authentication(None);
        without_setting["methods"][0]["forward_header"] = json!(true);
        let (status, created) = admin
            .post("surfaces", &surface_on(&h, route, protocol, without_setting))
            .await;
        assert_eq!(status, 201, "{protocol}: {created}");
        assert_eq!(
            created["declarations"],
            json!([{"variant": null, "outcome": "strip", "reason": "not_declared",
                "resource": format!("{PUBLIC_ORIGIN}{route}"), "authorization_servers": [],
                "required_scopes": [], "scopes_supported": [], "metadata_url": null}]),
            "{protocol}"
        );
        assert!(
            created["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .all(|warning| warning["code"] == "fail_open_policy"),
            "{protocol}: {created}"
        );

        let surface_id = created["surface_id"]
            .as_str()
            .expect("surface_id");
        let (status, read) = admin
            .get(&format!("surfaces/{surface_id}/declarations"))
            .await;
        assert_eq!(status, 200, "{protocol}: {read}");
        assert_eq!(read["declarations"], created["declarations"], "{protocol}");

        let forwarding_route = format!("{route}-declaring");
        let (status, refused) = admin
            .post(
                "surfaces",
                &surface_on(&h, &forwarding_route, protocol, forwarding_caller_authentication(&forwarding_route)),
            )
            .await;
        assert_eq!(status, 400, "{protocol}: {refused}");
        assert!(
            refused
                .to_string()
                .contains("cannot be combined with forward_header"),
            "{protocol}: {refused}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_mcp_protected_resource_is_refused_with_forward_header_and_declares_without_it() {
    let (h, admin) = declaring_admin().await;
    let route = "/smoke/explicit";
    let explicit = |forward_header: bool| {
        json!({
            "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [],
                "forward_header": forward_header}],
            "protected_resource": {"resource": format!("{PUBLIC_ORIGIN}{route}"),
                "authorization_servers": [ISSUER], "scopes": [REQUIRED_SCOPE]}
        })
    };

    let (status, refused) = admin
        .post("surfaces", &surface_on(&h, route, "mcp", explicit(true)))
        .await;
    assert_eq!(status, 400, "{refused}");
    assert!(
        refused
            .to_string()
            .contains("cannot be combined with forward_header"),
        "{refused}"
    );

    let (status, created) = admin
        .post("surfaces", &surface_on(&h, route, "mcp", explicit(false)))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(
        created["declarations"],
        json!([{"variant": null, "outcome": "declare", "reason": null, "resource": format!("{PUBLIC_ORIGIN}{route}"),
            "authorization_servers": [ISSUER], "required_scopes": [], "scopes_supported": [REQUIRED_SCOPE],
            "metadata_url": format!("{PUBLIC_ORIGIN}/.well-known/oauth-protected-resource{route}")}])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_strategy_issuer_change_is_advertised_without_a_surface_save() {
    let (h, admin) = declaring_admin().await;
    let route = "/smoke/issuer-change";
    let resource = format!("{PUBLIC_ORIGIN}{route}");
    let metadata_url = format!("{}/.well-known/oauth-protected-resource{route}", h.gateway_base);
    let read_metadata = || async {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .get(&metadata_url)
            .send()
            .await
            .expect("metadata request");
        assert_eq!(response.status().as_u16(), 200);
        response
            .json::<Value>()
            .await
            .expect("metadata JSON")
    };

    let (status, created) = admin
        .post("surfaces", &surface_on(&h, route, "a2a", jwt_bearer_caller_authentication(Some(&resource))))
        .await;
    assert_eq!(status, 201, "{created}");
    let surface_id = created["surface_id"]
        .as_str()
        .expect("surface id")
        .to_string();
    assert_eq!(read_metadata().await["authorization_servers"], json!([ISSUER]));

    let new_issuer = "https://as2.example";
    let (status, updated) = admin
        .put(
            &format!("jwt-verification-strategies/{STRATEGY_ID}"),
            &json!({
                "name": "Card security", "expected_issuer": new_issuer, "discover_metadata": false,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{new_issuer}/.well-known/jwks.json")}
            }),
        )
        .await;
    assert_eq!(status, 200, "{updated}");

    assert_eq!(
        read_metadata().await["authorization_servers"],
        json!([new_issuer]),
        "the advertised authorization server follows the strategy with no surface save"
    );
    let (status, read) = admin
        .get(&format!("surfaces/{surface_id}/declarations"))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["declarations"][0]["authorization_servers"], json!([new_issuer]), "{read}");
    assert!(
        read["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .all(|warning| warning["code"] != "authorization_servers_stale"),
        "a surface that stored no list is never stale: {read}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_route_at_or_under_the_metadata_path_is_refused() {
    let (h, admin) = declaring_admin().await;
    for route in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/agent"] {
        let (status, body) = admin
            .post("surfaces", &surface_on(&h, route, "a2a", json!(null)))
            .await;
        assert_eq!(status, 400, "{route}: {body}");
        assert!(
            body.to_string()
                .contains("protected resource metadata"),
            "{route}: {body}"
        );
    }
    let (status, body) = admin
        .post("surfaces", &surface_on(&h, "/smoke/oauth-protected-resource", "a2a", json!(null)))
        .await;
    assert_eq!(status, 201, "a route that only names the metadata path is accepted: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_declarations_read_hides_another_tenants_or_an_out_of_scope_surface() {
    let mut admin_client = None;
    let h = GatewayHarness::start(|_, _, bootstrap| {
        admin_client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = AdminApi::new(admin_client.expect("admin client"), &h);
    let (status, created) = admin
        .post(
            "surfaces",
            &json!({
                "name": "tenant-checks", "status": "active", "tenant_id": "tenant-a",
                "access_point": {"listen_address": listener_origin(&h), "route": "/tenant-checks", "protocol": "a2a"},
                "target": {"endpoint": "https://agent.example.invalid/a2a"}
            }),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["tenant_id"], "tenant-a");
    let surface_id = created["surface_id"]
        .as_str()
        .expect("surface_id")
        .to_string();
    let path = format!("surfaces/{surface_id}/declarations");
    let own_surface = format!("TENANT:${{x-external-account}}:surfaces:{}", regex::escape(&surface_id));

    let owner = admin
        .tenant_pat("tenant-a", &own_surface)
        .await;
    let (status, read) = admin
        .get_as_tenant(&path, &owner, "tenant-a")
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["declarations"][0]["variant"], Value::Null, "{read}");
    assert_eq!(read["declarations"][0]["outcome"], "pass_through", "{read}");

    let other_tenant = admin
        .tenant_pat("tenant-b", "TENANT:${x-external-account}:surfaces:.*")
        .await;
    let out_of_scope = admin
        .tenant_pat("tenant-a", "TENANT:${x-external-account}:surfaces:other-.*")
        .await;
    for (secret, tenant, label) in
        [(&other_tenant, "tenant-b", "another tenant"), (&out_of_scope, "tenant-a", "out of scope")]
    {
        let (status, body) = admin
            .get_as_tenant(&path, secret, tenant)
            .await;
        assert_eq!(status, 404, "{label}: {body}");
        assert!(
            body.get("declarations")
                .is_none()
                && body.get("warnings").is_none(),
            "{label}: {body}"
        );
    }
}

/// An A2A surface on `route` whose JWT Bearer method uses `strategy_id`. With
/// `declares` it sets `protected_resource` for the route.
fn configured_surface(
    surface_id: &str,
    route: &str,
    strategy_id: &str,
    declares: bool,
) -> crate::config::agent_surface::AgentSurface {
    let resource = format!("{PUBLIC_ORIGIN}{route}");
    let mut caller_authentication = json!({"methods": [{"type": "jwt_bearer",
        "jwt_verification_strategy_id": strategy_id, "audiences": [&resource], "required_scopes": [REQUIRED_SCOPE]}]});
    if declares {
        caller_authentication["methods"][0]["audiences"] = json!([]);
        caller_authentication["protected_resource"] = json!({"resource": resource});
    }
    serde_json::from_value(json!({
        "surface_id": surface_id, "name": surface_id, "status": "active",
        "access_point": {"listen_address": "inbound_port_placeholder", "route": route, "protocol": "a2a",
            "caller_authentication": caller_authentication},
        "target": {"endpoint": "inbound_target_placeholder"}
    }))
    .expect("surface JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_of_a_surface_whose_strategy_was_deleted_gets_a_500_that_names_no_strategy() {
    let mut admin_client = None;
    let h = GatewayHarness::start(|temp_dir, config, bootstrap| {
        advertise_public_origin(bootstrap);
        write_strategy(temp_dir, ISSUER, true);
        admin_client = Some(configure_admin_api(bootstrap));
        config.surfaces = vec![
            configured_surface("deleted-strategy-surface", "/smoke/deleted", DELETED_STRATEGY, false),
            configured_surface("present-strategy-surface", "/smoke/present", STRATEGY_ID, true),
        ];
    })
    .await;
    let admin = AdminApi::new(admin_client.expect("admin client"), &h);
    let message = json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": {"message": {"role": "user", "kind": "message", "messageId": "m-1",
            "parts": [{"kind": "text", "text": "hi"}]}}
    });
    let call = |route: &str| {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .post(format!("{}{route}", h.gateway_base))
            .header("content-type", "application/json")
            .bearer_auth("a-token-the-gateway-cannot-check")
            .body(message.to_string())
            .send()
    };

    let response = call("/smoke/deleted")
        .await
        .expect("caller request");
    assert_eq!(response.status().as_u16(), 500);
    let headers = format!("{:?}", response.headers());
    let text = response
        .text()
        .await
        .expect("body");
    assert!(!text.contains(DELETED_STRATEGY), "the body names the strategy: {text}");
    assert!(!headers.contains(DELETED_STRATEGY), "a header names the strategy: {headers}");
    let body: Value = serde_json::from_str(&text).expect("problem JSON");
    assert_eq!(body["status"], 500);
    assert_eq!(body["detail"], crate::source_auth::errors::CONFIG_NOT_FOUND_DETAIL);
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refused caller did not reach the target"
    );

    let present = call("/smoke/present")
        .await
        .expect("caller request");
    assert_eq!(present.status().as_u16(), 401, "a strategy that exists checks the token as the caller's fault");

    let route = "/smoke/strategy-gone";
    let resource = format!("{PUBLIC_ORIGIN}{route}");
    let (status, created) = admin
        .post("surfaces", &surface_on(&h, route, "a2a", jwt_bearer_caller_authentication(Some(&resource))))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["declarations"][0]["outcome"], "declare", "{created}");
    let surface_id = created["surface_id"]
        .as_str()
        .expect("surface id");
    let (status, deleted) = admin
        .body_of(
            admin
                .client
                .delete(admin.url(&format!("jwt-verification-strategies/{STRATEGY_ID}"))),
        )
        .await;
    assert_eq!(status, 204, "{deleted}");

    let (status, read) = admin
        .get(&format!("surfaces/{surface_id}/declarations"))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(
        read["declarations"],
        json!([{"variant": null, "outcome": "unservable", "reason": "strategy_unavailable", "resource": resource,
            "authorization_servers": [], "required_scopes": [], "scopes_supported": [], "metadata_url": null}])
    );

    let gone = call(route)
        .await
        .expect("caller request");
    assert_eq!(gone.status().as_u16(), 503, "a declaring Access Point whose strategy is gone fails closed");
    assert!(
        gone.headers()
            .get("www-authenticate")
            .is_none(),
        "an unservable declaration challenges no caller"
    );
    let text = gone
        .text()
        .await
        .expect("body");
    assert!(!text.contains(STRATEGY_ID), "the body names the strategy: {text}");
    let body: Value = serde_json::from_str(&text).expect("problem JSON");
    assert_eq!(body["detail"], "Caller authentication unavailable");
}
