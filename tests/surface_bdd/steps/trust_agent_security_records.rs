use cucumber::{given, then, when};
use reqwest::header;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::recorded_response;
use crate::steps::policy_changes::{client, user_id};
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

const TENANT_HEADER: &str = "x-external-account";

fn connection_id(
    world: &SurfaceWorld,
    name: &str,
) -> String {
    world
        .trust_agent_connections
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no trust agent connection named {name} was created"))
}

/// Sends the revoke with a personal access token of `tenant`, limited to the tenant's trust
/// agent connections.
async fn revoke_with_tenant_token(
    world: &mut SurfaceWorld,
    tenant: &str,
    name: &str,
) {
    ensure_admin_session(world).await;
    let request = json!({
        "name": "tenant trust agent token",
        "scopes": [],
        "resource_pattern": "TENANT:${x-external-account}:vta-connections:.*",
        "required_headers": [{"name": TENANT_HEADER, "pattern": tenant}],
    });
    let mut headers = header::HeaderMap::new();
    headers.insert(TENANT_HEADER, header::HeaderValue::from_str(tenant).expect("a tenant header"));
    let token_client = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .personal_access_token_client(&request, headers)
        .await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let path = format!("/v1/vta/connections/{}/revoke", connection_id(world, name));
    let response = token_client
        .post(format!("http://127.0.0.1:{port}/api{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("sending {path}: {error}"));
    world.admin_response = Some(
        recorded_response(response)
            .await
            .unwrap_or_else(|error| panic!("sending {path}: {error}")),
    );
}

#[when(expr = "a token of tenant {string} revokes the trust agent connection {string}")]
async fn tenant_token_revokes_connection(
    world: &mut SurfaceWorld,
    tenant: String,
    name: String,
) {
    revoke_with_tenant_token(world, &tenant, &name).await;
}

#[given(expr = "a token of tenant {string} has been refused revoking the trust agent connection {string}")]
async fn tenant_token_was_refused_revoking_connection(
    world: &mut SurfaceWorld,
    tenant: String,
    name: String,
) {
    revoke_with_tenant_token(world, &tenant, &name).await;
    let refused = world
        .admin_response
        .take()
        .expect("the gateway must have answered the revoke");
    assert_eq!(refused.status, 403, "the tenant token's revoke: {}", refused.body);
}

/// Waits for a VP Audit Log record of `category` that `matches`, and returns it.
async fn security_record(
    world: &mut SurfaceWorld,
    category: &str,
    matches: impl Fn(&Value) -> bool,
) -> Value {
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let details = &record["event"][category];
            details.is_object() && matches(details)
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a {category} record, got {events:?}");
    let record = events
        .iter()
        .map(|record| record["event"][category].clone())
        .find(|details| details.is_object() && matches(details))
        .expect("the matching record");
    for field in ["prev_hash", "record_hash"] {
        assert!(
            record[field]
                .as_str()
                .is_some_and(|hash| !hash.is_empty()),
            "{category} carries {field}: {record}"
        );
    }
    assert!(
        record["seq"]
            .as_u64()
            .is_some_and(|seq| seq > 0),
        "{category} carries its seq: {record}"
    );
    record
}

async fn refusal_record(
    world: &mut SurfaceWorld,
    name: &str,
) -> Value {
    let id = connection_id(world, name);
    security_record(world, "trust_agent_change_refused", |refused| {
        refused["action"] == "revoke_connection"
            && refused["connection_id"] == id.as_str()
            && refused["status"] == 403
            && refused["reason"] == "forbidden"
            && refused["actor"]["kind"] == "pat"
    })
    .await
}

async fn revoke_record(
    world: &mut SurfaceWorld,
    name: &str,
) -> Value {
    let id = connection_id(world, name);
    let actor = json!({ "kind": "user", "id": user_id(world, None).await });
    security_record(world, "trust_agent_connection_revoked", |revoked| {
        revoked["actor"] == actor && revoked["connection_id"] == id.as_str() && revoked["state"] == "revoked"
    })
    .await
}

#[then(expr = "the VP Audit Log records that a tenant token was refused revoking the trust agent connection {string}")]
async fn audit_log_records_refused_revoke(
    world: &mut SurfaceWorld,
    name: String,
) {
    refusal_record(world, &name).await;
}

#[then(expr = "the VP Audit Log records that the operator revoked the trust agent connection {string}")]
async fn audit_log_records_revoke(
    world: &mut SurfaceWorld,
    name: String,
) {
    revoke_record(world, &name).await;
}

#[then("the operator's revoke record follows the refusal record in the security record chain")]
async fn revoke_follows_refusal_in_chain(world: &mut SurfaceWorld) {
    let refused = refusal_record(world, "shared-agent").await;
    let revoked = revoke_record(world, "shared-agent").await;
    assert_eq!(revoked["prev_hash"], refused["record_hash"], "refused {refused}, revoked {revoked}");
    assert_eq!(
        revoked["seq"].as_u64(),
        refused["seq"]
            .as_u64()
            .map(|seq| seq + 1),
        "refused {refused}, revoked {revoked}"
    );
}
