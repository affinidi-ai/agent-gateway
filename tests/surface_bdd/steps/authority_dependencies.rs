use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::steps::credential_references::{delete_with_scoped_token, references};
use crate::steps::credential_save::{send, surface_id};
use crate::steps::given::{authority_list, create_unconnected_trust_registry};
use crate::steps::policy_changes::{client, user_id};
use crate::steps::when::build_primary_target_surface_payload;
use crate::world::SurfaceWorld;

async fn stored_authorities(world: &mut SurfaceWorld) -> Vec<Value> {
    let response = send(world, Method::GET, "/v1/authorities", None).await;
    assert_eq!(response.status, 200, "listing Authorities: {}", response.body);
    response
        .body
        .as_array()
        .expect("the Authority list is an array")
        .clone()
}

async fn authority(
    world: &mut SurfaceWorld,
    name: &str,
) -> Option<Value> {
    stored_authorities(world)
        .await
        .into_iter()
        .find(|authority| authority["name"] == name)
}

async fn authority_id(
    world: &mut SurfaceWorld,
    name: &str,
) -> String {
    authority(world, name)
        .await
        .and_then(|authority| {
            authority["id"]
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_else(|| panic!("no Authority {name} is stored"))
}

async fn create_surface(
    world: &mut SurfaceWorld,
    route: &str,
    configure: impl FnOnce(&mut Value, &str),
) {
    let trust_registry_id = create_unconnected_trust_registry(world).await;
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    configure(&mut payload, &trust_registry_id);
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    world.surface_under_test_id = response.body["surface_id"]
        .as_str()
        .map(str::to_string);
    world.admin_response = Some(response);
}

async fn create_surface_with_trust_check(
    world: &mut SurfaceWorld,
    route: &str,
    check_id: &str,
    did: &str,
) {
    create_surface(world, route, |payload, trust_registry_id| {
        payload["access_point"]["trust_check_list"] = json!([{
            "id": check_id, "trust_registry_id": trust_registry_id, "query_type": "recognition",
            "query": {"authority_id": did, "entity_id": "{{ input.agent.did }}"}
        }]);
    })
    .await;
}

async fn delete_authority(
    world: &mut SurfaceWorld,
    name: &str,
    force: bool,
) {
    let id = authority_id(world, name).await;
    let query = if force {
        "?force=true"
    } else {
        ""
    };
    let response = send(world, Method::DELETE, &format!("/v1/authorities/{id}{query}"), None).await;
    world.admin_response = Some(response);
}

fn refusal(world: &SurfaceWorld) -> &Value {
    &world
        .admin_response
        .as_ref()
        .expect("the operator must have been answered")
        .body
}

fn uses_of_surface_under_test(world: &SurfaceWorld) -> Vec<Value> {
    let surface = surface_id(world);
    refusal(world)["references"]
        .as_array()
        .unwrap_or_else(|| panic!("the refusal lists no references: {}", refusal(world)))
        .iter()
        .find(|reference| reference["kind"] == "surface" && reference["id"] == surface.as_str())
        .and_then(|reference| reference["uses"].as_array())
        .unwrap_or_else(|| panic!("the refusal lists no uses of surface {surface}: {}", refusal(world)))
        .clone()
}

async fn stored_trust_check(
    world: &mut SurfaceWorld,
    check_id: &str,
) -> Value {
    let id = surface_id(world);
    let response = send(world, Method::GET, &format!("/v1/surfaces/{id}"), None).await;
    assert_eq!(response.status, 200, "reading surface {id}: {}", response.body);
    let surface = response.body;
    surface["access_point"]["trust_check_list"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["id"] == check_id)
                .cloned()
        })
        .unwrap_or_else(|| panic!("surface {id} stores no Trust Check {check_id}: {surface}"))
}

#[given(expr = "the operator has created the Authority {string} with DID {string}")]
async fn operator_has_created_authority(
    world: &mut SurfaceWorld,
    name: String,
    did: String,
) {
    let body = json!({"name": name, "did": did});
    let response = send(world, Method::POST, "/v1/authorities", Some(&body)).await;
    assert_eq!(response.status, 201, "creating Authority {name}: {}", response.body);
}

#[given(
    expr = "the operator has created the surface for route {string} with a caller-leg Trust Check {string} against DID {string}"
)]
async fn operator_has_created_surface_with_trust_check(
    world: &mut SurfaceWorld,
    route: String,
    check_id: String,
    did: String,
) {
    create_surface_with_trust_check(world, &route, &check_id, &did).await;
    let response = world
        .admin_response
        .take()
        .expect("the surface create was answered");
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
}

#[given(
    expr = "the operator has created the surface for route {string} whose Trust Recorder takes DID {string} as its authority"
)]
async fn operator_has_created_surface_with_trust_recorder(
    world: &mut SurfaceWorld,
    route: String,
    did: String,
) {
    create_surface(world, &route, |payload, trust_registry_id| {
        payload["access_point"]["trust_recorder"] = json!({"entries": [{
            "trust_registry_id": trust_registry_id, "issuer_did": "did:web:example.com:issuer",
            "authority_did": did, "include_owned_agent": true
        }]});
    })
    .await;
    let response = world
        .admin_response
        .take()
        .expect("the surface create was answered");
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
}

#[given(expr = "the operator has deleted the Authority {string} with force")]
async fn operator_has_force_deleted_authority(
    world: &mut SurfaceWorld,
    name: String,
) {
    delete_authority(world, &name, true).await;
    let response = world
        .admin_response
        .take()
        .expect("the delete was answered");
    assert_eq!(response.status, 204, "force-deleting Authority {name}: {}", response.body);
}

#[when(
    expr = "the operator creates the surface for route {string} with a caller-leg Trust Check {string} against DID {string}"
)]
async fn operator_creates_surface_with_trust_check(
    world: &mut SurfaceWorld,
    route: String,
    check_id: String,
    did: String,
) {
    create_surface_with_trust_check(world, &route, &check_id, &did).await;
}

async fn create_surface_with_trust_check_query(
    world: &mut SurfaceWorld,
    route: &str,
    query: Value,
) {
    create_surface_with_trust_check_element(world, route, json!({ "query": query })).await;
}

async fn create_surface_with_trust_check_element(
    world: &mut SurfaceWorld,
    route: &str,
    fields: Value,
) {
    create_surface(world, route, |payload, trust_registry_id| {
        let mut element = json!({
            "id": "fi-recognised", "trust_registry_id": trust_registry_id, "query_type": "recognition"
        });
        for (key, value) in fields
            .as_object()
            .expect("the Trust Check fields are an object")
        {
            element[key] = value.clone();
        }
        payload["access_point"]["trust_check_list"] = json!([element]);
    })
    .await;
}

#[when(
    expr = "the operator creates the surface for route {string} with a caller-leg Trust Check listing authorities {string} and a timeout of {int} seconds"
)]
async fn operator_creates_surface_with_authority_list_and_timeout(
    world: &mut SurfaceWorld,
    route: String,
    authorities: String,
    timeout_secs: u32,
) {
    let fields = json!({
        "query": {"authority_ids": authority_list(&authorities), "entity_id": "{{ input.agent.did }}"},
        "timeout_secs": timeout_secs
    });
    create_surface_with_trust_check_element(world, &route, fields).await;
}

#[when(
    expr = "the operator creates the surface for route {string} with a caller-leg Trust Check listing authorities {string}"
)]
async fn operator_creates_surface_with_authority_list(
    world: &mut SurfaceWorld,
    route: String,
    authorities: String,
) {
    let query = json!({"authority_ids": authority_list(&authorities), "entity_id": "{{ input.agent.did }}"});
    create_surface_with_trust_check_query(world, &route, query).await;
}

#[when(
    expr = "the operator creates the surface for route {string} with a caller-leg Trust Check against DID {string} that also lists authorities {string}"
)]
async fn operator_creates_surface_with_authority_and_list(
    world: &mut SurfaceWorld,
    route: String,
    did: String,
    authorities: String,
) {
    let query = json!({
        "authority_id": did, "authority_ids": authority_list(&authorities), "entity_id": "{{ input.agent.did }}"
    });
    create_surface_with_trust_check_query(world, &route, query).await;
}

#[then(expr = "the stored Trust Check {string} of the surface under test lists authorities {string}")]
async fn stored_trust_check_lists_authorities(
    world: &mut SurfaceWorld,
    check_id: String,
    authorities: String,
) {
    let check = stored_trust_check(world, &check_id).await;
    assert_eq!(check["query"]["authority_ids"], json!(authority_list(&authorities)), "stored Trust Check: {check}");
    assert!(
        check["query"]
            .get("authority_id")
            .is_none(),
        "stored Trust Check: {check}"
    );
}

#[when(expr = "the operator deletes the Authority {string}")]
async fn operator_deletes_authority(
    world: &mut SurfaceWorld,
    name: String,
) {
    delete_authority(world, &name, false).await;
}

#[when(expr = "the operator deletes the Authority {string} with force")]
async fn operator_force_deletes_authority(
    world: &mut SurfaceWorld,
    name: String,
) {
    delete_authority(world, &name, true).await;
}

async fn restricted_token_deletes_authority(
    world: &mut SurfaceWorld,
    name: &str,
    query: &str,
) {
    let id = authority_id(world, name).await;
    let scopes = ["authorities.view", "authorities.delete"];
    let path = format!("/api/v1/authorities/{id}{query}");
    world.admin_response = Some(delete_with_scoped_token(world, &scopes, &path).await);
}

#[when(expr = "an access token that may delete Authorities but not view surfaces deletes the Authority {string}")]
async fn restricted_token_deletes_authority_without_force(
    world: &mut SurfaceWorld,
    name: String,
) {
    restricted_token_deletes_authority(world, &name, "").await;
}

#[when(
    expr = "an access token that may delete Authorities but not view surfaces deletes the Authority {string} with force"
)]
async fn restricted_token_force_deletes_authority(
    world: &mut SurfaceWorld,
    name: String,
) {
    restricted_token_deletes_authority(world, &name, "?force=true").await;
}

#[given(expr = "the operator has created the managed connection {string} with a Trust Check against DID {string}")]
async fn operator_has_created_sts_client_with_trust_check(
    world: &mut SurfaceWorld,
    client_id: String,
    did: String,
) {
    let body = json!({
        "client_id": client_id, "name": client_id,
        "trust_check_list": [{
            "id": "sts-check", "trust_registry_id": "bdd-registry", "query_type": "recognition",
            "query": {"authority_id": did, "entity_id": "{{ input.sts.client_id }}"}
        }]
    });
    let response = send(world, Method::POST, "/v1/sts/clients", Some(&body)).await;
    assert_eq!(response.status, 201, "creating STS client {client_id}: {}", response.body);
}

#[when("the operator renames the surface under test")]
async fn operator_renames_surface(world: &mut SurfaceWorld) {
    let id = surface_id(world);
    let stored = send(world, Method::GET, &format!("/v1/surfaces/{id}"), None).await;
    assert_eq!(stored.status, 200, "reading surface {id}: {}", stored.body);
    let mut surface = stored.body;
    for derived in ["access_point_status", "api_key_references", "serving_status"] {
        surface
            .as_object_mut()
            .expect("the surface is an object")
            .remove(derived);
    }
    surface["name"] = json!("renamed");
    let response = send(world, Method::PUT, &format!("/v1/surfaces/{id}"), Some(&surface)).await;
    world.admin_response = Some(response);
}

#[then(expr = "the refusal says Trust Check {string} of the surface under test uses the Authority")]
fn refusal_names_trust_check(
    world: &mut SurfaceWorld,
    check_id: String,
) {
    let uses = uses_of_surface_under_test(world);
    assert!(
        uses.iter()
            .any(|used| used["element"] == "trust_check" && used["id"] == check_id.as_str()),
        "expected Trust Check {check_id} among {uses:?}"
    );
}

#[then("the refusal says a Trust Recorder entry of the surface under test uses the Authority")]
fn refusal_names_trust_recorder_entry(world: &mut SurfaceWorld) {
    let uses = uses_of_surface_under_test(world);
    assert!(
        uses.iter()
            .any(|used| used["element"] == "trust_recorder"),
        "expected a Trust Recorder entry among {uses:?}"
    );
}

#[then(expr = "the Authority {string} is stored")]
async fn authority_is_stored(
    world: &mut SurfaceWorld,
    name: String,
) {
    assert!(
        authority(world, &name)
            .await
            .is_some(),
        "Authority {name} is not stored"
    );
}

#[then(expr = "no Authority {string} is stored")]
async fn authority_is_not_stored(
    world: &mut SurfaceWorld,
    name: String,
) {
    assert!(
        authority(world, &name)
            .await
            .is_none(),
        "Authority {name} is still stored"
    );
}

#[then(
    expr = "the stored Trust Check {string} of the surface under test takes its authority from the Authorities register"
)]
async fn stored_trust_check_takes_authority_from_register(
    world: &mut SurfaceWorld,
    check_id: String,
) {
    let check = stored_trust_check(world, &check_id).await;
    assert_eq!(check["authority_source"], "authority", "{check}");
}

#[then(expr = "the stored Trust Check {string} of the surface under test is not linked to any register")]
async fn stored_trust_check_is_not_linked(
    world: &mut SurfaceWorld,
    check_id: String,
) {
    let check = stored_trust_check(world, &check_id).await;
    assert!(
        check
            .get("authority_source")
            .is_none(),
        "{check}"
    );
}

#[then(expr = "the refusal names the managed connection {string} as a record that uses it")]
async fn refusal_names_sts_client(
    world: &mut SurfaceWorld,
    client_id: String,
) {
    let refusal = world
        .admin_response
        .take()
        .expect("the operator must have been answered");
    let clients = send(world, Method::GET, "/v1/sts/clients", None).await;
    world.admin_response = Some(refusal);
    assert_eq!(clients.status, 200, "listing STS clients: {}", clients.body);
    let id = clients
        .body
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|client| client["client_id"] == client_id.as_str())
        })
        .and_then(|client| client["id"].as_str())
        .unwrap_or_else(|| panic!("no STS client {client_id} is stored: {}", clients.body))
        .to_string();
    let expected = ("sts_client".to_string(), id);
    let listed = references(world);
    assert!(listed.contains(&expected), "expected {expected:?} among {listed:?}");
}

#[then(
    expr = "the VP Audit Log records that the operator force-deleted the Authority with DID {string} the surface still used"
)]
async fn audit_log_records_authority_force_deleted(
    world: &mut SurfaceWorld,
    did: String,
) {
    let actor = json!({ "kind": "user", "id": user_id(world, None).await });
    let referrers = json!([{ "kind": "surface", "id": surface_id(world) }]);
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let deleted = &record["event"]["authority_force_deleted"];
            deleted["actor"] == actor
                && deleted["did"] == did.as_str()
                && deleted["force"] == true
                && deleted["referrers"] == referrers
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected an authority_force_deleted record by {actor}, got {events:?}");
}
