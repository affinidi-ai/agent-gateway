//! Agent-keyed delegation vault tokens and delegation audit records of
//! credential providers that tenants own, read through the running gateway
//! with a tenant's personal access token or an operator's session.

use std::io::Write;
use std::path::PathBuf;

use cucumber::{given, then, when};
use reqwest::{Client, Method, header};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{RecordedResponse, recorded_response};
use crate::steps::credential_save::{create_provider, create_secret};
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

const TENANT_HEADER: &str = "x-external-account";
const AGENT_DID: &str = "did:web:agent.example";
const USER: &str = "sha256:bdd-user";
/// The user of the seeded revoke, the record that names no credential provider.
const REVOKED_USER: &str = "sha256:bdd-revoked-user";

fn provider_id(
    world: &SurfaceWorld,
    provider: &str,
) -> String {
    world
        .credential_provider_ids
        .get(provider)
        .cloned()
        .unwrap_or_else(|| panic!("credential provider {provider} must have been created"))
}

fn vault_token_id(provider: &str) -> String {
    format!("vault-token-of-{provider}")
}

fn storage(world: &SurfaceWorld) -> PathBuf {
    world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("_storage")
}

fn answer(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("the gateway must have answered a read")
}

/// A client sending a personal access token the operator minted for
/// `tenant`, and the tenant's selector header.
async fn tenant_token_client(
    world: &mut SurfaceWorld,
    tenant: &str,
) -> Client {
    ensure_admin_session(world).await;
    let request = json!({
        "name": "tenant records token",
        "scopes": [],
        "resource_pattern": "TENANT:${x-external-account}:credential-providers:.*",
        "required_headers": [{"name": TENANT_HEADER, "pattern": tenant}],
    });
    let created = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .send_recorded_json(Method::POST, "/v1/access-tokens", Some(&request))
        .await
        .expect("creating the access token");
    assert!(matches!(created.status, 200 | 201), "creating the access token: {}", created.body);
    let mut authorization = header::HeaderValue::from_str(&format!(
        "Bearer {}",
        created.body["token"]
            .as_str()
            .expect("the access token is returned once")
    ))
    .expect("a bearer header");
    authorization.set_sensitive(true);
    let mut headers = header::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, authorization);
    headers.insert(TENANT_HEADER, header::HeaderValue::from_str(tenant).expect("a tenant header"));
    Client::builder()
        .no_proxy()
        .default_headers(headers)
        .build()
        .expect("an HTTP client")
}

async fn read_as_tenant(
    world: &mut SurfaceWorld,
    tenant: &str,
    path: &str,
) {
    let client = tenant_token_client(world, tenant).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let response = client
        .get(format!("http://127.0.0.1:{port}/api{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("reading {path}: {error}"));
    world.admin_response = Some(
        recorded_response(response)
            .await
            .unwrap_or_else(|error| panic!("reading {path}: {error}")),
    );
}

#[given(expr = "tenant {string} owns the credential provider {string}")]
async fn tenant_owns_credential_provider(
    world: &mut SurfaceWorld,
    tenant: String,
    provider: String,
) {
    let client_id = format!("{provider}-client-id");
    let client_secret = format!("{provider}-client-secret");
    create_secret(world, &client_id, Some(&tenant)).await;
    create_secret(world, &client_secret, Some(&tenant)).await;
    create_provider(world, &provider, "https://192.0.2.1/token", Some(&tenant), (&client_id, &client_secret)).await;
    let created = world
        .admin_response
        .take()
        .expect("the gateway must have answered the provider create");
    assert_eq!(created.status, 201, "creating credential provider {provider}: {}", created.body);
    assert_eq!(created.body["tenant_id"], tenant.as_str(), "{}", created.body);
    let id = created.body["id"]
        .as_str()
        .expect("a created provider has an id")
        .to_string();
    world
        .credential_provider_ids
        .insert(provider, id);
}

/// The gateway rereads its VP Audit Log on every read, so records appended to
/// it are shown from the next read on.
#[given("the audit log holds a token injection of each credential provider and a revoke naming no provider")]
fn audit_log_holds_token_injections_and_a_revoke(world: &mut SurfaceWorld) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut records: Vec<Value> = world
        .credential_provider_ids
        .values()
        .map(|id| {
            json!({
                "timestamp": timestamp, "event": "token_injected", "agent_did": AGENT_DID,
                "user_identity_hash": USER, "provider_id": id,
            })
        })
        .collect();
    records.push(json!({
        "timestamp": timestamp, "event": "token_revoked", "agent_did": AGENT_DID,
        "user_identity_hash": REVOKED_USER,
    }));
    let lines: String = records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect();
    let directory = storage(world).join("audit");
    std::fs::create_dir_all(&directory).expect("the audit log directory");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("delegation-audit.jsonl"))
        .and_then(|mut log| log.write_all(lines.as_bytes()))
        .expect("appending to the VP Audit Log");
}

/// The vault is read from disk on every request.
#[given("the delegation vault holds a token of each credential provider")]
fn delegation_vault_holds_a_token_of_each_provider(world: &mut SurfaceWorld) {
    let directory = storage(world).join("delegation_vault");
    std::fs::create_dir_all(&directory).expect("the delegation vault directory");
    let now = chrono::Utc::now().to_rfc3339();
    for (provider, id) in &world.credential_provider_ids {
        let token = json!({
            "id": vault_token_id(provider), "agent_did": AGENT_DID, "user_identity_hash": USER,
            "credential_provider_id": id, "provider_id": provider, "access_token": "bdd-vault-access-token",
            "token_type": "Bearer", "scopes": ["calendar.read"],
            "consent_granted_at": now, "created_at": now, "updated_at": now,
        });
        std::fs::write(directory.join(format!("{}.json", vault_token_id(provider))), token.to_string())
            .expect("writing a delegation vault token");
    }
}

#[when(expr = "a token of tenant {string} reads the Credential Delegation Audit Log")]
async fn tenant_reads_credential_delegation_audit_log(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    read_as_tenant(world, &tenant, "/v1/delegation-audit?page_size=100").await;
}

#[when(expr = "a token of tenant {string} reads the VP Audit Log")]
async fn tenant_reads_vp_audit_log(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    read_as_tenant(world, &tenant, "/v1/audit?limit=100").await;
}

#[when(expr = "a token of tenant {string} lists the delegation vault")]
async fn tenant_lists_delegation_vault(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    read_as_tenant(world, &tenant, "/v1/delegation-vault").await;
}

#[when(expr = "a token of tenant {string} reads the vault token of credential provider {string}")]
async fn tenant_reads_vault_token(
    world: &mut SurfaceWorld,
    tenant: String,
    provider: String,
) {
    read_as_tenant(world, &tenant, &format!("/v1/delegation-vault/{}", vault_token_id(&provider))).await;
}

#[when("the operator lists the delegation vault")]
async fn operator_lists_delegation_vault(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .send_recorded_json::<Value>(Method::GET, "/v1/delegation-vault", None)
        .await
        .expect("listing the delegation vault");
    world.admin_response = Some(response);
}

fn audit_page(world: &SurfaceWorld) -> (&Value, &Vec<Value>) {
    let page = &answer(world).body;
    let events = page["events"]
        .as_array()
        .unwrap_or_else(|| panic!("an audit page, got {page}"));
    (page, events)
}

#[then(expr = "the audit read shows only the token injection of credential provider {string}")]
fn audit_read_shows_only_the_token_injection_of(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let id = provider_id(world, &provider);
    let (page, events) = audit_page(world);
    let shown: Vec<(&Value, &Value)> = events
        .iter()
        .map(|event| (&event["event"], &event["provider_id"]))
        .collect();
    assert_eq!(shown, [(&json!("token_injected"), &json!(id))], "{page}");
    assert_eq!((&page["total"], &page["total_pages"]), (&json!(1), &json!(1)), "{page}");
    assert_eq!(page["category_counts"], json!({"token_injected": 1}), "{page}");
}

#[then("the audit read shows the token injection of every credential provider and the revoke naming no provider")]
fn audit_read_shows_every_record(world: &mut SurfaceWorld) {
    let (page, events) = audit_page(world);
    for id in world
        .credential_provider_ids
        .values()
    {
        assert!(
            events
                .iter()
                .any(|event| event["event"] == "token_injected" && event["provider_id"] == id.as_str()),
            "no token injection of credential provider {id}: {page}"
        );
    }
    assert!(
        events.iter().any(|event| {
            event["event"] == "token_revoked"
                && event["user_identity_hash"] == REVOKED_USER
                && event
                    .get("provider_id")
                    .is_none()
        }),
        "no revoke naming no provider: {page}"
    );
    assert_eq!(page["total"], json!(events.len()), "{page}");
}

fn listed_vault_tokens(world: &SurfaceWorld) -> Vec<(String, String)> {
    let body = &answer(world).body;
    let mut tokens: Vec<(String, String)> = body
        .as_array()
        .unwrap_or_else(|| panic!("a vault token list, got {body}"))
        .iter()
        .map(|token| {
            (
                token["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                token["credential_provider_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    tokens.sort();
    tokens
}

#[then(expr = "the vault list shows only the token of credential provider {string}")]
fn vault_list_shows_only_the_token_of(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let expected = vec![(vault_token_id(&provider), provider_id(world, &provider))];
    assert_eq!(listed_vault_tokens(world), expected);
}

#[then("the vault list shows the token of every credential provider")]
fn vault_list_shows_every_token(world: &mut SurfaceWorld) {
    let mut expected: Vec<(String, String)> = world
        .credential_provider_ids
        .iter()
        .map(|(provider, id)| (vault_token_id(provider), id.clone()))
        .collect();
    expected.sort();
    assert_eq!(listed_vault_tokens(world), expected);
}

#[then(expr = "the vault read shows the token of credential provider {string}")]
fn vault_read_shows_the_token_of(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let id = provider_id(world, &provider);
    let token = &answer(world).body;
    assert_eq!(token["id"], vault_token_id(&provider).as_str(), "{token}");
    assert_eq!(token["credential_provider_id"], id.as_str(), "{token}");
    assert!(
        token
            .get("access_token")
            .is_none(),
        "the vault read shows the access token"
    );
}

#[then(expr = "the answer is the one a token of tenant {string} gets for a missing vault token")]
async fn answer_is_the_one_for_a_missing_vault_token(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let foreign = world
        .admin_response
        .take()
        .expect("the gateway must have answered a read");
    read_as_tenant(world, &tenant, "/v1/delegation-vault/no-such-token").await;
    let missing = answer(world);
    assert_eq!(missing.status, 404, "{}", missing.body);
    assert_eq!((foreign.status, &foreign.body), (missing.status, &missing.body));
}
