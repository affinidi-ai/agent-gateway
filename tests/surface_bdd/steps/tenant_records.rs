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

/// What a personal access token the operator mints for a read limits it to.
#[derive(Clone, Copy)]
enum TokenScope<'a> {
    /// A tenant's token: a resource pattern naming the tenant its selector
    /// header names.
    Tenant(&'a str),
    /// A token that requires the tenant selector header but has no resource
    /// pattern.
    RequiredHeadersAlone(&'a str),
    /// A token with neither a resource pattern nor a required header.
    ApplianceWide,
}

/// The tenant whose selector header a token scoped by required headers alone
/// requires.
const HEADER_TENANT: &str = "tenant-a";

/// A client sending a personal access token the operator minted with
/// `scope`, and the selector header the token requires.
async fn token_client(
    world: &mut SurfaceWorld,
    scope: TokenScope<'_>,
) -> Client {
    ensure_admin_session(world).await;
    let (resource_pattern, tenant) = match scope {
        TokenScope::Tenant(tenant) => (Some("TENANT:${x-external-account}:credential-providers:.*"), Some(tenant)),
        TokenScope::RequiredHeadersAlone(tenant) => (None, Some(tenant)),
        TokenScope::ApplianceWide => (None, None),
    };
    let required_headers: Vec<Value> = tenant
        .iter()
        .map(|tenant| json!({"name": TENANT_HEADER, "pattern": tenant}))
        .collect();
    let request = json!({
        "name": "tenant records token",
        "scopes": [],
        "resource_pattern": resource_pattern,
        "required_headers": required_headers,
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
    if let Some(tenant) = tenant {
        headers.insert(TENANT_HEADER, header::HeaderValue::from_str(tenant).expect("a tenant header"));
    }
    Client::builder()
        .no_proxy()
        .default_headers(headers)
        .build()
        .expect("an HTTP client")
}

/// Sends `method path` with a token of `scope` and records the answer.
async fn send_with_token(
    world: &mut SurfaceWorld,
    scope: TokenScope<'_>,
    method: Method,
    path: &str,
) {
    let client = token_client(world, scope).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let response = client
        .request(method, format!("http://127.0.0.1:{port}/api{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("sending {path}: {error}"));
    world.admin_response = Some(
        recorded_response(response)
            .await
            .unwrap_or_else(|error| panic!("sending {path}: {error}")),
    );
}

async fn read_as_tenant(
    world: &mut SurfaceWorld,
    tenant: &str,
    path: &str,
) {
    send_with_token(world, TokenScope::Tenant(tenant), Method::GET, path).await;
}

/// Creates the credential provider `provider` of `tenant`, or an
/// appliance-wide one, with client secrets of the same tenant, and keeps its
/// id under `provider`.
async fn own_credential_provider(
    world: &mut SurfaceWorld,
    tenant: Option<&str>,
    provider: &str,
) {
    let client_id = format!("{provider}-client-id");
    let client_secret = format!("{provider}-client-secret");
    create_secret(world, &client_id, tenant).await;
    create_secret(world, &client_secret, tenant).await;
    create_provider(world, provider, "https://192.0.2.1/token", tenant, (&client_id, &client_secret)).await;
    let created = world
        .admin_response
        .take()
        .expect("the gateway must have answered the provider create");
    assert_eq!(created.status, 201, "creating credential provider {provider}: {}", created.body);
    assert_eq!(created.body["tenant_id"], json!(tenant), "{}", created.body);
    let id = created.body["id"]
        .as_str()
        .expect("a created provider has an id")
        .to_string();
    world
        .credential_provider_ids
        .insert(provider.to_string(), id);
}

#[given(expr = "tenant {string} owns the credential provider {string}")]
async fn tenant_owns_credential_provider(
    world: &mut SurfaceWorld,
    tenant: String,
    provider: String,
) {
    own_credential_provider(world, Some(&tenant), &provider).await;
}

#[given(expr = "the appliance-wide credential provider {string} exists")]
async fn appliance_wide_credential_provider_exists(
    world: &mut SurfaceWorld,
    provider: String,
) {
    own_credential_provider(world, None, &provider).await;
}

#[given(expr = "a token of tenant {string} has tried to revoke the vault token of credential provider {string}")]
async fn tenant_has_tried_to_revoke_vault_token(
    world: &mut SurfaceWorld,
    tenant: String,
    provider: String,
) {
    revoke_vault_token(world, TokenScope::Tenant(&tenant), &provider).await;
}

async fn revoke_vault_token(
    world: &mut SurfaceWorld,
    scope: TokenScope<'_>,
    provider: &str,
) {
    let path = format!("/v1/delegation-vault/{}", vault_token_id(provider));
    send_with_token(world, scope, Method::DELETE, &path).await;
}

/// Revokes every vault token the user of the seeded tokens granted.
async fn revoke_user_tokens(
    world: &mut SurfaceWorld,
    scope: TokenScope<'_>,
) {
    send_with_token(world, scope, Method::DELETE, &format!("/v1/delegation-vault/by-user/{USER}")).await;
}

#[given(
    expr = "an access token scoped by required headers alone has tried to revoke the vault token of credential provider {string}"
)]
async fn header_scoped_token_has_tried_to_revoke_vault_token(
    world: &mut SurfaceWorld,
    provider: String,
) {
    revoke_vault_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), &provider).await;
}

#[given("an access token scoped by required headers alone has tried to revoke every vault token the user granted")]
async fn header_scoped_token_has_tried_to_revoke_user_tokens(world: &mut SurfaceWorld) {
    revoke_user_tokens(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT)).await;
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

/// The record id of the surface's delegated OAuth provider, whose slug is
/// `provider`.
fn delegated_provider_record_id(
    world: &SurfaceWorld,
    provider: &str,
) -> String {
    let delegation = world
        .surface_config
        .credential_delegation
        .as_ref()
        .expect("the surface requires delegated credentials");
    assert_eq!(delegation.provider_id, provider, "the surface's delegated provider");
    delegation
        .record_id()
        .to_string()
}

/// Audit records reach the log shortly after the request that produced them,
/// so this reads the operator's view of the Credential Delegation Audit Log
/// again until it holds a `consent_granted` naming the provider's record id,
/// for up to five seconds.
#[given(expr = "the Credential Delegation Audit Log holds the consent granted for OAuth provider {string}")]
async fn audit_log_holds_consent_granted(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let id = delegated_provider_record_id(world, &provider);
    ensure_admin_session(world).await;
    let client = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist");
    let mut page = Value::Null;
    for _ in 0..50 {
        page = client
            .send_recorded_json::<Value>(Method::GET, "/v1/delegation-audit?page_size=100", None)
            .await
            .expect("reading the Credential Delegation Audit Log")
            .body;
        let consents = page["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["event"] == "consent_granted" && event["provider_id"] == id.as_str())
            .count();
        if consents > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no consent granted for OAuth provider {provider} ({id}) reached the audit log: {page}");
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

#[when(expr = "a token of tenant {string} reads a vault token that does not exist")]
async fn tenant_reads_missing_vault_token(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    read_as_tenant(world, &tenant, "/v1/delegation-vault/no-such-token").await;
}

#[when(expr = "a token of tenant {string} revokes the vault token of credential provider {string}")]
async fn tenant_revokes_vault_token(
    world: &mut SurfaceWorld,
    tenant: String,
    provider: String,
) {
    revoke_vault_token(world, TokenScope::Tenant(&tenant), &provider).await;
}

#[when(expr = "a token of tenant {string} revokes every vault token the user granted")]
async fn tenant_revokes_user_tokens(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    revoke_user_tokens(world, TokenScope::Tenant(&tenant)).await;
}

#[when(
    expr = "an access token scoped by required headers alone revokes the vault token of credential provider {string}"
)]
async fn header_scoped_token_revokes_vault_token(
    world: &mut SurfaceWorld,
    provider: String,
) {
    revoke_vault_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), &provider).await;
}

#[when("an access token scoped by required headers alone revokes every vault token the user granted")]
async fn header_scoped_token_revokes_user_tokens(world: &mut SurfaceWorld) {
    revoke_user_tokens(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT)).await;
}

#[when("an access token scoped by required headers alone lists the delegation vault")]
async fn header_scoped_token_lists_delegation_vault(world: &mut SurfaceWorld) {
    send_with_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), Method::GET, "/v1/delegation-vault").await;
}

#[when(expr = "an access token scoped by required headers alone reads the vault token of credential provider {string}")]
async fn header_scoped_token_reads_vault_token(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let path = format!("/v1/delegation-vault/{}", vault_token_id(&provider));
    send_with_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), Method::GET, &path).await;
}

#[when("an access token scoped by required headers alone reads the Credential Delegation Audit Log")]
async fn header_scoped_token_reads_credential_delegation_audit_log(world: &mut SurfaceWorld) {
    let path = "/v1/delegation-audit?page_size=100";
    send_with_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), Method::GET, path).await;
}

#[when(expr = "a token of tenant {string} downloads the server logs")]
async fn tenant_downloads_server_logs(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    send_with_token(world, TokenScope::Tenant(&tenant), Method::GET, "/v1/logs/download").await;
}

#[when("an access token scoped by required headers alone downloads the server logs")]
async fn header_scoped_token_downloads_server_logs(world: &mut SurfaceWorld) {
    send_with_token(world, TokenScope::RequiredHeadersAlone(HEADER_TENANT), Method::GET, "/v1/logs/download").await;
}

#[when("an appliance-wide access token lists the delegation vault")]
async fn appliance_wide_token_lists_delegation_vault(world: &mut SurfaceWorld) {
    send_with_token(world, TokenScope::ApplianceWide, Method::GET, "/v1/delegation-vault").await;
}

#[when(expr = "an appliance-wide access token reads the vault token of credential provider {string}")]
async fn appliance_wide_token_reads_vault_token(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let path = format!("/v1/delegation-vault/{}", vault_token_id(&provider));
    send_with_token(world, TokenScope::ApplianceWide, Method::GET, &path).await;
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

#[then(expr = "the audit read shows the consent granted for OAuth provider {string} of tenant {string}")]
fn audit_read_shows_consent_granted_for(
    world: &mut SurfaceWorld,
    provider: String,
    tenant: String,
) {
    let owner = world
        .surface_config
        .credential_delegation
        .as_ref()
        .and_then(|delegation| {
            delegation
                .tenant_id
                .as_deref()
        });
    assert_eq!(owner, Some(tenant.as_str()), "the tenant of the surface's delegated provider");
    let id = json!(delegated_provider_record_id(world, &provider));
    let (page, events) = audit_page(world);
    let consents: Vec<&Value> = events
        .iter()
        .filter(|event| event["event"] == "consent_granted")
        .map(|event| &event["provider_id"])
        .collect();
    assert_eq!(consents, [&id], "{page}");
    assert!(
        events
            .iter()
            .all(|event| event["provider_id"] == id),
        "a record of another provider: {page}"
    );
    assert_eq!(page["total"], json!(events.len()), "{page}");
}

#[then("the audit read shows no record")]
fn audit_read_shows_no_record(world: &mut SurfaceWorld) {
    let (page, events) = audit_page(world);
    assert!(events.is_empty(), "{page}");
    assert_eq!((&page["total"], &page["category_counts"]), (&json!(0), &json!({})), "{page}");
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

#[then("the vault list is empty")]
fn vault_list_is_empty(world: &mut SurfaceWorld) {
    assert_eq!(listed_vault_tokens(world), Vec::<(String, String)>::new());
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

#[then("the vault read answers that the vault token is not found")]
fn vault_read_answers_not_found(world: &mut SurfaceWorld) {
    let answer = answer(world);
    assert_eq!((answer.status, &answer.body), (404, &json!({"error": "Delegation token not found"})));
}
