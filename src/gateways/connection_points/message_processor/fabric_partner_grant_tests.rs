//! A grant a person makes by connecting directly reaches the requests a
//! partner gateway sends for them over Fabric only on a view whose Target
//! releases it: looked up by the receiving surface and the caller that surface
//! verified, never by anything the partner sends, and never started through
//! the partner.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::fabric_transit_tests::{
    CALLER_KEY, JWT_AUDIENCE, PEER_CONNECTION_POINT_DID, PEER_ISSUER_DID, PER_USER_PROVIDER, SURFACE_ID, binding,
    forward_request, forward_response, header_values, naming, ran_in_child, receiver_trusting, refused, surface,
    test_issuer,
};
use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::component_tests::helpers::RecordingTarget;
use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::DelegationToken;
use crate::delegation_vault::audit::DelegationAuditAction;
use crate::delegation_vault::storage::DelegationVaultStorage;
use crate::gateways::GatewayStore;
use crate::gateways::connection_points::messages::ReceivedMessage;
use crate::jwt_bearer::storage::JwtVerificationStrategyStorage;
use crate::secrets::SecretsStore;
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const SECOND_PROVIDER: &str = "per-user-second";
const GATEWAY_BASE_URL: &str = "https://receiver.example";
const CALLBACK_URL: &str = "https://203.0.113.20/oauth/callback/per-user";

/// The rejection records of a refused request: stage, reason and `via_fabric`.
type Rejections = Vec<(RejectionStage, RejectionReason, bool)>;

/// The [`Rejections`] among captured audit `events`.
fn rejections(events: &[crate::delegation_vault::audit::DelegationAuditEvent]) -> Rejections {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected { stage, reason, .. } => Some((*stage, *reason, event.via_fabric)),
            _ => None,
        })
        .collect()
}

/// The answer's status, and the reason its body gives, of a forward response.
fn status_and_reason(response: &Value) -> (Value, Value) {
    let body: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or(Value::Null);
    (response["status"].clone(), body["reason"].clone())
}

/// An authorization server whose token endpoint exchanges the code `c` for the
/// access token `c-access` and the refresh token `c-refresh`, and refuses every
/// refresh with `invalid_grant`.
struct AuthorizationServer {
    token_endpoint: String,
    grant_types: Arc<Mutex<Vec<String>>>,
    _server: tokio::task::JoinHandle<()>,
}

impl AuthorizationServer {
    async fn start() -> Self {
        let grant_types = Arc::new(Mutex::new(Vec::new()));
        let recorded = grant_types.clone();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move |body: String| {
                let recorded = recorded.clone();
                async move {
                    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
                    let grant_type = form
                        .get("grant_type")
                        .cloned()
                        .unwrap_or_default();
                    recorded
                        .lock()
                        .unwrap()
                        .push(grant_type.clone());
                    match (grant_type.as_str(), form.get("code")) {
                        ("authorization_code", Some(code)) => (
                            axum::http::StatusCode::OK,
                            axum::Json(json!({ "access_token": format!("{code}-access"),
                                "refresh_token": format!("{code}-refresh"), "token_type": "Bearer",
                                "expires_in": 3600, "scope": "read" })),
                        ),
                        _ => (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant" }))),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        Self {
            token_endpoint,
            grant_types,
            _server: server,
        }
    }

    fn grant_types(&self) -> Vec<String> {
        self.grant_types
            .lock()
            .unwrap()
            .clone()
    }
}

fn identity_schema() -> Value {
    json!({ "type": "object", "properties": { "agentId": { "type": "string", "x-identity": true } },
        "required": ["agentId"] })
}

fn jwt_method(
    strategy: &str,
    audience: bool,
) -> Value {
    let audiences = if audience {
        vec![JWT_AUDIENCE]
    } else {
        Vec::new()
    };
    json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": strategy, "audiences": audiences })
}

/// The receiving surface: an A2A Access Point that verifies callers by a JWT
/// with an audience, through the verification strategy `strategy`, and
/// identifies the agent acting for them from the request body, whose Target,
/// at `target_url`, has a per-user binding and releases its grants to Fabric
/// callers when `releases`.
fn partner_surface(
    target_url: &str,
    strategy: &str,
    releases: bool,
) -> AgentSurface {
    let mut partner = surface("a2a", target_url, &[]);
    partner
        .access_point
        .caller_authentication =
        Some(serde_json::from_value(json!({ "methods": [jwt_method(strategy, true)] })).unwrap());
    partner.outbound_credentials = vec![binding(PER_USER_PROVIDER)];
    partner.identity_slots.inbound = Some(
        serde_json::from_value(
            json!({ "type": "payload_extraction", "meta_field": "agentIdentity", "json_schema": identity_schema() }),
        )
        .unwrap(),
    );
    partner
        .target
        .delegated_credentials_for_fabric_callers = releases;
    partner
}

/// The receiving gateway: its surface's Target behind a recording agent, the
/// identity provider whose tokens the surface verifies, an authorization
/// server, the delegation stores Fabric receive and the direct path share, and
/// the direct path's router.
struct Receiver {
    root: tempfile::TempDir,
    _peer_issuers: tempfile::TempDir,
    _identities: tempfile::TempDir,
    idp: JwksFixture,
    strategies: Arc<crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore>,
    strategy: String,
    target: RecordingTarget,
    authorization_server: AuthorizationServer,
    vault: Arc<dyn DelegationVaultStorage>,
    providers: Arc<dyn CredentialProviderStorage>,
    secrets: Arc<dyn SecretsStore>,
    direct: crate::state::MultiSurfaceProxyState,
}

impl Receiver {
    async fn start(releases: bool) -> Self {
        Self::start_with(|surface| {
            surface
                .target
                .delegated_credentials_for_fabric_callers = releases
        })
        .await
    }

    /// A receiving gateway serving [`partner_surface`], opted in, as `change`
    /// leaves it.
    async fn start_with(change: impl FnOnce(&mut AgentSurface)) -> Self {
        Self::start_trusting(change, Vec::new()).await
    }

    /// [`Self::start_with`], whose connection to the partner also trusts
    /// identity presentations from `trusted_issuers`.
    async fn start_trusting(
        change: impl FnOnce(&mut AgentSurface),
        trusted_issuers: Vec<String>,
    ) -> Self {
        Self::start_configured(change, trusted_issuers, None).await
    }

    /// [`Self::start_trusting`], whose JWT verification strategy expects
    /// `strategy_issuer` as `iss` instead of the identity provider's own.
    async fn start_configured(
        change: impl FnOnce(&mut AgentSurface),
        trusted_issuers: Vec<String>,
        strategy_issuer: Option<&str>,
    ) -> Self {
        use crate::credential_providers::storage::FileSystemCredentialProviderStore;
        use crate::delegation_vault::storage::FileSystemDelegationVaultStore;

        let idp = JwksFixture::start().await;
        let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
        let authorization_server = AuthorizationServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let strategies = Arc::new(
            crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.path().join("strategies"))
                .await
                .unwrap(),
        );
        let strategy = strategies
            .create(
                serde_json::from_value(json!({
                    "id": "partner-idp", "name": "Partner IdP",
                    "expected_issuer": strategy_issuer.unwrap_or(&idp.issuer),
                    "jwks_source": { "type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", idp.issuer) },
                    "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap()
            .id;
        let mut served = partner_surface(&target.url, &strategy, true);
        change(&mut served);
        let (_, peer_issuers) = receiver_trusting(root.path(), &served, strategies.clone(), trusted_issuers).await;

        let providers = FileSystemCredentialProviderStore::new(root.path().join("providers"))
            .await
            .unwrap();
        for provider in [PER_USER_PROVIDER, SECOND_PROVIDER] {
            providers
                .create(
                    serde_json::from_value(json!({
                        "id": provider, "name": provider, "provider_id": provider,
                        "provider_type": "oauth2_authorization_code",
                        "authorization_endpoint": "https://provider.example/authorize",
                        "token_endpoint": authorization_server.token_endpoint,
                        "client_id_secret_ref": "client-id", "client_secret_secret_ref": "client-secret",
                        "callback_url": CALLBACK_URL, "default_scopes": ["read"],
                        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let providers: Arc<dyn CredentialProviderStorage> = Arc::new(providers);
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            FileSystemDelegationVaultStore::new(root.path().join("vault"))
                .await
                .unwrap(),
        );
        let secrets = crate::secrets::FilesystemSecretsStore::new_async(
            root.path()
                .join("delegation-secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        for (secret_id, value) in [("client-id", "receiver-client"), ("client-secret", "receiver-client-secret")] {
            secrets
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "ApiKey".to_string(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let secrets: Arc<dyn SecretsStore> = Arc::new(secrets);
        super::init_credential_provider_store(providers.clone()).await;
        super::init_delegation_vault_store(vault.clone()).await;
        super::init_secrets_store(secrets.clone()).await;
        super::init_gateway_base_url(GATEWAY_BASE_URL.to_string()).await;

        let mut direct = crate::proxy::handler::variant_routing_tests::router(served);
        direct.config = Arc::new(
            serde_json::from_value(json!({
                "tls": { "cert_path": "unused.pem", "key_path": "unused-key.pem" },
                "integration": { "variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_",
                    "types": [], "categories": [] },
                "extension_inspection": { "enabled": true }
            }))
            .unwrap(),
        );
        direct.source_auth_middleware = Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            direct
                .didauth_session_store
                .clone(),
            strategies.clone(),
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets.clone()),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        )));
        direct.credential_provider_store = Some(providers.clone());
        direct.delegation_vault_store = Some(vault.clone());
        direct.secrets_store = Some(secrets.clone());
        direct.gateway_base_url = Some(GATEWAY_BASE_URL.to_string());
        let (identities, identities_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        direct.channels.write().await[0].identity_selector =
            Some(Arc::new(crate::identity::IdentitySelector::new(&identity_schema(), Arc::new(identities)).unwrap()));

        Self {
            root,
            _peer_issuers: peer_issuers,
            _identities: identities_dir,
            idp,
            strategies,
            strategy,
            target,
            authorization_server,
            vault,
            providers,
            secrets,
            direct,
        }
    }

    /// Serve `surface` from now on, to the direct path and over Fabric.
    async fn serve(
        &self,
        surface: &AgentSurface,
    ) {
        FileSystemAgentSurfaceStore::new(
            self.root
                .path()
                .join("agent_surfaces"),
        )
        .await
        .unwrap()
        .save(surface)
        .await
        .unwrap();
        self.direct
            .channels
            .write()
            .await[0]
            .surface = Arc::new(surface.clone());
    }

    fn surface(
        &self,
        releases: bool,
    ) -> AgentSurface {
        partner_surface(&self.target.url, &self.strategy, releases)
    }

    /// A token of the identity provider for `subject`, for the surface.
    fn token(
        &self,
        subject: &str,
    ) -> String {
        self.token_for(subject, JWT_AUDIENCE)
    }

    fn token_for(
        &self,
        subject: &str,
        audience: &str,
    ) -> String {
        sign_jwt(
            json!({ "iss": self.idp.issuer, "sub": subject, "aud": audience, "exp": now_secs() + 300 }),
            &self.idp.kid,
        )
    }

    /// The identity hash of `subject` as a surface of `tenant` verifies it.
    fn principal(
        &self,
        subject: &str,
        tenant: Option<&str>,
    ) -> String {
        crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: subject.to_string(),
            claims: json!({ "iss": self.idp.issuer, "sub": subject }),
            principal_claim: "sub".to_string(),
        }
        .principal_hash(tenant)
        .unwrap()
    }

    fn as_user(
        &self,
        subject: &str,
    ) -> Value {
        json!({ "content-type": "application/json", "authorization": format!("Bearer {}", self.token(subject)) })
    }

    /// A request the partner sends over Fabric with `headers`, its body naming
    /// the agent `researcher` and a DID for it.
    fn partner_request(
        &self,
        headers: Value,
    ) -> ReceivedMessage {
        forward_request(
            self.root.path(),
            headers,
            naming(json!({ "agentId": "researcher", "did": "did:web:researcher.example" })),
        )
    }

    /// `subject`'s own A2A request to the Access Point, its body naming the
    /// agent `agent`.
    async fn call_directly(
        &self,
        subject: &str,
        agent: &str,
    ) -> (axum::http::StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/agent")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token(subject)))
            .body(axum::body::Body::from(naming(json!({ "agentId": agent })).to_string()))
            .unwrap();
        let response = crate::proxy::handler::multi_channel_proxy_handler(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
            ),
            axum::extract::State(self.direct.clone()),
            request,
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn egress(&self) -> crate::delegation_vault::oauth::TokenEgress {
        crate::delegation_vault::oauth::TokenEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(
                self.authorization_server
                    .token_endpoint
                    .clone(),
            ),
            policy: Default::default(),
        }
    }

    /// Completes, as the authorization server's redirect with the code `code`
    /// would, the consent the authorization URL in a direct call's
    /// `consent_required` answer starts. Returns the state the URL carried.
    async fn complete_consent(
        &self,
        consent: &Value,
        code: &str,
    ) -> crate::delegation_vault::OAuthState {
        let authorization_url = url::Url::parse(
            consent["consent_required"][0]["authorization_url"]
                .as_str()
                .unwrap_or_else(|| panic!("no authorization URL: {consent}")),
        )
        .unwrap();
        let state = authorization_url
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let opened = crate::delegation_vault::oauth::decode_oauth_state(&state).unwrap();
        let callback = crate::delegation_vault::handlers::DelegationVaultState {
            vault_store: self.vault.clone(),
            provider_store: self.providers.clone(),
            secrets_store: self.secrets.clone(),
            gateway_base_url: GATEWAY_BASE_URL.to_string(),
            agent_surface_store: None,
            oauth_callback_route: "/oauth/callback".to_string(),
            vc_signer: None,
            vc_issuer: None,
            vault_population_notifier: None,
            egress_allowlist: None,
            resource_origins: Arc::new(HashMap::new()),
            issuers: Arc::new(None),
        };
        let response = self
            .egress()
            .scope(crate::delegation_vault::handlers::oauth_callback(
                axum::extract::State(callback),
                axum::extract::Path(PER_USER_PROVIDER.to_string()),
                axum::extract::Query(crate::delegation_vault::handlers::OAuthCallbackQuery {
                    code: Some(code.to_string()),
                    state: Some(state),
                    error: None,
                    error_description: None,
                }),
            ))
            .await
            .into_response();
        let page = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let page = String::from_utf8_lossy(&page);
        assert!(page.contains("Authorization Successful"), "{page}");
        opened
    }

    async fn grants(&self) -> Vec<DelegationToken> {
        self.vault
            .list_all()
            .await
            .unwrap()
    }

    /// Stores a grant of `provider` keyed by `agent_half` and `user`, expiring
    /// in `expires_in_secs`, with a refresh token. Returns its id.
    async fn store_grant(
        &self,
        agent_half: &str,
        user: &str,
        provider: &str,
        access_token: &str,
        expires_in_secs: i64,
    ) -> String {
        self.vault
            .store(
                serde_json::from_value(json!({
                    "id": uuid::Uuid::new_v4().to_string(), "agent_did": agent_half, "user_identity_hash": user,
                    "credential_provider_id": provider, "provider_id": provider,
                    "access_token": access_token, "refresh_token": format!("{access_token}-refresh"),
                    "scopes": ["read"], "expires_at": chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs),
                    "consent_granted_at": "2026-09-01T00:00:00Z",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap()
            .id
    }

    /// Stores `subject`'s grant of [`PER_USER_PROVIDER`] under the surface,
    /// whose access token is `<subject>-access`.
    async fn connected(
        &self,
        subject: &str,
    ) -> String {
        self.store_grant(
            SURFACE_ID,
            &self.principal(subject, None),
            PER_USER_PROVIDER,
            &format!("{subject}-access"),
            3600,
        )
        .await
    }

    /// Asserts that the partner's request was refused with `403` and
    /// `reason`, recorded at admission, and that the Target was not called.
    async fn assert_refused(
        &self,
        message: &ReceivedMessage,
        reason: &str,
        recorded: RejectionReason,
    ) -> Value {
        let reached = self.target.received().len();
        let (response, body, rejected) = self
            .egress()
            .scope(refused(message))
            .await;
        assert_eq!(response["status"], 403, "{response}");
        assert_eq!(body["reason"], reason, "{body}");
        assert_eq!(rejected, Rejections::from([(RejectionStage::Admission, recorded, true)]));
        assert_eq!(self.target.received().len(), reached, "the Target is not called: {response}");
        body
    }

    /// Asserts that the partner's request reached the Target once, carrying
    /// exactly `authorization` and no refresh token.
    async fn assert_released(
        &self,
        message: &ReceivedMessage,
        authorization: &str,
    ) -> axum::http::HeaderMap {
        let reached = self.target.received().len();
        let response = self
            .egress()
            .scope(forward_response(message))
            .await;
        assert_eq!(response["status"], 200, "{response}");
        let received = self.target.received();
        assert_eq!(received.len(), reached + 1, "the Target is called once");
        let headers = received[reached].clone();
        assert_eq!(header_values(&headers, "authorization"), [authorization]);
        assert!(
            headers
                .values()
                .all(|value| !value
                    .to_str()
                    .unwrap_or_default()
                    .contains("-refresh")),
            "a refresh token never leaves this gateway: {headers:?}"
        );
        headers
    }
}

/// A person connects directly, through the surface's Access Point, and the
/// grant is kept under the surface whatever agent the request names. The
/// partner's request for the same person, verified by the same identity
/// provider, is refused while the Target does not release grants, and gets the
/// person's access token, never the refresh token, once it does, whatever
/// agent and DID the partner names.
#[tokio::test]
async fn a_grant_a_person_connects_directly_reaches_their_partner_requests_once_the_target_opts_in() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_ACCEPTANCE_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    assert!(
        receiver
            .grants()
            .await
            .is_empty(),
        "nobody has connected yet"
    );

    let (status, consent) = receiver
        .call_directly("alice", "planner")
        .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{consent}");
    assert_eq!(consent["consent_required"][0]["provider_name"], PER_USER_PROVIDER, "{consent}");
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target waits for consent"
    );
    let state = receiver
        .complete_consent(&consent, "alice")
        .await;
    assert_eq!(state.agent_did, SURFACE_ID, "consent is asked for the surface, not the agent the caller named");

    let grants = receiver.grants().await;
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0].agent_did, SURFACE_ID);
    assert_eq!(grants[0].user_identity_hash, receiver.principal("alice", None));
    assert_eq!(grants[0].credential_provider_id, PER_USER_PROVIDER);
    assert_eq!(grants[0].access_token, "alice-access");

    receiver
        .serve(&receiver.surface(false))
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "delegation_not_enabled_for_partners",
            RejectionReason::DelegationNotEnabledForPartners,
        )
        .await;

    receiver
        .serve(&receiver.surface(true))
        .await;
    let (headers, events) = crate::audit::producer::capture(async {
        receiver
            .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
            .await
    })
    .await;
    assert!(header_values(&headers, "x-transit-token").is_empty(), "a surface without Transit Points passes no token");
    let injected: Vec<_> = events
        .iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::TokenInjected))
        .map(|event| {
            (
                event.agent_did.as_deref(),
                event
                    .user_identity_hash
                    .clone(),
                event.via_fabric,
            )
        })
        .collect();
    assert_eq!(injected, [(Some(SURFACE_ID), Some(receiver.principal("alice", None)), true)]);
}

/// The audit record of a grant released to a partner's request names it as a
/// Fabric request, the Target, the surface by its name, the caller the surface
/// verified and the paired gateway that sent it, and carries no presentation.
#[tokio::test]
async fn a_grant_released_to_a_partner_is_audited_with_the_peer_and_the_target() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_AUDIT_CHILD").await {
        return;
    }
    const SURFACE_NAME: &str = "Partner tools";
    let receiver = Receiver::start_with(|served| served.name = SURFACE_NAME.to_string()).await;
    receiver
        .connected("alice")
        .await;

    let (_, events) = crate::audit::producer::capture(async {
        receiver
            .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
            .await
    })
    .await;
    let injected: Vec<_> = events
        .into_iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::TokenInjected))
        .map(|event| {
            let caller = event
                .caller
                .expect("a released grant names its caller");
            (
                event.via_fabric,
                event.target_endpoint,
                event.channel_name,
                event.protocol,
                event.mcp_tool_name,
                event.vp_jwt,
                caller.auth_method,
                caller.iss,
                caller.sub,
                caller.peer_gateway,
            )
        })
        .collect();
    assert_eq!(
        injected,
        [(
            true,
            Some(receiver.target.url.clone()),
            Some(SURFACE_NAME.to_string()),
            Some("a2a".to_string()),
            None,
            None,
            "jwt_bearer".to_string(),
            Some(receiver.idp.issuer.clone()),
            Some("alice".to_string()),
            Some(PEER_ISSUER_DID.to_string()),
        )]
    );
}

/// Without the switch a direct caller's grant stays keyed by the agent its
/// request names: the same person calling through another agent is asked to
/// connect again, and a partner's request for them is refused.
#[tokio::test]
async fn direct_consent_keys_the_grant_by_the_caller_agent_without_the_switch() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_DIRECT_AGENT_CHILD").await {
        return;
    }
    let receiver = Receiver::start(false).await;

    let (status, consent) = receiver
        .call_directly("alice", "planner")
        .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{consent}");
    let state = receiver
        .complete_consent(&consent, "alice")
        .await;
    assert!(
        state
            .agent_did
            .starts_with("did:"),
        "the grant is kept under the agent DID the caller named"
    );
    assert_ne!(state.agent_did, SURFACE_ID);
    let grants = receiver.grants().await;
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0].agent_did, state.agent_did, "kept under the agent the caller named");

    let (status, again) = receiver
        .call_directly("alice", "researcher")
        .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "another agent has no grant: {again}");
    assert!(
        receiver
            .target
            .received()
            .is_empty()
    );

    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "delegation_not_enabled_for_partners",
            RejectionReason::DelegationNotEnabledForPartners,
        )
        .await;
}

/// Once the Target releases grants, a person's grant is one per surface: the
/// same person calling directly through another agent gets it too.
#[tokio::test]
async fn a_person_keeps_one_grant_per_surface_once_the_target_opts_in() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_PER_SURFACE_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    let (_, consent) = receiver
        .call_directly("alice", "planner")
        .await;
    receiver
        .complete_consent(&consent, "alice")
        .await;

    let (status, answer) = receiver
        .call_directly("alice", "researcher")
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert_eq!(answer, json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }));
    let received = receiver.target.received();
    assert_eq!(received.len(), 1, "{answer}");
    assert_eq!(header_values(&received[0], "authorization"), ["Bearer alice-access"]);

    let (status, consent) = receiver
        .call_directly("bob", "planner")
        .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "another person connects for themselves: {consent}");
    assert_eq!(
        receiver
            .target
            .received()
            .len(),
        1
    );
}

/// The partner's request for one person never gets another person's grant,
/// and its refusal carries no authorization URL; nothing is stored for the
/// person it names.
#[tokio::test]
async fn a_partner_request_for_another_user_gets_none_of_the_first_users_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_OTHER_USER_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;

    let body = receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("bob")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;
    for leaked in ["authorization_url", "provider.example", "state="] {
        assert!(
            !body
                .to_string()
                .contains(leaked),
            "{leaked}: {body}"
        );
    }
    let grants = receiver.grants().await;
    assert_eq!(grants.len(), 1, "nothing is stored for bob: {grants:?}");
    assert_eq!(grants[0].user_identity_hash, receiver.principal("alice", None));
    assert!(
        receiver
            .authorization_server
            .grant_types()
            .is_empty()
    );

    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
}

/// The agent the partner's request names, the identity hash this gateway
/// computes from it, the DID the partner names, the Target URL and the
/// partner's own record never key a grant: grants stored under any of them
/// for the same person stay unused.
#[tokio::test]
async fn a_partner_named_agent_or_presentation_never_selects_a_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_NAMED_AGENT_CHILD").await {
        return;
    }
    use sha2::{Digest, Sha256};

    let receiver = Receiver::start(true).await;
    let alice = receiver.principal("alice", None);
    let peer = crate::gateways::FileSystemGatewayStore::new(
        receiver
            .root
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap()
    .get_by_did(PEER_CONNECTION_POINT_DID)
    .await
    .unwrap()
    .unwrap();
    let payload_identity = format!("sha256:{:x}", Sha256::digest(br#""researcher""#));
    let target_url = receiver.target.url.clone();
    for (agent_half, access_token) in [
        (payload_identity.as_str(), "payload-access"),
        ("did:web:researcher.example", "named-did-access"),
        (target_url.as_str(), "target-url-access"),
        (peer.id.as_str(), "peer-record-access"),
        (PEER_CONNECTION_POINT_DID, "peer-did-access"),
    ] {
        receiver
            .store_grant(agent_half, &alice, PER_USER_PROVIDER, access_token, 3600)
            .await;
    }

    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;

    receiver
        .connected("alice")
        .await;
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
}

/// A presentation one of the partner's connection issuers signed, which this
/// gateway verifies and passes on as the caller DID, never selects a grant
/// either: a grant stored under that DID for the same person stays unused, and
/// the person's grant under the surface is the one released.
#[tokio::test]
async fn a_verified_partner_presentation_never_selects_a_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_VERIFIED_PRESENTATION_CHILD").await {
        return;
    }
    const CREDENTIAL_EXT: &str = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    let signed = crate::identity::test_helpers::signed_agent_presentation().await;
    super::init_vc_issuer(signed.issuer.clone(), None).await;
    let receiver = Receiver::start_trusting(
        |served| served.transit = surface("a2a", &served.target.endpoint, &["crm"]).transit,
        vec![signed.issuer_did.clone()],
    )
    .await;
    receiver
        .store_grant(
            &signed.holder_did,
            &receiver.principal("alice", None),
            PER_USER_PROVIDER,
            "presented-access",
            3600,
        )
        .await;
    let presenting = || {
        let mut body = naming(json!({ "agentId": "researcher", "did": signed.holder_did }));
        let message = &mut body["params"]["message"];
        message["extensions"]
            .as_array_mut()
            .unwrap()
            .push(json!(CREDENTIAL_EXT));
        message["metadata"][CREDENTIAL_EXT] =
            json!({ "did": signed.holder_did, "verifiablePresentation": signed.presentation.to_string() });
        forward_request(receiver.root.path(), receiver.as_user("alice"), body)
    };

    receiver
        .assert_refused(
            &presenting(),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;

    receiver
        .connected("alice")
        .await;
    let headers = receiver
        .assert_released(&presenting(), "Bearer alice-access")
        .await;
    let claims = test_issuer()
        .validate(header_values(&headers, "x-transit-token")[0], 300)
        .unwrap();
    assert_eq!(
        claims
            .fabric
            .and_then(|fabric| fabric.caller_did),
        Some(signed.holder_did.clone()),
        "the presentation verified, so the caller DID it names is passed on"
    );
}

/// A switch beside caller authentication that names every one of a partner's
/// users alike releases nothing, even a grant stored under the shared caller:
/// an API key, a JWT without an audience, or either beside a JWT with one.
#[tokio::test]
async fn a_partner_credential_that_names_every_user_alike_never_releases_a_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_SHARED_CALLER_CHILD").await {
        return;
    }
    let api_key = json!({ "type": "api_key", "secret_id": "peer-callers",
        "extraction": { "source": "http_header", "field": "x-api-key" } });
    let receiver = Receiver::start(true).await;
    let shared_key = crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "peer-callers".to_string(),
        provider_agent_id: None,
    }
    .principal_hash(None)
    .unwrap();
    receiver
        .store_grant(SURFACE_ID, &shared_key, PER_USER_PROVIDER, "shared-key-access", 3600)
        .await;
    receiver
        .connected("alice")
        .await;
    let key_headers = json!({ "content-type": "application/json", "x-api-key": CALLER_KEY });

    for (case, methods, requests) in [
        ("api_key", json!([api_key.clone()]), vec![key_headers.clone()]),
        (
            "jwt_bearer without an audience",
            json!([jwt_method(&receiver.strategy, false)]),
            vec![receiver.as_user("alice")],
        ),
        (
            "jwt_bearer with an audience beside api_key",
            json!([jwt_method(&receiver.strategy, true), api_key.clone()]),
            vec![receiver.as_user("alice"), key_headers.clone()],
        ),
    ] {
        let mut shared = receiver.surface(true);
        shared
            .access_point
            .caller_authentication = Some(serde_json::from_value(json!({ "methods": methods })).unwrap());
        assert!(
            shared
                .fabric_caller_authentication_gap()
                .is_some(),
            "{case}"
        );
        receiver.serve(&shared).await;
        for headers in requests {
            receiver
                .assert_refused(
                    &receiver.partner_request(headers),
                    "delegation_not_enabled_for_partners",
                    RejectionReason::DelegationNotEnabledForPartners,
                )
                .await;
        }
    }

    receiver
        .serve(&receiver.surface(true))
        .await;
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
}

/// A JWT verification strategy that names no issuer releases no grant to a
/// partner, though the request check never reads the issuer: the strategy
/// verifies only a token whose `iss` is empty, and a caller with an empty
/// issuer has no identity hash, so the request is refused as one whose caller
/// the surface did not verify. A grant kept under the hash an empty issuer
/// would give stays unused. A strategy that cannot be read verifies no caller
/// either: the request fails as a gateway fault, with no grant released.
#[tokio::test]
async fn a_strategy_that_names_no_issuer_releases_no_grant_to_a_partner() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_NO_ISSUER_CHILD").await {
        return;
    }
    let receiver = Receiver::start_configured(|_| {}, Vec::new(), Some("")).await;
    let empty_issuer = crate::source_auth::models::caller_identity_hash("jwt_bearer", "", None, "alice").unwrap();
    receiver
        .store_grant(SURFACE_ID, &empty_issuer, PER_USER_PROVIDER, "empty-issuer-access", 3600)
        .await;
    receiver
        .connected("alice")
        .await;
    let released = |events: &[crate::delegation_vault::audit::DelegationAuditEvent]| {
        events
            .iter()
            .filter(|event| {
                matches!(event.event, DelegationAuditAction::TokenInjected | DelegationAuditAction::TokenRefreshed)
            })
            .count()
    };

    let empty_iss =
        sign_jwt(json!({ "iss": "", "sub": "alice", "aud": JWT_AUDIENCE, "exp": now_secs() + 300 }), &receiver.idp.kid);
    let headers = json!({ "content-type": "application/json", "authorization": format!("Bearer {empty_iss}") });
    let (response, events) = crate::audit::producer::capture(
        receiver
            .egress()
            .scope(forward_response(&receiver.partner_request(headers))),
    )
    .await;
    assert_eq!(released(&events), 0, "no grant is released: {events:?}");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, DelegationAuditAction::AuthFailed { .. })),
        "the token verified under the strategy: {events:?}"
    );
    assert_eq!(status_and_reason(&response), (json!(403), json!("partner_caller_not_verified")), "{response}");
    assert_eq!(rejections(&events), [(RejectionStage::Admission, RejectionReason::ConsentIdentityRequired, true)]);

    let (response, events) = crate::audit::producer::capture(
        receiver
            .egress()
            .scope(forward_response(&receiver.partner_request(receiver.as_user("alice")))),
    )
    .await;
    assert_eq!(released(&events), 0, "a token naming an issuer does not verify: {events:?}");
    assert_eq!(status_and_reason(&response), (json!(403), json!("partner_caller_not_verified")), "{response}");
    assert_eq!(rejections(&events), [(RejectionStage::Admission, RejectionReason::ConsentIdentityRequired, true)]);

    receiver
        .strategies
        .delete(&receiver.strategy)
        .await
        .unwrap();
    let (response, events) = crate::audit::producer::capture(
        receiver
            .egress()
            .scope(forward_response(&receiver.partner_request(receiver.as_user("alice")))),
    )
    .await;
    assert_eq!(released(&events), 0, "no grant is released: {events:?}");
    let body: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or(Value::Null);
    assert_eq!(
        (&response["status"], &body["status"], &body["title"]),
        (&json!(500), &json!(500), &json!("Internal Server Error")),
        "a strategy that cannot be read fails the request as a gateway fault: {response}"
    );

    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target is never called"
    );
}

/// A partner's request whose caller the surface did not verify gets no grant:
/// a public Access Point refuses it with `partner_caller_not_verified`, a
/// closed one refuses the failed caller before anything else.
#[tokio::test]
async fn a_partner_whose_caller_the_surface_did_not_verify_gets_no_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_UNVERIFIED_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;
    let unverified = [
        json!({ "content-type": "application/json",
            "authorization": format!("Bearer {}", receiver.token_for("alice", "https://another.example")) }),
        json!({ "content-type": "application/json" }),
    ];

    let mut public = receiver.surface(true);
    public.access_point.public = Some(true);
    receiver.serve(&public).await;
    for headers in &unverified {
        receiver
            .assert_refused(
                &receiver.partner_request(headers.clone()),
                "partner_caller_not_verified",
                RejectionReason::ConsentIdentityRequired,
            )
            .await;
    }

    let mut closed = receiver.surface(true);
    closed.access_point.public = Some(false);
    receiver.serve(&closed).await;
    for headers in &unverified {
        let response = forward_response(&receiver.partner_request(headers.clone())).await;
        assert_eq!(response["status"], 401, "{response}");
    }
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target is never called"
    );
}

/// A transit token the peer sends, even one this gateway issued naming another
/// person who has a grant, never selects that grant, and never stands in for
/// a caller the surface verified.
#[tokio::test]
async fn a_transit_token_the_peer_sends_never_selects_a_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_TRANSIT_TOKEN_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    let bob = receiver.principal("bob", None);
    receiver
        .connected("bob")
        .await;
    let token = test_issuer()
        .issue(SURFACE_ID, Some("did:web:bob.example"), None, None, Some(&bob), None, Vec::new())
        .unwrap();

    let mut alice = receiver.as_user("alice");
    alice["X-Transit-Token"] = json!(token);
    receiver
        .assert_refused(
            &receiver.partner_request(alice),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(json!({ "content-type": "application/json", "x-transit-token": token })),
            "partner_caller_not_verified",
            RejectionReason::ConsentIdentityRequired,
        )
        .await;

    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("bob")), "Bearer bob-access")
        .await;
}

/// The identity hash names the surface's tenant and the agent half is the
/// surface, so a grant kept for the same person under another tenant, without
/// one, or under another surface is never released; a peer of another tenant
/// is refused before any grant is looked up.
#[tokio::test]
async fn a_grant_of_another_tenants_surface_is_never_released() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_TENANT_CHILD").await {
        return;
    }
    let receiver = Receiver::start_with(|surface| surface.tenant_id = Some("tenant-a".to_string())).await;
    for (agent_half, tenant, access_token) in [
        (SURFACE_ID, Some("tenant-b"), "other-tenant-access"),
        (SURFACE_ID, None, "no-tenant-access"),
        ("another-surface", Some("tenant-a"), "another-surface-access"),
    ] {
        receiver
            .store_grant(agent_half, &receiver.principal("alice", tenant), PER_USER_PROVIDER, access_token, 3600)
            .await;
    }
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;

    receiver
        .store_grant(
            SURFACE_ID,
            &receiver.principal("alice", Some("tenant-a")),
            PER_USER_PROVIDER,
            "alice-access",
            3600,
        )
        .await;
    let gateways = crate::gateways::FileSystemGatewayStore::new(
        receiver
            .root
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap();
    let mut peer = gateways
        .get_by_did(PEER_CONNECTION_POINT_DID)
        .await
        .unwrap()
        .unwrap();
    peer.tenant_id = Some("tenant-b".to_string());
    gateways
        .update(&peer)
        .await
        .unwrap();
    let response = forward_response(&receiver.partner_request(receiver.as_user("alice"))).await;
    assert_eq!(
        response,
        json!({ "status": 403, "error": "Channel is not exposed to sender",
            "body": json!({ "error": "Forbidden", "message": "Channel is not exposed to sender" }).to_string() })
    );
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "a peer of another tenant reaches nothing"
    );

    peer.tenant_id = None;
    gateways
        .update(&peer)
        .await
        .unwrap();
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
}

/// A grant the person disconnected, or whose vendor refuses to refresh it, is
/// not released, and the partner is not offered consent.
#[tokio::test]
async fn a_revoked_grant_is_never_released() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_REVOKED_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    let grant = receiver
        .connected("alice")
        .await;
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;

    assert!(
        receiver
            .vault
            .delete(&grant)
            .await
            .unwrap()
    );
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;

    receiver
        .store_grant(SURFACE_ID, &receiver.principal("alice", None), PER_USER_PROVIDER, "expired-access", -60)
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;
    assert_eq!(
        receiver
            .authorization_server
            .grant_types(),
        ["refresh_token"],
        "the expired grant was offered for refresh, which the vendor refused"
    );
}

/// The switch is read on every request: turning it off refuses the next
/// partner request, and turning it on again releases the same grant.
#[tokio::test]
async fn turning_the_opt_in_off_refuses_the_next_partner_request() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_TURNED_OFF_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;

    receiver
        .serve(&receiver.surface(false))
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "delegation_not_enabled_for_partners",
            RejectionReason::DelegationNotEnabledForPartners,
        )
        .await;

    receiver
        .serve(&receiver.surface(true))
        .await;
    receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
}

/// Each view decides for itself: a variant that turns the switch off, or a
/// complete variant that does not set it, releases nothing on a surface that
/// opts in, and a variant that turns it on releases on one that does not.
#[tokio::test]
async fn a_variant_that_does_not_opt_in_releases_nothing() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_VARIANT_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;
    let to_variant = |alias: &str| {
        let mut message = receiver.partner_request(receiver.as_user("alice"));
        message.message_body["virtual_channel_alias"] = json!(alias);
        message
    };
    let variant = |alias: &str, overrides: Value| {
        serde_json::from_value(json!({ "id": format!("id-{alias}"), "alias": alias, "name": alias,
            "overrides": overrides }))
        .unwrap()
    };

    let mut opted_in = receiver.surface(true);
    opted_in.variants = vec![
        variant("off", json!({ "target": { "delegated_credentials_for_fabric_callers": false } })),
        variant("frozen", json!({ "complete": true, "target": { "endpoint": receiver.target.url } })),
        variant("inherits", json!({ "target": { "endpoint": receiver.target.url } })),
    ];
    receiver
        .serve(&opted_in)
        .await;
    for alias in ["off", "frozen"] {
        receiver
            .assert_refused(
                &to_variant(alias),
                "delegation_not_enabled_for_partners",
                RejectionReason::DelegationNotEnabledForPartners,
            )
            .await;
    }
    receiver
        .assert_released(&to_variant("inherits"), "Bearer alice-access")
        .await;

    let mut opted_out = receiver.surface(false);
    opted_out.variants = vec![variant("on", json!({ "target": { "delegated_credentials_for_fabric_callers": true } }))];
    receiver
        .serve(&opted_out)
        .await;
    receiver
        .assert_released(&to_variant("on"), "Bearer alice-access")
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "delegation_not_enabled_for_partners",
            RejectionReason::DelegationNotEnabledForPartners,
        )
        .await;
}

/// With several per-user bindings, a request is refused before anything is
/// sent unless the person has a grant for each; then each is sent.
#[tokio::test]
async fn every_per_user_binding_needs_a_grant_before_any_is_released() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_EVERY_BINDING_CHILD").await {
        return;
    }
    let receiver = Receiver::start_with(|surface| {
        surface
            .outbound_credentials
            .push(
                serde_json::from_value(json!({ "credential_provider_id": SECOND_PROVIDER, "scopes": ["read"],
                    "inject_as": { "type": "custom_header", "name": "x-second-grant", "format": "{value}" } }))
                .unwrap(),
            )
    })
    .await;
    receiver
        .connected("alice")
        .await;
    receiver
        .assert_refused(
            &receiver.partner_request(receiver.as_user("alice")),
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        )
        .await;

    receiver
        .store_grant(SURFACE_ID, &receiver.principal("alice", None), SECOND_PROVIDER, "alice-second-access", 3600)
        .await;
    let headers = receiver
        .assert_released(&receiver.partner_request(receiver.as_user("alice")), "Bearer alice-access")
        .await;
    assert_eq!(header_values(&headers, "x-second-grant"), ["alice-second-access"]);
}

/// A partner's request never drives an elicitation, even naming a session
/// whose client accepts them and has a stream open: a person without a grant
/// is refused, and no consent prompt is sent.
#[tokio::test]
async fn a_partner_session_never_drives_an_elicitation() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_ELICITATION_CHILD").await {
        return;
    }
    let receiver = Receiver::start_with(|surface| {
        surface.outbound_credentials = vec![
            serde_json::from_value(json!({ "credential_provider_id": PER_USER_PROVIDER, "scopes": ["read"],
                "consent_mode": "elicit", "elicit_fallback": "fail", "elicit_timeout_secs": 1 }))
            .unwrap(),
        ]
    })
    .await;
    crate::mcp::elicitation::global_capability_registry()
        .record(
            SURFACE_ID,
            "partner-session",
            crate::mcp::elicitation::McpClientCapabilities {
                elicitation: true,
                ..Default::default()
            },
        )
        .await;
    let mut stream = crate::mcp::streamable_sse::global_streamable_session_registry()
        .register(SURFACE_ID, "partner-session")
        .await
        .expect("a stream for the partner's session");
    let mut headers = receiver.as_user("alice");
    headers["mcp-session-id"] = json!("partner-session");

    let (response, events) = crate::audit::producer::capture(
        receiver
            .egress()
            .scope(forward_response(&receiver.partner_request(headers))),
    )
    .await;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, DelegationAuditAction::ElicitationSent)),
        "{events:?}"
    );
    assert!(stream.try_recv().is_err(), "no consent prompt reaches the partner's session");
    assert_eq!(status_and_reason(&response), (json!(403), json!("consent_not_available_for_partners")), "{response}");
    assert_eq!(
        rejections(&events),
        [(RejectionStage::Admission, RejectionReason::ConsentNotAvailableForPartners, true)]
    );
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target is not called"
    );
}

/// The switch has no effect on a Target that is not an HTTP or HTTPS URL: a
/// `fabric://` Target that sets it refuses a partner's request as one that
/// does not, and the caller's grant under the surface is never released.
#[tokio::test]
async fn a_target_that_is_not_an_http_url_releases_nothing_with_the_switch_on() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_NON_HTTP_TARGET_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;

    for releases in [false, true] {
        let mut fabric_target = receiver.surface(releases);
        fabric_target.target.endpoint = "fabric://peer-gateway/peer-surface".to_string();
        receiver
            .serve(&fabric_target)
            .await;
        let (response, events) = crate::audit::producer::capture(
            receiver
                .egress()
                .scope(forward_response(&receiver.partner_request(receiver.as_user("alice")))),
        )
        .await;
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.event, DelegationAuditAction::TokenInjected)),
            "switch {releases}: no grant is released: {events:?}"
        );
        assert_eq!(
            status_and_reason(&response),
            (json!(403), json!("delegation_not_enabled_for_partners")),
            "switch {releases}: {response}"
        );
        assert_eq!(
            rejections(&events),
            [(RejectionStage::Admission, RejectionReason::DelegationNotEnabledForPartners, true)],
            "switch {releases}"
        );
    }
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target is not called"
    );
}

/// A peer the surface is not exposed to is refused before any grant is looked
/// up, even for a person who has one.
#[tokio::test]
async fn a_peer_the_surface_is_not_exposed_to_is_refused_before_any_grant() {
    if ran_in_child("ATG_FABRIC_PARTNER_GRANT_NOT_EXPOSED_CHILD").await {
        return;
    }
    let receiver = Receiver::start(true).await;
    receiver
        .connected("alice")
        .await;
    let gateways = crate::gateways::FileSystemGatewayStore::new(
        receiver
            .root
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap();
    let mut peer = gateways
        .get_by_did(PEER_CONNECTION_POINT_DID)
        .await
        .unwrap()
        .unwrap();
    peer.exposure_mode = Some(crate::gateways::types::ExposureMode::None);
    gateways
        .update(&peer)
        .await
        .unwrap();

    let (response, events) =
        crate::audit::producer::capture(forward_response(&receiver.partner_request(receiver.as_user("alice")))).await;
    assert_eq!(response["error"], "Channel is not exposed to sender", "{response}");
    assert!(
        receiver
            .target
            .received()
            .is_empty(),
        "the Target is never called"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, DelegationAuditAction::TokenInjected)),
        "{events:?}"
    );
}
