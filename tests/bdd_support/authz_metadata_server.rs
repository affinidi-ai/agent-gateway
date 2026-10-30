//! A local authorization server for real-process scenarios. Its issuer has a
//! path, so the gateway's discovery tries the RFC 8414 path insertion first and
//! the OpenID Connect path appending last. It publishes its metadata at one of
//! them, or a document a gateway must refuse, serves a key set holding a key
//! the BDD signing key is not, and records the path of every request it gets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const ISSUER_PATH: &str = "/realms/agents";
const RFC8414_PATH: &str = "/.well-known/oauth-authorization-server/realms/agents";
const OPENID_CONFIGURATION_PATH: &str = "/realms/agents/.well-known/openid-configuration";
const TOKEN_ENDPOINT_PATH: &str = "/realms/agents/protocol/token";
const KEY_SET_PATH: &str = "/realms/agents/protocol/keys";
const OVERSIZED_DOCUMENT_BYTES: usize = 70 * 1024;
const KEY_SET_KID: &str = "authorization-server-key";
const KEY_SET_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

/// What the authorization server publishes at its metadata URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataPublication {
    /// A valid document at the RFC 8414 URL only.
    OAuthAuthorizationServer,
    /// A valid document at the OpenID Connect discovery URL only.
    OpenIdConfiguration,
    /// No document: every metadata URL answers `404`.
    Absent,
    /// A document at the RFC 8414 URL whose issuer differs by a trailing slash.
    ForeignIssuer,
    /// A document at the RFC 8414 URL larger than the gateway reads.
    Oversized,
    /// A document at the RFC 8414 URL without a `jwks_uri`.
    WithoutKeySet,
}

#[derive(Debug)]
struct ServerState {
    origin: String,
    publication: Mutex<MetadataPublication>,
    requests: Mutex<Vec<String>>,
}

impl ServerState {
    fn issuer(&self) -> String {
        format!("{}{ISSUER_PATH}", self.origin)
    }

    fn document(&self) -> Value {
        json!({
            "issuer": self.issuer(),
            "token_endpoint": format!("{}{TOKEN_ENDPOINT_PATH}", self.origin),
            "jwks_uri": format!("{}{KEY_SET_PATH}", self.origin),
            "response_types_supported": ["code"],
        })
    }

    fn publication(&self) -> MetadataPublication {
        *self
            .publication
            .lock()
            .expect("publication lock")
    }
}

pub struct AuthorizationServer {
    port: u16,
    state: Arc<ServerState>,
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for AuthorizationServer {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("AuthorizationServer")
            .field("port", &self.port)
            .field("publication", &self.state.publication())
            .finish()
    }
}

impl Drop for AuthorizationServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl AuthorizationServer {
    pub async fn start(publication: MetadataPublication) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port for the authorization server");
        let addr: SocketAddr = listener
            .local_addr()
            .expect("authorization server address");
        let state = Arc::new(ServerState {
            origin: format!("http://{addr}"),
            publication: Mutex::new(publication),
            requests: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .fallback(serve)
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("authorization server stops only when aborted");
        });
        Self {
            port: addr.port(),
            state,
            handle,
        }
    }

    pub fn set_publication(
        &self,
        publication: MetadataPublication,
    ) {
        *self
            .state
            .publication
            .lock()
            .expect("publication lock") = publication;
    }

    pub fn issuer(&self) -> String {
        self.state.issuer()
    }

    /// The loopback address the server listens on, as `127.0.0.1:<port>`.
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn key_set_uri(&self) -> String {
        format!("{}{KEY_SET_PATH}", self.state.origin)
    }

    /// The metadata a gateway pins for this server: its issuer, the URL of the
    /// document that answered, its token endpoint and its key set URI.
    ///
    /// # Panics
    ///
    /// When the server publishes no valid document.
    pub fn published_metadata(&self) -> Value {
        let path = match self.state.publication() {
            MetadataPublication::OAuthAuthorizationServer => RFC8414_PATH,
            MetadataPublication::OpenIdConfiguration => OPENID_CONFIGURATION_PATH,
            other => panic!("the authorization server publishes no valid metadata ({other:?})"),
        };
        json!({
            "issuer": self.issuer(),
            "metadata_url": format!("{}{path}", self.state.origin),
            "token_endpoint": format!("{}{TOKEN_ENDPOINT_PATH}", self.state.origin),
            "jwks_uri": self.key_set_uri(),
        })
    }

    /// The paths of every request received so far, in order.
    pub fn requests(&self) -> Vec<String> {
        self.state
            .requests
            .lock()
            .expect("requests lock")
            .clone()
    }

    pub fn key_set_request_count(&self) -> usize {
        self.requests()
            .iter()
            .filter(|path| path.as_str() == KEY_SET_PATH)
            .count()
    }
}

/// The authorization servers of one scenario, by name.
#[derive(Debug, Default)]
pub struct AuthorizationServers {
    servers: HashMap<String, AuthorizationServer>,
}

impl AuthorizationServers {
    /// Start `name` with `publication`, or switch a running server to it.
    pub async fn publish(
        &mut self,
        name: &str,
        publication: MetadataPublication,
    ) -> &AuthorizationServer {
        if let Some(server) = self.servers.get(name) {
            server.set_publication(publication);
        } else {
            let server = AuthorizationServer::start(publication).await;
            self.servers
                .insert(name.to_string(), server);
        }
        self.get(name)
    }

    /// # Panics
    ///
    /// When no authorization server called `name` was started.
    pub fn get(
        &self,
        name: &str,
    ) -> &AuthorizationServer {
        self.servers
            .get(name)
            .unwrap_or_else(|| panic!("unknown authorization server '{name}'"))
    }
}

async fn serve(
    State(state): State<Arc<ServerState>>,
    uri: Uri,
) -> Response {
    let path = uri.path().to_string();
    state
        .requests
        .lock()
        .expect("requests lock")
        .push(path.clone());
    if path == KEY_SET_PATH {
        return json_response(key_set().to_string());
    }
    let publication = state.publication();
    let published_at = match publication {
        MetadataPublication::Absent => None,
        MetadataPublication::OpenIdConfiguration => Some(OPENID_CONFIGURATION_PATH),
        _ => Some(RFC8414_PATH),
    };
    if published_at != Some(path.as_str()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut document = state.document();
    match publication {
        MetadataPublication::ForeignIssuer => {
            document["issuer"] = json!(format!("{}/", state.issuer()));
        }
        MetadataPublication::Oversized => {
            document["padding"] = json!("x".repeat(OVERSIZED_DOCUMENT_BYTES));
        }
        MetadataPublication::WithoutKeySet => {
            document
                .as_object_mut()
                .expect("the metadata document is an object")
                .remove("jwks_uri");
        }
        _ => {}
    }
    json_response(document.to_string())
}

fn json_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn key_set() -> Value {
    json!({
        "keys": [{
            "kty": "OKP",
            "kid": KEY_SET_KID,
            "use": "sig",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": KEY_SET_X,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(
        server: &AuthorizationServer,
        path: &str,
    ) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("http://{}{path}", server.address()))
            .send()
            .await
            .expect("request to the authorization server")
    }

    async fn document_at(
        server: &AuthorizationServer,
        path: &str,
    ) -> Value {
        let response = get(server, path).await;
        assert_eq!(response.status(), 200, "GET {path}");
        response
            .json()
            .await
            .expect("a JSON metadata document")
    }

    #[tokio::test]
    async fn oauth_metadata_is_published_at_the_rfc8414_url_only() {
        let server = AuthorizationServer::start(MetadataPublication::OAuthAuthorizationServer).await;

        let document = document_at(&server, RFC8414_PATH).await;
        let other = get(&server, OPENID_CONFIGURATION_PATH).await;

        assert_eq!(document["issuer"], server.issuer());
        assert_eq!(document["jwks_uri"], server.key_set_uri());
        assert_eq!(other.status(), 404);
        assert_eq!(server.published_metadata()["metadata_url"], format!("http://{}{RFC8414_PATH}", server.address()));
        assert_eq!(server.requests(), vec![RFC8414_PATH.to_string(), OPENID_CONFIGURATION_PATH.to_string()]);
    }

    #[tokio::test]
    async fn openid_configuration_is_published_at_the_appended_url_only() {
        let server = AuthorizationServer::start(MetadataPublication::OpenIdConfiguration).await;

        let rfc8414 = get(&server, RFC8414_PATH).await;
        let document = document_at(&server, OPENID_CONFIGURATION_PATH).await;

        assert_eq!(rfc8414.status(), 404);
        assert_eq!(document["issuer"], server.issuer());
        assert_eq!(
            server.published_metadata(),
            json!({
                "issuer": server.issuer(),
                "metadata_url": format!("http://{}{OPENID_CONFIGURATION_PATH}", server.address()),
                "token_endpoint": format!("http://{}{TOKEN_ENDPOINT_PATH}", server.address()),
                "jwks_uri": server.key_set_uri(),
            })
        );
    }

    #[tokio::test]
    async fn an_absent_publication_answers_404_at_every_metadata_url() {
        let server = AuthorizationServer::start(MetadataPublication::Absent).await;

        for path in [RFC8414_PATH, OPENID_CONFIGURATION_PATH] {
            assert_eq!(
                get(&server, path)
                    .await
                    .status(),
                404,
                "GET {path}"
            );
        }
        assert_eq!(server.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_foreign_issuer_differs_only_by_a_trailing_slash() {
        let server = AuthorizationServer::start(MetadataPublication::ForeignIssuer).await;

        let document = document_at(&server, RFC8414_PATH).await;

        assert_eq!(document["issuer"], format!("{}/", server.issuer()));
        assert_eq!(document["jwks_uri"], server.key_set_uri());
    }

    #[tokio::test]
    async fn an_oversized_document_exceeds_the_64_kib_metadata_limit() {
        let server = AuthorizationServer::start(MetadataPublication::Oversized).await;

        let body = get(&server, RFC8414_PATH)
            .await
            .bytes()
            .await
            .expect("document body");

        assert!(body.len() > 64 * 1024, "document is {} bytes", body.len());
    }

    #[tokio::test]
    async fn a_document_without_a_key_set_names_no_jwks_uri() {
        let server = AuthorizationServer::start(MetadataPublication::WithoutKeySet).await;

        let document = document_at(&server, RFC8414_PATH).await;

        assert_eq!(document["issuer"], server.issuer());
        assert!(
            document
                .get("jwks_uri")
                .is_none(),
            "document {document}"
        );
    }

    #[tokio::test]
    async fn the_key_set_holds_a_key_other_than_the_bdd_signing_key_and_counts_requests() {
        let server = AuthorizationServer::start(MetadataPublication::Absent).await;

        let key_set: Value = get(&server, KEY_SET_PATH)
            .await
            .json()
            .await
            .expect("a JSON key set");

        assert_eq!(key_set["keys"][0]["kid"], KEY_SET_KID);
        assert_ne!(key_set["keys"][0]["kid"], crate::bdd_support::jwt::get_jwks_key_id());
        assert_ne!(key_set["keys"][0]["x"], crate::bdd_support::jwt::public_jwk()["x"]);
        assert_eq!(server.key_set_request_count(), 1);
    }

    #[tokio::test]
    async fn publishing_again_switches_a_running_server_without_restarting_it() {
        let mut servers = AuthorizationServers::default();
        let issuer = servers
            .publish("alpha", MetadataPublication::OAuthAuthorizationServer)
            .await
            .issuer();

        let server = servers
            .publish("alpha", MetadataPublication::Absent)
            .await;

        assert_eq!(server.issuer(), issuer);
        assert_eq!(
            get(server, RFC8414_PATH)
                .await
                .status(),
            404
        );
    }

    #[test]
    #[should_panic(expected = "unknown authorization server 'bravo'")]
    fn an_unknown_authorization_server_is_refused() {
        AuthorizationServers::default().get("bravo");
    }
}
