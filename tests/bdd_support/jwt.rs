use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;

const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPiOVQaSEcxl/NogGyUAX88ouBy1bWJFMp4gi0pcCgcY
-----END PRIVATE KEY-----";
const ED25519_JWK_X: &str = "xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU";
const KID: &str = "bdd-test-key";

pub struct JwksServer {
    pub base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl JwksServer {
    pub async fn start() -> Self {
        let jwks_body = build_jwks_body();

        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let body = jwks_body.clone();
                async move {
                    axum::response::Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .header("Cache-Control", "max-age=3600")
                        .body(axum::body::Body::from(body))
                        .unwrap()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });

        Self {
            base_url: format!("http://{}", addr),
            handle,
        }
    }
}

pub fn sign_jwt(claims: serde_json::Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.to_string());
    let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

pub fn get_jwks_key_id() -> &'static str {
    KID
}

/// The public JWK for the shared BDD signing key, suitable for embedding in a
/// `Static` JWT verification strategy (no running JWKS server required).
pub fn public_jwk() -> serde_json::Value {
    serde_json::json!({
        "kty": "OKP",
        "kid": KID,
        "use": "sig",
        "alg": "EdDSA",
        "crv": "Ed25519",
        "x": ED25519_JWK_X,
    })
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn build_jwks_body() -> String {
    format!(
        r#"{{"keys":[{{"kty":"OKP","kid":"{kid}","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"{x}"}}]}}"#,
        kid = KID,
        x = ED25519_JWK_X,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn sign_jwt_creates_three_part_token_with_expected_kid() {
        let token = super::sign_jwt(serde_json::json!({ "sub": "bdd-user" }));
        let parts = token
            .split('.')
            .collect::<Vec<_>>();

        assert_eq!(parts.len(), 3);
        assert!(
            !parts
                .iter()
                .any(|part| part.is_empty())
        );

        let header = jsonwebtoken::decode_header(&token).expect("decode JWT header");
        assert_eq!(header.kid.as_deref(), Some(super::get_jwks_key_id()));
    }

    #[test]
    fn build_jwks_body_contains_expected_key() {
        let body: serde_json::Value = serde_json::from_str(&super::build_jwks_body()).expect("JWKS JSON");

        assert_eq!(body["keys"][0]["kid"], super::get_jwks_key_id());
        assert_eq!(body["keys"][0]["kty"], "OKP");
        assert_eq!(body["keys"][0]["alg"], "EdDSA");
    }
}
