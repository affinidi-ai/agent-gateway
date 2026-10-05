//! JWT test utilities: key material, token signing, and JWKS fixture helpers.

use std::path::Path;

use crate::config::GatewayConfig;
use crate::jwt_bearer::test_utils::TestServer;

// Ed25519 test key pair (same as src/source_auth/middleware.rs tests)
const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPiOVQaSEcxl/NogGyUAX88ouBy1bWJFMp4gi0pcCgcY
-----END PRIVATE KEY-----";
const ED25519_JWK_X: &str = "xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU";

pub fn sign_jwt(
    claims: serde_json::Value,
    kid: &str,
) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Running JWKS server + pre-built strategy JSON for E2E JWT tests.
///
/// Holds the server guard so the JWKS endpoint stays alive for the test's
/// lifetime.
pub struct JwksFixture {
    pub kid: String,
    pub issuer: String,
    _jwks_server: TestServer,
}

impl JwksFixture {
    const DEFAULT_KID: &str = "e2e-test-key";

    /// Start a mock JWKS server with the Ed25519 public key and build the
    /// matching JWT verification strategy JSON.
    pub async fn start() -> Self {
        let kid = Self::DEFAULT_KID;

        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"OKP","kid":"{kid}","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"{x}"}}]}}"#,
            kid = kid,
            x = ED25519_JWK_X,
        );

        let (jwks_url, jwks_server) = crate::jwt_bearer::test_utils::start_jwks_server(jwks_body, Some(3600)).await;

        Self {
            kid: kid.to_string(),
            issuer: jwks_url.to_string(),
            _jwks_server: jwks_server,
        }
    }
}

const JWK_STRATEGY_ID: &str = "e2e-jwt-strategy";

/// Setup function for `jwt_bearer_auth_rejects_missing_then_accepts_valid`.
///
/// Writes a JWT verification strategy fixture to disk and configures the gateway
/// with a channel that requires JWT Bearer authentication.
pub fn setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(
    fixture: &JwksFixture,
    temp_dir: &Path,
    gw_config: &mut GatewayConfig,
) {
    // Build and write the JWT verification strategy fixture to disk.
    let strategy_json = serde_json::json!({
        "id": JWK_STRATEGY_ID,
        "name": "E2E EdDSA Test",
        "expected_issuer": fixture.issuer,
        "jwks_source": {
            "type": "remote",
            "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer),
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    let strat_dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&strat_dir).expect("create strategy dir");
    std::fs::write(
        strat_dir.join(format!("{}.json", JWK_STRATEGY_ID)),
        serde_json::to_string_pretty(&strategy_json).expect("serialize strategy"),
    )
    .expect("write strategy fixture");

    // Build a surface with JWT Bearer authentication on the access point.
    let json = serde_json::json!({
        "name": "jwt-auth-test",
        "description": "E2E JWT Bearer auth test",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a",
            "caller_authentication": {
                "methods": [{
                    "type": "jwt_bearer",
                    "jwt_verification_strategy_id": JWK_STRATEGY_ID,
                    "audiences": []
                }]
            }
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        }
    });
    gw_config.surfaces = vec![serde_json::from_value(json).expect("jwt channel: AgentSurface JSON")];
}

/// Setup for the inbound `from_jwt_claim` managed-identity E2E tests.
///
/// Writes a JWT verification strategy fixture and builds a surface that (a)
/// requires JWT Bearer auth on the access point and (b) derives the protected
/// agent DID from the validated `oid` claim (`identity_slots.protected =
/// from_jwt_claim`). The transit point lets `GatewayHarness::start_with_outbound_mock`
/// patch the forward target.
pub fn setup_jwt_claim_managed_identity(
    fixture: &JwksFixture,
    temp_dir: &Path,
    gw_config: &mut GatewayConfig,
) {
    let strategy_json = serde_json::json!({
        "id": JWK_STRATEGY_ID,
        "name": "E2E EdDSA Test",
        "expected_issuer": fixture.issuer,
        "jwks_source": {
            "type": "remote",
            "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer),
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    let strat_dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&strat_dir).expect("create strategy dir");
    std::fs::write(
        strat_dir.join(format!("{}.json", JWK_STRATEGY_ID)),
        serde_json::to_string_pretty(&strategy_json).expect("serialize strategy"),
    )
    .expect("write strategy fixture");

    let json = serde_json::json!({
        "name": "jwt-claim-identity",
        "description": "E2E from_jwt_claim managed identity test",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a",
            "caller_authentication": {
                "methods": [{
                    "type": "jwt_bearer",
                    "jwt_verification_strategy_id": JWK_STRATEGY_ID,
                    "audiences": []
                }]
            }
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false
            }]
        },
        "identity_slots": {
            "protected": {
                "type": "from_jwt_claim",
                "claim": "oid",
                "namespace_claims": ["iss"]
            }
        }
    });
    gw_config.surfaces = vec![serde_json::from_value(json).expect("jwt-claim channel: AgentSurface JSON")];
}

/// Setup for the **inbound-slot** `from_jwt_claim` E2E test.
///
/// Mirrors [`setup_jwt_claim_managed_identity`] but places the identity on the
/// request leg (`identity_slots.inbound = from_jwt_claim`) and enables
/// `inject_vp` on the target so the caller's derived identity VP is injected
/// into the request forwarded upstream.
pub fn setup_jwt_claim_inbound_identity(
    fixture: &JwksFixture,
    temp_dir: &Path,
    gw_config: &mut GatewayConfig,
) {
    let strategy_json = serde_json::json!({
        "id": JWK_STRATEGY_ID,
        "name": "E2E EdDSA Test",
        "expected_issuer": fixture.issuer,
        "jwks_source": {
            "type": "remote",
            "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer),
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    let strat_dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&strat_dir).expect("create strategy dir");
    std::fs::write(
        strat_dir.join(format!("{}.json", JWK_STRATEGY_ID)),
        serde_json::to_string_pretty(&strategy_json).expect("serialize strategy"),
    )
    .expect("write strategy fixture");

    let json = serde_json::json!({
        "name": "jwt-claim-inbound-identity",
        "description": "E2E inbound from_jwt_claim test",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a",
            "caller_authentication": {
                "methods": [{
                    "type": "jwt_bearer",
                    "jwt_verification_strategy_id": JWK_STRATEGY_ID,
                    "audiences": []
                }]
            }
        },
        "target": {
            "endpoint": "inbound_target_placeholder",
            "identity_injection": {
                "inject_vp": true
            }
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false
            }]
        },
        "identity_slots": {
            "inbound": {
                "type": "from_jwt_claim",
                "claim": "oid",
                "namespace_claims": ["iss"]
            }
        }
    });
    gw_config.surfaces = vec![serde_json::from_value(json).expect("jwt-claim inbound channel: AgentSurface JSON")];
}
