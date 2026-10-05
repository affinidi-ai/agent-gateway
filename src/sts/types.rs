//! RFC 8693 OAuth 2.0 Token Exchange + ID-JAG type vocabulary.
//!
//! Grant-type / token-type URNs and the request/response shapes for the
//! gateway Security Token Service (`src/sts/`). Kept dependency-light and free
//! of crypto/IO so the exchange and ID-JAG logic can be unit-tested in
//! isolation (see `token_exchange.rs`, `id_jag.rs`).

use serde::{Deserialize, Serialize};

// ── Grant type URNs ───────────────────────────────────────────────────────────

/// RFC 8693 token-exchange grant.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 7523 JWT bearer grant — used to redeem an ID-JAG for an access token.
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

// ── Token type URNs ───────────────────────────────────────────────────────────

pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
/// Identity Assertion JWT Authorization Grant (`draft-ietf-oauth-identity-assertion-authz-grant`).
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// Affinidi extension: a decentralized Verifiable Presentation as the subject assertion.
pub const TOKEN_TYPE_VP: &str = "urn:affinidi:params:oauth:token-type:vp";

/// Explicit JOSE `typ` header for an issued ID-JAG
/// (`draft-ietf-oauth-identity-assertion-authz-grant` §; RFC 8725 explicit typing).
/// Redemption requires this exact `typ` so a plain access/ID token from the same
/// issuer cannot be substituted for an ID-JAG (token confusion).
pub const ID_JAG_JWT_TYP: &str = "oauth-id-jag+jwt";

/// `token_type` value for a bearer access token response.
pub const BEARER: &str = "Bearer";
/// `token_type` value for a non-access issued token (RFC 8693 §2.2.1).
pub const TOKEN_TYPE_N_A: &str = "N_A";

/// A recognized subject/actor/requested token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    AccessToken,
    RefreshToken,
    IdToken,
    Jwt,
    Saml2,
    IdJag,
    Vp,
}

impl TokenType {
    /// Parse a token-type URN. Returns `None` for an unrecognized URN.
    pub fn from_urn(urn: &str) -> Option<Self> {
        match urn {
            TOKEN_TYPE_ACCESS_TOKEN => Some(Self::AccessToken),
            TOKEN_TYPE_REFRESH_TOKEN => Some(Self::RefreshToken),
            TOKEN_TYPE_ID_TOKEN => Some(Self::IdToken),
            TOKEN_TYPE_JWT => Some(Self::Jwt),
            TOKEN_TYPE_SAML2 => Some(Self::Saml2),
            TOKEN_TYPE_ID_JAG => Some(Self::IdJag),
            TOKEN_TYPE_VP => Some(Self::Vp),
            _ => None,
        }
    }

    /// The canonical URN for this token type.
    pub fn as_urn(&self) -> &'static str {
        match self {
            Self::AccessToken => TOKEN_TYPE_ACCESS_TOKEN,
            Self::RefreshToken => TOKEN_TYPE_REFRESH_TOKEN,
            Self::IdToken => TOKEN_TYPE_ID_TOKEN,
            Self::Jwt => TOKEN_TYPE_JWT,
            Self::Saml2 => TOKEN_TYPE_SAML2,
            Self::IdJag => TOKEN_TYPE_ID_JAG,
            Self::Vp => TOKEN_TYPE_VP,
        }
    }

    /// Whether this token type is a JWT-shaped assertion the gateway verifies
    /// with the JWT verifier (`src/jwt_bearer`). `id_token`, `jwt`, and `id-jag`
    /// are JWT-shaped; a Verifiable Presentation is verified by the VC verifier
    /// instead, and access/refresh tokens are opaque to the STS.
    pub fn is_jwt_shaped(&self) -> bool {
        matches!(self, Self::IdToken | Self::Jwt | Self::IdJag)
    }
}

// ── Wire shapes ───────────────────────────────────────────────────────────────

/// Raw, unvalidated `application/x-www-form-urlencoded` token-endpoint body.
///
/// Multi-valued `resource`/`audience` (RFC 8693 permits repetition) are read as
/// a single value in this iteration; repeated parameters collapse to the last
/// occurrence under `serde_urlencoded`. Client credentials may arrive here
/// (`client_secret_post`) or in the `Authorization` header (`client_secret_basic`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenEndpointForm {
    pub grant_type: Option<String>,
    // RFC 8693 token-exchange parameters
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub resource: Option<String>,
    pub audience: Option<String>,
    pub scope: Option<String>,
    // RFC 7523 jwt-bearer parameter (ID-JAG redemption)
    pub assertion: Option<String>,
    // client_secret_post client authentication
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// A validated RFC 8693 token-exchange request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangeRequest {
    pub subject_token: String,
    pub subject_token_type: TokenType,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<TokenType>,
    pub requested_token_type: TokenType,
    pub resource: Option<String>,
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

/// RFC 8693 §2.2.1 token-exchange success response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_type_urn_round_trips() {
        for urn in [
            TOKEN_TYPE_ACCESS_TOKEN,
            TOKEN_TYPE_REFRESH_TOKEN,
            TOKEN_TYPE_ID_TOKEN,
            TOKEN_TYPE_JWT,
            TOKEN_TYPE_SAML2,
            TOKEN_TYPE_ID_JAG,
            TOKEN_TYPE_VP,
        ] {
            let t = TokenType::from_urn(urn).expect("known urn");
            assert_eq!(t.as_urn(), urn, "as_urn must round-trip from_urn for {urn}");
        }
    }

    #[test]
    fn unknown_token_type_urn_is_none() {
        assert_eq!(TokenType::from_urn("urn:example:token-type:made-up"), None);
        assert_eq!(TokenType::from_urn(""), None);
    }

    #[test]
    fn jwt_shaped_classification_is_correct() {
        assert!(TokenType::IdToken.is_jwt_shaped());
        assert!(TokenType::Jwt.is_jwt_shaped());
        assert!(TokenType::IdJag.is_jwt_shaped());
        assert!(!TokenType::Vp.is_jwt_shaped());
        assert!(!TokenType::AccessToken.is_jwt_shaped());
        assert!(!TokenType::RefreshToken.is_jwt_shaped());
        assert!(!TokenType::Saml2.is_jwt_shaped());
    }

    #[test]
    fn response_omits_absent_optionals() {
        let resp = TokenExchangeResponse {
            access_token: "abc".to_string(),
            issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
            token_type: BEARER.to_string(),
            expires_in: None,
            scope: None,
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert!(
            json.get("expires_in")
                .is_none(),
            "expires_in must be omitted when None"
        );
        assert!(json.get("scope").is_none(), "scope must be omitted when None");
        assert_eq!(json["token_type"], "Bearer");
    }
}
