//! Source authentication data models
//!
//! Defines the unified authentication configuration that replaces the old
//! `source_authentication_strategy` and `identity_config` fields on channels.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt_bearer::models::JwtBearerAuthConfig;

// ── Source authentication configuration ──────────────────────────────────────

/// Unified source authentication configuration attached to a channel.
///
/// Replaces the old `AuthenticationStrategy` enum (JWT-only) and the
/// `IdentityConfig` struct (apikey / didauth / mtls modes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceAuthConfig {
    /// Validate inbound bearer tokens against a JWT verification strategy.
    JwtBearer(JwtBearerAuthConfig),

    /// Validate an API key extracted from the request against a secret in the secrets store.
    ApiKey(ApiKeyAuthConfig),

    /// Validate an API key extracted from the request against the API Key Provider.
    ApiKeyProvider(ApiKeyProviderAuthConfig),

    /// Validate a DID Auth session token extracted from the request.
    DidAuth(DidAuthAuthConfig),

    /// Validate via mutual TLS client certificate. Supports both directly
    /// terminated TLS handshakes and forwarded peer certs (XFCC). See
    /// [`MtlsAuthConfig`].
    Mtls(MtlsAuthConfig),
}

impl SourceAuthConfig {
    /// Snake_case identifier for the configured authentication method, matching
    /// the serde `type` discriminant. Used to label a failed source-auth
    /// attempt when handing the outcome to the policy layer.
    pub fn method_tag(&self) -> &'static str {
        match self {
            SourceAuthConfig::JwtBearer(_) => "jwt_bearer",
            SourceAuthConfig::ApiKey(_) => "api_key",
            SourceAuthConfig::ApiKeyProvider(_) => "api_key_provider",
            SourceAuthConfig::DidAuth(_) => "did_auth",
            SourceAuthConfig::Mtls(_) => "mtls",
        }
    }
}

/// API Key authentication configuration (backed by SecretsStore).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyAuthConfig {
    /// Where to extract the API key credential from the inbound request.
    pub extraction: CredentialExtraction,
    /// Secret ID in the secrets store containing valid API keys (comma-separated).
    pub secret_id: String,
}

/// API Key Provider authentication configuration (backed by ApiKeyValidator).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyProviderAuthConfig {
    /// Where to extract the API key credential from the inbound request.
    pub extraction: CredentialExtraction,
    /// Agent ID to validate keys against in the API Key Provider.
    pub agent_id: String,
}

/// DID Auth authentication configuration.
///
/// The caller proves control of a DID by signing a challenge issued by the
/// gateway. The signed challenge is presented as a compact JWS whose `kid`
/// resolves to a verification method in the DID Document. On success the
/// gateway mints an opaque session token that the caller presents in the
/// configured `extraction` slot on subsequent requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DidAuthAuthConfig {
    /// Where to extract the DID Auth session token from the inbound request.
    pub extraction: CredentialExtraction,

    /// Optional allow-list of DIDs authorised to authenticate through this
    /// surface. Empty (default) means any DID that passes signature
    /// verification is accepted. Non-empty entries must start with `did:`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_dids: Vec<String>,

    /// Challenge lifetime in seconds. `None` (default) uses 300s. Rejected at
    /// validation time when `Some(0)` or greater than 3600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_ttl_seconds: Option<u64>,

    /// Session lifetime in seconds. `None` (default) uses 86400s (24h).
    /// Rejected at validation time when `Some(0)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ttl_seconds: Option<u64>,

    /// Required JWS `aud` claim value. When set, the challenge-response JWS
    /// must carry a matching `aud` claim. When `None` the audience check is
    /// skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// JWS `alg` allow-list. Empty (default) uses
    /// `["EdDSA"]` — the algorithm every `did:key` / `did:web` /
    /// `did:webvh` / `did:peer` verification method supported by the
    /// gateway can produce. Additional entries must be one of the
    /// supported algorithms; unknown entries are rejected at validation
    /// time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_algorithms: Vec<String>,
}

impl DidAuthAuthConfig {
    /// Default challenge TTL applied when `challenge_ttl_seconds` is unset.
    pub const DEFAULT_CHALLENGE_TTL_SECONDS: u64 = 300;

    /// Default session TTL applied when `session_ttl_seconds` is unset.
    pub const DEFAULT_SESSION_TTL_SECONDS: u64 = 86_400;

    /// Upper bound for `challenge_ttl_seconds`. Longer challenges expand the
    /// replay window without a real use-case.
    pub const MAX_CHALLENGE_TTL_SECONDS: u64 = 3_600;

    /// Every `alg` value the JWS verifier recognises. Config values outside
    /// this set are rejected at validation time.
    pub const SUPPORTED_ALGORITHMS: &'static [&'static str] = &["EdDSA", "ES256"];

    /// Effective challenge TTL, applying the default when unset.
    pub fn effective_challenge_ttl_seconds(&self) -> u64 {
        self.challenge_ttl_seconds
            .unwrap_or(Self::DEFAULT_CHALLENGE_TTL_SECONDS)
    }

    /// Effective session TTL, applying the default when unset.
    pub fn effective_session_ttl_seconds(&self) -> u64 {
        self.session_ttl_seconds
            .unwrap_or(Self::DEFAULT_SESSION_TTL_SECONDS)
    }

    /// Effective algorithm allow-list, applying the `["EdDSA"]` default when
    /// unset.
    pub fn effective_allowed_algorithms(&self) -> Vec<String> {
        if self
            .allowed_algorithms
            .is_empty()
        {
            vec!["EdDSA".to_string()]
        } else {
            self.allowed_algorithms
                .clone()
        }
    }
}

/// mTLS authentication configuration.
///
/// Two-dimensional model:
/// - `trust` — how the presented client certificate is trusted (pinned to
///   exact certs, or chain-validated against one or more CAs).
/// - `identity_binding` — how the verified certificate is converted into a
///   stable principal string for downstream OPA / audit / metrics use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MtlsAuthConfig {
    /// How to establish trust in the presented client certificate.
    pub trust: MtlsTrust,

    /// How to derive the caller's principal from the verified cert.
    pub identity_binding: MtlsIdentityBinding,

    /// Optional principal allow-list (post-binding, supports `*` glob).
    /// Empty list = allow any principal that passes the trust check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_subjects: Vec<String>,

    /// Whether this channel accepts certificates that came in via a
    /// forwarded-client-cert header (XFCC or similar). Defaults to `true`.
    /// Set to `false` to require that this channel only honour
    /// directly-terminated TLS client certs even on a listener that allows
    /// XFCC.
    #[serde(default = "default_true")]
    pub allow_forwarded: bool,
}

fn default_true() -> bool {
    true
}

/// How to verify trust in an inbound client certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MtlsTrust {
    /// Accept only these exact certificates, matched by SHA-256
    /// fingerprint of the stored leaf DER. No chain verification.
    /// `certificate_ids` references entries in the certificates store
    /// whose `kind == ClientLeaf`.
    Pinned { certificate_ids: Vec<String> },

    /// Verify the presented leaf chains to one of the configured CAs.
    /// `ca_certificate_ids` references entries in the certificates store
    /// whose `kind == Ca`.
    Ca {
        ca_certificate_ids: Vec<String>,
        /// Require the leaf certificate to carry the TLS Client
        /// Authentication EKU (1.3.6.1.5.5.7.3.2). Defaults `true`.
        #[serde(default = "default_true")]
        require_client_auth_eku: bool,
        /// CRL checking (not yet implemented — `true` is rejected at
        /// authentication time with a clear error).
        #[serde(default)]
        check_crl: bool,
        /// OCSP stapling (not yet implemented — `true` is rejected at
        /// authentication time with a clear error).
        #[serde(default)]
        require_ocsp: bool,
    },
}

/// How to derive a principal string from a verified client certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MtlsIdentityBinding {
    /// Lowercase hex SHA-256 fingerprint of the leaf DER. Always available.
    Fingerprint,
    /// Subject Common Name (CN). Errors at runtime if the cert has no CN.
    SubjectCn,
    /// First DNS SubjectAltName. Errors if absent.
    DnsSan,
    /// First URI SubjectAltName. Errors if absent. (SPIFFE IDs flow
    /// through this binding mode.)
    UriSan,
    /// First IP SubjectAltName, rendered canonically (`1.2.3.4` or `::1`).
    /// Errors if absent.
    IpSan,
    /// Take an arbitrary RDN by OID from the Subject DN (e.g. UID =
    /// `0.9.2342.19200300.100.1.1`). Errors if the RDN is not present.
    SubjectRdn { oid: String },
}

impl SourceAuthConfig {
    /// Returns the HTTP header name that this source auth extracts credentials
    /// from, if any. Used to strip the header before forwarding upstream — the
    /// source credential is consumed by the gateway and must not leak.
    pub fn credential_header_name(&self) -> Option<&str> {
        match self {
            SourceAuthConfig::JwtBearer(c) => Some(c.token_header.as_str()),
            SourceAuthConfig::ApiKey(c) => extraction_header(&c.extraction),
            SourceAuthConfig::ApiKeyProvider(c) => extraction_header(&c.extraction),
            SourceAuthConfig::DidAuth(c) => extraction_header(&c.extraction),
            SourceAuthConfig::Mtls(_) => None,
        }
    }
}

fn extraction_header(extraction: &CredentialExtraction) -> Option<&str> {
    match extraction {
        CredentialExtraction::HttpHeader { field } => Some(field.as_str()),
        CredentialExtraction::McpMeta | CredentialExtraction::A2aExtension => None,
    }
}

// ── Credential extraction ────────────────────────────────────────────────────

/// Describes where to extract a credential from the inbound request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CredentialExtraction {
    /// Extract from an HTTP header.
    HttpHeader {
        /// Header field name (e.g. `X-API-Key`, `Authorization`).
        field: String,
    },

    /// Extract from MCP `_meta` object. Requires request body parsing.
    McpMeta,

    /// Extract from A2A message extension. Requires request body parsing.
    A2aExtension,
}

// ── Authenticated identity (result of authentication) ────────────────────────

/// The identity extracted after successful source authentication.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatedIdentity {
    /// JWT Bearer authentication succeeded.
    JwtBearer {
        /// The `sub` claim from the token.
        subject: String,
        /// All decoded claims.
        claims: Value,
    },

    /// API Key authentication succeeded.
    ApiKey {
        /// The human-readable name of the validated key.
        key_name: String,
    },

    /// DID Auth session authentication succeeded.
    DidAuth {
        /// The authenticated DID.
        did: String,
    },

    /// mTLS authentication succeeded. Populated by [`MtlsAuthConfig`]
    /// after the presented client certificate has been verified against
    /// the configured trust policy and the identity binding has been
    /// applied.
    Mtls {
        /// Principal derived per [`MtlsIdentityBinding`].
        principal: String,
        /// Lowercase hex SHA-256 of the leaf DER. Always populated.
        fingerprint: String,
        /// Subject DN as an RFC 4514 string.
        subject_dn: String,
        /// Issuer DN. Empty for [`MtlsTrust::Pinned`] (no chain verified).
        issuer_dn: String,
        /// SANs captured from the leaf, for audit / OPA visibility even
        /// when they are not used as the principal.
        sans: MtlsSans,
        /// Where the certificate was captured from (direct TLS handshake
        /// vs forwarded-client-cert header).
        source: PeerCertSource,
    },
}

impl AuthenticatedIdentity {
    /// The decoded JWT claim set, when this identity was produced by JWT
    /// Bearer source authentication. Returns `None` for every other auth
    /// mode. Used by `ManagedIdentityConfig::FromJwtClaim` to derive the
    /// agent DID from a validated token claim (e.g. an Entra Agent ID `oid`).
    pub fn jwt_claims(&self) -> Option<&Value> {
        match self {
            AuthenticatedIdentity::JwtBearer { claims, .. } => Some(claims),
            _ => None,
        }
    }

    /// A stable key for the authenticated caller, distinct across auth modes,
    /// for per-caller limits.
    pub fn principal_key(&self) -> String {
        match self {
            AuthenticatedIdentity::JwtBearer { subject, .. } => format!("jwt:{subject}"),
            AuthenticatedIdentity::ApiKey { key_name } => format!("api-key:{key_name}"),
            AuthenticatedIdentity::DidAuth { did } => format!("did-auth:{did}"),
            AuthenticatedIdentity::Mtls { principal, .. } => format!("mtls:{principal}"),
        }
    }
}

/// SubjectAltName values lifted off a verified leaf certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsSans {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uri: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
}

/// Where the inbound client certificate was captured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCertSource {
    /// Captured from the rustls TLS handshake on this gateway.
    DirectTls,
    /// Parsed out of a trusted forwarded-client-cert header (XFCC etc.).
    Forwarded,
}

impl PeerCertSource {
    /// Stable low-cardinality string used in metrics labels, structured
    /// logs and the audit record. Kept in sync with the serde rename.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerCertSource::DirectTls => "direct_tls",
            PeerCertSource::Forwarded => "forwarded",
        }
    }
}

impl std::fmt::Display for PeerCertSource {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A raw inbound client certificate captured by the listener layer and
/// stashed into request extensions for the source-auth middleware to
/// consume. This type intentionally carries only the wire bytes — all
/// parsing, trust checks, and identity binding happen in
/// [`crate::source_auth::mtls`].
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    /// Leaf certificate DER bytes.
    pub leaf_der: Vec<u8>,
    /// Intermediate certificates the peer offered, in chain order (closest
    /// to the leaf first, root last). Excludes the leaf — it lives in
    /// `leaf_der`. May be empty if the peer sent only the leaf or if the
    /// capture path (e.g. XFCC) does not carry intermediates.
    pub chain_der: Vec<Vec<u8>>,
    /// Where this certificate came from.
    pub source: PeerCertSource,
}

// ── Managed identity configuration ──────────────────────────────────────────

/// Configuration for deriving the *upstream* agent identity that a Surface
/// represents. This is logically distinct from `SourceAuthConfig` (which
/// authenticates the inbound caller); it tells the runtime where to find
/// the identity of the agent on the other side of the Target.
///
/// Today the proxy pipeline acts on `PayloadExtraction` only — the other
/// variants are persisted faithfully so the dashboard and the
/// `AgentSurface ↔ ChannelMapping` round-trip do not silently drop user
/// configuration. Runtime support for the remaining variants is added
/// incrementally; the tag string matches the surface's
/// `IdentityInjectionConfig.identity_type` discriminator
/// (`from_payload` / `from_api_key` / `from_mtls` / `static`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum ManagedIdentityConfig {
    /// Extract identity from a field in the request payload metadata.
    /// Serialized tag is `payload_extraction` for backward compatibility
    /// with channel JSON written by older builds; `from_payload` is
    /// accepted on the wire to match the dashboard's
    /// `IdentityInjectionConfig.identity_type` discriminator.
    #[serde(alias = "from_payload")]
    PayloadExtraction(PayloadExtractionConfig),

    /// Use an API key (presented by the caller or bound to the surface)
    /// to look up the upstream agent identity.
    FromApiKey {
        /// API key identifier (matches a stored key in the secret store).
        api_key_id: String,
    },

    /// Take the upstream agent identity from the TLS client certificate.
    FromMtls {
        /// Stored certificate identifier.
        certificate_id: String,
    },

    /// Always present a fixed DID as the upstream agent identity (test
    /// fixtures, stub agents).
    Static {
        /// The DID to present as the upstream agent.
        did: String,
    },

    /// Derive the agent identity from a validated inbound JWT claim — e.g. a
    /// Microsoft Entra Agent ID `oid`. **Request-bound**: unlike `FromMtls` /
    /// `FromApiKey` (which read a stored credential and are independent of
    /// source auth), this mode consumes the claim set produced by
    /// `SourceAuthConfig::JwtBearer` on the same surface, so the token is
    /// cryptographically verified before the DID is derived. One stable
    /// `did:webvh` is minted per distinct claim value (namespaced by
    /// `namespace_claims`), so token rotation keeps the DID stable while a
    /// shared identity-hash pepper keeps it identical across every gateway in
    /// the fabric.
    FromJwtClaim {
        /// Claim whose value identifies the agent. Defaults to `oid` (the
        /// stable, immutable Entra Agent ID object identifier).
        #[serde(default = "default_jwt_identity_claim")]
        claim: String,

        /// Additional claims folded into the identity hash to namespace the
        /// agent across tenants / issuers (e.g. `["iss", "tid"]`). All listed
        /// claims must be present on the token or resolution fails.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        namespace_claims: Vec<String>,
    },
}

impl ManagedIdentityConfig {
    /// How a caller DID derived through this mode counts in policy input.
    /// Only `FromJwtClaim` binds the DID to the credential authenticated on
    /// the request; every other mode reads stored configuration or the
    /// payload, which nothing about the request proves.
    pub fn caller_verification(&self) -> crate::surface_context::IdentityVerification {
        match self {
            Self::FromJwtClaim { .. } => crate::surface_context::IdentityVerification::SourceAuth,
            Self::PayloadExtraction(_) | Self::FromApiKey { .. } | Self::FromMtls { .. } | Self::Static { .. } => {
                crate::surface_context::IdentityVerification::Unverified
            }
        }
    }
}

/// Default identity claim for [`ManagedIdentityConfig::FromJwtClaim`].
///
/// `oid` is the Microsoft Entra object identifier — stable and immutable per
/// agent identity, which is exactly what a durable DID must key off.
pub fn default_jwt_identity_claim() -> String {
    "oid".to_string()
}

/// Configuration for payload-based identity extraction.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PayloadExtractionConfig {
    /// The A2A metadata extension URI that carries this slot's identity payload.
    /// Defaults to Affinidi's existing agent-identity extension for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_uri: Option<String>,

    /// The field name in the payload metadata to extract identity from.
    pub meta_field: String,

    /// Dot-notation paths inside the extracted identity object that are
    /// concatenated and hashed to derive the agent DID. Mirrors the
    /// dashboard's `IdentityInjectionConfig.fields` — persisted here so
    /// the wire format is the source of truth instead of relying on the
    /// opaque per-surface canvas blob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,

    /// JSON Schema describing the expected identity object on the wire.
    /// Generated by the dashboard's identity onboarding flow and used
    /// (by extension validation) to reject malformed identity payloads
    /// before extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// Validation rules for the `agent-identity/v1` extension payload.
    /// When present, the identity extension is validated against these rules
    /// before extraction, flattening, hashing, and DID issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<crate::config::ExtensionRules>,

    /// When `true`, the raw `_meta[meta_field]` entry is removed from the
    /// forwarded message after the gateway has extracted the identity and
    /// injected the signed credential extension. Defaults to `false` so
    /// existing surfaces retain their current behaviour (raw field passes
    /// through alongside the credential). Set to `true` to ensure the MCP
    /// server or upstream only ever sees the signed VP, not the raw identity
    /// block.
    ///
    /// Applies to both the inbound slot (raw `agentIdentity` in the
    /// forwarded request) and the protected slot (raw `serverIdentity` in
    /// the response returned to the caller).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub strip_raw_meta: bool,
}

impl PayloadExtractionConfig {
    pub fn identity_extension_uri(&self) -> &str {
        self.extension_uri
            .as_deref()
            .unwrap_or(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_request_bound_managed_identity_counts_as_verified() {
        use crate::surface_context::IdentityVerification;

        let jwt = ManagedIdentityConfig::FromJwtClaim {
            claim: "oid".to_string(),
            namespace_claims: vec!["iss".to_string()],
        };
        assert_eq!(jwt.caller_verification(), IdentityVerification::SourceAuth);
        assert!(
            jwt.caller_verification()
                .is_verified()
        );

        for configured in [
            ManagedIdentityConfig::Static {
                did: "did:web:agent.example".to_string(),
            },
            ManagedIdentityConfig::FromMtls {
                certificate_id: "cert-1".to_string(),
            },
            ManagedIdentityConfig::FromApiKey {
                api_key_id: "key-1".to_string(),
            },
        ] {
            assert_eq!(configured.caller_verification(), IdentityVerification::Unverified, "{configured:?}");
            assert!(
                !configured
                    .caller_verification()
                    .is_verified()
            );
        }
    }

    #[test]
    fn source_auth_config_jwt_bearer_roundtrip() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec!["aud1".to_string()],
            ..Default::default()
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.credential_header_name(), Some("Authorization"));
        assert_eq!(back, config);
    }

    #[test]
    fn jwt_bearer_legacy_json_defaults_to_authorization_bearer() {
        // Stored surfaces created before token_header/token_scheme existed must
        // still deserialise and behave like the canonical Authorization: Bearer.
        let legacy = r#"{
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "strat-1",
            "audiences": []
        }"#;
        let cfg: SourceAuthConfig = serde_json::from_str(legacy).unwrap();
        match cfg {
            SourceAuthConfig::JwtBearer(c) => {
                assert_eq!(c.token_header, "Authorization");
                assert_eq!(c.token_scheme, "Bearer");
                assert!(!c.forward_header);
            }
            _ => panic!("expected JwtBearer"),
        }
    }

    #[test]
    fn jwt_bearer_custom_header_and_scheme_roundtrip() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec![],
            token_header: "X-Auth-Token".to_string(),
            token_scheme: String::new(),
            forward_header: false,
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn source_auth_config_apikey_roundtrip() {
        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_from_jwt_claim_roundtrip() {
        let config = ManagedIdentityConfig::FromJwtClaim {
            claim: "oid".to_string(),
            namespace_claims: vec!["iss".to_string(), "tid".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"from_jwt_claim\""));
        assert!(json.contains("\"claim\":\"oid\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_from_jwt_claim_defaults_claim_to_oid() {
        // The dashboard may omit `claim` to accept the Entra default. Verify
        // the serde default fills it in and `namespace_claims` defaults empty.
        let json = r#"{"type":"from_jwt_claim"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            ManagedIdentityConfig::FromJwtClaim {
                claim: "oid".to_string(),
                namespace_claims: Vec::new(),
            }
        );
    }

    #[test]
    fn authenticated_identity_jwt_claims_accessor() {
        let id = AuthenticatedIdentity::JwtBearer {
            subject: "agent-1".to_string(),
            claims: serde_json::json!({"oid": "abc", "tid": "tenant-1"}),
        };
        let claims = id
            .jwt_claims()
            .expect("JwtBearer exposes claims");
        assert_eq!(
            claims
                .get("oid")
                .and_then(|v| v.as_str()),
            Some("abc")
        );

        let other = AuthenticatedIdentity::ApiKey { key_name: "k".to_string() };
        assert!(other.jwt_claims().is_none());
    }

    #[test]
    fn source_auth_config_apikey_provider_roundtrip() {
        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn source_auth_config_didauth_roundtrip() {
        let config = SourceAuthConfig::DidAuth(DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader {
                field: "Authorization".to_string(),
            },
            allowed_dids: vec![],
            challenge_ttl_seconds: None,
            session_ttl_seconds: None,
            audience: None,
            allowed_algorithms: vec![],
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn source_auth_config_didauth_optional_fields_round_trip() {
        let config = SourceAuthConfig::DidAuth(DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-Session".to_string() },
            allowed_dids: vec!["did:example:alice".to_string()],
            challenge_ttl_seconds: Some(600),
            session_ttl_seconds: Some(3600),
            audience: Some("https://gw.example.com/agent".to_string()),
            allowed_algorithms: vec!["EdDSA".to_string(), "ES256".to_string()],
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn didauth_default_ttl_and_alg_helpers() {
        let cfg = DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-Session".to_string() },
            allowed_dids: vec![],
            challenge_ttl_seconds: None,
            session_ttl_seconds: None,
            audience: None,
            allowed_algorithms: vec![],
        };
        assert_eq!(cfg.effective_challenge_ttl_seconds(), 300);
        assert_eq!(cfg.effective_session_ttl_seconds(), 86_400);
        assert_eq!(cfg.effective_allowed_algorithms(), vec!["EdDSA".to_string()]);

        let custom = DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-Session".to_string() },
            allowed_dids: vec![],
            challenge_ttl_seconds: Some(60),
            session_ttl_seconds: Some(120),
            audience: None,
            allowed_algorithms: vec!["ES256".to_string()],
        };
        assert_eq!(custom.effective_challenge_ttl_seconds(), 60);
        assert_eq!(custom.effective_session_ttl_seconds(), 120);
        assert_eq!(custom.effective_allowed_algorithms(), vec!["ES256".to_string()]);
    }

    #[test]
    fn source_auth_config_mtls_roundtrip() {
        let config = SourceAuthConfig::Mtls(MtlsAuthConfig {
            trust: crate::source_auth::models::MtlsTrust::Pinned {
                certificate_ids: vec!["cert-1".to_string()],
            },
            identity_binding: crate::source_auth::models::MtlsIdentityBinding::Fingerprint,
            allowed_subjects: Vec::new(),
            allow_forwarded: true,
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn payload_extraction_defaults_to_agent_identity_extension_uri() {
        let cfg = PayloadExtractionConfig {
            meta_field: "agentIdentity".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.identity_extension_uri(), crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION);

        let json = serde_json::json!({
            "meta_field": "agentIdentity"
        });
        let cfg: PayloadExtractionConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.identity_extension_uri(), crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION);
    }

    #[test]
    fn payload_extraction_custom_extension_uri_roundtrips() {
        let cfg = PayloadExtractionConfig {
            extension_uri: Some(
                crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI.to_string(),
            ),
            meta_field: "agentIdentity".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            json["extension_uri"].as_str(),
            Some(crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI)
        );
        let back: PayloadExtractionConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.identity_extension_uri(),
            crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI
        );
    }

    #[test]
    fn managed_identity_payload_extraction_roundtrip() {
        let config = ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: false,
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn payload_extraction_strip_raw_meta_roundtrip() {
        // strip_raw_meta=true must be persisted and round-trip correctly.
        let config = ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: true,
        });
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("strip_raw_meta"), "strip_raw_meta=true must appear in serialized JSON");
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn payload_extraction_strip_raw_meta_defaults_false() {
        // Existing stored surfaces without strip_raw_meta must default to false.
        let json = r#"{"type":"payload_extraction","meta_field":"agentIdentity"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        match back {
            ManagedIdentityConfig::PayloadExtraction(cfg) => {
                assert!(!cfg.strip_raw_meta, "strip_raw_meta must default to false");
            }
            _ => panic!("expected PayloadExtraction"),
        }
    }

    #[test]
    fn managed_identity_payload_extraction_legacy_tag() {
        // Channel JSON written by previous builds uses `payload_extraction`
        // as the discriminator. Verify the tag stays stable so disk state
        // continues to deserialize after the enum was extended.
        let json = r#"{"type":"payload_extraction","meta_field":"agentIdentity"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            })
        );
    }

    #[test]
    fn managed_identity_payload_extraction_from_payload_alias() {
        // Dashboard sends the `IdentityInjectionConfig.identity_type` tag
        // (`from_payload`) for identity slots; accept it as an alias.
        let json = r#"{"type":"from_payload","meta_field":"agentIdentity"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            })
        );
    }

    #[test]
    fn managed_identity_from_api_key_roundtrip() {
        let config = ManagedIdentityConfig::FromApiKey {
            api_key_id: "key-1".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"from_api_key\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_from_mtls_roundtrip() {
        let config = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"from_mtls\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_static_roundtrip() {
        let config = ManagedIdentityConfig::Static {
            did: "did:example:42".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"static\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn credential_extraction_http_header_roundtrip() {
        let extraction = CredentialExtraction::HttpHeader {
            field: "X-Custom-Header".to_string(),
        };
        let json = serde_json::to_string(&extraction).unwrap();
        let back: CredentialExtraction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, extraction);
    }

    #[test]
    fn payload_extraction_config_persists_fields_and_json_schema() {
        let cfg = PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: vec!["a.b".to_string(), "a.c".to_string()],
            json_schema: Some(serde_json::json!({"type": "object"})),
            extension_rules: None,
            strip_raw_meta: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"fields\":[\"a.b\",\"a.c\"]"));
        assert!(json.contains("\"json_schema\":{"));
        let back: PayloadExtractionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn payload_extraction_config_omits_empty_fields_and_schema() {
        let cfg = PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("\"fields\""));
        assert!(!json.contains("\"json_schema\""));
        let back: PayloadExtractionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }
}
