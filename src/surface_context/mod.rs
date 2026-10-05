use serde::Serialize;
use std::collections::HashMap;

// ── PolicyInput ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<SurfaceRoutingContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a: Option<A2aContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_identity: Option<ExtensionIdentityContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<IdentityBindingContext>,

    /// Per-leg Trust Check results: outcomes of the configured
    /// `AccessPoint.trust_check_list` / `Target.trust_check_list` elements
    /// the Trust Check stage executed on this request leg. `None` when no
    /// element fired (either no list was configured for the leg or the
    /// stage was not wired into this code path); `Some` carries both
    /// `caller` and `target` lists (the leg that didn't run on this seam
    /// is an empty list, so OPA rules don't need null checks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_check_results: Option<crate::trust_registry_verification::TrustCheckResultsContext>,
}

impl PolicyInput {
    /// Build a `PolicyInput` with HTTP, gateway, and channel context pre-populated.
    ///
    /// Callers set remaining optional fields (`source_auth`, `agent`, `mcp`,
    /// `extension_identity`, `payment`) on the returned value.
    pub fn new(
        method: &str,
        path: &str,
        filtered_headers: HashMap<String, String>,
        direction: &str,
        source_id: Option<String>,
        target_id: Option<String>,
        config_id: Option<String>,
        channel_name: &str,
    ) -> Self {
        Self {
            http: Some(HttpContext {
                method: method.to_string(),
                path: path.to_string(),
                headers: filtered_headers,
            }),
            gateway: Some(GatewayContext {
                direction: direction.to_string(),
                source_id,
                target_id,
            }),
            channel: Some(SurfaceRoutingContext {
                config_id,
                name: Some(channel_name.to_string()),
                variant_alias: None,
            }),
            ..Default::default()
        }
    }

    /// Promote the gateway-derived caller DID into `input.agent.did` when
    /// the inbound payload didn't assert one. After the caller is
    /// identified (`extension_identity.did` populated by the managed-
    /// identity resolver) `input.agent.did` is the *effective* caller DID,
    /// not just the value asserted by the trust-registry extension in the
    /// body. Templates, OPA rules and Trust Check entries can read
    /// `input.agent.did` without per-site fallback chains. The promoted DID
    /// carries `extension_identity.verified` / `verification` into
    /// `agent.did_verified` / `did_verification`; a payload-asserted
    /// `agent.did` equal to the resolved extension DID is marked verified when
    /// the extension identity is. No-op when `agent.did` is already set to a
    /// different DID or `extension_identity.did` is missing.
    pub fn normalize_caller_did(&mut self) {
        let Some((ext_did, verification)) = self
            .extension_identity
            .as_ref()
            .and_then(|e| {
                e.did
                    .clone()
                    .map(|did| (did, e.verification))
            })
        else {
            return;
        };
        match self.agent.as_mut() {
            Some(agent) if agent.tr_identity_mismatch => {}
            Some(agent) if agent.did.is_none() => {
                agent.did = Some(ext_did);
                agent.did_verified = verification.is_verified();
                agent.did_verification = Some(verification);
            }
            Some(agent) if agent.did.as_deref() == Some(ext_did.as_str()) => {
                agent.did_verified = verification.is_verified();
                agent.did_verification = Some(verification);
            }
            Some(_) => {}
            None => {
                self.agent = Some(AgentContext {
                    trust_verification: None,
                    source_trust_verification: None,
                    target_trust_verification: None,
                    did: Some(ext_did),
                    did_verified: verification.is_verified(),
                    did_verification: Some(verification),
                    agent_dna: None,
                    trust_registry_did: None,
                    provider_did: None,
                    authority_did: None,
                    identity_issuer_did: None,
                    tr_identity_mismatch: false,
                });
            }
        }
    }
}

/// Returns `true` if the header name is sensitive and should be stripped.
///
/// Delegates to the single canonical classifier in
/// `config::header_metadata_mapping` so every header-filtering call site
/// (inbound, outbound, fabric) excludes the same set of credential-bearing
/// headers instead of each defining its own partial denylist.
fn is_sensitive_header(name: &str) -> bool {
    crate::config::header_metadata_mapping::is_sensitive_header(name)
}

/// Filter sensitive headers (authorization, cookie, token, secret, credential, api-key) from an axum `HeaderMap`.
pub fn filter_sensitive_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_sensitive_header(&k.as_str().to_lowercase()))
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect()
}

/// Filter sensitive headers from a JSON header map (used by connection-point message processing).
pub fn filter_sensitive_json_headers(
    headers: Option<&serde_json::Map<String, serde_json::Value>>
) -> HashMap<String, String> {
    headers
        .map(|h| {
            h.iter()
                .filter(|(k, _)| !is_sensitive_header(&k.to_lowercase()))
                .filter_map(|(k, v)| {
                    v.as_str()
                        .map(|val| (k.clone(), val.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Context types (moved from opa.rs) ──────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HttpContext {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct McpContext {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_capabilities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_info: Option<serde_json::Value>,
}

/// A2A/AP2 request payload injected as `input.a2a` into Rego, letting policies
/// inspect the actual agent message. `message` is the A2A message object
/// (`params.message` or top-level `message`), carrying `role`, `parts`,
/// `metadata`, `messageId`, etc. `method` is exactly as the caller sent it;
/// `method_canonical` is its v0.3 slash-form when the method is a recognised A2A
/// method in either era, and absent otherwise.
#[derive(Debug, Clone, Serialize)]
pub struct A2aContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_canonical: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<serde_json::Value>,
}

impl A2aContext {
    pub fn new(
        method: Option<String>,
        message: Option<serde_json::Value>,
    ) -> Self {
        let method_canonical = method
            .as_deref()
            .and_then(crate::a2a::recognised_canonical)
            .map(str::to_string);
        Self {
            method,
            method_canonical,
            message,
        }
    }
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Resolved agent context injected as `input.agent` into Rego.
/// `trust_verification` is `Some(true)` when all trust registry recognition queries pass,
/// `Some(false)` when any query returns false, and `None` when TR data is unavailable.
/// `trust_registry_did` / `provider_did` / `authority_did` mirror the fields the
/// caller's `https://fabric.affinidi.io/extensions/trust-registry` extension carries
/// in the request body so policies (and Trust Check templates) can reference them
/// as `input.agent.{trust_registry_did|provider_did|authority_did}` without parsing
/// the body themselves. All three are `None` when the extension is absent.
/// `tr_identity_mismatch` is `true` when the TR extension's `agent_did` contradicts
/// the identity extension's DID — signals to OPA and prevents `normalize_caller_did`
/// from restoring `agent.did`, keeping the Trust Check entity unresolvable.
/// `did_verified` is `true` only when `did` was carried over from a verified
/// `extension_identity` by `normalize_caller_did`, and `did_verification` says
/// how (see [`IdentityVerification`]). A DID read from the request body or
/// agent card is caller-asserted: `did_verified` stays `false` and
/// `did_verification` is absent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_verification: Option<bool>,
    /// Source (caller) verification result — populated in Both mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_trust_verification: Option<bool>,
    /// Target verification result — populated in Both mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_trust_verification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub did_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_verification: Option<IdentityVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_dna: Option<crate::identity::uai::types::AgentDna>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_issuer_did: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tr_identity_mismatch: bool,
}

// ── Context types (moved from gateway_manager.rs) ──────────

/// Gateway-level policy context added to `input.gateway` in Rego
#[derive(Debug, Clone, Serialize)]
pub struct GatewayContext {
    /// Traffic direction: "inbound" (self gateway) or "outbound" (remote gateway)
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

/// Channel routing context added to `input.channel` in Rego
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceRoutingContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Surface variant alias selected by the request URL (`/route$alias/...`).
    /// `None` when the request targets the default variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,
}

// ── New context types ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SourceAuthContext {
    JwtBearer {
        subject: String,
        claims: serde_json::Value,
    },
    ApiKey {
        key_name: String,
    },
    DidAuth {
        did: String,
    },
    Mtls {
        principal: String,
        fingerprint: String,
        subject_dn: String,
        issuer_dn: String,
        sans: crate::source_auth::models::MtlsSans,
    },
    /// Source authentication was configured and attempted, but the caller's
    /// credential failed to verify (missing or invalid). The request is NOT
    /// blocked at the source-auth stage; instead this outcome is handed to the
    /// policy layer, which decides whether to allow or deny. Policies branch on
    /// `input.source_auth.method == "failed"`.
    ///
    /// Note: the inner field is `attempted_method` (not `method`) to avoid
    /// colliding with the `#[serde(tag = "method")]` discriminant.
    Failed {
        attempted_method: String,
        reason: String,
    },
}

impl From<&crate::source_auth::AuthenticatedIdentity> for SourceAuthContext {
    fn from(identity: &crate::source_auth::AuthenticatedIdentity) -> Self {
        use crate::source_auth::AuthenticatedIdentity;
        match identity {
            AuthenticatedIdentity::JwtBearer { subject, claims } => SourceAuthContext::JwtBearer {
                subject: subject.clone(),
                claims: claims.clone(),
            },
            AuthenticatedIdentity::ApiKey { key_name } => SourceAuthContext::ApiKey { key_name: key_name.clone() },
            AuthenticatedIdentity::DidAuth { did } => SourceAuthContext::DidAuth { did: did.clone() },
            AuthenticatedIdentity::Mtls {
                principal,
                fingerprint,
                subject_dn,
                issuer_dn,
                sans,
                source: _,
            } => SourceAuthContext::Mtls {
                principal: principal.clone(),
                fingerprint: fingerprint.clone(),
                subject_dn: subject_dn.clone(),
                issuer_dn: issuer_dn.clone(),
                sans: sans.clone(),
            },
        }
    }
}

/// How the caller DID in `input.extension_identity` (and, once promoted,
/// `input.agent.did`) was established. Serialized as `verification`;
/// `verified` is its boolean projection: `vp`, `vp_unanchored` and
/// `source_auth` are verified, `unverified` is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityVerification {
    /// The caller proved control of the DID with an identity presentation that
    /// verified cryptographically and whose issuer is a trust anchor: on the
    /// fabric receive path, one of the sending connection's issuers.
    Vp,
    /// The caller proved control of the DID with an identity presentation that
    /// verified cryptographically, but no trust anchor vouches for its issuer.
    /// The direct A2A path has no authenticated sending gateway, so any issuer
    /// that signs a valid credential ends here, a self-issued one included. The
    /// DID is the caller's; the identity fields are only as trustworthy as
    /// `input.agent.identity_issuer_did`.
    VpUnanchored,
    /// The DID is bound to the source credential this gateway authenticated on
    /// this request (`from_jwt_claim`).
    SourceAuth,
    /// Nothing in this request proves the DID: `x-identity` payload
    /// pseudonyms and identities configured on the surface (`static`,
    /// `from_mtls`, `from_api_key`).
    Unverified,
}

impl IdentityVerification {
    pub fn is_verified(self) -> bool {
        !matches!(self, Self::Unverified)
    }
}

/// Caller identity resolved from the inbound identity extension, injected as
/// `input.extension_identity` with `verified` and `verification`
/// (see [`IdentityVerification`]).
#[derive(Debug, Clone)]
pub struct ExtensionIdentityContext {
    pub did: Option<String>,
    pub identity_hash: Option<String>,
    pub verification: IdentityVerification,
}

impl ExtensionIdentityContext {
    pub fn verified(&self) -> bool {
        self.verification
            .is_verified()
    }
}

impl serde::Serialize for ExtensionIdentityContext {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        if let Some(did) = &self.did {
            map.serialize_entry("did", did)?;
        }
        if let Some(hash) = &self.identity_hash {
            map.serialize_entry("identity_hash", hash)?;
        }
        map.serialize_entry("verified", &self.verified())?;
        map.serialize_entry("verification", &self.verification)?;
        map.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentContext {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_header: Option<String>,
}

/// Identity binding from an upstream gateway's request-path VP.
/// Available as `input.identity_binding` in Rego policies.
///
/// The struct keeps flat internal fields (`agent_did`, `gateway_did`,
/// `identity_fields`, `inbound_credentials`) for the gateway's own re-chaining
/// logic, but serializes to OPA/audit as the nested Workload Binding shape:
///
/// ```json
/// {
///   "verified": true,
///   "agent": { "did": "...", "identity_fields": { ... } },
///   "caller": { "fields": { ... }, "user_hash": "...", "assurance": "gateway_attested" },
///   "delegated": true,
///   "issuer_gateway": "did:web:gw1.example",
///   "target": "fabric://gw2/...",
///   "intent": { ... }
/// }
/// ```
///
/// `verified` is `false` when the VP signature verified but no trust anchor
/// vouched for `issuer_gateway`; policies must check it before relying on
/// `agent.did`.
#[derive(Debug, Clone)]
pub struct IdentityBindingContext {
    /// Whether the binding may be relied on as the agent's identity: the VP
    /// signature verified, the holder matches the credential subject, and the
    /// issuer is one of the sending connection's issuers. `false` when the
    /// signature verified but no trust anchor vouched for the issuer.
    pub verified: bool,
    /// The agent DID (VP holder / subject)
    pub agent_did: String,
    /// The gateway DID that signed the VP (issuer) — serialized as `issuer_gateway`.
    pub gateway_did: String,
    /// The managed-agent identity fields (from `workloadBinding.agentIdentity`
    /// when present, otherwise the flat credential subject). Serialized under
    /// `agent.identity_fields`.
    pub identity_fields: HashMap<String, serde_json::Value>,
    /// Caller context parsed from `workloadBinding.caller`, when the binding
    /// carried one. `None` for a legacy flat identity credential.
    pub caller: Option<CallerBindingContext>,
    /// Whether the managed agent acted on behalf of a caller.
    pub delegated: bool,
    /// The bound target endpoint from `workloadBinding.target`, when present.
    pub target: Option<String>,
    /// The structured intent from `workloadBinding.intent`, when present.
    pub intent: Option<serde_json::Value>,
    /// Raw `verifiableCredential` entries from the inbound VP, preserved so
    /// this gateway can flatten them into a re-issued chained-provenance VP
    /// when forwarding (request path) or responding (serverIdentity path).
    /// Empty for unverified bindings or VPs with no credentials. Never
    /// serialized to OPA.
    pub inbound_credentials: Vec<serde_json::Value>,
}

/// Caller-context sub-shape of a verified identity binding, mirroring the
/// `credentialSubject.workloadBinding.caller` object the producing gateway
/// signed. Available as `input.identity_binding.caller` in Rego.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CallerBindingContext {
    /// Allowlisted caller-context fields, copied verbatim by the producer.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// Stable correlation hash for the caller identity, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_hash: Option<String>,
    /// Assurance level: `gateway_attested` or `caller_credential_chained`.
    pub assurance: String,
    /// Where the producing gateway sourced caller context (`transit_token` /
    /// `jwt_bearer`), when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<String>,
}

impl IdentityBindingContext {
    /// Build a binding context from the raw parts returned by VP signature
    /// verification. `issuer_trusted` records whether a trust anchor vouched
    /// for the issuer and becomes `verified`. When the credential subject
    /// carried a `workloadBinding` object, its `caller`, `delegated`,
    /// `target`, `intent`, and `agentIdentity` are parsed into the nested
    /// shape; otherwise the flat `identity_fields` are preserved and `caller`
    /// is `None`.
    pub fn from_verified_parts(
        agent_did: String,
        gateway_did: String,
        identity_fields: HashMap<String, serde_json::Value>,
        inbound_credentials: Vec<serde_json::Value>,
        issuer_trusted: bool,
    ) -> Self {
        if let Some(serde_json::Value::Object(wb)) = identity_fields.get("workloadBinding") {
            let caller = wb
                .get("caller")
                .and_then(|c| c.as_object())
                .map(|c| CallerBindingContext {
                    fields: c
                        .get("fields")
                        .and_then(|f| f.as_object())
                        .cloned()
                        .unwrap_or_default(),
                    user_hash: c
                        .get("user_hash")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    assurance: c
                        .get("assurance")
                        .and_then(|v| v.as_str())
                        .unwrap_or("gateway_attested")
                        .to_string(),
                    identity_source: c
                        .get("identity_source")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                });
            let delegated = wb
                .get("delegated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let target = wb
                .get("target")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let intent = wb.get("intent").cloned();
            let agent_identity_fields = wb
                .get("agentIdentity")
                .and_then(|v| v.as_object())
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            Self {
                verified: issuer_trusted,
                agent_did,
                gateway_did,
                identity_fields: agent_identity_fields,
                caller,
                delegated,
                target,
                intent,
                inbound_credentials,
            }
        } else {
            Self {
                verified: issuer_trusted,
                agent_did,
                gateway_did,
                identity_fields,
                caller: None,
                delegated: false,
                target: None,
                intent: None,
                inbound_credentials,
            }
        }
    }
}

impl Serialize for IdentityBindingContext {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("verified", &self.verified)?;

        let mut agent = serde_json::Map::new();
        agent.insert("did".to_string(), serde_json::Value::String(self.agent_did.clone()));
        agent.insert(
            "identity_fields".to_string(),
            serde_json::to_value(&self.identity_fields).unwrap_or(serde_json::Value::Null),
        );
        map.serialize_entry("agent", &agent)?;

        if let Some(caller) = &self.caller {
            map.serialize_entry("caller", caller)?;
        }
        map.serialize_entry("delegated", &self.delegated)?;
        map.serialize_entry("issuer_gateway", &self.gateway_did)?;
        if let Some(target) = &self.target {
            map.serialize_entry("target", target)?;
        }
        if let Some(intent) = &self.intent {
            map.serialize_entry("intent", intent)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn source_auth_failed_variant_serializes_without_tag_collision() {
        let ctx = SourceAuthContext::Failed {
            attempted_method: "jwt_bearer".to_string(),
            reason: "Token has expired".to_string(),
        };
        let value = serde_json::to_value(&ctx).unwrap();
        assert_eq!(value["method"], "failed");
        assert_eq!(value["attempted_method"], "jwt_bearer");
        assert_eq!(value["reason"], "Token has expired");
        // The `#[serde(tag = "method")]` discriminant must not be clobbered by an
        // inner field — the inner field is deliberately named `attempted_method`.
        assert_ne!(value["method"], "jwt_bearer");
    }

    #[test]
    fn filter_sensitive_headers_strips_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer secret"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .unwrap(),
        );

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("authorization"));
        assert_eq!(
            result
                .get("content-type")
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn filter_sensitive_headers_strips_cookie_and_token() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc".parse().unwrap());
        headers.insert("x-csrf-token", "tok123".parse().unwrap());
        headers.insert("x-request-id", "req-1".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("cookie"));
        assert!(!result.contains_key("x-csrf-token"));
        assert_eq!(
            result
                .get("x-request-id")
                .unwrap(),
            "req-1"
        );
    }

    #[test]
    fn filter_sensitive_headers_strips_credential_style_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret-key".parse().unwrap());
        headers.insert(
            "x-client-secret",
            "secret-value"
                .parse()
                .unwrap(),
        );
        headers.insert("proxy-authorization", "Basic abc".parse().unwrap());
        headers.insert("set-cookie", "session=abc".parse().unwrap());
        headers.insert(
            "x-signal-id",
            "TA-CVE-2023-29300"
                .parse()
                .unwrap(),
        );

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("x-api-key"));
        assert!(!result.contains_key("x-client-secret"));
        assert!(!result.contains_key("proxy-authorization"));
        assert!(!result.contains_key("set-cookie"));
        assert_eq!(
            result
                .get("x-signal-id")
                .unwrap(),
            "TA-CVE-2023-29300"
        );
    }

    #[test]
    fn filter_sensitive_headers_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            "Bearer secret"
                .parse()
                .unwrap(),
        );
        headers.insert("accept", "text/html".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("authorization"));
        assert_eq!(result.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn filter_sensitive_headers_empty_map() {
        let headers = HeaderMap::new();
        let result = filter_sensitive_headers(&headers);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_sensitive_headers_keeps_all_non_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        headers.insert("accept", "*/*".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn filter_sensitive_json_headers_strips_sensitive() {
        let mut map = serde_json::Map::new();
        map.insert("authorization".into(), serde_json::Value::String("Bearer secret".into()));
        map.insert("cookie".into(), serde_json::Value::String("sess=1".into()));
        map.insert("x-token".into(), serde_json::Value::String("t".into()));
        map.insert("content-type".into(), serde_json::Value::String("application/json".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("authorization"));
        assert!(!result.contains_key("cookie"));
        assert!(!result.contains_key("x-token"));
        assert_eq!(
            result
                .get("content-type")
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn filter_sensitive_json_headers_case_insensitive() {
        let mut map = serde_json::Map::new();
        map.insert("Authorization".into(), serde_json::Value::String("secret".into()));
        map.insert("X-Request-Id".into(), serde_json::Value::String("123".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("Authorization"));
        assert_eq!(
            result
                .get("X-Request-Id")
                .unwrap(),
            "123"
        );
    }

    #[test]
    fn filter_sensitive_json_headers_none_returns_empty() {
        let result = filter_sensitive_json_headers(None);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_sensitive_json_headers_skips_non_string_values() {
        let mut map = serde_json::Map::new();
        map.insert("x-count".into(), serde_json::json!(42));
        map.insert("x-request-id".into(), serde_json::Value::String("abc".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("x-count"));
        assert_eq!(
            result
                .get("x-request-id")
                .unwrap(),
            "abc"
        );
    }

    fn make_input() -> PolicyInput {
        PolicyInput::new("POST", "/x", HashMap::new(), "inbound", None, None, Some("surf".into()), "surface-name")
    }

    #[test]
    fn normalize_caller_did_promotes_from_extension_when_agent_did_absent() {
        let mut input = make_input();
        input.extension_identity = Some(ExtensionIdentityContext {
            did: Some("did:webvh:from-ext".into()),
            identity_hash: None,
            verification: IdentityVerification::Vp,
        });
        input.agent = Some(AgentContext {
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            did: None,
            did_verified: false,
            did_verification: None,
            agent_dna: None,
            trust_registry_did: None,
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            tr_identity_mismatch: false,
        });

        input.normalize_caller_did();

        assert_eq!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did
                .as_deref(),
            Some("did:webvh:from-ext")
        );
    }

    #[test]
    fn normalize_caller_did_creates_agent_when_missing() {
        let mut input = make_input();
        input.extension_identity = Some(ExtensionIdentityContext {
            did: Some("did:webvh:from-ext".into()),
            identity_hash: None,
            verification: IdentityVerification::Vp,
        });
        assert!(input.agent.is_none());

        input.normalize_caller_did();

        assert_eq!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did
                .as_deref(),
            Some("did:webvh:from-ext")
        );
    }

    #[test]
    fn normalize_caller_did_preserves_payload_asserted_did() {
        let mut input = make_input();
        input.extension_identity = Some(ExtensionIdentityContext {
            did: Some("did:webvh:from-ext".into()),
            identity_hash: None,
            verification: IdentityVerification::Vp,
        });
        input.agent = Some(AgentContext {
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            did: Some("did:webvh:from-payload".into()),
            did_verified: false,
            did_verification: None,
            agent_dna: None,
            trust_registry_did: None,
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            tr_identity_mismatch: false,
        });

        input.normalize_caller_did();

        assert_eq!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did
                .as_deref(),
            Some("did:webvh:from-payload"),
            "payload-asserted DID must win over the gateway-derived fallback"
        );
    }

    #[test]
    fn normalize_caller_did_noop_without_extension_identity() {
        let mut input = make_input();
        input.normalize_caller_did();
        assert!(input.agent.is_none());
    }

    #[test]
    fn normalize_caller_did_noop_when_tr_identity_mismatch() {
        let mut input = make_input();
        input.extension_identity = Some(ExtensionIdentityContext {
            did: Some("did:webvh:from-ext".into()),
            identity_hash: None,
            verification: IdentityVerification::Vp,
        });
        input.agent = Some(AgentContext {
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            did: None,
            did_verified: false,
            did_verification: None,
            agent_dna: None,
            trust_registry_did: None,
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            tr_identity_mismatch: true,
        });

        input.normalize_caller_did();

        assert!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did
                .is_none(),
            "normalize must not restore agent.did when tr_identity_mismatch is set"
        );
    }

    /// Build a `PolicyInput` carrying an A2A message whose single text part has
    /// the supplied content, then return it serialized to the `input.*` JSON a
    /// Rego policy receives.
    fn a2a_policy_input_json(text: &str) -> serde_json::Value {
        let mut input =
            PolicyInput::new("POST", "/example", HashMap::new(), "inbound", None, None, None, "example-surface");
        input.a2a = Some(A2aContext::new(
            Some("message/send".to_string()),
            Some(serde_json::json!({
                "role": "user",
                "parts": [{ "kind": "text", "text": text }]
            })),
        ));
        serde_json::to_value(&input).expect("PolicyInput serializes to JSON")
    }

    #[test]
    fn a2a_context_serializes_into_input_a2a() {
        let value = a2a_policy_input_json("hello");

        assert_eq!(value["a2a"]["method"], "message/send");
        assert_eq!(value["a2a"]["message"]["parts"][0]["text"], "hello");
    }

    #[test]
    fn policy_allows_when_a2a_message_text_matches() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.a2a.method == "message/send"
    input.a2a.message.parts[_].text == "hello"
}
"#;
        engine
            .load_policy("a2a-test", policy)
            .unwrap();

        let decision = engine
            .evaluate(a2a_policy_input_json("hello"))
            .unwrap();
        assert!(decision.allow, "policy should allow when message text matches");
    }

    /// Same as `a2a_policy_input_json` but with a caller-chosen JSON-RPC method,
    /// so a policy can be evaluated against both A2A protocol eras.
    fn a2a_policy_input_for_method(method: &str) -> serde_json::Value {
        let mut input =
            PolicyInput::new("POST", "/example", HashMap::new(), "inbound", None, None, None, "example-surface");
        input.a2a =
            Some(A2aContext::new(Some(method.to_string()), Some(serde_json::json!({ "role": "user", "parts": [] }))));
        serde_json::to_value(&input).expect("PolicyInput serializes to JSON")
    }

    /// Build policy input carrying a caller-supplied A2A message object, so a
    /// policy can be evaluated against both eras' message shapes.
    fn a2a_policy_input_for_message(message: serde_json::Value) -> serde_json::Value {
        let mut input =
            PolicyInput::new("POST", "/example", HashMap::new(), "inbound", None, None, None, "example-surface");
        input.a2a = Some(A2aContext::new(Some("SendMessage".to_string()), Some(message)));
        serde_json::to_value(&input).expect("PolicyInput serializes to JSON")
    }

    /// A2A v1.0 changed the message shape as well as the method names: `role`
    /// became `ROLE_USER`/`ROLE_AGENT`, and `Part` became a choice between
    /// `text`, `raw`, `url` and `data` with no `kind` discriminator. Because
    /// `input.a2a.message` reaches policy exactly as the caller sent it,
    /// `docs/PROTOCOLS.md#writing-policy-for-both-versions` documents
    /// cross-version patterns for both fields. Those patterns are pinned here
    /// against the real engine so the documentation cannot drift.
    #[test]
    fn documented_cross_era_message_shape_policies_match_both_versions() {
        let v0_3 = serde_json::json!({
            "role": "user",
            "parts": [{ "kind": "text", "text": "hello" }]
        });
        let v1_0 = serde_json::json!({
            "role": "ROLE_USER",
            "parts": [{ "text": "hello" }]
        });

        // The documented cross-version role pattern.
        let role_policy = r#"
package surface.policy

default allow = false

allow if input.a2a.message.role in {"user", "ROLE_USER"}
"#;
        // The documented cross-version text-part pattern: identify a text part by the
        // presence of `text` rather than by `kind`.
        let text_part_policy = r#"
package surface.policy

default allow = false

allow if input.a2a.message.parts[_].text
"#;

        for (label, policy) in [("role", role_policy), ("text part", text_part_policy)] {
            let engine = crate::policies::opa::OpaEngine::new();
            engine
                .load_policy("a2a-shape", policy)
                .unwrap_or_else(|e| panic!("documented '{label}' policy should compile: {e}"));

            for (era, message) in [("v0.3", &v0_3), ("v1.0", &v1_0)] {
                let decision = engine
                    .evaluate(a2a_policy_input_for_message(message.clone()))
                    .unwrap();
                assert!(decision.allow, "documented '{label}' policy should allow a {era} message");
            }
        }

        // The v0.3-only patterns the documentation warns about must genuinely fail on a
        // v1.0 message, otherwise the warning is misleading.
        let v0_3_only = r#"
package surface.policy

default allow = false

allow if input.a2a.message.parts[_].kind == "text"
"#;
        let engine = crate::policies::opa::OpaEngine::new();
        engine
            .load_policy("a2a-shape-legacy", v0_3_only)
            .unwrap();
        assert!(
            engine
                .evaluate(a2a_policy_input_for_message(v0_3.clone()))
                .unwrap()
                .allow,
            "a kind-based policy should still match a v0.3 message"
        );
        assert!(
            !engine
                .evaluate(a2a_policy_input_for_message(v1_0.clone()))
                .unwrap()
                .allow,
            "a kind-based policy must not match a v1.0 message"
        );
    }

    /// `docs/PROTOCOLS.md#writing-policy-for-both-versions` shows how one policy
    /// accepts both the v0.3 and v1.0 spelling of a method, because the gateway
    /// exposes `input.a2a.method` exactly as the caller sent it. Both documented
    /// forms are pinned here against the real engine so the documentation cannot
    /// drift into something that does not compile or does not match.
    #[test]
    fn documented_dual_era_method_policies_match_both_spellings() {
        // Option A in the documentation: a set membership check.
        let membership = r#"
package surface.policy

default allow = false

allow if input.a2a.method in {"message/send", "SendMessage"}
"#;
        // Option B in the documentation: two rules, which OPA evaluates as a logical OR.
        let two_rules = r#"
package surface.policy

default allow = false

allow if input.a2a.method == "message/send"
allow if input.a2a.method == "SendMessage"
"#;

        for (label, policy) in [("set membership", membership), ("two rules", two_rules)] {
            let engine = crate::policies::opa::OpaEngine::new();
            engine
                .load_policy("a2a-dual-era", policy)
                .unwrap_or_else(|e| panic!("documented '{label}' policy should compile: {e}"));

            for method in ["message/send", "SendMessage"] {
                let decision = engine
                    .evaluate(a2a_policy_input_for_method(method))
                    .unwrap();
                assert!(decision.allow, "documented '{label}' policy should allow {method}");
            }

            let decision = engine
                .evaluate(a2a_policy_input_for_method("tasks/cancel"))
                .unwrap();
            assert!(!decision.allow, "documented '{label}' policy should still deny an unlisted method");
        }
    }

    #[test]
    fn a2a_context_canonicalises_recognised_methods_in_both_eras() {
        for method in ["SendMessage", "message/send"] {
            let ctx = A2aContext::new(Some(method.to_string()), None);
            assert_eq!(ctx.method.as_deref(), Some(method));
            assert_eq!(
                ctx.method_canonical
                    .as_deref(),
                Some("message/send")
            );
        }
    }

    #[test]
    fn a2a_context_has_no_canonical_method_for_unknown_or_missing_method() {
        for method in ["custom/thing", "FooBar"] {
            let ctx = A2aContext::new(Some(method.to_string()), None);
            assert_eq!(ctx.method.as_deref(), Some(method));
            assert_eq!(ctx.method_canonical, None);
        }
        let ctx = A2aContext::new(None, None);
        assert_eq!(ctx.method, None);
        assert_eq!(ctx.method_canonical, None);
    }

    #[test]
    fn a2a_context_serializes_method_canonical_only_when_present() {
        let known = serde_json::to_value(A2aContext::new(Some("SendMessage".to_string()), None)).unwrap();
        assert_eq!(known, serde_json::json!({ "method": "SendMessage", "method_canonical": "message/send" }));

        let unknown = serde_json::to_value(A2aContext::new(Some("FooBar".to_string()), None)).unwrap();
        assert_eq!(unknown, serde_json::json!({ "method": "FooBar" }));

        let none = serde_json::to_value(A2aContext::new(None, None)).unwrap();
        assert_eq!(none, serde_json::json!({}));
    }

    #[test]
    fn policy_on_method_canonical_denies_both_spellings_only() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow := true

allow := false if input.a2a.method_canonical == "message/send"
"#;
        engine
            .load_policy("a2a-canonical-deny", policy)
            .unwrap();

        for method in ["SendMessage", "message/send"] {
            let decision = engine
                .evaluate(a2a_policy_input_for_method(method))
                .unwrap();
            assert!(!decision.allow, "canonical deny rule should deny {method}");
        }
        let decision = engine
            .evaluate(a2a_policy_input_for_method("GetTask"))
            .unwrap();
        assert!(decision.allow, "canonical deny rule should allow GetTask");
    }

    #[test]
    fn duplicate_method_keys_yield_consistent_method_and_canonical() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"GetTask","method":"SendMessage","id":1}"#).unwrap();
        let method = body
            .get("method")
            .and_then(|m| m.as_str())
            .map(str::to_string);
        let ctx = A2aContext::new(method, None);
        assert_eq!(ctx.method.as_deref(), Some("SendMessage"));
        assert_eq!(
            ctx.method_canonical
                .as_deref(),
            Some("message/send")
        );
    }

    #[test]
    fn policy_denies_when_a2a_message_text_differs() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.a2a.message.parts[_].text == "hello"
}
"#;
        engine
            .load_policy("a2a-test", policy)
            .unwrap();

        let decision = engine
            .evaluate(a2a_policy_input_json("goodbye"))
            .unwrap();
        assert!(!decision.allow, "policy should deny when message text differs");
    }

    // ── Identity binding (Workload Binding) ──────────────────────────────────

    fn binding_with_workload(assurance: &str) -> IdentityBindingContext {
        let mut caller = serde_json::Map::new();
        let mut fields = serde_json::Map::new();
        fields.insert("sub".to_string(), serde_json::json!("alice"));
        fields.insert("email".to_string(), serde_json::json!("alice@example.test"));
        caller.insert("fields".to_string(), serde_json::Value::Object(fields));
        caller.insert("user_hash".to_string(), serde_json::json!("hash-1"));
        caller.insert("assurance".to_string(), serde_json::json!(assurance));
        caller.insert("identity_source".to_string(), serde_json::json!("jwt_bearer"));

        let mut agent_identity = serde_json::Map::new();
        agent_identity.insert("model".to_string(), serde_json::json!("gpt-4"));

        let mut wb = serde_json::Map::new();
        wb.insert("caller".to_string(), serde_json::Value::Object(caller));
        wb.insert("agentIdentity".to_string(), serde_json::Value::Object(agent_identity));
        wb.insert("delegated".to_string(), serde_json::json!(true));
        wb.insert("target".to_string(), serde_json::json!("fabric://gw2/alpha"));

        let mut identity_fields = HashMap::new();
        identity_fields.insert("workloadBinding".to_string(), serde_json::Value::Object(wb));

        IdentityBindingContext::from_verified_parts(
            "did:web:agent.example".to_string(),
            "did:web:gw1.example".to_string(),
            identity_fields,
            Vec::new(),
            true,
        )
    }

    #[test]
    fn identity_binding_serializes_nested_shape() {
        let binding = binding_with_workload("gateway_attested");
        let v = serde_json::to_value(&binding).unwrap();
        assert_eq!(v["verified"], serde_json::json!(true));
        assert_eq!(v["agent"]["did"], serde_json::json!("did:web:agent.example"));
        assert_eq!(v["agent"]["identity_fields"]["model"], serde_json::json!("gpt-4"));
        assert_eq!(v["caller"]["fields"]["sub"], serde_json::json!("alice"));
        assert_eq!(v["caller"]["user_hash"], serde_json::json!("hash-1"));
        assert_eq!(v["caller"]["assurance"], serde_json::json!("gateway_attested"));
        assert_eq!(v["caller"]["identity_source"], serde_json::json!("jwt_bearer"));
        assert_eq!(v["delegated"], serde_json::json!(true));
        assert_eq!(v["issuer_gateway"], serde_json::json!("did:web:gw1.example"));
        assert_eq!(v["target"], serde_json::json!("fabric://gw2/alpha"));
        // inbound_credentials is never serialized to OPA.
        assert!(
            v.get("inbound_credentials")
                .is_none()
        );
    }

    #[test]
    fn from_verified_parts_flat_when_no_workload_binding() {
        let mut identity_fields = HashMap::new();
        identity_fields.insert("role".to_string(), serde_json::json!("assistant"));
        let binding = IdentityBindingContext::from_verified_parts(
            "did:web:agent.example".to_string(),
            "did:web:gw1.example".to_string(),
            identity_fields,
            Vec::new(),
            true,
        );
        assert!(binding.caller.is_none(), "flat credential carries no caller context");
        assert!(!binding.delegated);
        let v = serde_json::to_value(&binding).unwrap();
        assert_eq!(v["agent"]["identity_fields"]["role"], serde_json::json!("assistant"));
        assert!(v.get("caller").is_none());
    }

    fn policy_input_json(binding: Option<IdentityBindingContext>) -> serde_json::Value {
        let input = PolicyInput {
            identity_binding: binding,
            ..PolicyInput::default()
        };
        serde_json::to_value(&input).unwrap()
    }

    #[test]
    fn policy_input_omits_identity_binding_when_absent() {
        let v = policy_input_json(None);
        assert!(
            v.get("identity_binding")
                .is_none(),
            "absent binding must not serialize"
        );
    }

    #[test]
    fn opa_allows_on_caller_user_hash() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.identity_binding.caller.user_hash == "hash-1"
}
"#;
        engine
            .load_policy("ib-test", policy)
            .unwrap();
        assert!(
            engine
                .evaluate(policy_input_json(Some(binding_with_workload("gateway_attested"))))
                .unwrap()
                .allow
        );
    }

    #[test]
    fn opa_denies_when_identity_binding_missing() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.identity_binding
}
"#;
        engine
            .load_policy("ib-test", policy)
            .unwrap();
        assert!(
            engine
                .evaluate(policy_input_json(Some(binding_with_workload("gateway_attested"))))
                .unwrap()
                .allow,
            "present binding allows"
        );
        assert!(
            !engine
                .evaluate(policy_input_json(None))
                .unwrap()
                .allow,
            "missing binding denies"
        );
    }

    #[test]
    fn opa_distinguishes_assurance_level() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.identity_binding.caller.assurance == "caller_credential_chained"
}
"#;
        engine
            .load_policy("ib-test", policy)
            .unwrap();
        assert!(
            !engine
                .evaluate(policy_input_json(Some(binding_with_workload("gateway_attested"))))
                .unwrap()
                .allow,
            "gateway_attested does not satisfy a chained-credential requirement"
        );
        assert!(
            engine
                .evaluate(policy_input_json(Some(binding_with_workload("caller_credential_chained"))))
                .unwrap()
                .allow,
            "caller_credential_chained satisfies it"
        );
    }

    // ── Identity verification markers ────────────────────────────────────────

    fn extension_identity(verified: bool) -> ExtensionIdentityContext {
        ExtensionIdentityContext {
            did: Some("did:webvh:caller".into()),
            identity_hash: Some("hash-1".into()),
            verification: if verified {
                IdentityVerification::Vp
            } else {
                IdentityVerification::Unverified
            },
        }
    }

    fn agent_with_did(did: &str) -> AgentContext {
        AgentContext {
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            did: Some(did.into()),
            did_verified: false,
            did_verification: None,
            agent_dna: None,
            trust_registry_did: None,
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            tr_identity_mismatch: false,
        }
    }

    #[test]
    fn unanchored_presentation_is_verified_but_distinguishable_from_an_anchored_one() {
        assert!(IdentityVerification::VpUnanchored.is_verified());
        assert_ne!(IdentityVerification::VpUnanchored, IdentityVerification::Vp);
        assert_eq!(
            serde_json::to_value(IdentityVerification::VpUnanchored).unwrap(),
            serde_json::json!("vp_unanchored")
        );
    }

    #[test]
    fn normalize_caller_did_never_promotes_an_unverified_did_as_verified() {
        let mut input = make_input();
        input.extension_identity = Some(extension_identity(false));

        input.normalize_caller_did();

        let agent = input.agent.as_ref().unwrap();
        assert_eq!(agent.did.as_deref(), Some("did:webvh:caller"));
        assert!(!agent.did_verified);
    }

    #[test]
    fn normalize_caller_did_carries_verification_onto_promoted_did() {
        let mut input = make_input();
        input.extension_identity = Some(extension_identity(true));

        input.normalize_caller_did();

        assert!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did_verified
        );
    }

    #[test]
    fn normalize_caller_did_upgrades_only_a_matching_payload_did() {
        let mut input = make_input();
        input.extension_identity = Some(extension_identity(true));
        input.agent = Some(agent_with_did("did:webvh:caller"));
        input.normalize_caller_did();
        assert!(
            input
                .agent
                .as_ref()
                .unwrap()
                .did_verified,
            "a payload DID equal to the verified extension DID is verified"
        );

        let mut input = make_input();
        input.extension_identity = Some(extension_identity(true));
        input.agent = Some(agent_with_did("did:webvh:from-payload"));
        input.normalize_caller_did();
        let agent = input.agent.as_ref().unwrap();
        assert_eq!(agent.did.as_deref(), Some("did:webvh:from-payload"));
        assert!(!agent.did_verified, "a differing payload DID must never inherit the extension's verification");
    }

    fn identity_policy_input_json(verified: bool) -> serde_json::Value {
        let mut input = make_input();
        input.extension_identity = Some(extension_identity(verified));
        input.normalize_caller_did();
        serde_json::to_value(&input).unwrap()
    }

    #[test]
    fn identity_verification_markers_serialize_explicitly() {
        let v = identity_policy_input_json(false);
        assert_eq!(v["extension_identity"]["did"], serde_json::json!("did:webvh:caller"));
        assert_eq!(v["extension_identity"]["verified"], serde_json::json!(false));
        assert_eq!(v["extension_identity"]["verification"], serde_json::json!("unverified"));
        assert_eq!(v["agent"]["did"], serde_json::json!("did:webvh:caller"));
        assert_eq!(v["agent"]["did_verified"], serde_json::json!(false));
        assert_eq!(v["agent"]["did_verification"], serde_json::json!("unverified"));

        let v = identity_policy_input_json(true);
        assert_eq!(v["extension_identity"]["verified"], serde_json::json!(true));
        assert_eq!(v["extension_identity"]["verification"], serde_json::json!("vp"));
        assert_eq!(v["agent"]["did_verified"], serde_json::json!(true));
        assert_eq!(v["agent"]["did_verification"], serde_json::json!("vp"));

        let mut input = make_input();
        input.extension_identity = Some(ExtensionIdentityContext {
            did: Some("did:webvh:caller".into()),
            identity_hash: None,
            verification: IdentityVerification::SourceAuth,
        });
        input.normalize_caller_did();
        let v = serde_json::to_value(&input).unwrap();
        assert_eq!(v["extension_identity"]["verified"], serde_json::json!(true));
        assert_eq!(v["extension_identity"]["verification"], serde_json::json!("source_auth"));
        assert_eq!(v["agent"]["did_verification"], serde_json::json!("source_auth"));
    }

    #[test]
    fn opa_distinguishes_verified_from_asserted_caller_did() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.agent.did == "did:webvh:caller"
    input.agent.did_verified == true
    input.extension_identity.verified == true
}
"#;
        engine
            .load_policy("verified-did", policy)
            .unwrap();
        assert!(
            !engine
                .evaluate(identity_policy_input_json(false))
                .unwrap()
                .allow,
            "an asserted DID must not satisfy a verified-DID rule"
        );
        assert!(
            engine
                .evaluate(identity_policy_input_json(true))
                .unwrap()
                .allow,
            "a verified DID satisfies it"
        );
    }

    #[test]
    fn opa_distinguishes_unanchored_identity_binding() {
        let engine = crate::policies::opa::OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.identity_binding.verified == true
}
"#;
        engine
            .load_policy("ib-verified", policy)
            .unwrap();
        let unanchored = IdentityBindingContext::from_verified_parts(
            "did:web:agent.example".to_string(),
            "did:web:gw1.example".to_string(),
            HashMap::new(),
            Vec::new(),
            false,
        );
        let v = serde_json::to_value(&unanchored).unwrap();
        assert_eq!(v["verified"], serde_json::json!(false));
        assert_eq!(v["agent"]["did"], serde_json::json!("did:web:agent.example"));
        assert_eq!(
            v["issuer_gateway"],
            serde_json::json!("did:web:gw1.example"),
            "the unanchored issuer stays visible to policy"
        );
        assert!(
            !engine
                .evaluate(policy_input_json(Some(unanchored)))
                .unwrap()
                .allow,
            "an unanchored binding must not satisfy a verified-binding rule"
        );
        assert!(
            engine
                .evaluate(policy_input_json(Some(binding_with_workload("gateway_attested"))))
                .unwrap()
                .allow,
            "a trusted-issuer binding satisfies it"
        );
    }
}
