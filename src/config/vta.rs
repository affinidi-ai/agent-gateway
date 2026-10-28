//! `[vta]` bootstrap configuration — Verifiable Trust Agent (VTA) integration.
//!
//! **Startup-only.** Changing any field requires a restart (it selects the
//! credential-signing backend at boot). Runtime toggles that need hot-reload
//! belong in the settings store, not here.
//!
//! The block is **off by default**: an absent `[vta]` table, or `enabled =
//! false`, leaves the gateway signing locally with its in-process issuer key
//! exactly as before (see the `CredentialAuthority` port, VTA-01). When
//! `enabled = true` the gateway delegates private-key operations to a VTA,
//! acting as a thin REST/Trust-Task **client** of the VTA's `/trust-tasks`
//! surface (the gateway and VTA are separate services; the gateway does not
//! link the VTA's internals — see `src/vta/`).

use serde::{Deserialize, Serialize};

/// Transport carrier for VTA Trust Tasks. Only `rest` is wired today; `didcomm`
/// and `tsp` are accepted so config written now stays valid when those carriers
/// land, but selecting them is rejected by [`VtaConfig::validate`] until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VtaTransport {
    #[default]
    Rest,
    Didcomm,
    Tsp,
}

/// Deployment shape of the VTA the gateway signs with.
///
/// This is **not** a custody tier and must never be presented as one. A
/// bundled sidecar shares a host and a blast radius with the gateway, so the
/// gateway holding super-admin over it changes nothing about who could reach
/// the keys — which is precisely why no custody claim attaches to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VtaMode {
    /// A separately-operated VTA the gateway is a least-privilege client of.
    #[default]
    Appliance,
    /// `vta-service` shipped inside the gateway's own deployment unit — a
    /// sidecar container, a second process in the Pod, a systemd bundle —
    /// reached over loopback or a unix socket.
    ///
    /// Spelled `embedded` on the wire for compatibility with config written
    /// before the shape was named; the semantics are **bundled packaging**,
    /// never an in-process library. Linking is blocked by a dependency
    /// conflict (see VTA-02/VTA-21), and the gateway code path here is
    /// identical to a remote VTA — only the endpoint differs.
    #[serde(rename = "embedded", alias = "bundled")]
    Bundled,
}

impl VtaMode {
    /// Operator-facing tier label, surfaced by the management API and the
    /// dashboard.
    pub fn tier(self) -> &'static str {
        match self {
            Self::Appliance => "self-hosted",
            Self::Bundled => "bundled",
        }
    }

    /// Whether this deployment supports a key-custody claim.
    ///
    /// A bundled sidecar never does: it shares a host, a disk and an operator
    /// with the gateway, so "the keys are held by a separate agent" is not a
    /// property the deployment actually has. Saying otherwise in product copy
    /// would be the single most damaging thing this integration could do.
    pub fn supports_custody_claim(self) -> bool {
        matches!(self, Self::Appliance)
    }

    /// Whether the gateway may hold super-admin over this VTA, and therefore
    /// auto-provision contexts and self-grant.
    ///
    /// Only on the bundled tier, where it grants no authority the gateway's own
    /// host does not already have. On any separately-operated VTA the grant is
    /// the customer's to give, and must stay least-privilege.
    pub fn allows_self_administration(self) -> bool {
        matches!(self, Self::Bundled)
    }
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_max_concurrent() -> usize {
    16
}

fn default_audit_queue_capacity() -> usize {
    256
}

/// Conservative-but-generous default: 600 signatures a minute sustained is far
/// above normal gateway traffic while still bounding a runaway caller.
fn default_sign_quota_max() -> u64 {
    600
}

fn default_sign_quota_window_secs() -> u64 {
    60
}

/// Generous enough for a per-surface context on a large appliance, low enough
/// that a loop or a misconfiguration cannot mint contexts without bound.
fn default_max_contexts() -> usize {
    256
}

/// What a key is allowed to sign.
///
/// A **security control**, not metadata: it is the gateway-side mirror of the
/// VTA `typ` allow-list, so a key provisioned to mint access tokens cannot be
/// turned on credentials. Which backend can serve which purpose is decided by
/// `crate::vta::key_directory::supports`, and enforced here at startup rather
/// than at the first signing call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Access tokens, ID-JAGs and VC-JWTs — anything signed as a compact JWS.
    Jwt,
    /// A Verifiable Credential issued under a context's issuer DID.
    Credential,
    /// A Data Integrity proof (e.g. on a Verifiable Presentation).
    Proof,
}

impl KeyPurpose {
    /// Stable wire/error name, matching the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::Credential => "credential",
            Self::Proof => "proof",
        }
    }
}

/// The flat `[vta] signing_key_id` has always described a JWT key, so an
/// unqualified block asks the backend for exactly that and nothing more.
fn default_purposes() -> Vec<KeyPurpose> {
    vec![KeyPurpose::Jwt]
}

/// A VTA-held key the gateway **publishes but no longer signs with**.
///
/// A per-surface migration and a key rotation both mean two keys are live at
/// once: the new one signs, the old one must still verify. A verifier selects
/// between them by `kid` (VTA-17 / SEC0-6115 condition 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiringKey {
    /// The VTA key record id — also the published `kid`.
    pub key_id: String,

    /// Multibase (`z…`) Ed25519 **public** key. Optional: when absent the
    /// connector resolves it from the VTA via `keys/show`.
    ///
    /// **Required for an internal (non-exportable) key.** The VTA refuses to
    /// return an internal key's record to *any* caller at *any* role — the
    /// guarantee is "never exported by any surface" — so its public half has to
    /// be captured at provisioning time (`keys/create` returns it) and recorded
    /// here. Public key material is not a secret.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// `[vta]` configuration block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtaConfig {
    /// Master switch. When `false` (default) the gateway signs locally and no
    /// VTA client is constructed — every other field is ignored.
    #[serde(default)]
    pub enabled: bool,

    /// What this appliance signs with when nobody has said (VTA-26).
    ///
    /// `auto` (the default) decides from the install: a **new** install takes
    /// the bundled agent and asks nothing, an **existing** install keeps the
    /// local key it has already been signing with. Settable explicitly so a
    /// fleet or IaC install never needs the dashboard.
    ///
    /// Ignored when [`Self::enabled`] is set: an explicitly configured agent
    /// always wins, because a default that could override configured behaviour
    /// would not be a default.
    #[serde(default)]
    pub default_backend: crate::vta::onboarding_default::DefaultBackend,

    /// Base URL of the VTA's REST surface (e.g. `https://vta.internal:8443`).
    /// Required when `enabled` and `transport = rest`.
    #[serde(default)]
    pub base_url: Option<String>,

    /// The VTA service DID (`did:webvh`). Pinned and resolved so the gateway
    /// talks to the intended VTA. Required when `enabled`.
    #[serde(default)]
    pub vta_did: Option<String>,

    /// The VTA context the gateway's scoped ACL grant lives in. Required when
    /// `enabled`.
    #[serde(default)]
    pub context_id: Option<String>,

    /// The VTA **key record id** the gateway's tokens are signed with — the
    /// *pinned JWT key* the VTA holds on the gateway's behalf (provisioned at
    /// onboarding in the gateway's context). Required when `enabled`: the
    /// connector's whole purpose is to sign, and a connector with no key to
    /// sign with is a misconfiguration, so it is a startup error rather than a
    /// first-signing-call surprise. The gateway never sees the private key;
    /// it only names which VTA-held key signs (VTA-06/07).
    #[serde(default)]
    pub signing_key_id: Option<String>,

    /// Multibase (`z…`) Ed25519 **public** key of [`Self::signing_key_id`].
    ///
    /// Optional, and worth setting: when present the gateway publishes its JWKS
    /// with **no VTA call at all**, so key publication cannot be affected by VTA
    /// availability.
    ///
    /// **Required when the signing key is internal (non-exportable).** The VTA
    /// will not return an internal key's record to any caller at any role, so
    /// capture the `publicKey` that `keys/create` returned and record it here.
    #[serde(default)]
    pub signing_key_public: Option<String>,

    /// Keys that are **retiring**: still published so the tokens they signed
    /// keep verifying, but no longer used to sign (VTA-17).
    #[serde(default)]
    pub retiring_keys: Vec<RetiringKey>,

    /// Which signing purposes this backend is asked to serve (VTA-18).
    /// Defaults to `["jwt"]`, which is what the flat `signing_key_id` has
    /// always meant.
    ///
    /// Validated against the backend's capabilities at startup, so asking the
    /// VTA for a purpose it cannot serve is a configuration error naming both
    /// — never a failure on the first request that needs it.
    #[serde(default = "default_purposes")]
    pub purposes: Vec<KeyPurpose>,

    /// Trust Task transport carrier. Defaults to `rest`.
    #[serde(default)]
    pub transport: VtaTransport,

    /// Deployment shape. Defaults to `appliance`.
    #[serde(default)]
    pub mode: VtaMode,

    /// How the gateway's auth/control key (the Ed25519 `did:key` the gateway
    /// authenticates to the VTA with) is sourced: e.g. `env://VAR` or
    /// `file://path`. Optional in the PoC — when absent the connector uses an
    /// ephemeral control key (resets on restart). Custody (encryption at rest,
    /// non-exportable KMS) is formalised in VTA-03.
    #[serde(default)]
    pub auth_key_source: Option<String>,

    /// The gateway's auth/control **identifier**, when it should be stable
    /// across key rotation (VTA-13).
    ///
    /// Absent (the default) the identifier is derived from the key itself as a
    /// `did:key`, so rotating the key means a new identity and a fresh VTA
    /// grant. Set to a `did:webvh:…` and the identifier stays put while the key
    /// rotates at the DID document — the VTA's ACL grant, its audit trail and
    /// the relationship all survive the rotation.
    ///
    /// The gateway holds only the **current auth signing key**. The
    /// update/pre-rotation key that can re-point verification methods is the
    /// crown jewel and is deliberately **not** configurable here: a
    /// request-serving process should not be able to rewrite its own identity.
    /// Rotation is performed off this host.
    #[serde(default)]
    pub auth_did: Option<String>,

    /// Publish a `did:webvh` at `/vta-auth/did.jsonl` and authenticate as it,
    /// instead of as the control key's own `did:key`.
    ///
    /// **Off by default, and that is deliberate.** The benefit is rotation: a
    /// `did:key` *is* its key, so replacing the key needs a fresh grant. But
    /// the trust agent resolves the published document on every
    /// authentication, so a gateway whose address it cannot reach — behind
    /// NAT, on a private network, or serving HTTPS on a port the DID's `http`
    /// URL cannot reach — stops authenticating **at all**. Defaulting this on
    /// would trade a working deployment for a convenience, which is the wrong
    /// way round.
    ///
    /// Turn it on when the gateway's `/vta-auth/did.jsonl` is reachable from
    /// the agent. `auth_did` still overrides it: an operator who hosts their
    /// own identity keeps it.
    #[serde(default)]
    pub publish_auth_did: bool,

    /// The verification method id within [`auth_did`](Self::auth_did) that the
    /// held signing key corresponds to — the fragment the auth proof names.
    ///
    /// Defaults to the first assertion/authentication method the DID document
    /// declares that matches the held key, so a rotation that keeps the same
    /// fragment needs no config change.
    #[serde(default)]
    pub auth_verification_method: Option<String>,

    /// Optional expected AWS Nitro enclave PCR0 (hex). When set, the VTA
    /// connector verifies the attestation surfaced on the auth challenge during
    /// connect. Off by default (not wired in the initial PoC).
    #[serde(default)]
    pub expect_pcr0: Option<String>,

    /// Per-call timeout to the VTA in milliseconds (VTA-04). The gateway owns
    /// the deadline so a hung VTA cannot tie up a surface.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Max concurrent in-flight VTA calls (VTA-04). Excess fails fast rather
    /// than queueing unboundedly.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,

    /// Emit a **data-minimized** (identifiers + hashes only), **bounded**,
    /// **non-blocking** audit record to the VTA for each signing event (VTA-08).
    /// Off by default; audit never blocks or fails the request it describes.
    #[serde(default)]
    pub audit_enabled: bool,

    /// Capacity of the bounded audit queue. A full queue drops records (counted)
    /// rather than growing memory. Ignored when `audit_enabled` is false.
    #[serde(default = "default_audit_queue_capacity")]
    pub audit_queue_capacity: usize,

    /// Max signing calls allowed per [`Self::sign_quota_window_secs`] window
    /// (VTA-17 / SEC0-6115 condition 5). Bounds how much a compromised or
    /// looping caller can mint before someone notices; exceeding it **fails
    /// closed** and is metered. `0` disables the quota.
    #[serde(default = "default_sign_quota_max")]
    pub sign_quota_max: u64,

    /// Length of the signing-quota window in seconds. Ignored when
    /// [`Self::sign_quota_max`] is `0`.
    #[serde(default = "default_sign_quota_window_secs")]
    pub sign_quota_window_secs: u64,

    /// Create a VTA context per surface (and per overriding variant) on first
    /// use (VTA-19).
    ///
    /// Off by default, because it requires **super-admin on the target VTA** —
    /// authority a customer-owned (BYO) VTA does not grant. With it off, a
    /// surface that asks for a VTA backend must name `signing.context_id`
    /// itself, and failing to is a configuration error rather than a runtime
    /// surprise.
    #[serde(default)]
    pub auto_provision_contexts: bool,

    /// Upper bound on contexts this gateway may create (VTA-19). Bounds the
    /// blast radius of a loop or a misconfiguration; exceeding it **fails
    /// closed** and is audited with the limit named.
    #[serde(default = "default_max_contexts")]
    pub max_contexts: usize,
}

impl Default for VtaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_backend: crate::vta::onboarding_default::DefaultBackend::default(),
            base_url: None,
            vta_did: None,
            context_id: None,
            signing_key_id: None,
            transport: VtaTransport::default(),
            mode: VtaMode::default(),
            auth_key_source: None,
            auth_did: None,
            publish_auth_did: false,
            auth_verification_method: None,
            expect_pcr0: None,
            timeout_ms: default_timeout_ms(),
            max_concurrent: default_max_concurrent(),
            audit_enabled: false,
            audit_queue_capacity: default_audit_queue_capacity(),
            signing_key_public: None,
            retiring_keys: Vec::new(),
            purposes: default_purposes(),
            sign_quota_max: default_sign_quota_max(),
            sign_quota_window_secs: default_sign_quota_window_secs(),
            auto_provision_contexts: false,
            max_contexts: default_max_contexts(),
        }
    }
}

impl VtaConfig {
    /// Validate the block at startup. A disabled block is always valid (no-op).
    /// An enabled block must name the VTA (`base_url` + `vta_did` + `context_id`)
    /// and may only select carriers/modes that are wired.
    ///
    /// Fails **closed**: an enabled-but-incomplete block is a startup error
    /// rather than a silent fallback to local signing, so an operator who meant
    /// to delegate signing is never quietly left signing locally.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.transport != VtaTransport::Rest {
            return Err(format!("[vta] transport = {:?} is not yet supported; only `rest` is wired", self.transport));
        }
        // Both modes are wired: `appliance` talks to a separately-operated VTA,
        // `embedded` (bundled) to one shipped in the gateway's own deployment
        // unit. The gateway code path is identical — only the endpoint differs
        // — which is exactly what makes switching between them a configuration
        // change (VTA-21).
        let require = |field: &str, value: &Option<String>| -> Result<(), String> {
            match value {
                Some(v) if !v.trim().is_empty() => Ok(()),
                _ => Err(format!("[vta] enabled but `{field}` is missing or empty")),
            }
        };
        require("base_url", &self.base_url)?;
        require("vta_did", &self.vta_did)?;
        require("context_id", &self.context_id)?;
        if self.timeout_ms == 0 {
            return Err("[vta] timeout_ms must be greater than zero".to_string());
        }
        if self.max_concurrent == 0 {
            return Err("[vta] max_concurrent must be greater than zero".to_string());
        }
        // Pinned signing key last: an enabled connector that cannot sign is a
        // misconfiguration, so fail closed at startup rather than at the first
        // signing call.
        require("signing_key_id", &self.signing_key_id)?;
        // A quota window of zero would make the limit meaningless (every call
        // starts a fresh window), so reject it rather than silently disabling
        // the control.
        if self.sign_quota_max > 0 && self.sign_quota_window_secs == 0 {
            return Err("[vta] sign_quota_window_secs must be greater than zero when sign_quota_max is set".to_string());
        }
        // A zero context quota with auto-provisioning on would refuse the very
        // first surface, so reject the combination rather than fail at runtime.
        if self.auto_provision_contexts && self.max_contexts == 0 {
            return Err(
                "[vta] max_contexts must be greater than zero when auto_provision_contexts is enabled".to_string()
            );
        }
        // A retiring key that is also the active key is a copy-paste slip: it
        // would publish the same `kid` twice.
        if self
            .retiring_keys
            .iter()
            .any(|k| Some(&k.key_id) == self.signing_key_id.as_ref())
        {
            return Err("[vta] retiring_keys must not contain the active signing_key_id".to_string());
        }
        // Capability negotiation (VTA-18): an operator who asks the VTA backend
        // for a purpose it cannot serve finds out now, with the backend and the
        // purpose both named, rather than when the first request that needs it
        // fails.
        if self.purposes.is_empty() {
            return Err("[vta] purposes must not be empty when enabled".to_string());
        }
        let backend = crate::vta::key_directory::KeyBackend::Vta {
            connection_id: crate::vta::key_directory::DEFAULT_CONNECTION_ID.to_string(),
        };
        for purpose in &self.purposes {
            if !crate::vta::key_directory::supports(&backend, *purpose) {
                return Err(format!(
                    "[vta] backend `{}` cannot sign for purpose `{}`",
                    backend.name(),
                    purpose.as_str()
                ));
            }
        }
        // Auto-provisioning used to be refused on anything but a bundled
        // sidecar, on the belief that creating a context means holding
        // super-admin over the agent. That is true only of a **top-level**
        // context. A sub-context is gated on reaching its parent, so an agent
        // grant carrying the narrow `context-create` capability — scoped to
        // the one context the operator named — can branch underneath it and
        // nothing more. That is exactly the grant the pairing wizard prints,
        // and the agent's own authorisation code calls it "exactly the grant
        // an agent gateway is paired with".
        //
        // So the deployment tier is not the right gate: the **grant** is, and
        // the agent is the authority on it. A gateway that was not granted
        // `context-create` is refused by the agent itself, with its own
        // reason — which is both correct and more informative than a
        // config-time guess. Refusing here as well only blocked operators who
        // had already granted the capability deliberately.
        Ok(())
    }

    /// The operator-facing deployment tier, for the management API and the
    /// dashboard. Reported even when the block is disabled, so the UI can say
    /// "local key" rather than guessing.
    pub fn tier(&self) -> &'static str {
        if !self.enabled {
            "local"
        } else {
            self.mode.tier()
        }
    }

    /// Whether this deployment supports a key-custody claim.
    ///
    /// Disabled (local signing) and bundled both answer `false`: in neither
    /// case are the keys held by anything the gateway's own host does not
    /// already control. Nothing in product copy or the dashboard may claim
    /// custody when this is `false`.
    pub fn supports_custody_claim(&self) -> bool {
        self.enabled
            && self
                .mode
                .supports_custody_claim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_and_valid() {
        let cfg = VtaConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.transport, VtaTransport::Rest);
        assert_eq!(cfg.mode, VtaMode::Appliance);
        assert_eq!(cfg.timeout_ms, 5_000);
        assert_eq!(cfg.max_concurrent, 16);
        cfg.validate()
            .expect("disabled block validates");
    }

    #[test]
    fn absent_block_parses_as_disabled() {
        // An empty bootstrap-style table must deserialize to the disabled default.
        let cfg: VtaConfig = toml::from_str("").expect("empty table parses");
        assert!(!cfg.enabled);
        cfg.validate()
            .expect("empty block validates");
    }

    #[test]
    fn enabled_requires_vta_coordinates() {
        let cfg: VtaConfig = toml::from_str("enabled = true").expect("parse");
        let err = cfg
            .validate()
            .expect_err("missing coordinates must fail");
        assert!(err.contains("base_url"), "names the missing field: {err}");
    }

    #[test]
    fn enabled_with_full_coordinates_validates() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse");
        cfg.validate()
            .expect("full coordinates validate");
    }

    #[test]
    fn enabled_requires_a_pinned_signing_key() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("a connector with no signing key must fail closed");
        assert!(err.contains("signing_key_id"), "names the missing field: {err}");
    }

    #[test]
    fn a_retiring_key_may_not_be_the_active_key() {
        // Publishing the same `kid` twice is a copy-paste slip, not a rotation.
        let cfg = VtaConfig {
            enabled: true,
            base_url: Some("https://vta.internal".to_string()),
            vta_did: Some("did:webvh:vta".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("key-active".to_string()),
            retiring_keys: vec![RetiringKey {
                key_id: "key-active".to_string(),
                public_key: None,
            }],
            ..VtaConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("the active key cannot also be retiring");
        assert!(err.contains("retiring_keys"), "names the field: {err}");
    }

    #[test]
    fn a_quota_with_a_zero_window_is_rejected() {
        // Every call would start a fresh window, so the limit would never bind.
        let cfg = VtaConfig {
            enabled: true,
            base_url: Some("https://vta.internal".to_string()),
            vta_did: Some("did:webvh:vta".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("key-active".to_string()),
            sign_quota_max: 100,
            sign_quota_window_secs: 0,
            ..VtaConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("a zero window makes the quota meaningless");
        assert!(err.contains("sign_quota_window_secs"), "names the field: {err}");
    }

    #[test]
    fn the_default_quota_is_enabled_and_bounded() {
        // Enabled by default with conservative limits, matching the STS
        // token-endpoint throttle convention.
        let cfg = VtaConfig::default();
        assert!(cfg.sign_quota_max > 0, "the quota is on by default");
        assert!(cfg.sign_quota_window_secs > 0);
        assert!(cfg.retiring_keys.is_empty(), "nothing is retiring on a fresh install");
    }

    #[test]
    fn enabled_rejects_unwired_transport() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            transport = "didcomm"
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("didcomm not wired");
        assert!(err.contains("transport"), "explains carrier: {err}");
    }

    #[test]
    fn enabled_rejects_zero_timeout() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            timeout_ms = 0
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("zero timeout invalid");
        assert!(err.contains("timeout_ms"), "explains timeout: {err}");
    }

    #[test]
    fn purposes_default_to_jwt_so_existing_config_parses_unchanged() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.purposes, vec![KeyPurpose::Jwt]);
        cfg.validate()
            .expect("the default purpose is one the backend serves");
    }

    #[test]
    fn a_purpose_the_backend_cannot_serve_fails_validation_naming_both() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            purposes = ["jwt", "proof"]
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("the vta backend cannot build data integrity proofs yet");
        assert!(err.contains("vta"), "names the backend: {err}");
        assert!(err.contains("proof"), "names the purpose: {err}");
    }

    #[test]
    fn an_empty_purpose_list_is_rejected() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            purposes = []
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("a connector that may sign nothing is a misconfiguration");
        assert!(err.contains("purposes"), "explains purposes: {err}");
    }

    #[test]
    fn a_disabled_block_never_fails_on_purposes() {
        let cfg = VtaConfig {
            purposes: vec![KeyPurpose::Proof],
            ..VtaConfig::default()
        };
        cfg.validate()
            .expect("a disabled block is always valid");
    }

    #[test]
    fn context_auto_provisioning_is_off_by_default() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse");
        // It needs super-admin on the target VTA, which a customer-owned VTA
        // does not grant, so it must be opted into rather than assumed.
        assert!(!cfg.auto_provision_contexts);
        assert_eq!(cfg.max_contexts, 256);
        cfg.validate()
            .expect("the default combination is valid");
    }

    #[test]
    fn auto_provisioning_with_a_zero_context_quota_is_rejected() {
        let cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            auto_provision_contexts = true
            max_contexts = 0
            "#,
        )
        .expect("parse");
        let err = cfg
            .validate()
            .expect_err("a zero quota would refuse the very first surface");
        assert!(err.contains("max_contexts"), "explains the quota: {err}");
    }

    // ── Deployment tier (VTA-21) ─────────────────────────────────────────

    fn bundled() -> VtaConfig {
        toml::from_str(
            r#"
            enabled = true
            mode = "embedded"
            base_url = "http://127.0.0.1:3000"
            vta_did = "did:webvh:localhost"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse")
    }

    #[test]
    fn the_bundled_mode_is_wired_and_keeps_its_legacy_wire_name() {
        let cfg = bundled();
        assert_eq!(cfg.mode, VtaMode::Bundled);
        cfg.validate()
            .expect("the bundled deployment is supported");
        // `bundled` is accepted as an alias so new config reads naturally.
        let aliased: VtaConfig = toml::from_str(
            r#"
            enabled = true
            mode = "bundled"
            base_url = "http://127.0.0.1:3000"
            vta_did = "did:webvh:localhost"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse");
        assert_eq!(aliased.mode, VtaMode::Bundled);
        // …and the legacy spelling is what is written back, so existing
        // deployments round-trip unchanged.
        assert!(
            serde_json::to_string(&cfg)
                .unwrap()
                .contains("\"embedded\"")
        );
    }

    /// The single most damaging thing this integration could do is claim key
    /// custody it does not have. A bundled sidecar shares a host, a disk and
    /// an operator with the gateway, so it is not a custody tier.
    #[test]
    fn no_custody_claim_attaches_to_the_bundled_or_local_tier() {
        assert_eq!(bundled().tier(), "bundled");
        assert!(!bundled().supports_custody_claim());

        let local = VtaConfig::default();
        assert_eq!(local.tier(), "local");
        assert!(!local.supports_custody_claim());

        let appliance: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            "#,
        )
        .expect("parse");
        assert_eq!(appliance.tier(), "self-hosted");
        assert!(appliance.supports_custody_claim());
    }

    /// `allows_self_administration` still distinguishes the tiers — it gates
    /// what the dashboard claims about custody — but it must **not** gate
    /// context auto-provisioning.
    ///
    /// Creating a *sub*-context needs only the narrow `context-create`
    /// capability scoped to its parent, which is exactly what the pairing
    /// wizard asks the operator to grant. Only a *top-level* context needs
    /// super-admin, and the agent enforces that itself. Refusing at config
    /// time blocked operators who had deliberately granted the capability,
    /// and the agent is the authority on its own grants.
    #[test]
    fn auto_provisioning_does_not_depend_on_the_deployment_tier() {
        assert!(VtaMode::Bundled.allows_self_administration(), "the gateway may administer a VTA on its own host");
        assert!(
            !VtaMode::Appliance.allows_self_administration(),
            "a VTA somebody else operates is theirs to administer"
        );

        let mut cfg: VtaConfig = toml::from_str(
            r#"
            enabled = true
            base_url = "https://vta.internal:8443"
            vta_did = "did:webvh:vta.internal:agent"
            context_id = "ctx-gateway"
            signing_key_id = "key-gateway-jwt"
            auto_provision_contexts = true
            "#,
        )
        .expect("parse");
        cfg.validate()
            .expect("a self-hosted agent may grant context-create; the agent decides, not this check");

        cfg.mode = VtaMode::Bundled;
        cfg.validate()
            .expect("auto-provisioning is fine on a bundled sidecar");
    }

    /// Switching bundled → remote must be a configuration change only: the
    /// same fields, the same validation, no code path difference.
    #[test]
    fn switching_between_tiers_is_a_configuration_change_only() {
        let mut cfg = bundled();
        cfg.validate()
            .expect("bundled is valid");

        cfg.mode = VtaMode::Appliance;
        cfg.base_url = Some("https://vta.customer.example".to_string());
        cfg.vta_did = Some("did:webvh:vta.customer.example".to_string());
        cfg.validate()
            .expect("the same block, re-pointed, is valid as a remote appliance");
        assert_eq!(cfg.tier(), "self-hosted");
    }
}
