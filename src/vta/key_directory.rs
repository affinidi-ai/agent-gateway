//! `KeyRef` + `KeyDirectory` — which key signs what, resolved per request.
//!
//! Before this module the appliance picked **one** [`CredentialAuthority`] at
//! boot, pinned to one key id. That singleton is what blocks per-surface and
//! per-variant contexts, per-tenant selection, per-agent keys
//! and an HSM backend: they all need the same thing —
//! *resolve which key, per request, behind the existing seam*.
//!
//! A [`KeyRef`] names a key without holding it: which **backend** holds it, in
//! which **context**, under which **key id**, and — crucially — for which
//! **purpose**. A [`KeyDirectory`] turns a request's
//! tenant/surface/variant coordinates into a `KeyRef`, and a `KeyRef` into a
//! connector.
//!
//! ## Purpose is a security control, not metadata
//!
//! [`KeyPurpose`] is the gateway-side mirror of the trust agent's `typ` allow-list: the
//! key that signs access tokens must not be usable to sign credentials, and
//! vice-versa. [`KeyDirectory::authority_for`] therefore takes the purpose the
//! caller is signing *for* and refuses a `KeyRef` minted for a different one —
//! enforced in code, not by convention.
//!
//! ## Capability negotiation happens at config-validation time
//!
//! A backend that cannot serve a purpose is rejected when the config is
//! validated, never at the first signing call: see [`supports`] and
//! `VtaConfig::validate`. An operator who asks the VTA backend to sign Data
//! Integrity proofs finds out at startup, not when the first request fails.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::vta::{KeyPurpose, VtaConfig};
use crate::identity::authority::CredentialAuthority;
use crate::vta::VtaError;

/// A VTA key-record id — also the `kid` the key is published under.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    /// Read the id back out. Used by callers that render a `KeyRef` (the Key
    /// Management dashboard) and by this module's tests.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A VTA context id — the scope a key and its issuer DID live in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContextId(pub String);

impl ContextId {
    /// See [`KeyId::as_str`].
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ContextId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Who holds the private key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyBackend {
    /// The gateway's own in-process issuer key.
    Local,
    /// A VTA, addressed by stored connection: `connection_id` selects the
    /// `[vta]` block's connection or a managed one.
    Vta { connection_id: String },
}

impl KeyBackend {
    /// Stable name for error messages, so a capability rejection says which
    /// backend refused.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Vta { .. } => "vta",
        }
    }
}

/// Names a signing key without holding it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyRef {
    pub backend: KeyBackend,
    pub context: Option<ContextId>,
    /// **Purpose-dependent.** Present for [`KeyPurpose::Jwt`] —
    /// `keys/sign-jws` takes a caller-named `keyId`. Absent for
    /// [`KeyPurpose::Credential`] / [`KeyPurpose::Proof`], where the key is
    /// *determined* by the context's issuer DID and resolved VTA-side; letting
    /// a caller name it there would let a caller sign a credential under a key
    /// the context's issuer DID does not account for.
    pub key_id: Option<KeyId>,
    pub purpose: KeyPurpose,
}

impl KeyRef {
    /// The appliance's local key, for `purpose`. This is what every resolution
    /// falls back to, and what the gateway used exclusively before the VTA
    /// connector existed.
    pub fn local(purpose: KeyPurpose) -> Self {
        Self {
            backend: KeyBackend::Local,
            context: None,
            key_id: None,
            purpose,
        }
    }

    /// Reject a `KeyRef` whose `key_id` presence contradicts its purpose, and
    /// whose backend cannot serve that purpose at all.
    pub fn validate(&self) -> Result<(), VtaError> {
        if !supports(&self.backend, self.purpose) {
            return Err(VtaError::Config(format!(
                "[vta] backend `{}` cannot sign for purpose `{}`",
                self.backend.name(),
                self.purpose.as_str()
            )));
        }
        // The local backend derives everything from its own issuer key, so a
        // caller-named key id there would name something that does not exist.
        if self.backend == KeyBackend::Local && self.key_id.is_some() {
            return Err(VtaError::Config("[vta] the local backend has no caller-nameable key id".to_string()));
        }
        if self.backend != KeyBackend::Local {
            match (self.purpose, &self.key_id) {
                (KeyPurpose::Jwt, None) => {
                    return Err(VtaError::Config(
                        "[vta] purpose `jwt` requires a key_id — keys/sign-jws names the key".to_string(),
                    ));
                }
                (KeyPurpose::Credential | KeyPurpose::Proof, Some(_)) => {
                    return Err(VtaError::Config(format!(
                        "[vta] purpose `{}` must not name a key_id — the key is determined by the context's issuer DID",
                        self.purpose.as_str()
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Whether `backend` can serve `purpose` today.
///
/// This is the single source of truth behind both config validation and
/// [`KeyDirectory::authority_for`], so the two can never disagree.
///
/// The VTA backend signs JWS (`keys/sign-jws`) and issues credentials
/// under the *context's* own issuer DID (`keys/sign-document`), which
/// is what lets a surface's own agent sign the credential embedded in the
/// presentation it forwards. It cannot yet build a standalone Data Integrity
/// proof for an arbitrary document, so asking it to is still a
/// misconfiguration rather than a runtime failure.
pub fn supports(
    backend: &KeyBackend,
    purpose: KeyPurpose,
) -> bool {
    match backend {
        // The in-process issuer key does all three: it signs JWTs, VC-JWTs, and
        // Data Integrity proofs via the local suite.
        KeyBackend::Local => true,
        KeyBackend::Vta { .. } => matches!(purpose, KeyPurpose::Jwt | KeyPurpose::Credential),
    }
}

/// The coordinates a key is resolved against. All optional: an appliance-wide
/// signing call supplies none, and matches the appliance default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyScope {
    pub tenant_id: Option<String>,
    pub surface_id: Option<String>,
    pub variant_id: Option<String>,
}

impl KeyScope {
    /// Convenience constructors for a request's surface, variant and tenant
    /// coordinates.
    pub fn surface(surface_id: impl Into<String>) -> Self {
        Self {
            surface_id: Some(surface_id.into()),
            ..Self::default()
        }
    }

    /// The surface a request is served by, its owner, and the variant serving
    /// it, if any. The owner names the surface's derived context, so a surface
    /// created under another tenant with a deleted surface's id never signs in
    /// that surface's context.
    pub fn serving(
        surface: &crate::config::agent_surface::AgentSurface,
        variant_id: Option<&str>,
    ) -> Self {
        Self {
            tenant_id: surface.tenant_id.clone(),
            surface_id: Some(surface.surface_id.clone()),
            variant_id: variant_id.map(str::to_string),
        }
    }

    #[cfg(test)]
    pub fn variant(
        surface_id: impl Into<String>,
        variant_id: impl Into<String>,
    ) -> Self {
        Self {
            surface_id: Some(surface_id.into()),
            variant_id: Some(variant_id.into()),
            ..Self::default()
        }
    }
}

/// What a mapping is scoped to. Ordered most-specific first — the discriminant
/// order *is* the resolution order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum MappingScope {
    /// A specific variant of a specific surface.
    Variant {
        surface_id: String,
        variant_id: String,
    },
    Surface {
        surface_id: String,
    },
}

/// Supplies the appliance-wide signing override, read fresh on every
/// resolution.
///
/// A port rather than a direct read of the settings store so the resolution
/// order is unit-testable without a process-wide global, and so the override
/// could later come from somewhere else without touching the directory.
pub trait ApplianceSigningDefault: Send + Sync {
    /// The configured override, or `None` to fall through to the `[vta]`
    /// defaults. Returning `None` must be indistinguishable from never having
    /// installed a source at all.
    fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig>;
}

/// Reads the appliance override from the dashboard settings store.
pub struct SettingsApplianceDefault;

impl ApplianceSigningDefault for SettingsApplianceDefault {
    fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
        crate::storage::settings_store::global_settings()?
            .default_signing
            .filter(|s| !s.is_empty())
    }
}

/// A configured override: "for this scope and this purpose, use this key".
#[derive(Debug, Clone)]
struct KeyMapping {
    scope: MappingScope,
    purpose: KeyPurpose,
    key_ref: KeyRef,
}

/// What a scope says about which issuer signs its agent-identity credential.
///
/// Three-state on purpose: an `Option` conflated "this surface asks for the
/// gateway's own key" with "this surface has no opinion", so an explicit local
/// fell through to the appliance default and the setting appeared to do nothing.
pub enum ScopedDiIssuer {
    /// The scope resolves to an agent-backed issuer.
    Agent(Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>),
    /// The scope explicitly asks for the gateway's own key.
    Local,
    /// The scope has no opinion — use the appliance default.
    Inherit,
    /// The scope maps a trust agent that cannot issue right now. Issuing under
    /// any other issuer would change it under callers, so this is an error.
    Unavailable(String),
}

/// What the appliance says about who signs the fabric issuer attestation,
/// decided by the same resolution as the agent-identity credential's issuer so
/// the DID it attests is the one peers receive credentials from.
pub enum ScopedContextSigner {
    /// Sign as the agent context that issues the appliance's credentials.
    Agent(Arc<dyn crate::vta::context_signer::ContextSigner>),
    /// The appliance explicitly asks for the gateway's own key.
    Local,
    /// No opinion — use whatever signer was installed for `[vta]`, or the
    /// gateway's own key.
    Inherit,
    /// The chosen trust agent cannot sign right now; nothing else may attest.
    Unavailable(String),
}

/// The agent context a scope issues credentials as.
enum IssuingContext {
    Agent { client: Arc<crate::vta::client::VtaRestClient>, context_id: String },
    Local,
    Inherit,
    Unavailable(String),
}

/// Resolves request coordinates to a [`KeyRef`], and a `KeyRef` to a connector.
pub struct KeyDirectory {
    /// Appliance-wide default per purpose. Populated from `[vta]` by
    /// [`KeyDirectory::build`]; falls back to the local key for any purpose the
    /// config does not cover.
    defaults: HashMap<KeyPurpose, KeyRef>,
    /// Scoped overrides, consulted before the defaults.
    mappings: Vec<KeyMapping>,
    local: Arc<dyn CredentialAuthority>,
    /// Contexts already given a signing identity, so the bootstrap costs one
    /// round trip per context rather than one per request.
    identified: tokio::sync::RwLock<std::collections::HashSet<String>>,
    /// Attestation signers by client and context, so a context's identity is
    /// read once per connection client rather than on every attestation.
    context_signers: RwLock<HashMap<(usize, String), Arc<dyn crate::vta::context_signer::ContextSigner>>>,
    /// The bootstrap-configured VTA connector, if `[vta]` is enabled. Used for
    /// [`DEFAULT_CONNECTION_ID`] so a gateway with no connection records — and
    /// no secrets store — still resolves exactly what `[vta]` always built.
    vta: Option<Arc<dyn CredentialAuthority>>,
    /// The Data-Integrity agent-identity issuer built from the same bootstrap
    /// client as `vta`. Shared rather than built separately because
    /// one control DID gets one VTA session — a second client authenticating as
    /// the same DID supersedes the first.
    di_vc_issuer: Option<Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>>,
    /// Creates per-surface contexts under the gateway's own, from the same
    /// bootstrap client. `None` when `[vta]` is disabled or
    /// auto-provisioning is off.
    context_creator: Option<Arc<dyn crate::vta::provisioning::ContextCreator>>,
    /// Provisions a per-agent context so an agent's holder key lives in the
    /// VTA rather than on this host. `None` under the same conditions
    /// as `context_creator`.
    agent_provisioner: Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>>,
    /// The client the holder-proof issuer dials, shared so a second
    /// session for the same control DID never supersedes the first.
    client: Option<Arc<crate::vta::client::VtaRestClient>>,
    /// Managed connection records. When present, any other
    /// `connection_id` resolves through it, so several VTAs can be mapped at
    /// once and edits take effect without a restart.
    connections: Option<Arc<crate::vta::registry::VtaConnectionRegistry>>,
    /// Read at resolution time so a surface written **after** startup is
    /// honoured. The `mappings` below are a boot-time snapshot: surfaces are
    /// hot-reloadable everywhere else in the gateway, and a key mapping that
    /// needed a restart to take effect silently signed with the wrong key.
    surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    /// Read at resolution time for the issuer that owns a surface, whose `signing` is the default
    /// for every surface it owns that sets none of its own.
    issuers: Option<Arc<dyn crate::issuers::IssuerStore>>,
    /// An appliance-wide override set in the dashboard, consulted **after**
    /// scoped mappings and **before** the `[vta]`-derived defaults.
    ///
    /// Read on every resolution rather than captured at build time, so
    /// changing the appliance's signing backend in the UI takes effect without
    /// a restart — the same reason registry-backed connections are resolved
    /// per call rather than cached here.
    appliance_default: Option<Arc<dyn ApplianceSigningDefault>>,
    /// Lazy context provisioning. When present, a VTA-backed `KeyRef`
    /// that names no context has one derived and created on first use.
    provisioner: Option<Arc<crate::vta::provisioning::ContextProvisioner>>,
    /// Connectors are reusable across requests; cache per `KeyRef` so a
    /// per-request resolution costs a map lookup, not a reconnect.
    ///
    /// Deliberately **not** used for registry-backed connections: the registry
    /// owns their lifecycle, and caching them a second time here would keep a
    /// disabled connection alive after the registry invalidated it.
    cache: RwLock<HashMap<KeyRef, Arc<dyn CredentialAuthority>>>,
}

impl KeyDirectory {
    /// Build the directory from `[vta]` config. This is the former
    /// `select_credential_authority` promoted to a directory builder: it picks
    /// the same connector, but records it as the appliance **default** rather
    /// than pinning it for the whole process.
    ///
    /// Fails closed exactly as before — an enabled-but-unbuildable connector is
    /// a startup error, never a silent fallback to local signing.
    pub async fn build(
        config: &VtaConfig,
        local: Arc<dyn CredentialAuthority>,
    ) -> Result<Self, VtaError> {
        let selected = super::select_signing_backends(config, Arc::clone(&local)).await?;
        let di_vc_issuer = selected.di_vc_issuer.clone();
        let context_creator = selected
            .context_creator
            .clone();
        let agent_provisioner = selected
            .agent_provisioner
            .clone();
        let client = selected.client.clone();
        let vta = if config.enabled {
            Some(selected.authority)
        } else {
            None
        };

        let mut defaults = HashMap::new();
        if config.enabled {
            // Backwards compatibility: the flat `[vta] signing_key_id` becomes
            // the appliance default `KeyRef` for every purpose the operator
            // asked the VTA to serve. `validate()` has already rejected any
            // purpose the backend cannot serve, so this cannot install an
            // unusable default.
            let backend = KeyBackend::Vta {
                connection_id: DEFAULT_CONNECTION_ID.to_string(),
            };
            let context = config
                .context_id
                .as_deref()
                .map(ContextId::from);
            for purpose in config
                .purposes
                .iter()
                .copied()
            {
                let key_id = match purpose {
                    KeyPurpose::Jwt => config
                        .signing_key_id
                        .as_deref()
                        .map(KeyId::from),
                    KeyPurpose::Credential | KeyPurpose::Proof => None,
                };
                let key_ref = KeyRef {
                    backend: backend.clone(),
                    context: context.clone(),
                    key_id,
                    purpose,
                };
                key_ref.validate()?;
                defaults.insert(purpose, key_ref);
            }
        }

        Ok(Self {
            identified: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            context_signers: RwLock::new(HashMap::new()),
            defaults,
            mappings: Vec::new(),
            local,
            vta,
            di_vc_issuer,
            context_creator,
            agent_provisioner,
            client,
            connections: None,
            surfaces: None,
            issuers: None,
            provisioner: None,
            appliance_default: None,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Install the appliance-wide override source (the dashboard setting).
    pub fn with_appliance_default(
        mut self,
        source: Arc<dyn ApplianceSigningDefault>,
    ) -> Self {
        self.appliance_default = Some(source);
        self
    }

    /// The Data-Integrity agent-identity issuer, when `[vta]` selected one.
    ///
    /// `None` leaves the gateway's local issuer in place, which is the
    /// pre-VTA behaviour.
    pub fn di_vc_issuer(&self) -> Option<Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>> {
        self.di_vc_issuer.clone()
    }

    /// Give a context reached through this directory an identity so it can
    /// issue, remembering the ones already done.
    async fn ensure_can_issue(
        &self,
        client: &Arc<crate::vta::client::VtaRestClient>,
        context_id: &str,
    ) {
        if self
            .identified
            .read()
            .await
            .contains(context_id)
        {
            return;
        }
        if crate::vta::context_creator::ensure_context_can_issue(client, context_id).await {
            self.identified
                .write()
                .await
                .insert(context_id.to_string());
        }
    }

    /// The Data-Integrity credential issuer for one request's coordinates, or
    /// `None` to sign locally.
    ///
    /// Resolves through the ordinary order — variant, surface, issuer,
    /// dashboard default, `[vta]`, local — so a surface's own `signing` block
    /// governs the credential inside an injected presentation exactly as it
    /// governs a token. A scope that resolves to the local key returns `None`,
    /// which is what keeps a gateway that never adopted an agent on precisely
    /// the path it was always on.
    ///
    /// Provisioning is deliberate, not incidental: a surface mapped to an
    /// agent with no context named gets one derived from its stable id and
    /// created on first use, the same context its tokens already use.
    pub async fn di_vc_issuer_for(
        &self,
        scope: &KeyScope,
    ) -> ScopedDiIssuer {
        match self
            .issuing_context_for(scope)
            .await
        {
            IssuingContext::Agent { client, context_id } => {
                ScopedDiIssuer::Agent(Arc::new(crate::vta::vc_issuer::VtaVcIssuer::new(client, context_id))
                    as Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>)
            }
            IssuingContext::Local => ScopedDiIssuer::Local,
            IssuingContext::Inherit => ScopedDiIssuer::Inherit,
            IssuingContext::Unavailable(reason) => ScopedDiIssuer::Unavailable(reason),
        }
    }

    /// Who signs the fabric issuer attestation: the context that issues the
    /// appliance-wide agent-identity credential, resolved the same way and at
    /// the same moment, so the attested DID and the credential issuer agree.
    pub async fn attestation_signer(&self) -> ScopedContextSigner {
        let (client, context_id) = match self
            .issuing_context_for(&KeyScope::default())
            .await
        {
            IssuingContext::Agent { client, context_id } => (client, context_id),
            IssuingContext::Local => return ScopedContextSigner::Local,
            IssuingContext::Inherit => return ScopedContextSigner::Inherit,
            IssuingContext::Unavailable(reason) => return ScopedContextSigner::Unavailable(reason),
        };
        let key = (Arc::as_ptr(&client) as usize, context_id.clone());
        if let Some(signer) = self
            .context_signers
            .read()
            .await
            .get(&key)
        {
            return ScopedContextSigner::Agent(Arc::clone(signer));
        }
        let signer: Arc<dyn crate::vta::context_signer::ContextSigner> =
            Arc::new(crate::vta::context_signer::VtaContextSigner::new(client, context_id));
        self.context_signers
            .write()
            .await
            .insert(key, Arc::clone(&signer));
        ScopedContextSigner::Agent(signer)
    }

    async fn issuing_context_for(
        &self,
        scope: &KeyScope,
    ) -> IssuingContext {
        // An explicit `local` on the surface is an **answer**, not an absence.
        // Reading it as "no opinion" let it fall through to the appliance
        // default, so a surface switched back to the gateway's own key carried
        // on issuing through the agent and the setting looked inert.
        if let Ok(Some(declared)) = self
            .live_surface_ref(KeyPurpose::Credential, scope)
            .await
            && matches!(declared.backend, KeyBackend::Local)
        {
            return IssuingContext::Local;
        }
        // Someone chose this trust agent — the surface, its variant or issuer,
        // or the gateway-wide default naming a connection. When it cannot
        // issue, another issuer would change the credential's issuer under
        // callers, so that is refused. With no such choice the scope inherits
        // the appliance's issuer, which is what it always issued under.
        let chosen = self
            .has_explicit_mapping(KeyPurpose::Credential, scope)
            .await
            || self.default_names_a_connection();
        let unusable = |reason: String| {
            tracing::warn!(
                target: "vta_audit",
                surface_id = ?scope.surface_id,
                error = %reason,
                chosen,
                "the trust agent that issues this scope's credential is unusable",
            );
            if chosen {
                IssuingContext::Unavailable(reason)
            } else {
                IssuingContext::Inherit
            }
        };
        let key_ref = match self
            .resolve_and_provision(KeyPurpose::Credential, scope)
            .await
        {
            Ok(key_ref) => key_ref,
            Err(e) => return unusable(e.log_detail().to_string()),
        };
        let KeyBackend::Vta { connection_id } = &key_ref.backend else {
            // A gateway-wide default of the gateway's own key is an answer too:
            // inheriting would hand the credential to the `[vta]` issuer while
            // tokens sign locally.
            if chosen || self.default_is_local() {
                return IssuingContext::Local;
            }
            return IssuingContext::Inherit;
        };
        // A credential is issued **as** a context: its designated key signs and
        // its DID becomes the issuer. Without one there is nothing to issue as.
        let Some(context_id) = key_ref.context.as_ref() else {
            return unusable(format!("trust agent connection `{connection_id}` names no context to issue as"));
        };
        let Some(registry) = self.connections.as_ref() else {
            return unusable(format!("trust agent connection `{connection_id}` is not available"));
        };
        match registry
            .client(connection_id)
            .await
        {
            Ok(client) => {
                // A context reached through a surface mapping needs the same
                // identity bootstrap the appliance default gets. Without it a
                // hand-made parent context — the one the operator creates in
                // the walkthrough — refuses the first issuance outright.
                self.ensure_can_issue(&client, context_id.as_str())
                    .await;
                IssuingContext::Agent {
                    client,
                    context_id: context_id
                        .as_str()
                        .to_string(),
                }
            }
            Err(e) => unusable(format!("trust agent connection `{connection_id}`: {}", e.log_detail())),
        }
    }

    /// Whether the gateway-wide default names a stored trust agent connection,
    /// rather than the gateway's own key or the `[vta]` bootstrap connection,
    /// which the `[vta]` issuer serves when the registry cannot.
    fn default_names_a_connection(&self) -> bool {
        self.appliance_default
            .as_ref()
            .and_then(|source| source.signing())
            .is_some_and(|signing| {
                signing.backend == Some(crate::config::agent_surface::SigningBackendKind::Vta)
                    && signing
                        .connection_id
                        .as_deref()
                        .is_some_and(|id| id != DEFAULT_CONNECTION_ID)
            })
    }

    /// Whether the gateway-wide default explicitly asks for the gateway's own key.
    fn default_is_local(&self) -> bool {
        self.appliance_default
            .as_ref()
            .and_then(|source| source.signing())
            .is_some_and(|signing| signing.backend == Some(crate::config::agent_surface::SigningBackendKind::Local))
    }

    /// The context creator, when `[vta]` selected one and auto-provisioning is
    /// enabled.
    ///
    /// `None` means an unmapped surface stays a configuration error the
    /// operator fixes by naming a context, rather than something provisioned
    /// behind their back.
    pub fn context_creator(&self) -> Option<Arc<dyn crate::vta::provisioning::ContextCreator>> {
        self.context_creator.clone()
    }

    /// The agent-identity provisioner, when `[vta]` selected one and
    /// auto-provisioning is enabled.
    ///
    /// `None` leaves onboarding generating an agent key on this host, which is
    /// the pre-migration behaviour.
    pub fn agent_provisioner(&self) -> Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>> {
        self.agent_provisioner.clone()
    }

    /// The shared VTA client, when one was built.
    pub fn client(&self) -> Option<Arc<crate::vta::client::VtaRestClient>> {
        self.client.clone()
    }

    /// Attach the managed connection registry, so a `KeyRef` naming
    /// any stored connection resolves through it. Without this only the
    /// bootstrap connection is reachable.
    pub fn with_connections(
        mut self,
        connections: Arc<crate::vta::registry::VtaConnectionRegistry>,
    ) -> Self {
        self.connections = Some(connections);
        self
    }

    /// Attach the surface store so a surface's `signing` block is read at
    /// resolution time rather than taken from the boot-time snapshot.
    ///
    /// Surfaces are hot-reloadable everywhere else in the gateway, so a key
    /// mapping that only took effect after a restart was a trap: an operator
    /// pointed a freshly created surface at an agent, saw it saved, and it
    /// kept signing with the appliance default until someone restarted the
    /// process — with nothing logged, because nothing had failed.
    pub fn with_surface_store(
        mut self,
        surfaces: Arc<dyn crate::surfaces::AgentSurfaceStore>,
    ) -> Self {
        self.surfaces = Some(surfaces);
        self
    }

    /// Attach the issuer store so the `signing` of the issuer that owns a surface is honoured as
    /// that surface's default, read at resolution time like the surface itself.
    pub fn with_issuer_store(
        mut self,
        issuers: Arc<dyn crate::issuers::IssuerStore>,
    ) -> Self {
        self.issuers = Some(issuers);
        self
    }

    /// The `signing` of the issuer that owns `surface`, when it has one.
    ///
    /// An issuer that no longer exists sets nothing; one that cannot be read is
    /// an error, because its `signing` may be the mapping that decides the key.
    async fn issuer_signing(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> Result<Option<crate::config::agent_surface::SurfaceSigningConfig>, VtaError> {
        let (Some(store), Some(issuer_id)) = (self.issuers.as_ref(), surface.issuer_id.as_deref()) else {
            return Ok(None);
        };
        let issuer = store
            .get(issuer_id)
            .await
            .map_err(|e| VtaError::Config(format!("issuer `{issuer_id}` could not be read for its signing: {e}")))?;
        Ok(issuer
            .and_then(|issuer| issuer.signing)
            .filter(|signing| !signing.is_empty()))
    }

    /// The mapping a surface declares **right now**, if it declares one.
    ///
    /// `Ok(None)` — no store, no such surface, or nothing declared — falls
    /// through to the snapshot and then the appliance default, which is what an
    /// unmapped surface has always resolved. A store that cannot be read, or a
    /// declared block this backend cannot serve for `purpose`, is an error: the
    /// surface may map a trust agent key, and reading either as "no mapping"
    /// would sign with the appliance key instead.
    /// The tenant owning the surface `scope` names: the stored surface's, which
    /// a caller cannot get wrong, then the scope's.
    async fn surface_owner(
        &self,
        scope: &KeyScope,
    ) -> Result<Option<String>, VtaError> {
        if let (Some(store), Some(surface_id)) = (self.surfaces.as_ref(), scope.surface_id.as_deref())
            && let Some(surface) = crate::surfaces::AgentSurfaceStore::get_checked(store.as_ref(), surface_id)
                .await
                .map_err(|e| VtaError::Config(format!("surface `{surface_id}` could not be read for its owner: {e}")))?
        {
            return Ok(surface.tenant_id);
        }
        Ok(scope.tenant_id.clone())
    }

    async fn live_surface_ref(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> Result<Option<KeyRef>, VtaError> {
        let (Some(store), Some(surface_id)) = (self.surfaces.as_ref(), scope.surface_id.as_deref()) else {
            return Ok(None);
        };
        let Some(surface) = crate::surfaces::AgentSurfaceStore::get_checked(store.as_ref(), surface_id)
            .await
            .map_err(|e| VtaError::Config(format!("surface `{surface_id}` could not be read for its signing: {e}")))?
        else {
            return Ok(None);
        };

        // A variant override wins over its surface, matching `resolve`.
        let variant_signing = scope
            .variant_id
            .as_deref()
            .and_then(|variant_id| {
                surface
                    .variants
                    .iter()
                    .find(|v| v.id == variant_id)
            })
            .and_then(|v| v.overrides.signing.as_ref())
            .filter(|s| !s.is_empty());
        // A surface that sets nothing follows the issuer that owns it, before the appliance default.
        let issuer_signing;
        let signing = match variant_signing.or(surface
            .signing
            .as_ref()
            .filter(|s| !s.is_empty()))
        {
            Some(own) => own,
            None => match self
                .issuer_signing(&surface)
                .await?
            {
                Some(signing) => {
                    issuer_signing = signing;
                    &issuer_signing
                }
                None => return Ok(None),
            },
        };

        signing_key_ref(signing, purpose)
            .map(Some)
            .map_err(|e| {
                VtaError::Config(format!(
                    "surface `{surface_id}` declares a signing key it cannot use: {}",
                    e.log_detail()
                ))
            })
    }

    /// Attach the lazy context provisioner, so a surface that asks
    /// for a VTA backend without naming a context gets one created on first
    /// use. Without it, such a surface is a configuration error — which is
    /// what surface validation reports.
    pub fn with_provisioner(
        mut self,
        provisioner: Arc<crate::vta::provisioning::ContextProvisioner>,
    ) -> Self {
        self.provisioner = Some(provisioner);
        self
    }

    /// Install a scoped override, fed from per-surface and per-variant
    /// `signing` config.
    ///
    /// Returns an error for a `KeyRef` the backend cannot honour, so a bad
    /// mapping is rejected when it is installed rather than when it first signs.
    fn push_variant_mapping(
        &mut self,
        surface_id: impl Into<String>,
        variant_id: impl Into<String>,
        key_ref: KeyRef,
    ) -> Result<(), VtaError> {
        key_ref.validate()?;
        self.mappings
            .push(KeyMapping {
                scope: MappingScope::Variant {
                    surface_id: surface_id.into(),
                    variant_id: variant_id.into(),
                },
                purpose: key_ref.purpose,
                key_ref,
            });
        Ok(())
    }

    /// Install a surface-scoped override. See [`Self::push_variant_mapping`].
    fn push_surface_mapping(
        &mut self,
        surface_id: impl Into<String>,
        key_ref: KeyRef,
    ) -> Result<(), VtaError> {
        key_ref.validate()?;
        self.mappings
            .push(KeyMapping {
                scope: MappingScope::Surface { surface_id: surface_id.into() },
                purpose: key_ref.purpose,
                key_ref,
            });
        Ok(())
    }

    /// Install the mappings a surface and its variants declare.
    ///
    /// A surface with no `signing` block installs nothing and therefore keeps
    /// resolving the appliance default — exactly today's behaviour. A variant
    /// with no override installs nothing either and so **inherits** its
    /// surface's mapping, because a variant is a sparse delta everywhere else
    /// in the system and signing follows the same rule.
    ///
    /// All-or-nothing: every mapping is validated before any is installed, so
    /// a surface with one bad variant does not end up half-mapped.
    pub fn with_surface(
        &mut self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> Result<(), VtaError> {
        // Translate and validate everything first, then install: a surface
        // with one bad variant must not end up half-mapped.
        //
        // Installed for **every purpose the backend can serve**, not just
        // `Jwt`. A surface's `signing` block says "this surface signs with
        // that key"; mapping only tokens left the credential inside its
        // forwarded presentation resolving the appliance default instead,
        // which is not what the control claims to do.
        let purposes_for = |signing: &crate::config::agent_surface::SurfaceSigningConfig| {
            [KeyPurpose::Jwt, KeyPurpose::Credential]
                .into_iter()
                .filter(|purpose| {
                    signing_key_ref(signing, *purpose)
                        .map(|key_ref| supports(&key_ref.backend, *purpose))
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>()
        };

        let mut surface_refs = Vec::new();
        if let Some(signing) = surface
            .signing
            .as_ref()
            .filter(|s| !s.is_empty())
        {
            // `Jwt` is validated unconditionally so an unusable backend is
            // still reported, rather than silently mapping nothing.
            signing_key_ref(signing, KeyPurpose::Jwt)?;
            for purpose in purposes_for(signing) {
                surface_refs.push(signing_key_ref(signing, purpose)?);
            }
        }
        let mut variant_refs = Vec::new();
        for variant in &surface.variants {
            let Some(signing) = variant
                .overrides
                .signing
                .as_ref()
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            signing_key_ref(signing, KeyPurpose::Jwt)?;
            for purpose in purposes_for(signing) {
                variant_refs.push((variant.id.clone(), signing_key_ref(signing, purpose)?));
            }
        }

        for key_ref in surface_refs {
            self.push_surface_mapping(surface.surface_id.clone(), key_ref)?;
        }
        for (variant_id, key_ref) in variant_refs {
            self.push_variant_mapping(surface.surface_id.clone(), variant_id, key_ref)?;
        }
        Ok(())
    }

    /// Resolve which key signs for `purpose` at `scope`.
    ///
    /// First match wins, in the order **variant → surface → issuer → tenant →
    /// appliance default → local**, mirroring the surface-variant override semantics used
    /// everywhere else in the gateway. The final fallback is the legacy local
    /// key, so a gateway with nothing configured resolves exactly what it
    /// signed with before this module existed.
    pub fn resolve(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> Result<KeyRef, VtaError> {
        if let (Some(surface_id), Some(variant_id)) = (
            scope
                .surface_id
                .as_deref(),
            scope
                .variant_id
                .as_deref(),
        ) && let Some(m) = self.find(purpose, |s| {
            matches!(s, MappingScope::Variant { surface_id: sid, variant_id: vid } if sid == surface_id && vid == variant_id)
        }) {
            return Ok(m);
        }
        if let Some(surface_id) = scope.surface_id.as_deref()
            && let Some(m) =
                self.find(purpose, |s| matches!(s, MappingScope::Surface { surface_id: sid } if sid == surface_id))
        {
            return Ok(m);
        }
        // The dashboard override outranks the `[vta]` block: an operator who
        // points the appliance at a paired connection in the UI expects that
        // to win over a file they may not be able to edit. It is an explicit
        // choice of signer, so one that cannot sign tokens refuses every
        // purpose rather than splitting them between it and another key. A
        // purpose its backend does not serve, such as a Data Integrity proof
        // on a trust agent, still follows the `[vta]` defaults.
        if let Some(source) = self
            .appliance_default
            .as_ref()
            && let Some(signing) = source.signing()
        {
            signing_key_ref(&signing, KeyPurpose::Jwt).map_err(|e| {
                VtaError::Config(format!(
                    "the gateway-wide default signing choice cannot sign tokens: {}",
                    e.log_detail()
                ))
            })?;
            if let Ok(key_ref) = signing_key_ref(&signing, purpose) {
                return Ok(key_ref);
            }
        }
        Ok(self
            .defaults
            .get(&purpose)
            .cloned()
            .unwrap_or_else(|| KeyRef::local(purpose)))
    }

    /// Whether `scope` has a mapping of its own: a variant or surface
    /// mapping, or a `signing` block on the surface or its issuer. The appliance default
    /// and the local key are what *everything* resolves to, so they do not count.
    ///
    /// An explicit mapping is a decision somebody made about whose key signs
    /// here. When that key cannot be reached, signing with a different one is
    /// not a graceful degradation: it changes the issuer under callers' feet and
    /// can hand a tenant's tokens to the operator's key.
    ///
    /// A surface whose mapping cannot be read counts as mapped, so its signing
    /// fails closed rather than falling back to the appliance key.
    /// Whether the managed connection `connection_id` was deleted, disabled or
    /// revoked, so keys it signed with are no longer this gateway's. A
    /// directory with no connection records retires nothing.
    pub async fn connection_retired(
        &self,
        connection_id: &str,
    ) -> bool {
        match &self.connections {
            Some(connections) => {
                connections
                    .retired(connection_id)
                    .await
            }
            None => false,
        }
    }

    pub async fn has_explicit_mapping(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> bool {
        if !matches!(
            self.live_surface_ref(purpose, scope)
                .await,
            Ok(None)
        ) {
            return true;
        }
        self.mappings
            .iter()
            .filter(|m| m.purpose == purpose)
            .any(|m| match &m.scope {
                MappingScope::Variant { surface_id, variant_id } => {
                    scope.surface_id.as_deref() == Some(surface_id) && scope.variant_id.as_deref() == Some(variant_id)
                }
                MappingScope::Surface { surface_id } => scope.surface_id.as_deref() == Some(surface_id),
            })
    }

    /// [`Self::resolve`], plus **lazy context provisioning**.
    ///
    /// A VTA-backed key that names no context has one derived from the scope's
    /// stable ids and created on first use. Deriving the name rather than
    /// storing it is what makes a rename safe: the name is a pure function of
    /// the surface/variant UUIDs, so renaming cannot orphan the context or
    /// cause a second one to be provisioned for the same surface.
    ///
    /// Without a provisioner attached, such a key is returned unchanged and the
    /// signing call fails — which is why surface validation rejects the
    /// combination up front, with a message naming the fix.
    pub async fn resolve_and_provision(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> Result<KeyRef, VtaError> {
        let mut key_ref = match self
            .live_surface_ref(purpose, scope)
            .await?
        {
            Some(live) => live,
            None => self.resolve(purpose, scope)?,
        };
        let KeyBackend::Vta { connection_id } = &key_ref.backend else {
            return Ok(key_ref);
        };
        if key_ref.context.is_some() {
            return Ok(key_ref);
        }
        // Contexts are created as children of the `[vta]` grant, through its
        // client. Another connection's key is left without one rather than
        // given a context that connection does not hold.
        if !is_bootstrap_connection(connection_id) {
            return Ok(key_ref);
        }
        let Some(provisioner) = self.provisioner.as_ref() else {
            return Ok(key_ref);
        };
        // An appliance-wide signing call has no surface to derive a name from,
        // so there is nothing to provision — the appliance default is expected
        // to carry its own context.
        let Some(surface_id) = scope.surface_id.as_deref() else {
            return Ok(key_ref);
        };
        let owner = self
            .surface_owner(scope)
            .await?;
        let name = crate::config::agent_surface::derived_context_name(
            owner.as_deref(),
            surface_id,
            scope.variant_id.as_deref(),
        );
        key_ref.context = Some(
            provisioner
                .ensure_context(&name)
                .await?,
        );
        Ok(key_ref)
    }

    fn find(
        &self,
        purpose: KeyPurpose,
        matches_scope: impl Fn(&MappingScope) -> bool,
    ) -> Option<KeyRef> {
        self.mappings
            .iter()
            .find(|m| m.purpose == purpose && matches_scope(&m.scope))
            .map(|m| m.key_ref.clone())
    }

    /// The connector that signs for `key_ref`, for the purpose the caller is
    /// signing for.
    ///
    /// `purpose` is **not** redundant with `key_ref.purpose`: it is what the
    /// call site is actually doing, and a mismatch means a key minted for one
    /// purpose is about to sign for another. That is the gateway-side half of
    /// the VTA `typ` allow-list, so it is rejected here rather than trusted to
    /// convention at the call site.
    pub async fn authority_for(
        &self,
        key_ref: &KeyRef,
        purpose: KeyPurpose,
    ) -> Result<Arc<dyn CredentialAuthority>, VtaError> {
        if key_ref.purpose != purpose {
            return Err(VtaError::Config(format!(
                "[vta] key resolved for purpose `{}` cannot sign for purpose `{}`",
                key_ref.purpose.as_str(),
                purpose.as_str()
            )));
        }
        key_ref.validate()?;

        // A registry-backed connection is resolved every time: the registry
        // owns its lifecycle, so caching it here would keep a disabled
        // connection signing after the registry invalidated it.
        if let KeyBackend::Vta { connection_id } = &key_ref.backend
            && connection_id != DEFAULT_CONNECTION_ID
        {
            let connections = self
                .connections
                .as_ref()
                .ok_or_else(|| VtaError::Config(format!("[vta] no VTA connection `{connection_id}` is configured")))?;
            return connections
                .authority_for_key(
                    connection_id,
                    key_ref
                        .key_id
                        .as_ref()
                        .map(|k| k.as_str()),
                )
                .await;
        }

        if let Some(hit) = self
            .cache
            .read()
            .await
            .get(key_ref)
            .cloned()
        {
            return Ok(hit);
        }

        let authority = match &key_ref.backend {
            KeyBackend::Local => Arc::clone(&self.local),
            KeyBackend::Vta { connection_id } => match self.vta.clone() {
                Some(bootstrap) => bootstrap,
                // No `[vta]` block, but the bootstrap connection may still
                // exist as a migrated record.
                None => {
                    let connections = self
                        .connections
                        .as_ref()
                        .ok_or_else(|| {
                            VtaError::Config(format!("[vta] no VTA connection `{connection_id}` is configured"))
                        })?;
                    return connections
                        .authority_for_key(
                            connection_id,
                            key_ref
                                .key_id
                                .as_ref()
                                .map(|k| k.as_str()),
                        )
                        .await;
                }
            },
        };

        self.cache
            .write()
            .await
            .insert(key_ref.clone(), Arc::clone(&authority));
        Ok(authority)
    }
}

/// Connection id of the `[vta]` block's own connection.
pub const DEFAULT_CONNECTION_ID: &str = "default";

/// Whether `connection_id` names the `[vta]` connection, the only one this
/// gateway creates contexts through.
fn is_bootstrap_connection(connection_id: &str) -> bool {
    connection_id == DEFAULT_CONNECTION_ID || connection_id == crate::vta::connections::BOOTSTRAP_CONNECTION_ID
}

/// Whether this gateway creates the context of a `signing` block that names
/// none on `connection_id` (`None` meaning the `[vta]` connection): only through
/// an enabled `[vta]` connection that auto-provisions contexts.
pub fn provisions_contexts_on(
    vta: &VtaConfig,
    connection_id: Option<&str>,
) -> bool {
    vta.enabled && vta.auto_provision_contexts && connection_id.is_none_or(is_bootstrap_connection)
}

/// The appliance-wide token signer, resolved through the directory on every
/// call: the dashboard's gateway-wide default, then `[vta]`, then the local key.
///
/// Resolving per call is what lets a trust agent connected and chosen in the
/// dashboard sign STS tokens, ID-JAGs, MCP access tokens and payment receipts
/// without a restart, and keeps the JWKS those are verified against the one of
/// the key that signs them. A key that cannot be resolved is an error, never a
/// fallback to the local key.
///
/// The JWKS also publishes the keys tokens signed earlier may carry: the local
/// key, the `[vta]` key, and each key this authority signed with before the
/// default moved off it, so a switch does not invalidate tokens in flight. An
/// earlier signer is dropped once every token it signed has expired
/// ([`EARLIER_SIGNER_GRACE_SECS`] after the switch), and at once when its
/// connection is deleted, disabled or revoked.
///
/// The current signer is recorded the first time it resolves, and kept in a
/// file with the earlier signers when one is given. A switch made while this
/// process was down, or before the new signer signed, still records the one it
/// replaced, and a current signer that cannot be resolved stays published until
/// the tokens it last signed have expired.
pub struct ApplianceAuthority {
    directory: Arc<KeyDirectory>,
    /// The signer the default last resolved to in this process.
    signer: RwLock<Option<KeyRef>>,
    history: RwLock<SignerHistory>,
    history_path: Option<std::path::PathBuf>,
}

/// The signer the gateway-wide default resolves to and the signers it moved
/// off. Public material only.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct SignerHistory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<CurrentSigner>,
    #[serde(default)]
    signers: Vec<EarlierSigner>,
}

/// The signer the default last resolved to. It is saved the first time it
/// resolves, so its keys stay published while it cannot be resolved, also
/// after a restart, and a switch made before it resolves again still records
/// it as an earlier signer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct CurrentSigner {
    signer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_id: Option<String>,
    #[serde(default)]
    keys: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_did: Option<String>,
    /// When it last signed, to within [`SIGNER_SEEN_REFRESH_SECS`].
    seen_at: chrono::DateTime<chrono::Utc>,
}

impl CurrentSigner {
    /// When the last token it may have signed expires.
    fn not_after(&self) -> chrono::DateTime<chrono::Utc> {
        self.seen_at + chrono::Duration::seconds(SIGNER_SEEN_REFRESH_SECS + EARLIER_SIGNER_GRACE_SECS)
    }

    /// It as an earlier signer, replaced at `now`.
    fn replaced_at(
        self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> EarlierSigner {
        EarlierSigner {
            connection_id: self.connection_id,
            keys: self.keys,
            issuer_did: self.issuer_did,
            not_after: now + chrono::Duration::seconds(EARLIER_SIGNER_GRACE_SECS),
        }
    }
}

/// A signer the gateway-wide default moved off: the connection it signed
/// through, its public keys and issuer DID, and when the last token it signed
/// expires.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct EarlierSigner {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_id: Option<String>,
    #[serde(default)]
    keys: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_did: Option<String>,
    not_after: chrono::DateTime<chrono::Utc>,
}

/// How long an earlier signer stays this gateway's after the default moves off
/// it: the longest lifetime of a token the gateway signs as itself, plus clock
/// leeway.
pub const EARLIER_SIGNER_GRACE_SECS: i64 = crate::sts::handlers::MAX_ACCESS_TOKEN_TTL_SECS as i64 + 300;

/// How often the time the current signer was last seen signing is saved.
const SIGNER_SEEN_REFRESH_SECS: i64 = 60;

/// The managed connection `key_ref` signs through; `None` for the local key
/// and the `[vta]` block, which stay published as built-in signers.
fn managed_connection(key_ref: &KeyRef) -> Option<String> {
    match &key_ref.backend {
        KeyBackend::Vta { connection_id } if !is_bootstrap_connection(connection_id) => Some(connection_id.clone()),
        _ => None,
    }
}

/// A stable name for the key `key_ref` names, kept in the signer history.
fn signer_name(key_ref: &KeyRef) -> String {
    let backend = match &key_ref.backend {
        KeyBackend::Local => "local".to_string(),
        KeyBackend::Vta { connection_id } => format!("vta:{connection_id}"),
    };
    format!(
        "{backend}/{}/{}",
        key_ref
            .context
            .as_ref()
            .map_or("", ContextId::as_str),
        key_ref
            .key_id
            .as_ref()
            .map_or("", KeyId::as_str),
    )
}

/// `signers` without the expired ones, and one entry per connection and issuer
/// DID, the one kept longest.
fn unexpired(
    mut signers: Vec<EarlierSigner>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<EarlierSigner> {
    signers.retain(|s| s.not_after > now);
    signers.sort_by_key(|s| std::cmp::Reverse(s.not_after));
    let mut kept: Vec<EarlierSigner> = Vec::new();
    for signer in signers {
        if !kept
            .iter()
            .any(|k| k.connection_id == signer.connection_id && k.issuer_did == signer.issuer_did)
        {
            kept.push(signer);
        }
    }
    kept
}

/// File name of the signer history under the gateway's storage directory.
pub const SIGNER_HISTORY_FILE: &str = "appliance_signer_history.json";

async fn read_history_file(path: &std::path::Path) -> SignerHistory {
    match tokio::fs::read(path).await {
        Ok(bytes) => match serde_json::from_slice::<SignerHistory>(&bytes) {
            Ok(history) => return history,
            Err(e) => tracing::warn!(
                target: "vta_audit",
                error = %e,
                "the earlier gateway-wide signers could not be read; tokens they signed may stop verifying",
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            target: "vta_audit",
            error = %e,
            "the earlier gateway-wide signers could not be read; tokens they signed may stop verifying",
        ),
    }
    SignerHistory::default()
}

impl ApplianceAuthority {
    pub fn new(directory: Arc<KeyDirectory>) -> Self {
        Self {
            directory,
            signer: RwLock::new(None),
            history: RwLock::new(SignerHistory::default()),
            history_path: None,
        }
    }

    /// Keep the signer history in `path`, starting from what it already holds.
    pub async fn with_history(
        mut self,
        path: std::path::PathBuf,
    ) -> Self {
        *self.history.get_mut() = read_history_file(&path).await;
        self.history_path = Some(path);
        self
    }

    async fn save_history(
        &self,
        history: &SignerHistory,
    ) {
        let Some(path) = &self.history_path else {
            return;
        };
        let written = match serde_json::to_vec_pretty(history) {
            Ok(bytes) => crate::storage::filesystem::atomic_write_file_with_mode(path, &bytes, None)
                .await
                .map_err(|e| format!("{e:?}")),
            Err(e) => Err(e.to_string()),
        };
        if let Err(e) = written {
            tracing::warn!(
                target: "vta_audit",
                error = %e,
                "the earlier gateway-wide signers could not be saved; tokens they signed stop verifying after a restart",
            );
        }
    }

    async fn current(&self) -> anyhow::Result<Arc<dyn CredentialAuthority>> {
        let failed =
            |e: VtaError| anyhow::anyhow!("the appliance signing key could not be resolved: {}", e.log_detail());
        let key_ref = self
            .directory
            .resolve_and_provision(KeyPurpose::Jwt, &KeyScope::default())
            .await
            .map_err(failed)?;
        let authority = self
            .directory
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .map_err(failed)?;
        self.note_signer(key_ref, &authority)
            .await;
        Ok(authority)
    }

    /// The signer the default last resolved to, while tokens it signed may
    /// still be outstanding and its connection is still in use.
    async fn last_signer(&self) -> Option<CurrentSigner> {
        let last = self
            .history
            .read()
            .await
            .current
            .clone()?;
        if last.not_after() <= chrono::Utc::now() {
            return None;
        }
        if let Some(connection) = &last.connection_id
            && self
                .directory
                .connection_retired(connection)
                .await
        {
            return None;
        }
        Some(last)
    }

    /// The earlier signers tokens may still carry: not yet past their
    /// `not_after`, and with a connection that is still in use.
    async fn live_signers(&self) -> Vec<EarlierSigner> {
        let now = chrono::Utc::now();
        let kept = self
            .history
            .read()
            .await
            .signers
            .clone();
        let mut live = Vec::new();
        for signer in kept {
            if signer.not_after <= now {
                continue;
            }
            if let Some(connection) = &signer.connection_id
                && self
                    .directory
                    .connection_retired(connection)
                    .await
            {
                continue;
            }
            live.push(signer);
        }
        live
    }

    /// Records `key_ref` as the current signer the first time it resolves, and
    /// the signer it replaces, from this process or from the saved history, as
    /// an earlier one. While it stays current, when it was last seen signing
    /// is saved again at most every [`SIGNER_SEEN_REFRESH_SECS`].
    async fn note_signer(
        &self,
        key_ref: KeyRef,
        authority: &Arc<dyn CredentialAuthority>,
    ) {
        let now = chrono::Utc::now();
        let name = signer_name(&key_ref);
        let known = self
            .signer
            .read()
            .await
            .as_ref()
            == Some(&key_ref);
        let saved = self
            .history
            .read()
            .await
            .current
            .clone()
            .filter(|c| c.signer == name);
        let current = match saved {
            Some(saved) if known => {
                if (now - saved.seen_at).num_seconds() < SIGNER_SEEN_REFRESH_SECS {
                    return;
                }
                CurrentSigner { seen_at: now, ..saved }
            }
            _ => CurrentSigner {
                signer: name,
                connection_id: managed_connection(&key_ref),
                keys: match authority.issuer_jwks().await {
                    Ok(jwks) => jwks_keys(&jwks),
                    Err(e) => {
                        tracing::warn!(
                            target: "vta_audit",
                            error = %e,
                            "the gateway-wide signer's keys could not be read; tokens it signs may stop verifying once it is replaced",
                        );
                        Vec::new()
                    }
                },
                issuer_did: authority
                    .issuer_did()
                    .await
                    .ok(),
                seen_at: now,
            },
        };
        *self.signer.write().await = Some(key_ref);
        self.save_current(current, now)
            .await;
    }

    /// Makes `current` the current signer, merged with the history saved by
    /// another process, and moves any other current signer to the earlier ones.
    async fn save_current(
        &self,
        mut current: CurrentSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let mut history = self.history.write().await;
        if history
            .current
            .as_ref()
            .is_some_and(|c| c.signer == current.signer && (now - c.seen_at).num_seconds() < SIGNER_SEEN_REFRESH_SECS)
        {
            return;
        }
        let saved = match &self.history_path {
            Some(path) => read_history_file(path).await,
            None => SignerHistory::default(),
        };
        let mut signers = std::mem::take(&mut history.signers);
        signers.extend(saved.signers);
        for other in history
            .current
            .take()
            .into_iter()
            .chain(saved.current)
        {
            if other.signer == current.signer {
                current.seen_at = current
                    .seen_at
                    .max(other.seen_at);
            } else {
                signers.push(other.replaced_at(now));
            }
        }
        history.signers = unexpired(signers, now);
        history.current = Some(current);
        self.save_history(&history)
            .await;
    }

    /// Keys of the signers built into this appliance, which tokens signed under
    /// an earlier default may carry.
    async fn built_in_keys(&self) -> Vec<serde_json::Value> {
        let mut keys = Vec::new();
        let built_in = std::iter::once(&self.directory.local).chain(self.directory.vta.as_ref());
        for authority in built_in {
            match authority.issuer_jwks().await {
                Ok(jwks) => merge_keys(&mut keys, jwks_keys(&jwks)),
                Err(e) => tracing::debug!(
                    target: "vta_audit",
                    error = %e,
                    "a built-in signer's keys could not be read; publishing without them",
                ),
            }
        }
        keys
    }
}

fn jwks_keys(jwks: &serde_json::Value) -> Vec<serde_json::Value> {
    jwks.get("keys")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Appends each of `more` that `keys` does not already hold.
fn merge_keys(
    keys: &mut Vec<serde_json::Value>,
    more: Vec<serde_json::Value>,
) {
    for key in more {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
}

#[async_trait::async_trait]
impl CredentialAuthority for ApplianceAuthority {
    async fn issuer_did(&self) -> anyhow::Result<String> {
        self.current()
            .await?
            .issuer_did()
            .await
    }

    /// The current signer's keys, then every earlier and built-in key. A
    /// current signer that cannot be resolved, such as one whose connection was
    /// just disabled, still leaves the keys outstanding tokens carry published.
    async fn issuer_jwks(&self) -> anyhow::Result<serde_json::Value> {
        let current = match self.current().await {
            Ok(current) => current.issuer_jwks().await,
            Err(e) => Err(e),
        };
        let mut keys = match current {
            Ok(current) => jwks_keys(&current),
            Err(e) => {
                tracing::warn!(
                    target: "vta_audit",
                    error = %e,
                    "the gateway-wide signer's keys could not be read; publishing the earlier ones",
                );
                self.last_signer()
                    .await
                    .map(|last| last.keys)
                    .unwrap_or_default()
            }
        };
        for signer in self.live_signers().await {
            merge_keys(&mut keys, signer.keys);
        }
        merge_keys(&mut keys, self.built_in_keys().await);
        Ok(serde_json::json!({ "keys": keys }))
    }

    /// The issuer DIDs of the last signer, while it may have signed
    /// outstanding tokens, of the live earlier signers and of the built-in ones.
    async fn earlier_issuer_dids(&self) -> Vec<String> {
        let mut dids: Vec<String> = Vec::new();
        let last = self
            .last_signer()
            .await
            .and_then(|last| last.issuer_did);
        for did in last.into_iter().chain(
            self.live_signers()
                .await
                .into_iter()
                .filter_map(|signer| signer.issuer_did),
        ) {
            if !dids.contains(&did) {
                dids.push(did);
            }
        }
        let built_in = std::iter::once(&self.directory.local).chain(self.directory.vta.as_ref());
        for authority in built_in {
            if let Ok(did) = authority.issuer_did().await
                && !dids.contains(&did)
            {
                dids.push(did);
            }
        }
        dids
    }

    async fn sign_token(
        &self,
        claims: &serde_json::Value,
    ) -> anyhow::Result<String> {
        self.current()
            .await?
            .sign_token(claims)
            .await
    }

    async fn sign_token_typ(
        &self,
        claims: &serde_json::Value,
        typ: &str,
    ) -> anyhow::Result<String> {
        self.current()
            .await?
            .sign_token_typ(claims, typ)
            .await
    }
}

/// Translate a surface/variant `signing` block into a [`KeyRef`].
///
/// A block that names no backend resolves to the local key: there is nothing to
/// delegate to, and inventing a backend would be guessing at the operator's
/// intent. `validate()` has already rejected the contradictory combinations.
pub fn signing_key_ref(
    signing: &crate::config::agent_surface::SurfaceSigningConfig,
    purpose: KeyPurpose,
) -> Result<KeyRef, VtaError> {
    use crate::config::agent_surface::SigningBackendKind;

    signing
        .validate()
        .map_err(VtaError::Config)?;

    let backend = match signing.backend {
        None | Some(SigningBackendKind::Local) => KeyBackend::Local,
        Some(SigningBackendKind::Vta) => KeyBackend::Vta {
            connection_id: signing
                .connection_id
                .clone()
                .unwrap_or_else(|| DEFAULT_CONNECTION_ID.to_string()),
        },
    };
    let key_ref = KeyRef {
        context: signing
            .context_id
            .as_deref()
            .map(ContextId::from),
        // Only a `jwt` key is caller-named; for the other purposes the
        // key follows the context's issuer DID and a named one would be wrong.
        key_id: match (backend == KeyBackend::Local, purpose) {
            (false, KeyPurpose::Jwt) => signing
                .key_id
                .as_deref()
                .map(KeyId::from),
            _ => None,
        },
        backend,
        purpose,
    };
    key_ref.validate()?;
    Ok(key_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::authority::LocalCredentialAuthority;
    use serde_json::Value;

    struct StubAuthority {
        did: &'static str,
        kids: Vec<&'static str>,
    }

    impl StubAuthority {
        fn new(
            did: &'static str,
            kids: Vec<&'static str>,
        ) -> Arc<Self> {
            Arc::new(Self { did, kids })
        }
    }

    #[async_trait::async_trait]
    impl CredentialAuthority for StubAuthority {
        async fn issuer_did(&self) -> anyhow::Result<String> {
            Ok(self.did.to_string())
        }

        async fn issuer_jwks(&self) -> anyhow::Result<Value> {
            Ok(serde_json::json!({
                "keys": self
                    .kids
                    .iter()
                    .map(|kid| serde_json::json!({ "kty": "OKP", "kid": kid }))
                    .collect::<Vec<_>>()
            }))
        }

        async fn sign_token(
            &self,
            _claims: &Value,
        ) -> anyhow::Result<String> {
            Ok(format!("signed-by-{}", self.did))
        }

        async fn sign_token_typ(
            &self,
            claims: &Value,
            _typ: &str,
        ) -> anyhow::Result<String> {
            self.sign_token(claims).await
        }
    }

    fn vta_jwt_ref(key_id: &str) -> KeyRef {
        KeyRef {
            backend: KeyBackend::Vta {
                connection_id: DEFAULT_CONNECTION_ID.to_string(),
            },
            context: Some(ContextId::from("ctx")),
            key_id: Some(KeyId::from(key_id)),
            purpose: KeyPurpose::Jwt,
        }
    }

    fn directory_with(vta: Option<Arc<dyn CredentialAuthority>>) -> KeyDirectory {
        KeyDirectory {
            identified: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            context_signers: RwLock::new(HashMap::new()),
            di_vc_issuer: None,
            context_creator: None,
            agent_provisioner: None,
            client: None,
            defaults: HashMap::new(),
            mappings: Vec::new(),
            local: StubAuthority::new("did:key:local", vec!["local-1"]),
            vta,
            connections: None,
            surfaces: None,
            issuers: None,
            provisioner: None,
            appliance_default: None,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// `Arc<dyn CredentialAuthority>` is not `Debug`, so `expect_err` is
    /// unavailable; and `log_detail` borrows the error, so it has to outlive
    /// the expression.
    fn error_detail<T>(
        result: Result<T, VtaError>,
        expectation: &str,
    ) -> String {
        match result {
            Ok(_) => panic!("{expectation}"),
            Err(e) => e.log_detail().to_string(),
        }
    }

    // ---- resolution order -------------------------------------------------

    #[test]
    fn with_nothing_configured_every_purpose_resolves_to_the_local_key() {
        let dir = directory_with(None);
        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential, KeyPurpose::Proof] {
            let resolved = dir
                .resolve(purpose, &KeyScope::default())
                .unwrap();
            assert_eq!(resolved, KeyRef::local(purpose), "purpose {purpose:?} must fall back to local");
        }
    }

    #[test]
    fn the_appliance_default_is_used_when_no_scope_matches() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));

        let resolved = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::surface("surface-a"))
            .unwrap();
        assert_eq!(
            resolved
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn a_variant_mapping_beats_a_surface_mapping() {
        let mut dir = directory_with(None);
        dir.push_surface_mapping("surface-a", vta_jwt_ref("surface-key"))
            .unwrap();
        dir.push_variant_mapping("surface-a", "variant-a", vta_jwt_ref("variant-key"))
            .unwrap();

        let scope = KeyScope {
            tenant_id: Some("tenant-a".to_string()),
            surface_id: Some("surface-a".to_string()),
            variant_id: Some("variant-a".to_string()),
        };
        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &scope)
                .unwrap()
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("variant-key")
        );
        // An unmapped variant of the same surface falls back to the surface.
        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::variant("surface-a", "variant-z"))
                .unwrap()
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("surface-key")
        );
    }

    /// A gateway that never adopted an agent must get no issuer for any
    /// scope — the credential inside an injected presentation keeps being
    /// signed by the local key, which is the whole backward-compatibility
    /// claim.
    #[tokio::test]
    async fn without_an_agent_no_scope_resolves_a_credential_issuer() {
        let dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds");
        for scope in [KeyScope::default(), KeyScope::surface("surface-a"), KeyScope::variant("surface-a", "blue")] {
            assert!(
                matches!(
                    dir.di_vc_issuer_for(&scope)
                        .await,
                    ScopedDiIssuer::Inherit
                ),
                "nothing to issue through for {scope:?}"
            );
        }
    }

    #[test]
    fn a_mapping_for_one_purpose_does_not_serve_another() {
        let mut dir = directory_with(None);
        dir.push_surface_mapping("surface-a", vta_jwt_ref("surface-key"))
            .unwrap();

        // The JWT mapping must not be picked up by a credential resolution.
        let resolved = dir
            .resolve(KeyPurpose::Credential, &KeyScope::surface("surface-a"))
            .unwrap();
        assert_eq!(resolved, KeyRef::local(KeyPurpose::Credential));
    }

    // ---- purpose enforcement ---------------------------------------------

    #[tokio::test]
    async fn a_jwt_key_cannot_be_used_for_credential_signing() {
        let vta = StubAuthority::new("did:webvh:vta", vec!["vta-1"]);
        let dir = directory_with(Some(vta));
        let key_ref = vta_jwt_ref("jwt-key");

        dir.authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .expect("the jwt key signs jwts");

        let msg = error_detail(
            dir.authority_for(&key_ref, KeyPurpose::Credential)
                .await,
            "a jwt key must not sign credentials",
        );
        assert!(msg.contains("jwt") && msg.contains("credential"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn the_local_backend_serves_every_purpose() {
        let dir = directory_with(None);
        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential, KeyPurpose::Proof] {
            dir.authority_for(&KeyRef::local(purpose), purpose)
                .await
                .unwrap_or_else(|e| panic!("local must serve {purpose:?}: {}", e.log_detail()));
        }
    }

    #[tokio::test]
    async fn the_connector_is_cached_across_resolutions() {
        let vta = StubAuthority::new("did:webvh:vta", vec!["vta-1"]);
        let dir = directory_with(Some(vta));
        let key_ref = vta_jwt_ref("jwt-key");

        let first = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        let second = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second), "a KeyRef must not rebuild its connector");
    }

    #[tokio::test]
    async fn an_unconfigured_connection_is_rejected_by_name() {
        let dir = directory_with(None);
        let key_ref = KeyRef {
            backend: KeyBackend::Vta {
                connection_id: "nope".to_string(),
            },
            ..vta_jwt_ref("jwt-key")
        };
        let msg = error_detail(
            dir.authority_for(&key_ref, KeyPurpose::Jwt)
                .await,
            "an unknown connection must not resolve",
        );
        assert!(msg.contains("nope"), "the error must name the connection: {msg}");
    }

    // ---- managed connections ------------------------------------

    /// Two surfaces mapped to different connections must reach **different**
    /// VTAs, and a connection the registry refuses must fail closed rather than
    /// silently falling back to the bootstrap or local connector.
    #[tokio::test]
    async fn two_mapped_connections_resolve_to_different_vtas() {
        use crate::vta::connections::{VtaConnection, VtaConnectionStatus, VtaConnectionTransport};

        fn record(
            id: &str,
            enabled: bool,
        ) -> VtaConnection {
            let now = chrono::Utc::now();
            VtaConnection {
                id: id.to_string(),
                tenant_id: None,
                name: id.to_string(),
                description: None,
                enabled,
                transport: VtaConnectionTransport::Https,
                endpoint: format!("https://{id}.example"),
                vta_did: format!("did:webvh:{id}.example"),
                default_context_id: Some("ctx".to_string()),
                control_key_ref: Some(format!("secret-{id}")),
                control_did: None,
                control_key_state: Default::default(),
                status: VtaConnectionStatus::Connected,
                keys: Default::default(),
                // Paired, so the registry gets past the pairing gate and this
                // test exercises connection *selection* rather than the pairing
                // gate's fail-closed path (which has its own tests).
                pairing: crate::vta::pairing::PairingRecord {
                    state: crate::vta::pairing::PairingState::Connected,
                    ..Default::default()
                },
                created_at: now,
                updated_at: now,
            }
        }

        struct Store(Vec<VtaConnection>);

        #[async_trait::async_trait]
        impl crate::vta::connections::VtaConnectionStorage for Store {
            async fn create(
                &self,
                c: VtaConnection,
            ) -> anyhow::Result<VtaConnection> {
                Ok(c)
            }

            async fn get(
                &self,
                id: &str,
            ) -> anyhow::Result<Option<VtaConnection>> {
                Ok(self
                    .0
                    .iter()
                    .find(|c| c.id == id)
                    .cloned())
            }

            async fn list(&self) -> anyhow::Result<Vec<VtaConnection>> {
                Ok(self.0.clone())
            }

            async fn update(
                &self,
                c: VtaConnection,
            ) -> anyhow::Result<VtaConnection> {
                Ok(c)
            }

            async fn delete(
                &self,
                _id: &str,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let store: Arc<dyn crate::vta::connections::VtaConnectionStorage> =
            Arc::new(Store(vec![record("alpha", true), record("beta", false)]));
        let registry = Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            store,
            None,
            None,
            None,
            std::time::Duration::from_secs(5),
            4,
        ));
        let dir = directory_with(Some(StubAuthority::new("did:webvh:bootstrap", vec!["boot-1"])))
            .with_connections(Arc::clone(&registry));

        // `alpha` is enabled, so it is attempted against its own VTA. It has no
        // resolvable control key here, which is what proves the directory asked
        // the *registry* rather than handing back the bootstrap connector.
        let msg = error_detail(
            dir.authority_for(
                &KeyRef {
                    backend: KeyBackend::Vta {
                        connection_id: "alpha".to_string(),
                    },
                    ..vta_jwt_ref("k")
                },
                KeyPurpose::Jwt,
            )
            .await,
            "the registry owns this connection",
        );
        assert!(msg.contains("secrets store"), "unexpected error: {msg}");

        // `beta` is disabled: fail closed, never a fallback to the bootstrap
        // connector or to local signing.
        let msg = error_detail(
            dir.authority_for(
                &KeyRef {
                    backend: KeyBackend::Vta {
                        connection_id: "beta".to_string(),
                    },
                    ..vta_jwt_ref("k")
                },
                KeyPurpose::Jwt,
            )
            .await,
            "a disabled connection must not sign",
        );
        assert!(msg.contains("disabled"), "unexpected error: {msg}");

        // The bootstrap connection is unaffected by either of them.
        let bootstrap = dir
            .authority_for(&vta_jwt_ref("k"), KeyPurpose::Jwt)
            .await
            .expect("the bootstrap connection still resolves");
        assert_eq!(
            bootstrap
                .issuer_did()
                .await
                .unwrap(),
            "did:webvh:bootstrap"
        );
    }

    /// A surface's `signing` block must govern **everything that surface
    /// signs**, not only its tokens.
    ///
    /// It was installed for `Jwt` alone, so the credential embedded in the
    /// presentation a surface forwards resolved the appliance default — or
    /// the local key — while the UI said the surface was mapped to an agent.
    #[tokio::test]
    async fn a_surface_mapping_covers_credentials_as_well_as_tokens() {
        let mut dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds");

        let surface = crate::config::agent_surface::AgentSurface {
            surface_id: "surface-a".to_string(),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                connection_id: Some("vta-a".to_string()),
                context_id: Some("ctx-a".to_string()),
                // Required for the jwt purpose; stripped for credential,
                // whose key follows the context's issuer DID.
                key_id: Some("gateway-jwt-1".to_string()),
            }),
            ..Default::default()
        };
        dir.with_surface(&surface)
            .expect("the mapping installs");

        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential] {
            let resolved = dir
                .resolve(purpose, &KeyScope::surface("surface-a"))
                .unwrap();
            assert!(
                matches!(&resolved.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-a"),
                "{purpose:?} must resolve the surface's agent, got {:?}",
                resolved.backend
            );
        }
    }

    /// A surface written **after** the directory was built must be honoured
    /// without a restart.
    ///
    /// `with_surface` runs once at startup over `list_all()`, so a freshly
    /// created surface was invisible to it: the operator pointed it at an
    /// agent, saw it saved, and it kept signing with the appliance default
    /// until someone restarted the process — and nothing was logged, because
    /// nothing had failed. Surfaces are hot-reloadable everywhere else.
    #[tokio::test]
    async fn a_surface_created_after_startup_is_honoured_without_a_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(tmp.path().to_path_buf())
                .await
                .expect("surface store"),
        ) as Arc<dyn crate::surfaces::AgentSurfaceStore>;

        // Built while the store is empty, exactly as at boot.
        let dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds")
            .with_surface_store(Arc::clone(&store));

        let scope = KeyScope::surface("surface-late");
        assert_eq!(
            dir.resolve_and_provision(KeyPurpose::Credential, &scope)
                .await
                .expect("resolves")
                .backend,
            KeyBackend::Local,
            "nothing is mapped yet"
        );

        // The operator creates the surface and points it at an agent.
        crate::surfaces::AgentSurfaceStore::save(
            store.as_ref(),
            &crate::config::agent_surface::AgentSurface {
                surface_id: "surface-late".to_string(),
                signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                    backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                    connection_id: Some("vta-a".to_string()),
                    context_id: Some("ctx-a".to_string()),
                    key_id: Some("gateway-jwt-1".to_string()),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("save the surface");

        let resolved = dir
            .resolve_and_provision(KeyPurpose::Credential, &scope)
            .await
            .expect("resolves");
        assert!(
            matches!(&resolved.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-a"),
            "the new surface's agent must be used immediately, got {:?}",
            resolved.backend
        );
    }

    /// Switching a surface back to the gateway's own key must take effect.
    ///
    /// The scoped answer used to be an `Option`, which read an explicit
    /// `local` the same as "no opinion" — so the surface fell through to the
    /// appliance default and carried on issuing through the agent. Observed
    /// live: flipping the setting to local produced a byte-identical agent
    /// trace, with `keys/sign-document` still signing as the
    /// appliance context.
    #[tokio::test]
    async fn a_surface_asking_for_the_local_key_is_not_sent_to_the_appliance_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(tmp.path().to_path_buf())
                .await
                .expect("surface store"),
        ) as Arc<dyn crate::surfaces::AgentSurfaceStore>;

        crate::surfaces::AgentSurfaceStore::save(
            store.as_ref(),
            &crate::config::agent_surface::AgentSurface {
                surface_id: "surface-local".to_string(),
                signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                    backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("save the surface");

        let dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds")
            .with_surface_store(Arc::clone(&store));

        assert!(
            matches!(
                dir.di_vc_issuer_for(&KeyScope::surface("surface-local"))
                    .await,
                ScopedDiIssuer::Local
            ),
            "an explicit local must be answered as local, not as an absence"
        );
    }

    async fn directory_with_issuer(
        issuer_signing: Option<crate::config::agent_surface::SurfaceSigningConfig>,
        surface_signing: Option<crate::config::agent_surface::SurfaceSigningConfig>,
    ) -> (KeyDirectory, Arc<crate::issuers::FileSystemIssuerStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(tmp.path().join("surfaces"))
                .await
                .expect("surface store"),
        );
        let issuers = Arc::new(
            crate::issuers::FileSystemIssuerStore::new(tmp.path().join("issuers"))
                .await
                .expect("issuer store"),
        );
        let mut issuer = crate::issuers::types::Issuer::new(
            "issuer-a".into(),
            "Issuer A".into(),
            "did:example:issuer".into(),
            serde_json::json!([]),
            serde_json::json!({}),
        );
        issuer.signing = issuer_signing;
        crate::issuers::IssuerStore::create(issuers.as_ref(), &issuer)
            .await
            .expect("save the issuer");
        crate::surfaces::AgentSurfaceStore::save(
            surfaces.as_ref(),
            &crate::config::agent_surface::AgentSurface {
                surface_id: "surface-a".to_string(),
                issuer_id: Some("issuer-a".to_string()),
                signing: surface_signing,
                ..Default::default()
            },
        )
        .await
        .expect("save the surface");
        let dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds")
            .with_surface_store(surfaces as Arc<dyn crate::surfaces::AgentSurfaceStore>)
            .with_issuer_store(Arc::clone(&issuers) as Arc<dyn crate::issuers::IssuerStore>);
        (dir, issuers, tmp)
    }

    fn issuer_agent_signing(connection: &str) -> crate::config::agent_surface::SurfaceSigningConfig {
        crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: Some(connection.to_string()),
            context_id: Some("ctx-a".to_string()),
            key_id: Some("key-a".to_string()),
        }
    }

    fn issuer_local_signing() -> crate::config::agent_surface::SurfaceSigningConfig {
        crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_surface_that_sets_nothing_signs_through_the_trust_agent_of_its_issuer() {
        let (dir, _issuers, _tmp) = directory_with_issuer(Some(issuer_agent_signing("vta-issuer")), None).await;

        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential] {
            let resolved = dir
                .resolve_and_provision(purpose, &KeyScope::surface("surface-a"))
                .await
                .expect("resolves");
            assert!(
                matches!(&resolved.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-issuer"),
                "{purpose:?} must follow the issuer's agent, got {:?}",
                resolved.backend
            );
            assert_eq!(resolved.context, Some(ContextId::from("ctx-a")));
        }
        assert!(
            dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::surface("surface-a"))
                .await,
            "the issuer's choice is a decision somebody made, so it is not silently replaced when the agent is unreachable"
        );
    }

    #[tokio::test]
    async fn a_surface_with_its_own_signing_wins_over_its_issuer() {
        let (dir, _issuers, _tmp) =
            directory_with_issuer(Some(issuer_agent_signing("vta-issuer")), Some(issuer_agent_signing("vta-surface")))
                .await;

        let resolved = dir
            .resolve_and_provision(KeyPurpose::Jwt, &KeyScope::surface("surface-a"))
            .await
            .expect("resolves");

        assert!(
            matches!(&resolved.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-surface"),
            "got {:?}",
            resolved.backend
        );
    }

    #[tokio::test]
    async fn an_issuer_asking_for_the_local_key_is_answered_as_local() {
        let (dir, _issuers, _tmp) = directory_with_issuer(Some(issuer_local_signing()), None).await;

        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::surface("surface-a"))
                .await,
            ScopedDiIssuer::Local
        ));
    }

    #[tokio::test]
    async fn an_issuer_without_signing_leaves_its_surfaces_on_the_appliance_default() {
        let (dir, _issuers, _tmp) = directory_with_issuer(None, None).await;

        let resolved = dir
            .resolve_and_provision(KeyPurpose::Jwt, &KeyScope::surface("surface-a"))
            .await
            .expect("resolves");

        assert_eq!(resolved.backend, KeyBackend::Local);
        assert!(
            !dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::surface("surface-a"))
                .await
        );
    }

    #[tokio::test]
    async fn a_change_to_the_issuer_is_honoured_without_a_restart() {
        let (dir, issuers, _tmp) = directory_with_issuer(None, None).await;
        let scope = KeyScope::surface("surface-a");
        assert_eq!(
            dir.resolve_and_provision(KeyPurpose::Jwt, &scope)
                .await
                .expect("resolves")
                .backend,
            KeyBackend::Local
        );

        let mut issuer = crate::issuers::IssuerStore::get(issuers.as_ref(), "issuer-a")
            .await
            .expect("read")
            .expect("present");
        issuer.signing = Some(issuer_agent_signing("vta-later"));
        crate::issuers::IssuerStore::update(issuers.as_ref(), &issuer)
            .await
            .expect("update the issuer");

        let resolved = dir
            .resolve_and_provision(KeyPurpose::Jwt, &scope)
            .await
            .expect("resolves");
        assert!(
            matches!(&resolved.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-later"),
            "got {:?}",
            resolved.backend
        );
    }

    // ---- capability negotiation ------------------------------------------

    /// The agent issues credentials under its context's own issuer DID
    /// (`keys/sign-document`, exercised live in
    /// `vta::appliance_di::live_tests`), which is what lets a surface's agent
    /// sign the credential embedded in the presentation it forwards.
    ///
    /// A standalone Data Integrity proof over an arbitrary document is still
    /// not something it offers, so that stays a misconfiguration caught at
    /// config time rather than a runtime failure.
    #[test]
    fn the_vta_backend_issues_credentials_but_not_standalone_proofs() {
        let vta = KeyBackend::Vta {
            connection_id: DEFAULT_CONNECTION_ID.to_string(),
        };
        assert!(supports(&vta, KeyPurpose::Jwt));
        assert!(supports(&vta, KeyPurpose::Credential));
        assert!(!supports(&vta, KeyPurpose::Proof));
        assert!(supports(&KeyBackend::Local, KeyPurpose::Proof));
    }

    #[test]
    fn a_key_ref_the_backend_cannot_serve_is_rejected_naming_both() {
        let key_ref = KeyRef {
            backend: KeyBackend::Vta {
                connection_id: DEFAULT_CONNECTION_ID.to_string(),
            },
            context: Some(ContextId::from("ctx")),
            key_id: None,
            purpose: KeyPurpose::Proof,
        };
        let msg = error_detail(key_ref.validate(), "the vta backend cannot build proofs yet");
        assert!(msg.contains("vta") && msg.contains("proof"), "unexpected error: {msg}");
    }

    // ---- key_id presence is purpose-dependent -----------------------------

    #[test]
    fn a_jwt_key_ref_without_a_key_id_is_rejected() {
        let key_ref = KeyRef {
            key_id: None,
            ..vta_jwt_ref("ignored")
        };
        let msg = error_detail(key_ref.validate(), "keys/sign-jws names the key");
        assert!(msg.contains("key_id"), "unexpected error: {msg}");
    }

    #[test]
    fn a_credential_key_ref_naming_a_key_id_is_rejected() {
        // The rule is independent of the backend, so assert it against the
        // local backend, which already serves the purpose.
        let key_ref = KeyRef {
            backend: KeyBackend::Local,
            context: None,
            key_id: Some(KeyId::from("whatever")),
            purpose: KeyPurpose::Credential,
        };
        let msg = error_detail(key_ref.validate(), "the local backend has no nameable key id");
        assert!(msg.contains("key id"), "unexpected error: {msg}");
    }

    // ---- appliance-wide override (dashboard setting) ---------------------

    struct StubApplianceDefault(Option<crate::config::agent_surface::SurfaceSigningConfig>);

    impl ApplianceSigningDefault for StubApplianceDefault {
        fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
            self.0.clone()
        }
    }

    fn appliance_vta_signing(connection_id: &str) -> crate::config::agent_surface::SurfaceSigningConfig {
        crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: Some(connection_id.to_string()),
            context_id: Some("ctx".to_string()),
            key_id: Some("key-1".to_string()),
        }
    }

    /// The point of the setting: an operator can move the whole appliance onto
    /// a paired connection from the dashboard, without editing `[vta]`.
    #[tokio::test]
    async fn the_dashboard_override_replaces_the_appliance_default() {
        let (local, _tmp) = local_authority().await;
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-b")))));

        let key_ref = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::default())
            .unwrap();
        assert_eq!(
            key_ref.backend,
            KeyBackend::Vta {
                connection_id: "vta-b".to_string()
            },
            "the appliance must resolve the connection named in the dashboard"
        );
    }

    /// Installing the source with nothing configured must be indistinguishable
    /// from not installing it, or every gateway would change signing key the
    /// moment this shipped.
    #[tokio::test]
    async fn an_unset_override_resolves_exactly_what_it_did_before() {
        let (local, _tmp) = local_authority().await;
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(None)));

        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::default())
                .unwrap(),
            KeyRef::local(KeyPurpose::Jwt),
            "an unset override must leave the local default in place"
        );
    }

    /// A surface mapping is more specific than an appliance-wide setting, so
    /// it has to win — otherwise setting the appliance default would silently
    /// undo every per-surface exception.
    #[tokio::test]
    async fn a_surface_mapping_outranks_the_dashboard_override() {
        let (local, _tmp) = local_authority().await;
        let mut dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-appliance")))));
        let surface = crate::config::agent_surface::AgentSurface {
            surface_id: "s1".to_string(),
            signing: Some(appliance_vta_signing("vta-surface")),
            ..Default::default()
        };
        dir.with_surface(&surface)
            .expect("the surface mapping installs");

        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"))
                .unwrap()
                .backend,
            KeyBackend::Vta {
                connection_id: "vta-surface".to_string()
            },
            "the surface's own mapping must beat the appliance-wide setting"
        );
    }

    /// A default that cannot sign tokens is an explicit choice of signer that
    /// cannot be honoured, so every purpose refuses rather than tokens falling
    /// back to another key while credentials follow the default.
    #[tokio::test]
    async fn a_default_that_cannot_sign_tokens_refuses_every_purpose() {
        let (local, _tmp) = local_authority().await;
        let keyless = crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: Some("vta-b".to_string()),
            context_id: Some("ctx".to_string()),
            key_id: None,
        };
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(keyless))));

        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential, KeyPurpose::Proof] {
            let error = dir
                .resolve(purpose, &KeyScope::default())
                .expect_err("a default that cannot sign tokens must not resolve");
            assert!(
                error
                    .log_detail()
                    .contains("key_id"),
                "{purpose:?}: {}",
                error.log_detail()
            );
        }
    }

    /// A trust agent default does not serve Data Integrity proofs, so those
    /// follow the `[vta]` defaults while tokens and credentials follow it.
    #[tokio::test]
    async fn a_trust_agent_default_leaves_proofs_to_the_vta_defaults() {
        let (local, _tmp) = local_authority().await;
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-b")))));

        let backend = |purpose| {
            dir.resolve(purpose, &KeyScope::default())
                .unwrap()
                .backend
        };
        let agent = KeyBackend::Vta {
            connection_id: "vta-b".to_string(),
        };
        assert_eq!(backend(KeyPurpose::Jwt), agent);
        assert_eq!(backend(KeyPurpose::Credential), agent);
        assert_eq!(backend(KeyPurpose::Proof), KeyBackend::Local);
    }

    // ---- backwards compatibility -----------------------------------------

    async fn local_authority() -> (Arc<dyn CredentialAuthority>, tempfile::TempDir) {
        let (issuer, tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        (Arc::new(LocalCredentialAuthority::new(Arc::new(issuer))), tmp)
    }

    #[tokio::test]
    async fn a_disabled_block_builds_a_directory_that_resolves_the_local_key() {
        let (local, _tmp) = local_authority().await;
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds");

        let key_ref = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::default())
            .unwrap();
        assert_eq!(key_ref, KeyRef::local(KeyPurpose::Jwt));

        let authority = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        // The very same local connector, so output is identical to today.
        assert!(Arc::ptr_eq(&local, &authority));
    }

    // ---- per-surface / per-variant signing -----------------------

    fn surface_with(
        surface_id: &str,
        signing: Option<crate::config::agent_surface::SurfaceSigningConfig>,
        variants: Vec<(&str, Option<crate::config::agent_surface::SurfaceSigningConfig>)>,
    ) -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant};

        crate::config::agent_surface::AgentSurface {
            surface_id: surface_id.to_string(),
            name: format!("surface {surface_id}"),
            signing,
            variants: variants
                .into_iter()
                .map(|(id, signing)| SurfaceVariant {
                    id: id.to_string(),
                    alias: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    enabled: true,
                    overrides: SurfaceOverrides {
                        signing,
                        ..SurfaceOverrides::default()
                    },
                })
                .collect(),
            ..Default::default()
        }
    }

    fn vta_signing(
        context: &str,
        key: &str,
    ) -> crate::config::agent_surface::SurfaceSigningConfig {
        crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: None,
            context_id: Some(context.to_string()),
            key_id: Some(key.to_string()),
        }
    }

    #[test]
    fn a_surface_with_no_signing_block_keeps_the_appliance_default() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));
        dir.with_surface(&surface_with("s1", None, vec![]))
            .unwrap();

        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"))
                .unwrap()
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn two_surfaces_mapped_to_different_contexts_resolve_different_keys() {
        let mut dir = directory_with(None);
        dir.with_surface(&surface_with("s1", Some(vta_signing("ctx-one", "key-one")), vec![]))
            .unwrap();
        dir.with_surface(&surface_with("s2", Some(vta_signing("ctx-two", "key-two")), vec![]))
            .unwrap();

        let first = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"))
            .unwrap();
        let second = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::surface("s2"))
            .unwrap();

        // The `key_id` *is* the published `kid`, so different keys here means
        // a verifier can tell the two surfaces apart.
        assert_eq!(
            first
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("key-one")
        );
        assert_eq!(
            second
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("key-two")
        );
        assert_eq!(
            first
                .context
                .as_ref()
                .map(ContextId::as_str),
            Some("ctx-one")
        );
        assert_ne!(first.context, second.context);
    }

    #[test]
    fn a_variant_without_an_override_inherits_its_surfaces_context() {
        let mut dir = directory_with(None);
        dir.with_surface(&surface_with(
            "s1",
            Some(vta_signing("ctx-surface", "key-surface")),
            vec![("v-plain", None), ("v-own", Some(vta_signing("ctx-variant", "key-variant")))],
        ))
        .unwrap();

        // Inherits — a variant is a sparse delta, so absent means the surface's.
        let inherited = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::variant("s1", "v-plain"))
            .unwrap();
        assert_eq!(
            inherited
                .context
                .as_ref()
                .map(ContextId::as_str),
            Some("ctx-surface")
        );
        assert_eq!(
            inherited
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("key-surface")
        );

        // Overrides — only when the operator deliberately asked.
        let own = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::variant("s1", "v-own"))
            .unwrap();
        assert_eq!(
            own.context
                .as_ref()
                .map(ContextId::as_str),
            Some("ctx-variant")
        );
        assert_eq!(
            own.key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("key-variant")
        );
    }

    #[test]
    fn an_empty_signing_block_is_treated_as_absent() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));
        dir.with_surface(&surface_with(
            "s1",
            Some(crate::config::agent_surface::SurfaceSigningConfig::default()),
            vec![],
        ))
        .unwrap();

        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"))
                .unwrap()
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn a_surface_with_one_bad_variant_installs_nothing() {
        use crate::config::agent_surface::{SigningBackendKind, SurfaceSigningConfig};

        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));
        let bad = SurfaceSigningConfig {
            // `local` cannot carry a context — contradictory, so rejected.
            backend: Some(SigningBackendKind::Local),
            connection_id: None,
            context_id: Some("ctx".to_string()),
            key_id: None,
        };
        let surface = surface_with("s1", Some(vta_signing("ctx-surface", "key-surface")), vec![("v", Some(bad))]);

        assert!(
            dir.with_surface(&surface)
                .is_err()
        );
        // All-or-nothing: the valid surface-level mapping must not be left
        // installed alongside a rejected variant.
        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"))
                .unwrap()
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn a_block_naming_no_backend_resolves_locally() {
        use crate::config::agent_surface::SurfaceSigningConfig;

        let key_ref = signing_key_ref(
            &SurfaceSigningConfig {
                backend: None,
                connection_id: None,
                context_id: None,
                key_id: Some("ignored".to_string()),
            },
            KeyPurpose::Jwt,
        )
        .expect("a backend-less block is the local key");
        assert_eq!(key_ref, KeyRef::local(KeyPurpose::Jwt));
    }

    #[test]
    fn a_block_naming_a_connection_without_a_backend_is_rejected() {
        use crate::config::agent_surface::SurfaceSigningConfig;

        let msg = error_detail(
            signing_key_ref(
                &SurfaceSigningConfig {
                    backend: None,
                    connection_id: Some("c1".to_string()),
                    context_id: None,
                    key_id: None,
                },
                KeyPurpose::Jwt,
            ),
            "an appliance default of local would silently ignore the connection",
        );
        assert!(msg.contains("signing.backend"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn the_legacy_signing_key_id_becomes_the_appliance_default() {
        let (local, _tmp) = local_authority().await;
        let config = VtaConfig {
            enabled: true,
            base_url: Some("http://localhost:3000".to_string()),
            vta_did: Some("did:webvh:vta.example".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("key-gateway-jwt".to_string()),
            ..VtaConfig::default()
        };
        let dir = KeyDirectory::build(&config, Arc::clone(&local))
            .await
            .expect("build");

        let key_ref = dir
            .resolve(KeyPurpose::Jwt, &KeyScope::default())
            .unwrap();
        assert_eq!(
            key_ref.backend,
            KeyBackend::Vta {
                connection_id: DEFAULT_CONNECTION_ID.to_string()
            }
        );
        assert_eq!(
            key_ref
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("key-gateway-jwt")
        );
        assert_eq!(
            key_ref
                .context
                .as_ref()
                .map(ContextId::as_str),
            Some("ctx")
        );

        // Unlisted purposes still fall back to local — the flat config only
        // ever described a JWT key.
        assert_eq!(
            dir.resolve(KeyPurpose::Credential, &KeyScope::default())
                .unwrap(),
            KeyRef::local(KeyPurpose::Credential)
        );

        let authority = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&local, &authority), "an enabled block must resolve the VTA connector");
    }

    #[tokio::test]
    async fn an_unmapped_scope_has_no_explicit_mapping_so_it_may_fall_back() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));

        assert!(
            !dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::surface("s1"))
                .await,
            "the appliance default is what everything resolves to, not a mapping"
        );
        assert!(
            !dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::default())
                .await
        );
    }

    #[tokio::test]
    async fn a_surface_or_variant_mapping_is_explicit_only_for_its_own_scope() {
        let mut dir = directory_with(None);
        dir.push_surface_mapping("surface-1", vta_jwt_ref("surface-key"))
            .unwrap();

        assert!(
            dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::surface("surface-1"))
                .await
        );
        assert!(
            !dir.has_explicit_mapping(KeyPurpose::Jwt, &KeyScope::surface("surface-2"))
                .await
        );
        assert!(
            !dir.has_explicit_mapping(KeyPurpose::Credential, &KeyScope::surface("surface-1"))
                .await,
            "a mapping for one purpose says nothing about another"
        );
    }

    /// A surface store that holds the surface but cannot read it.
    struct UnreadableSurfaces;

    #[async_trait::async_trait]
    impl crate::surfaces::AgentSurfaceStore for UnreadableSurfaces {
        async fn save(
            &self,
            _surface: &crate::config::agent_surface::AgentSurface,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            Ok(None)
        }

        async fn get_checked(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            anyhow::bail!("surface `{surface_id}` is stored but unreadable")
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::config::agent_surface::AgentSurface>> {
            Ok(Vec::new())
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// A surface whose mapping cannot be read may map a trust agent key, so
    /// its signing fails closed rather than resolving the appliance default.
    #[tokio::test]
    async fn a_surface_whose_mapping_cannot_be_read_fails_closed() {
        let dir = KeyDirectory::build(&VtaConfig::default(), StubAuthority::new("did:key:local", vec!["local-1"]))
            .await
            .expect("a disabled [vta] block builds")
            .with_surface_store(Arc::new(UnreadableSurfaces) as Arc<dyn crate::surfaces::AgentSurfaceStore>);
        let scope = KeyScope::surface("surface-a");

        let err = dir
            .resolve_and_provision(KeyPurpose::Jwt, &scope)
            .await
            .expect_err("an unreadable mapping is not \"no mapping\"");
        assert!(
            err.log_detail()
                .contains("could not be read"),
            "{}",
            err.log_detail()
        );
        assert!(
            dir.has_explicit_mapping(KeyPurpose::Jwt, &scope)
                .await,
            "an unreadable mapping counts as one, so the signer refuses rather than falls back"
        );
    }

    /// A declared block the backend cannot serve is an error, not an absence:
    /// a VTA block without a key id cannot sign a token, and reading it as
    /// unmapped signed that surface's tokens with the appliance key.
    #[tokio::test]
    async fn a_declared_block_that_cannot_sign_a_token_fails_closed() {
        let unusable = crate::config::agent_surface::SurfaceSigningConfig {
            key_id: None,
            ..issuer_agent_signing("vta-a")
        };
        let (dir, _issuers, _tmp) = directory_with_issuer(None, Some(unusable)).await;
        let scope = KeyScope::surface("surface-a");

        let err = dir
            .resolve_and_provision(KeyPurpose::Jwt, &scope)
            .await
            .expect_err("a block that cannot sign a token must not resolve the appliance key");
        assert!(
            err.log_detail()
                .contains("cannot use"),
            "{}",
            err.log_detail()
        );
        assert!(
            dir.has_explicit_mapping(KeyPurpose::Jwt, &scope)
                .await
        );
        let credential = dir
            .resolve_and_provision(KeyPurpose::Credential, &scope)
            .await
            .expect("the same block still names the context a credential issues as");
        assert!(matches!(&credential.backend, KeyBackend::Vta { connection_id } if connection_id == "vta-a"));
    }

    /// The gateway-wide default as the dashboard holds it: changed while the
    /// gateway runs.
    struct SwitchableDefault(std::sync::Mutex<Option<crate::config::agent_surface::SurfaceSigningConfig>>);

    impl ApplianceSigningDefault for SwitchableDefault {
        fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Tokens and their JWKS follow the gateway-wide default as it changes,
    /// with no restart: the authority resolves the key on every call.
    #[tokio::test]
    async fn the_appliance_authority_follows_the_gateway_wide_default_as_it_changes() {
        let default = Arc::new(SwitchableDefault(std::sync::Mutex::new(None)));
        let mut dir = directory_with(Some(StubAuthority::new("did:webvh:vta", vec!["vta-1"])));
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));
        let authority = ApplianceAuthority::new(Arc::new(
            dir.with_appliance_default(Arc::clone(&default) as Arc<dyn ApplianceSigningDefault>),
        ));
        assert_eq!(
            authority
                .issuer_did()
                .await
                .unwrap(),
            "did:webvh:vta",
            "[vta] signs while nothing is chosen"
        );

        *default.0.lock().unwrap() = Some(crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
            ..Default::default()
        });
        assert_eq!(
            authority
                .issuer_did()
                .await
                .unwrap(),
            "did:key:local"
        );
        assert_eq!(
            authority
                .issuer_jwks()
                .await
                .unwrap()["keys"][0]["kid"],
            "local-1",
            "the published keys follow the signer"
        );
    }

    fn kids(jwks: &Value) -> Vec<String> {
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| {
                key["kid"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    fn default_signing_with(key_id: &str) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
        Some(crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: None,
            context_id: Some("ctx".to_string()),
            key_id: Some(key_id.to_string()),
        })
    }

    /// Moving the gateway-wide default to another key keeps the key that
    /// signed before it published, so tokens it signed still verify.
    #[tokio::test]
    async fn the_jwks_keeps_the_key_that_signed_before_the_default_moved() {
        let default = Arc::new(SwitchableDefault(std::sync::Mutex::new(default_signing_with("key-a"))));
        let dir = directory_with(None);
        for (key_id, authority) in [
            ("key-a", StubAuthority::new("did:key:a", vec!["a-1"])),
            ("key-b", StubAuthority::new("did:key:b", vec!["b-1"])),
        ] {
            dir.cache
                .write()
                .await
                .insert(vta_jwt_ref(key_id), authority as Arc<dyn CredentialAuthority>);
        }
        let authority = ApplianceAuthority::new(Arc::new(
            dir.with_appliance_default(Arc::clone(&default) as Arc<dyn ApplianceSigningDefault>),
        ));
        assert_eq!(
            authority
                .sign_token(&serde_json::json!({ "sub": "u" }))
                .await
                .unwrap(),
            "signed-by-did:key:a"
        );

        *default.0.lock().unwrap() = default_signing_with("key-b");
        assert_eq!(
            authority
                .sign_token(&serde_json::json!({ "sub": "u" }))
                .await
                .unwrap(),
            "signed-by-did:key:b"
        );
        assert_eq!(
            kids(
                &authority
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["b-1", "a-1", "local-1"],
            "the signing key first, then the earlier signer's and the gateway's own"
        );
    }

    /// A signer that stops resolving, such as one whose connection was disabled,
    /// still leaves the keys outstanding tokens carry published.
    #[tokio::test]
    async fn the_jwks_keeps_the_earlier_keys_when_the_signer_cannot_be_resolved() {
        let default = Arc::new(SwitchableDefault(std::sync::Mutex::new(default_signing_with("key-a"))));
        let dir = directory_with(None);
        dir.cache
            .write()
            .await
            .insert(vta_jwt_ref("key-a"), StubAuthority::new("did:key:a", vec!["a-1"]) as Arc<dyn CredentialAuthority>);
        let authority = ApplianceAuthority::new(Arc::new(
            dir.with_appliance_default(Arc::clone(&default) as Arc<dyn ApplianceSigningDefault>),
        ));
        authority
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .unwrap();

        *default.0.lock().unwrap() = Some(appliance_vta_signing("vta-gone"));
        assert!(
            authority
                .sign_token(&serde_json::json!({ "sub": "u" }))
                .await
                .is_err(),
            "nothing signs with an unresolvable key"
        );
        assert_eq!(
            kids(
                &authority
                    .issuer_jwks()
                    .await
                    .expect("the JWKS is still served")
            ),
            vec!["a-1", "local-1"]
        );
    }

    /// The earlier signers survive a restart, and their issuer DIDs, with the
    /// built-in ones, are offered as this gateway's own.
    #[tokio::test]
    async fn the_earlier_signers_are_kept_across_a_restart() {
        let history = tempfile::tempdir().unwrap();
        let path = history
            .path()
            .join(SIGNER_HISTORY_FILE);
        let default = Arc::new(SwitchableDefault(std::sync::Mutex::new(default_signing_with("key-a"))));
        let build = |default: Arc<SwitchableDefault>| async move {
            let dir = directory_with(None);
            for (key_id, authority) in [
                ("key-a", StubAuthority::new("did:key:a", vec!["a-1"])),
                ("key-b", StubAuthority::new("did:key:b", vec!["b-1"])),
            ] {
                dir.cache
                    .write()
                    .await
                    .insert(vta_jwt_ref(key_id), authority as Arc<dyn CredentialAuthority>);
            }
            ApplianceAuthority::new(Arc::new(dir.with_appliance_default(default as Arc<dyn ApplianceSigningDefault>)))
        };
        let before = build(Arc::clone(&default))
            .await
            .with_history(path.clone())
            .await;
        before
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .unwrap();
        *default.0.lock().unwrap() = default_signing_with("key-b");
        before
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .unwrap();

        let after = build(Arc::clone(&default))
            .await
            .with_history(path)
            .await;
        assert_eq!(
            kids(
                &after
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["b-1", "a-1", "local-1"],
            "the key that signed before the switch is still published"
        );
        assert_eq!(
            after
                .earlier_issuer_dids()
                .await,
            vec!["did:key:b".to_string(), "did:key:a".to_string(), "did:key:local".to_string()],
            "the current signer's, though it has not resolved since the restart, then the earlier one's"
        );
    }

    fn managed_jwt_ref(connection_id: &str) -> KeyRef {
        KeyRef {
            backend: KeyBackend::Vta {
                connection_id: connection_id.to_string(),
            },
            ..vta_jwt_ref("key-1")
        }
    }

    async fn connected_store(
        ids: &[&str]
    ) -> (Arc<dyn crate::vta::connections::VtaConnectionStorage>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store: Arc<dyn crate::vta::connections::VtaConnectionStorage> = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(tmp.path().to_path_buf())
                .await
                .unwrap(),
        );
        for id in ids {
            store
                .create(crate::vta::connections::VtaConnection {
                    id: id.to_string(),
                    tenant_id: None,
                    name: id.to_string(),
                    description: None,
                    enabled: true,
                    transport: crate::vta::connections::VtaConnectionTransport::Https,
                    endpoint: format!("https://{id}.example"),
                    vta_did: format!("did:webvh:{id}.example"),
                    default_context_id: None,
                    control_key_ref: None,
                    control_did: None,
                    control_key_state: Default::default(),
                    status: crate::vta::connections::VtaConnectionStatus::Connected,
                    keys: Default::default(),
                    pairing: crate::vta::pairing::PairingRecord {
                        state: crate::vta::pairing::PairingState::Connected,
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }
        (store, tmp)
    }

    /// Retiring an agent means moving the default off it and then revoking,
    /// deleting or disabling its connection. From then on its keys are no
    /// longer published and a token claiming its issuer is no longer this
    /// gateway's.
    #[tokio::test]
    async fn an_earlier_signer_is_dropped_once_its_connection_is_retired() {
        for retire in ["revoke", "disable", "delete"] {
            let (store, _tmp) = connected_store(&["vta-a", "vta-b"]).await;
            let registry = Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
                Arc::clone(&store),
                None,
                None,
                None,
                std::time::Duration::from_secs(5),
                4,
            ));
            let authority = ApplianceAuthority::new(Arc::new(directory_with(None).with_connections(registry)));
            authority
                .note_signer(
                    managed_jwt_ref("vta-a"),
                    &(StubAuthority::new("did:key:a", vec!["a-1"]) as Arc<dyn CredentialAuthority>),
                )
                .await;
            authority
                .note_signer(
                    managed_jwt_ref("vta-b"),
                    &(StubAuthority::new("did:key:b", vec!["b-1"]) as Arc<dyn CredentialAuthority>),
                )
                .await;
            assert!(
                authority
                    .earlier_issuer_dids()
                    .await
                    .contains(&"did:key:a".to_string()),
                "{retire}: still this gateway's right after the switch"
            );
            assert!(
                kids(
                    &authority
                        .issuer_jwks()
                        .await
                        .unwrap()
                )
                .contains(&"a-1".to_string()),
                "{retire}"
            );

            match retire {
                "delete" => store
                    .delete("vta-a")
                    .await
                    .unwrap(),
                _ => {
                    crate::vta::connections::modify(store.as_ref(), "vta-a", |c| {
                        if retire == "revoke" {
                            c.pairing.state = crate::vta::pairing::PairingState::Revoked;
                        } else {
                            c.enabled = false;
                        }
                    })
                    .await
                    .unwrap();
                }
            }

            assert!(
                !authority
                    .earlier_issuer_dids()
                    .await
                    .contains(&"did:key:a".to_string()),
                "{retire}: a token claiming the retired signer is refused"
            );
            assert!(
                !kids(
                    &authority
                        .issuer_jwks()
                        .await
                        .unwrap()
                )
                .contains(&"a-1".to_string()),
                "{retire}"
            );
        }
    }

    /// An earlier signer stays published only until every token it signed has
    /// expired, including across a restart.
    #[tokio::test]
    async fn an_earlier_signer_is_dropped_once_its_tokens_have_expired() {
        let history = tempfile::tempdir().unwrap();
        let path = history
            .path()
            .join(SIGNER_HISTORY_FILE);
        let signer = |did: &str, kid: &str, not_after: chrono::DateTime<chrono::Utc>| EarlierSigner {
            connection_id: None,
            keys: vec![serde_json::json!({ "kid": kid })],
            issuer_did: Some(did.to_string()),
            not_after,
        };
        let now = chrono::Utc::now();
        std::fs::write(
            &path,
            serde_json::to_vec(&SignerHistory {
                current: None,
                signers: vec![
                    signer("did:key:old", "old-1", now - chrono::Duration::seconds(1)),
                    signer("did:key:recent", "recent-1", now + chrono::Duration::seconds(60)),
                ],
            })
            .unwrap(),
        )
        .unwrap();

        let authority = ApplianceAuthority::new(Arc::new(directory_with(None)))
            .with_history(path)
            .await;

        assert_eq!(
            authority
                .earlier_issuer_dids()
                .await,
            vec!["did:key:recent".to_string(), "did:key:local".to_string()]
        );
        assert_eq!(
            kids(
                &authority
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["local-1", "recent-1"]
        );
    }

    /// A switch keeps the earlier signer for the longest token lifetime, no longer.
    #[tokio::test]
    async fn a_switch_keeps_the_earlier_signer_for_the_longest_token_lifetime() {
        let authority = ApplianceAuthority::new(Arc::new(directory_with(None)));
        let before = chrono::Utc::now();
        authority
            .note_signer(
                managed_jwt_ref("vta-a"),
                &(StubAuthority::new("did:key:a", vec!["a-1"]) as Arc<dyn CredentialAuthority>),
            )
            .await;
        authority
            .note_signer(
                managed_jwt_ref("vta-b"),
                &(StubAuthority::new("did:key:b", vec!["b-1"]) as Arc<dyn CredentialAuthority>),
            )
            .await;
        let kept = authority
            .history
            .read()
            .await
            .signers
            .clone();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0]
                .connection_id
                .as_deref(),
            Some("vta-a")
        );
        let grace = (kept[0].not_after - before).num_seconds();
        assert!((EARLIER_SIGNER_GRACE_SECS - 2..=EARLIER_SIGNER_GRACE_SECS).contains(&grace), "{grace}");
        assert!(EARLIER_SIGNER_GRACE_SECS > crate::sts::handlers::MAX_ACCESS_TOKEN_TTL_SECS as i64);
    }

    /// A gateway whose default resolves `key-a` or `key-b`, keeping its signer
    /// history in `path`, as it starts after a restart.
    async fn restarted(
        default: Arc<dyn ApplianceSigningDefault>,
        path: &std::path::Path,
    ) -> ApplianceAuthority {
        let dir = directory_with(None);
        for (key_id, authority) in [
            ("key-a", StubAuthority::new("did:key:a", vec!["a-1"])),
            ("key-b", StubAuthority::new("did:key:b", vec!["b-1"])),
        ] {
            dir.cache
                .write()
                .await
                .insert(vta_jwt_ref(key_id), authority as Arc<dyn CredentialAuthority>);
        }
        ApplianceAuthority::new(Arc::new(dir.with_appliance_default(default)))
            .with_history(path.to_path_buf())
            .await
    }

    /// A default switched while the gateway was down, or before the new signer
    /// signed anything, still keeps the signer it replaced.
    #[tokio::test]
    async fn a_switch_made_across_a_restart_keeps_the_replaced_signer() {
        let history = tempfile::tempdir().unwrap();
        let path = history
            .path()
            .join(SIGNER_HISTORY_FILE);
        restarted(Arc::new(StubApplianceDefault(default_signing_with("key-a"))), &path)
            .await
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .unwrap();

        let after = restarted(Arc::new(StubApplianceDefault(default_signing_with("key-b"))), &path).await;
        assert_eq!(
            after
                .sign_token(&serde_json::json!({ "sub": "u" }))
                .await
                .unwrap(),
            "signed-by-did:key:b"
        );
        assert_eq!(
            kids(
                &after
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["b-1", "a-1", "local-1"]
        );
        assert!(
            after
                .earlier_issuer_dids()
                .await
                .contains(&"did:key:a".to_string())
        );
    }

    /// After a restart, a signer that cannot be resolved keeps its keys and
    /// issuer published, until the tokens it last signed have expired.
    #[tokio::test]
    async fn an_unresolvable_signer_stays_published_until_its_last_tokens_expire() {
        let history = tempfile::tempdir().unwrap();
        let path = history
            .path()
            .join(SIGNER_HISTORY_FILE);
        restarted(Arc::new(StubApplianceDefault(default_signing_with("key-a"))), &path)
            .await
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .unwrap();
        let gone: Arc<dyn ApplianceSigningDefault> =
            Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-gone"))));

        let after = restarted(Arc::clone(&gone), &path).await;
        assert_eq!(
            kids(
                &after
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["a-1", "local-1"]
        );
        assert!(
            after
                .earlier_issuer_dids()
                .await
                .contains(&"did:key:a".to_string())
        );

        let mut saved: SignerHistory = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let current = saved
            .current
            .as_mut()
            .expect("the signer is saved the first time it resolves");
        current.seen_at =
            chrono::Utc::now() - chrono::Duration::seconds(EARLIER_SIGNER_GRACE_SECS + SIGNER_SEEN_REFRESH_SECS + 1);
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();

        let later = restarted(gone, &path).await;
        assert_eq!(
            kids(
                &later
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["local-1"]
        );
        assert!(
            !later
                .earlier_issuer_dids()
                .await
                .contains(&"did:key:a".to_string())
        );
    }

    /// The last signer is no longer this gateway's once its connection is retired.
    #[tokio::test]
    async fn the_last_signer_is_dropped_once_its_connection_is_retired() {
        let (store, _tmp) = connected_store(&["vta-a"]).await;
        let registry = Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            Arc::clone(&store),
            None,
            None,
            None,
            std::time::Duration::from_secs(5),
            4,
        ));
        let authority = ApplianceAuthority::new(Arc::new(directory_with(None).with_connections(registry)));
        authority
            .note_signer(
                managed_jwt_ref("vta-a"),
                &(StubAuthority::new("did:key:a", vec!["a-1"]) as Arc<dyn CredentialAuthority>),
            )
            .await;
        assert_eq!(
            authority
                .last_signer()
                .await
                .and_then(|last| last.issuer_did),
            Some("did:key:a".to_string())
        );

        crate::vta::connections::modify(store.as_ref(), "vta-a", |c| c.enabled = false)
            .await
            .unwrap();
        assert_eq!(authority.last_signer().await, None);
    }

    /// A save keeps what another node wrote to the shared history since this
    /// one read it.
    #[tokio::test]
    async fn a_switch_keeps_the_signers_another_node_saved() {
        let history = tempfile::tempdir().unwrap();
        let path = history
            .path()
            .join(SIGNER_HISTORY_FILE);
        let authority = ApplianceAuthority::new(Arc::new(directory_with(None)))
            .with_history(path.clone())
            .await;
        std::fs::write(
            &path,
            serde_json::to_vec(&SignerHistory {
                current: None,
                signers: vec![EarlierSigner {
                    connection_id: None,
                    keys: vec![serde_json::json!({ "kid": "other-1" })],
                    issuer_did: Some("did:key:other".to_string()),
                    not_after: chrono::Utc::now() + chrono::Duration::seconds(60),
                }],
            })
            .unwrap(),
        )
        .unwrap();

        for (connection, did, kid) in [("vta-a", "did:key:a", "a-1"), ("vta-b", "did:key:b", "b-1")] {
            authority
                .note_signer(
                    managed_jwt_ref(connection),
                    &(StubAuthority::new(did, vec![kid]) as Arc<dyn CredentialAuthority>),
                )
                .await;
        }

        let saved: SignerHistory = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut earlier: Vec<_> = saved
            .signers
            .iter()
            .filter_map(|s| s.issuer_did.clone())
            .collect();
        earlier.sort();
        assert_eq!(earlier, vec!["did:key:a".to_string(), "did:key:other".to_string()]);
        assert_eq!(
            saved
                .current
                .and_then(|c| c.issuer_did),
            Some("did:key:b".to_string())
        );
    }

    /// Before any switch the JWKS is the signer's own keys and the built-in ones.
    #[tokio::test]
    async fn the_jwks_publishes_no_earlier_signer_before_the_default_moves() {
        let dir =
            directory_with(None).with_appliance_default(Arc::new(StubApplianceDefault(default_signing_with("key-a"))));
        dir.cache
            .write()
            .await
            .insert(vta_jwt_ref("key-a"), StubAuthority::new("did:key:a", vec!["a-1"]) as Arc<dyn CredentialAuthority>);
        let authority = ApplianceAuthority::new(Arc::new(dir));

        assert_eq!(
            kids(
                &authority
                    .issuer_jwks()
                    .await
                    .unwrap()
            ),
            vec!["a-1", "local-1"]
        );
    }

    /// A default naming a trust agent that cannot be reached refuses to sign
    /// rather than signing with the gateway's own key.
    #[tokio::test]
    async fn the_appliance_authority_fails_closed_when_its_key_cannot_be_resolved() {
        let authority = ApplianceAuthority::new(Arc::new(
            directory_with(None)
                .with_appliance_default(Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-gone"))))),
        ));

        let err = authority
            .sign_token(&serde_json::json!({ "sub": "u" }))
            .await
            .expect_err("an unreachable agent is not replaced by the local key");
        assert!(
            err.to_string()
                .contains("could not be resolved"),
            "{err}"
        );
    }

    /// A registry whose store holds no connection, so every named one is unusable.
    async fn registry_without_connections(dir: &std::path::Path) -> Arc<crate::vta::registry::VtaConnectionRegistry> {
        let store = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(dir.join("connections"))
                .await
                .expect("connection store"),
        );
        Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            store,
            None,
            None,
            None,
            std::time::Duration::from_secs(5),
            4,
        ))
    }

    /// A surface whose issuer maps a trust agent that cannot be reached does
    /// not have its credential issued by anyone else.
    #[tokio::test]
    async fn a_surface_mapped_to_an_unusable_trust_agent_is_refused_its_credential_issuer() {
        let (dir, _issuers, tmp) = directory_with_issuer(Some(issuer_agent_signing("vta-gone")), None).await;
        let dir = dir.with_connections(registry_without_connections(tmp.path()).await);

        match dir
            .di_vc_issuer_for(&KeyScope::surface("surface-a"))
            .await
        {
            ScopedDiIssuer::Unavailable(reason) => assert!(reason.contains("vta-gone"), "{reason}"),
            ScopedDiIssuer::Agent(_) => panic!("there is no agent to issue through"),
            ScopedDiIssuer::Local => panic!("the surface did not ask for the gateway's key"),
            ScopedDiIssuer::Inherit => panic!("another issuer must not stand in for the chosen one"),
        }
    }

    /// The gateway-wide default naming a connection that cannot be reached
    /// refuses the credential and the attestation alike, rather than leaving
    /// both to the gateway's own key.
    #[tokio::test]
    async fn a_default_naming_an_unusable_connection_refuses_issuance_and_attestation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = directory_with(None)
            .with_connections(registry_without_connections(tmp.path()).await)
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(appliance_vta_signing("vta-gone")))));

        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::default())
                .await,
            ScopedDiIssuer::Unavailable(_)
        ));
        assert!(matches!(dir.attestation_signer().await, ScopedContextSigner::Unavailable(_)));
    }

    /// A scope nobody chose a trust agent for keeps inheriting the appliance's
    /// issuer, as it always has.
    #[tokio::test]
    async fn a_scope_with_no_choice_still_inherits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = directory_with(None).with_connections(registry_without_connections(tmp.path()).await);

        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::surface("surface-a"))
                .await,
            ScopedDiIssuer::Inherit
        ));
        assert!(matches!(dir.attestation_signer().await, ScopedContextSigner::Inherit));
    }

    fn vta_credential_default() -> KeyRef {
        KeyRef {
            backend: KeyBackend::Vta {
                connection_id: DEFAULT_CONNECTION_ID.to_string(),
            },
            context: Some(ContextId::from("ctx")),
            key_id: None,
            purpose: KeyPurpose::Credential,
        }
    }

    /// With `[vta]` configured and the gateway-wide default set to the
    /// gateway's own key, credentials and the attestation are signed locally,
    /// as tokens are, rather than inherited by the `[vta]` issuer.
    #[tokio::test]
    async fn a_default_of_the_gateway_key_issues_credentials_locally() {
        let mut dir = directory_with(None).with_appliance_default(Arc::new(StubApplianceDefault(Some(
            crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
                ..Default::default()
            },
        ))));
        dir.defaults
            .insert(KeyPurpose::Credential, vta_credential_default());

        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::default())
                .await,
            ScopedDiIssuer::Local
        ));
        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::surface("surface-a"))
                .await,
            ScopedDiIssuer::Local
        ));
        assert!(matches!(dir.attestation_signer().await, ScopedContextSigner::Local));
    }

    /// With no gateway-wide default, the `[vta]` issuer keeps issuing.
    #[tokio::test]
    async fn without_a_default_the_vta_block_still_issues_credentials() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Credential, vta_credential_default());

        assert!(matches!(
            dir.di_vc_issuer_for(&KeyScope::default())
                .await,
            ScopedDiIssuer::Inherit
        ));
        assert!(matches!(dir.attestation_signer().await, ScopedContextSigner::Inherit));
    }

    struct RecordingCreator(std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl crate::vta::provisioning::ContextCreator for RecordingCreator {
        async fn create_context(
            &self,
            name: &str,
        ) -> Result<ContextId, VtaError> {
            self.0
                .lock()
                .unwrap()
                .push(name.to_string());
            Ok(ContextId::from("created"))
        }
    }

    fn context_less_credential_ref(connection_id: &str) -> KeyRef {
        KeyRef {
            backend: KeyBackend::Vta {
                connection_id: connection_id.to_string(),
            },
            context: None,
            key_id: None,
            purpose: KeyPurpose::Credential,
        }
    }

    /// Contexts are created through the `[vta]` connection only: a key on
    /// another connection that names no context is not given one created there.
    #[tokio::test]
    async fn a_context_is_provisioned_only_on_the_vta_connection() {
        let creator = Arc::new(RecordingCreator(std::sync::Mutex::new(Vec::new())));
        let mut dir = directory_with(None);
        dir.push_surface_mapping("on-vta", context_less_credential_ref(DEFAULT_CONNECTION_ID))
            .unwrap();
        dir.push_surface_mapping("on-other", context_less_credential_ref("vta-a"))
            .unwrap();
        let dir = dir.with_provisioner(Arc::new(crate::vta::provisioning::ContextProvisioner::new(
            Arc::clone(&creator) as Arc<dyn crate::vta::provisioning::ContextCreator>,
            10,
        )));

        let provisioned = dir
            .resolve_and_provision(KeyPurpose::Credential, &KeyScope::surface("on-vta"))
            .await
            .expect("the `[vta]` connection provisions");
        assert_eq!(provisioned.context, Some(ContextId::from("created")));

        let other = dir
            .resolve_and_provision(KeyPurpose::Credential, &KeyScope::surface("on-other"))
            .await
            .expect("resolves without provisioning");
        assert_eq!(other.context, None);
        assert_eq!(
            creator
                .0
                .lock()
                .unwrap()
                .len(),
            1,
            "only the `[vta]` connection's context was created"
        );
    }

    /// A surface's derived context is named for its owner, read from the
    /// stored surface. A surface created under another tenant with a deleted
    /// surface's id therefore gets a context of its own, not the deleted
    /// surface's, even when the caller's scope names no tenant.
    #[tokio::test]
    async fn a_surface_recreated_under_another_tenant_gets_its_own_context() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(tmp.path().to_path_buf())
                .await
                .expect("surface store"),
        ) as Arc<dyn crate::surfaces::AgentSurfaceStore>;
        let creator = Arc::new(RecordingCreator(std::sync::Mutex::new(Vec::new())));
        let dir = directory_with(None)
            .with_surface_store(Arc::clone(&store))
            .with_provisioner(Arc::new(crate::vta::provisioning::ContextProvisioner::new(
                Arc::clone(&creator) as Arc<dyn crate::vta::provisioning::ContextCreator>,
                10,
            )));
        let owned_by = |tenant: &str| crate::config::agent_surface::AgentSurface {
            surface_id: "reused".to_string(),
            tenant_id: Some(tenant.to_string()),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                ..Default::default()
            }),
            ..Default::default()
        };

        for tenant in ["tenant-a", "tenant-b"] {
            crate::surfaces::AgentSurfaceStore::delete(store.as_ref(), "reused")
                .await
                .ok();
            crate::surfaces::AgentSurfaceStore::save(store.as_ref(), &owned_by(tenant))
                .await
                .expect("save the surface");
            dir.resolve_and_provision(KeyPurpose::Credential, &KeyScope::surface("reused"))
                .await
                .expect("provisions");
        }

        assert_eq!(
            *creator.0.lock().unwrap(),
            vec!["ctx:tenant-a/reused".to_string(), "ctx:tenant-b/reused".to_string()],
        );
    }

    #[test]
    fn only_an_enabled_auto_provisioning_vta_block_provisions_contexts() {
        let provisioning = VtaConfig {
            enabled: true,
            auto_provision_contexts: true,
            ..Default::default()
        };
        assert!(provisions_contexts_on(&provisioning, None));
        assert!(provisions_contexts_on(&provisioning, Some(DEFAULT_CONNECTION_ID)));
        assert!(provisions_contexts_on(&provisioning, Some(crate::vta::connections::BOOTSTRAP_CONNECTION_ID)));
        assert!(!provisions_contexts_on(&provisioning, Some("vta-a")));
        let disabled = VtaConfig {
            enabled: false,
            ..provisioning.clone()
        };
        assert!(!provisions_contexts_on(&disabled, None));
        let manual = VtaConfig {
            auto_provision_contexts: false,
            ..provisioning
        };
        assert!(!provisions_contexts_on(&manual, None));
    }
}
