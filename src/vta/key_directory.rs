//! `KeyRef` + `KeyDirectory` — which key signs what, resolved per request.
//!
//! Before this module the appliance picked **one** [`CredentialAuthority`] at
//! boot, pinned to one key id. That singleton is what blocks per-surface and
//! per-variant contexts (VTA-19), per-tenant selection (VTA-15), per-agent keys
//! (VTA-12) and an HSM backend (VTA-22): they all need the same thing —
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
//! [`KeyPurpose`] is the gateway-side mirror of the VTA-06 `typ` allow-list: the
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

use serde_json::Value;
use tokio::sync::RwLock;

use crate::config::vta::{KeyPurpose, VtaConfig};
use crate::identity::authority::CredentialAuthority;
use crate::vta::VtaError;

/// A VTA key-record id — also the `kid` the key is published under.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    /// Read the id back out. Used by callers that render a `KeyRef` (the Key
    /// Management dashboard, VTA-20) and by this module's tests.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    /// A VTA, addressed by stored connection. A single bootstrap-configured
    /// connection exists today; VTA-23 makes connections managed records, at
    /// which point `connection_id` selects between several.
    Vta { connection_id: String },
    /// An external HSM/KMS signer. The arm and its capability profile exist so
    /// the directory's shape is final; the implementation is VTA-22.
    #[allow(dead_code)]
    Hsm { provider: String },
}

impl KeyBackend {
    /// Stable name for error messages, so a capability rejection says which
    /// backend refused.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Vta { .. } => "vta",
            Self::Hsm { .. } => "hsm",
        }
    }
}

/// Names a signing key without holding it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyRef {
    pub backend: KeyBackend,
    pub context: Option<ContextId>,
    /// **Purpose-dependent (decision D-11).** Present for [`KeyPurpose::Jwt`] —
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

    /// Reject a `KeyRef` whose `key_id` presence contradicts its purpose
    /// (decision D-11), and whose backend cannot serve that purpose at all.
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
/// The VTA backend signs JWS (`keys/sign-jws`, VTA-06) and issues credentials
/// under the *context's* own issuer DID (`credentials/issue-in-context`), which
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
        // An HSM signs raw JWS. Credential/proof assembly is not an HSM
        // operation, so those stay with whichever backend owns the issuer DID.
        KeyBackend::Hsm { .. } => matches!(purpose, KeyPurpose::Jwt),
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
    /// Convenience constructors for the coordinates VTA-19 will supply from a
    /// request's surface/variant and VTA-15 from its tenant.
    pub fn surface(surface_id: impl Into<String>) -> Self {
        Self {
            surface_id: Some(surface_id.into()),
            ..Self::default()
        }
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: Some(tenant_id.into()),
            ..Self::default()
        }
    }
}

/// What a mapping is scoped to. Ordered most-specific first — the discriminant
/// order *is* the resolution order.
///
/// No mapping is installed until VTA-19 provides per-surface/variant config; the
/// resolution order it defines is unit-tested here so that ticket only has to
/// supply the data.
#[allow(dead_code)]
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
    Tenant {
        tenant_id: String,
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

/// Resolves request coordinates to a [`KeyRef`], and a `KeyRef` to a connector.
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
}

pub struct KeyDirectory {
    /// Appliance-wide default per purpose. Populated from `[vta]` by
    /// [`KeyDirectory::build`]; falls back to the local key for any purpose the
    /// config does not cover.
    defaults: HashMap<KeyPurpose, KeyRef>,
    /// Scoped overrides, consulted before the defaults. Empty until VTA-19
    /// provides per-surface/variant config.
    mappings: Vec<KeyMapping>,
    local: Arc<dyn CredentialAuthority>,
    /// Contexts already given a signing identity, so the bootstrap costs one
    /// round trip per context rather than one per request.
    identified: tokio::sync::RwLock<std::collections::HashSet<String>>,
    /// The bootstrap-configured VTA connector, if `[vta]` is enabled. Used for
    /// [`DEFAULT_CONNECTION_ID`] so a gateway with no connection records — and
    /// no secrets store — still resolves exactly what `[vta]` always built.
    vta: Option<Arc<dyn CredentialAuthority>>,
    /// The Data-Integrity agent-identity issuer built from the same bootstrap
    /// client as `vta` (VTA-11b). Shared rather than built separately because
    /// one control DID gets one VTA session — a second client authenticating as
    /// the same DID supersedes the first.
    di_vc_issuer: Option<Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>>,
    /// Creates per-surface contexts under the gateway's own, from the same
    /// bootstrap client (VTA-16). `None` when `[vta]` is disabled or
    /// auto-provisioning is off.
    context_creator: Option<Arc<dyn crate::vta::provisioning::ContextCreator>>,
    /// Provisions a per-agent context so an agent's holder key lives in the
    /// VTA rather than on this host (VTA-12). `None` under the same conditions
    /// as `context_creator`.
    agent_provisioner: Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>>,
    /// The client the holder-proof issuer dials (VTA-12), shared so a second
    /// session for the same control DID never supersedes the first.
    client: Option<Arc<crate::vta::client::VtaRestClient>>,
    /// Managed connection records (VTA-23). When present, any other
    /// `connection_id` resolves through it, so several VTAs can be mapped at
    /// once and edits take effect without a restart.
    connections: Option<Arc<crate::vta::registry::VtaConnectionRegistry>>,
    /// Read at resolution time so a surface written **after** startup is
    /// honoured. The `mappings` below are a boot-time snapshot: surfaces are
    /// hot-reloadable everywhere else in the gateway, and a key mapping that
    /// needed a restart to take effect silently signed with the wrong key.
    surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    /// An appliance-wide override set in the dashboard, consulted **after**
    /// scoped mappings and **before** the `[vta]`-derived defaults.
    ///
    /// Read on every resolution rather than captured at build time, so
    /// changing the appliance's signing backend in the UI takes effect without
    /// a restart — the same reason registry-backed connections are resolved
    /// per call rather than cached here.
    appliance_default: Option<Arc<dyn ApplianceSigningDefault>>,
    /// Lazy context provisioning (VTA-19). When present, a VTA-backed `KeyRef`
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

    /// The Data-Integrity credential issuer for one request's coordinates, or
    /// `None` to sign locally.
    ///
    /// Resolves through the ordinary order — variant, surface, tenant,
    /// dashboard default, `[vta]`, local — so a surface's own `signing` block
    /// governs the credential inside an injected presentation exactly as it
    /// governs a token. A scope that resolves to the local key returns `None`,
    /// which is what keeps a gateway that never adopted an agent on precisely
    /// the path it was always on.
    ///
    /// Provisioning is deliberate, not incidental: a surface mapped to an
    /// agent with no context named gets one derived from its stable id and
    /// created on first use, the same context its tokens already use.
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

    pub async fn di_vc_issuer_for(
        &self,
        scope: &KeyScope,
    ) -> ScopedDiIssuer {
        // An explicit `local` on the surface is an **answer**, not an absence.
        // Reading it as "no opinion" let it fall through to the appliance
        // default, so a surface switched back to the gateway's own key carried
        // on issuing through the agent and the setting looked inert.
        if let Some(declared) = self
            .live_surface_ref(KeyPurpose::Credential, scope)
            .await
            && matches!(declared.backend, KeyBackend::Local)
        {
            return ScopedDiIssuer::Local;
        }
        let key_ref = match self
            .resolve_and_provision(KeyPurpose::Credential, scope)
            .await
        {
            Ok(key_ref) => key_ref,
            Err(e) => {
                // The mapping was validated when the surface was written, so a
                // failure here is transient. Signing locally beats failing the
                // request, and the warning is what stops that being silent.
                tracing::warn!(
                    target: "vta_audit",
                    surface_id = ?scope.surface_id,
                    error = %e.log_detail(),
                    "could not resolve a credential issuer; signing locally",
                );
                return ScopedDiIssuer::Inherit;
            }
        };
        let KeyBackend::Vta { connection_id } = &key_ref.backend else {
            return ScopedDiIssuer::Inherit;
        };
        // A credential is issued **as** a context: its designated key signs and
        // its DID becomes the issuer. Without one there is nothing to issue as.
        let Some(context_id) = key_ref.context.as_ref() else {
            return ScopedDiIssuer::Inherit;
        };
        let Some(registry) = self.connections.as_ref() else {
            return ScopedDiIssuer::Inherit;
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
                ScopedDiIssuer::Agent(Arc::new(crate::vta::vc_issuer::VtaVcIssuer::new(
                    client,
                    context_id
                        .as_str()
                        .to_string(),
                )) as Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>)
            }
            Err(e) => {
                tracing::warn!(
                    target: "vta_audit",
                    connection_id = %connection_id,
                    error = %e.log_detail(),
                    "trust agent is unusable; issuing the agent-identity credential locally",
                );
                ScopedDiIssuer::Inherit
            }
        }
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
    /// auto-provisioning is enabled (VTA-12).
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

    /// Attach the managed connection registry (VTA-23), so a `KeyRef` naming
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

    /// The mapping a surface declares **right now**, if it declares one.
    ///
    /// A miss — no store, no such surface, nothing declared, or a block this
    /// backend cannot serve for `purpose` — falls through to the snapshot and
    /// then the appliance default, which is what an unmapped surface has
    /// always resolved.
    async fn live_surface_ref(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> Option<KeyRef> {
        let store = self.surfaces.as_ref()?;
        let surface_id = scope.surface_id.as_deref()?;
        let surface = crate::surfaces::AgentSurfaceStore::get(store.as_ref(), surface_id)
            .await
            .ok()
            .flatten()?;

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
        let signing = variant_signing.or(surface
            .signing
            .as_ref()
            .filter(|s| !s.is_empty()))?;

        signing_key_ref(signing, purpose).ok()
    }

    /// Attach the lazy context provisioner (VTA-19), so a surface that asks
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
    /// `signing` config (VTA-19).
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

    /// Install a tenant-scoped override. Fed by per-tenant selection (VTA-15);
    /// the resolution order it participates in is tested here so that ticket
    /// only has to supply the data.
    #[allow(dead_code)]
    pub fn with_tenant_mapping(
        mut self,
        tenant_id: impl Into<String>,
        key_ref: KeyRef,
    ) -> Result<Self, VtaError> {
        key_ref.validate()?;
        self.mappings
            .push(KeyMapping {
                scope: MappingScope::Tenant { tenant_id: tenant_id.into() },
                purpose: key_ref.purpose,
                key_ref,
            });
        Ok(self)
    }

    /// Install the mappings a surface and its variants declare (VTA-19).
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
    /// First match wins, in the order **variant → surface → tenant → appliance
    /// default → local**, mirroring the surface-variant override semantics used
    /// everywhere else in the gateway. The final fallback is the legacy local
    /// key, so a gateway with nothing configured resolves exactly what it
    /// signed with before this module existed.
    pub fn resolve(
        &self,
        purpose: KeyPurpose,
        scope: &KeyScope,
    ) -> KeyRef {
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
            return m;
        }
        if let Some(surface_id) = scope.surface_id.as_deref()
            && let Some(m) =
                self.find(purpose, |s| matches!(s, MappingScope::Surface { surface_id: sid } if sid == surface_id))
        {
            return m;
        }
        if let Some(tenant_id) = scope.tenant_id.as_deref()
            && let Some(m) =
                self.find(purpose, |s| matches!(s, MappingScope::Tenant { tenant_id: tid } if tid == tenant_id))
        {
            return m;
        }
        // The dashboard override outranks the `[vta]` block: an operator who
        // points the appliance at a paired connection in the UI expects that
        // to win over a file they may not be able to edit. A malformed
        // override is ignored rather than fatal — it cannot be rejected at
        // startup like config can, and refusing to sign because an optional
        // setting is wrong would take the appliance down.
        if let Some(source) = self
            .appliance_default
            .as_ref()
            && let Some(signing) = source.signing()
            && let Ok(key_ref) = signing_key_ref(&signing, purpose)
        {
            return key_ref;
        }
        self.defaults
            .get(&purpose)
            .cloned()
            .unwrap_or_else(|| KeyRef::local(purpose))
    }

    /// [`Self::resolve`], plus **lazy context provisioning** (VTA-19).
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
            .await
        {
            Some(live) => live,
            None => self.resolve(purpose, scope),
        };
        let needs_context = matches!(key_ref.backend, KeyBackend::Vta { .. }) && key_ref.context.is_none();
        if !needs_context {
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
        let name = crate::config::agent_surface::derived_context_name(
            scope.tenant_id.as_deref(),
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
            KeyBackend::Hsm { provider } => {
                return Err(VtaError::Config(format!("[vta] HSM backend `{provider}` is not implemented yet")));
            }
        };

        self.cache
            .write()
            .await
            .insert(key_ref.clone(), Arc::clone(&authority));
        Ok(authority)
    }

    /// Every key the gateway publishes, aggregated across the backends the
    /// directory can reach and deduplicated by `kid`.
    ///
    /// A verifier picks between an active and a retiring key by `kid`, so a key
    /// missing here breaks tokens that are still in flight. A backend that
    /// cannot be reached is therefore **warned and skipped** rather than
    /// failing the whole set: publishing most of the keys beats publishing
    /// none.
    ///
    /// Not yet served at `/oauth2/jwks.json`: with a single backend, VTA-17's
    /// carried-over JWKS already publishes the local key alongside the VTA's.
    /// This becomes the endpoint's source once several connections or an HSM
    /// can hold keys at once (VTA-22, VTA-23).
    #[allow(dead_code)]
    pub async fn jwks(&self) -> Value {
        let mut keys: Vec<Value> = Vec::new();
        let mut seen: Vec<String> = Vec::new();

        let mut sources: Vec<Arc<dyn CredentialAuthority>> = vec![Arc::clone(&self.local)];
        if let Some(vta) = &self.vta {
            sources.push(Arc::clone(vta));
        }

        for source in sources {
            match source.issuer_jwks().await {
                Ok(jwks) => {
                    let Some(entries) = jwks
                        .get("keys")
                        .and_then(Value::as_array)
                    else {
                        continue;
                    };
                    for key in entries {
                        // A `kid`-less key cannot be selected by a verifier and
                        // cannot be deduplicated, so keep it rather than drop
                        // it, but do not let it suppress a later named key.
                        match key
                            .get("kid")
                            .and_then(Value::as_str)
                        {
                            Some(kid) if seen.iter().any(|s| s == kid) => continue,
                            Some(kid) => seen.push(kid.to_string()),
                            None => {}
                        }
                        keys.push(key.clone());
                    }
                }
                Err(e) => tracing::warn!(
                    target: "vta_audit",
                    error = %e,
                    "a signing backend's JWKS is unavailable; its keys are omitted from the published set",
                ),
            }
        }

        serde_json::json!({ "keys": keys })
    }
}

/// Connection id of the single bootstrap-configured VTA. VTA-23 replaces this
/// with real stored connection records.
pub const DEFAULT_CONNECTION_ID: &str = "default";

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
        Some(SigningBackendKind::Hsm) => KeyBackend::Hsm {
            provider: signing
                .connection_id
                .clone()
                .unwrap_or_else(|| "default".to_string()),
        },
    };
    let key_ref = KeyRef {
        context: signing
            .context_id
            .as_deref()
            .map(ContextId::from),
        // D-11: only a `jwt` key is caller-named; for the other purposes the
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

    struct UnreachableAuthority;

    #[async_trait::async_trait]
    impl CredentialAuthority for UnreachableAuthority {
        async fn issuer_did(&self) -> anyhow::Result<String> {
            anyhow::bail!("unreachable")
        }

        async fn issuer_jwks(&self) -> anyhow::Result<Value> {
            anyhow::bail!("unreachable")
        }

        async fn sign_token(
            &self,
            _claims: &Value,
        ) -> anyhow::Result<String> {
            anyhow::bail!("unreachable")
        }

        async fn sign_token_typ(
            &self,
            _claims: &Value,
            _typ: &str,
        ) -> anyhow::Result<String> {
            anyhow::bail!("unreachable")
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
            let resolved = dir.resolve(purpose, &KeyScope::default());
            assert_eq!(resolved, KeyRef::local(purpose), "purpose {purpose:?} must fall back to local");
        }
    }

    #[test]
    fn the_appliance_default_is_used_when_no_scope_matches() {
        let mut dir = directory_with(None);
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));

        let resolved = dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("surface-a"));
        assert_eq!(
            resolved
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn a_tenant_mapping_beats_the_appliance_default() {
        let mut dir = directory_with(None)
            .with_tenant_mapping("tenant-a", vta_jwt_ref("tenant-key"))
            .unwrap();
        dir.defaults
            .insert(KeyPurpose::Jwt, vta_jwt_ref("appliance-key"));

        let resolved = dir.resolve(KeyPurpose::Jwt, &KeyScope::tenant("tenant-a"));
        assert_eq!(
            resolved
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("tenant-key")
        );
        // A different tenant still falls through to the default.
        let other = dir.resolve(KeyPurpose::Jwt, &KeyScope::tenant("tenant-b"));
        assert_eq!(
            other
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("appliance-key")
        );
    }

    #[test]
    fn a_surface_mapping_beats_a_tenant_mapping() {
        let mut dir = directory_with(None)
            .with_tenant_mapping("tenant-a", vta_jwt_ref("tenant-key"))
            .unwrap();
        dir.push_surface_mapping("surface-a", vta_jwt_ref("surface-key"))
            .unwrap();

        let scope = KeyScope {
            tenant_id: Some("tenant-a".to_string()),
            surface_id: Some("surface-a".to_string()),
            variant_id: None,
        };
        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &scope)
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("surface-key")
        );
    }

    #[test]
    fn a_variant_mapping_beats_a_surface_mapping() {
        let mut dir = directory_with(None)
            .with_tenant_mapping("tenant-a", vta_jwt_ref("tenant-key"))
            .unwrap();
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
                .key_id
                .as_ref()
                .map(KeyId::as_str),
            Some("variant-key")
        );
        // An unmapped variant of the same surface falls back to the surface.
        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::variant("surface-a", "variant-z"))
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
        let resolved = dir.resolve(KeyPurpose::Credential, &KeyScope::surface("surface-a"));
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

    // ---- managed connections (VTA-23) ------------------------------------

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
                status: VtaConnectionStatus::Connected,
                keys: Default::default(),
                // Paired, so the registry gets past the pairing gate and this
                // test exercises connection *selection* rather than VTA-24's
                // fail-closed path (which has its own tests).
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
                // whose key follows the context's issuer DID (D-11).
                key_id: Some("gateway-jwt-1".to_string()),
            }),
            ..Default::default()
        };
        dir.with_surface(&surface)
            .expect("the mapping installs");

        for purpose in [KeyPurpose::Jwt, KeyPurpose::Credential] {
            let resolved = dir.resolve(purpose, &KeyScope::surface("surface-a"));
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
    /// trace, with `credentials/issue-in-context` still signing as the
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

    // ---- capability negotiation ------------------------------------------

    /// The agent issues credentials under its context's own issuer DID
    /// (`credentials/issue-in-context`, exercised live in
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

    #[tokio::test]
    async fn the_hsm_backend_signs_jws_only_and_is_not_implemented_yet() {
        let hsm = KeyBackend::Hsm {
            provider: "cloudhsm".to_string(),
        };
        assert!(supports(&hsm, KeyPurpose::Jwt));
        // Credential/proof assembly is not an HSM operation, so a config that
        // asks for it is rejected before anything is built.
        assert!(!supports(&hsm, KeyPurpose::Credential));

        let msg = error_detail(
            KeyRef {
                backend: hsm.clone(),
                context: None,
                key_id: None,
                purpose: KeyPurpose::Proof,
            }
            .validate(),
            "the hsm backend cannot build proofs",
        );
        assert!(msg.contains("hsm") && msg.contains("proof"), "unexpected error: {msg}");

        // The arm exists so the directory's shape is final; the signer itself
        // is VTA-22, and until then it must fail rather than silently fall back.
        let dir = directory_with(None);
        let msg = error_detail(
            dir.authority_for(
                &KeyRef {
                    backend: hsm,
                    context: None,
                    key_id: Some(KeyId::from("hsm-key")),
                    purpose: KeyPurpose::Jwt,
                },
                KeyPurpose::Jwt,
            )
            .await,
            "the hsm signer is not implemented",
        );
        assert!(msg.contains("cloudhsm"), "the error must name the provider: {msg}");
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

    // ---- decision D-11: key_id presence is purpose-dependent -------------

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
        // Hypothetically allowed backend-wise once VTA-28 lands; the D-11 rule
        // is independent of that, so assert it against the local backend which
        // already serves the purpose.
        let key_ref = KeyRef {
            backend: KeyBackend::Local,
            context: None,
            key_id: Some(KeyId::from("whatever")),
            purpose: KeyPurpose::Credential,
        };
        let msg = error_detail(key_ref.validate(), "the local backend has no nameable key id");
        assert!(msg.contains("key id"), "unexpected error: {msg}");
    }

    // ---- jwks aggregation -------------------------------------------------

    #[tokio::test]
    async fn jwks_aggregates_every_backend_and_dedupes_by_kid() {
        let vta = StubAuthority::new("did:webvh:vta", vec!["vta-active", "vta-retiring", "local-1"]);
        let dir = directory_with(Some(vta));

        let jwks = dir.jwks().await;
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();

        assert_eq!(kids, vec!["local-1", "vta-active", "vta-retiring"], "got {kids:?}");
    }

    #[tokio::test]
    async fn an_unreachable_backend_does_not_empty_the_published_set() {
        let dir = directory_with(Some(Arc::new(UnreachableAuthority)));

        let jwks = dir.jwks().await;
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        // The local key is still published, so tokens it signed keep verifying.
        assert_eq!(kids, vec!["local-1"]);
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

        let key_ref = dir.resolve(KeyPurpose::Jwt, &KeyScope::default());
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
            dir.resolve(KeyPurpose::Jwt, &KeyScope::default()),
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
                .backend,
            KeyBackend::Vta {
                connection_id: "vta-surface".to_string()
            },
            "the surface's own mapping must beat the appliance-wide setting"
        );
    }

    /// A malformed override must not take the appliance down. It cannot be
    /// rejected at startup the way config can, so it is ignored and the
    /// previous default stands.
    #[tokio::test]
    async fn a_malformed_override_falls_through_instead_of_breaking_signing() {
        let (local, _tmp) = local_authority().await;
        // `vta` backend with no key id is invalid for the `jwt` purpose (D-11).
        let broken = crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: Some("vta-b".to_string()),
            ..Default::default()
        };
        let dir = KeyDirectory::build(&VtaConfig::default(), Arc::clone(&local))
            .await
            .expect("a disabled block always builds")
            .with_appliance_default(Arc::new(StubApplianceDefault(Some(broken))));

        assert_eq!(
            dir.resolve(KeyPurpose::Jwt, &KeyScope::default()),
            KeyRef::local(KeyPurpose::Jwt),
            "a broken override must fall through, not panic or poison signing"
        );
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

        let key_ref = dir.resolve(KeyPurpose::Jwt, &KeyScope::default());
        assert_eq!(key_ref, KeyRef::local(KeyPurpose::Jwt));

        let authority = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        // The very same local connector, so output is identical to today.
        assert!(Arc::ptr_eq(&local, &authority));
    }

    // ---- per-surface / per-variant signing (VTA-19) -----------------------

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

        let first = dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s1"));
        let second = dir.resolve(KeyPurpose::Jwt, &KeyScope::surface("s2"));

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
        let inherited = dir.resolve(KeyPurpose::Jwt, &KeyScope::variant("s1", "v-plain"));
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
        let own = dir.resolve(KeyPurpose::Jwt, &KeyScope::variant("s1", "v-own"));
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

        let key_ref = dir.resolve(KeyPurpose::Jwt, &KeyScope::default());
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
        assert_eq!(dir.resolve(KeyPurpose::Credential, &KeyScope::default()), KeyRef::local(KeyPurpose::Credential));

        let authority = dir
            .authority_for(&key_ref, KeyPurpose::Jwt)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&local, &authority), "an enabled block must resolve the VTA connector");
    }
}
