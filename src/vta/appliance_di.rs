//! Data-Integrity issuance driven by a **dashboard-managed connection**, for
//! installs that never enable the `[vta]` config block.
//!
//! The `[vta]` block builds its issuers once at boot, which is why it was the
//! only way to make VP injection issue through an agent: a gateway configured
//! entirely from the dashboard had `di_vc_issuer` unset and signed the embedded
//! credential locally, no matter which agent the operator had connected.
//!
//! This closes that gap without reintroducing boot-time wiring. An operator
//! connects an agent while the gateway is running, so anything resolved once at
//! startup would be wrong until the next restart — the opposite of the
//! hot-reload behaviour every other connection edit already has. Instead the
//! issuer installed here is a **delegate**: it resolves the appliance's current
//! agent on each call and uses the local issuer only when none was chosen.
//!
//! Resolution deliberately reuses [`ApplianceSigningDefault`] — the same port
//! the key directory consults — so "which agent signs for this appliance" has
//! exactly one answer, whether the caller is signing a token or issuing the
//! credential inside an injected presentation.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::identity::ssi::vc_issuer::{IssueVcPayload, VcIssuer};
use crate::vta::key_directory::ApplianceSigningDefault;
use crate::vta::registry::VtaConnectionRegistry;

/// Issues the agent-identity credential through whichever agent is currently
/// the appliance default, or with the local issuer when none was chosen.
pub struct ApplianceVcIssuer {
    registry: Arc<VtaConnectionRegistry>,
    appliance_default: Arc<dyn ApplianceSigningDefault>,
    local: Arc<dyn VcIssuer>,
    /// Contexts already known to carry a signing identity, so the check costs
    /// one round trip per context per process rather than one per request.
    identified: tokio::sync::RwLock<std::collections::HashSet<String>>,
}

impl ApplianceVcIssuer {
    pub fn new(
        registry: Arc<VtaConnectionRegistry>,
        appliance_default: Arc<dyn ApplianceSigningDefault>,
        local: Arc<dyn VcIssuer>,
    ) -> Self {
        Self {
            registry,
            appliance_default,
            local,
            identified: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Make sure the context can sign as itself before issuing through it.
    ///
    /// A context the operator created by hand has no DID, and the agent
    /// refuses issuance with exactly that reason. The same grant that lets the
    /// gateway create contexts also lets it set a DID **while unset**, so the
    /// gap is closable rather than something the operator must know to fix.
    ///
    /// Best effort: a failure here is logged and issuance is still attempted,
    /// because the context may already be fine in a way this cannot see (for
    /// instance an administrator configured it), and the agent's own refusal
    /// is a better error than one invented here.
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

    /// The agent-backed issuer for the current appliance default, or `None`
    /// when nobody chose a trust agent and the local issuer signs.
    ///
    /// A trust agent that was chosen but cannot be used (no connection or
    /// context named, or the connection disabled, unpaired, revoked or
    /// unreachable) is an error: issuing with the local key instead would put
    /// the gateway's own DID on a credential the operator meant a trust agent
    /// to issue.
    async fn resolve(&self) -> Result<Option<Arc<dyn VcIssuer>>> {
        let Some(signing) = self
            .appliance_default
            .signing()
            .filter(|signing| signing.backend == Some(crate::config::agent_surface::SigningBackendKind::Vta))
        else {
            return Ok(None);
        };
        let (Some(connection_id), Some(context_id)) = (
            signing
                .connection_id
                .as_deref(),
            signing.context_id.as_deref(),
        ) else {
            anyhow::bail!(
                "Gateway signing names a trust agent without a connection and a context to issue the credential as"
            );
        };
        let client = self
            .registry
            .client(connection_id)
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "vta_audit",
                    connection_id = %connection_id,
                    error = %e.log_detail(),
                    "the gateway-wide trust agent is unusable; the agent-identity credential is not issued",
                );
                anyhow::anyhow!("the trust agent Gateway signing names cannot be used: {e}")
            })?;
        self.ensure_can_issue(&client, context_id)
            .await;
        Ok(Some(Arc::new(crate::vta::vc_issuer::VtaVcIssuer::new(client, context_id.to_string())) as Arc<dyn VcIssuer>))
    }
}

#[async_trait]
impl VcIssuer for ApplianceVcIssuer {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value> {
        match self.resolve().await? {
            Some(vta) => vta.issue(payload).await,
            None => {
                self.local
                    .issue(payload)
                    .await
            }
        }
    }
}

/// Resolves the appliance's current agent for the **holder** side.
///
/// `RegistryVtaClients` needs a bootstrap client, which only `[vta]` provides.
/// This resolves the appliance default instead, so a gateway configured purely
/// from the dashboard can still reach an agent for a holder proof.
pub struct ApplianceVtaClients {
    registry: Arc<VtaConnectionRegistry>,
    appliance_default: Arc<dyn ApplianceSigningDefault>,
}

impl ApplianceVtaClients {
    pub fn new(
        registry: Arc<VtaConnectionRegistry>,
        appliance_default: Arc<dyn ApplianceSigningDefault>,
    ) -> Self {
        Self { registry, appliance_default }
    }

    /// The connection an agent record names, or the appliance default.
    fn connection_id(
        &self,
        named: Option<&str>,
    ) -> Option<String> {
        if let Some(id) = named.filter(|id| *id != crate::vta::connections::BOOTSTRAP_CONNECTION_ID) {
            return Some(id.to_string());
        }
        let signing = self
            .appliance_default
            .signing()?;
        if signing.backend != Some(crate::config::agent_surface::SigningBackendKind::Vta) {
            return None;
        }
        signing.connection_id
    }
}

#[async_trait]
impl crate::vta::vp_issuer::VtaClients for ApplianceVtaClients {
    async fn client_for(
        &self,
        connection_id: Option<&str>,
    ) -> Result<Arc<crate::vta::client::VtaRestClient>> {
        let id = self
            .connection_id(connection_id)
            .ok_or_else(|| anyhow::anyhow!("no trust agent is the appliance default"))?;
        self.registry
            .client(&id)
            .await
            .map_err(|e| anyhow::anyhow!("trust agent `{id}` is unavailable: {}", e.log_detail()))
    }
}

/// Mints a newly onboarded agent's key inside the trust agent that signs for
/// the gateway right now: the one Gateway signing names, else the `[vta]`
/// block's. When the gateway signs with its own key there is nothing to
/// provision into, and the gateway mints the agent's key as it always did.
///
/// Once a trust agent signs, its agents' keys belong in it, so a failure, a
/// refusal included, fails the onboarding with the reason rather than leaving
/// the agent with a key on this host for good.
pub struct ApplianceAgentProvisioner {
    registry: Arc<VtaConnectionRegistry>,
    appliance_default: Arc<dyn ApplianceSigningDefault>,
    /// The `[vta]` block's context, when the block is enabled.
    bootstrap_context: Option<String>,
}

impl ApplianceAgentProvisioner {
    pub fn new(
        registry: Arc<VtaConnectionRegistry>,
        appliance_default: Arc<dyn ApplianceSigningDefault>,
        bootstrap_context: Option<String>,
    ) -> Self {
        Self {
            registry,
            appliance_default,
            bootstrap_context,
        }
    }

    /// The connection and parent context a new agent's key is minted under:
    /// `None` when the gateway signs with its own key, an error when the trust
    /// agent that signs names nowhere to mint it.
    fn target(&self) -> Option<Result<(String, String)>> {
        use crate::config::agent_surface::SigningBackendKind;
        let bootstrap = crate::vta::connections::BOOTSTRAP_CONNECTION_ID;
        match self
            .appliance_default
            .signing()
            .filter(|signing| !signing.is_empty())
        {
            Some(signing) if signing.backend == Some(SigningBackendKind::Vta) => {
                let connection_id = signing
                    .connection_id
                    .filter(|id| id != crate::vta::key_directory::DEFAULT_CONNECTION_ID)
                    .unwrap_or_else(|| bootstrap.to_string());
                let context_id = signing
                    .context_id
                    .or_else(|| {
                        (connection_id == bootstrap)
                            .then(|| self.bootstrap_context.clone())
                            .flatten()
                    });
                Some(
                    context_id
                        .map(|context_id| (connection_id, context_id))
                        .ok_or_else(|| {
                            anyhow::anyhow!("Gateway signing names no trust agent context to mint agent keys in")
                        }),
                )
            }
            Some(_) => None,
            None => self
                .bootstrap_context
                .clone()
                .map(|context_id| Ok((bootstrap.to_string(), context_id))),
        }
    }
}

#[async_trait]
impl crate::vta::agent_contexts::AgentKeyProvisioner for ApplianceAgentProvisioner {
    async fn provision(
        &self,
        identity_hash: &str,
    ) -> Result<crate::vta::agent_contexts::ProvisionedAgent> {
        let (connection_id, context_id) = self
            .target()
            .ok_or_else(|| {
                anyhow::anyhow!("the gateway signs with its own key, so no trust agent mints agent keys")
            })??;
        let client = self
            .registry
            .client(&connection_id)
            .await
            .map_err(|e| anyhow::anyhow!("trust agent `{connection_id}` is unavailable: {}", e.log_detail()))?;

        crate::vta::agent_contexts::VtaAgentProvisioner::new(
            crate::vta::context_creator::GatewayContextCreator::new(client, context_id),
            connection_id,
        )
        .provision(identity_hash)
        .await
    }

    /// Only when a trust agent signs for the gateway. An install that never
    /// adopted one, or chose its own key, onboards agents as it always did,
    /// with no attempt and no warning.
    fn available(&self) -> bool {
        self.target().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{SigningBackendKind, SurfaceSigningConfig};

    /// Records which issuer was reached.
    struct Marker(&'static str);

    #[async_trait]
    impl VcIssuer for Marker {
        async fn issue<'a>(
            &self,
            _payload: IssueVcPayload<'a>,
        ) -> Result<Value> {
            Ok(Value::String(self.0.to_string()))
        }
    }

    pub(super) struct Fixed(pub(super) Option<SurfaceSigningConfig>);
    impl ApplianceSigningDefault for Fixed {
        fn signing(&self) -> Option<SurfaceSigningConfig> {
            self.0.clone()
        }
    }

    pub(super) fn vta_signing(
        connection: Option<&str>,
        context: Option<&str>,
    ) -> SurfaceSigningConfig {
        SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Vta),
            connection_id: connection.map(str::to_string),
            context_id: context.map(str::to_string),
            key_id: None,
        }
    }

    /// Builds an issuer whose registry holds nothing, so any connection lookup
    /// fails — enough to prove which branch the resolution took.
    async fn issuer(default: Option<SurfaceSigningConfig>) -> ApplianceVcIssuer {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(tmp.path().join("connections"))
                .await
                .expect("store"),
        );
        // Leaked so the temp dir outlives the registry for the test's duration.
        std::mem::forget(tmp);
        ApplianceVcIssuer::new(
            Arc::new(VtaConnectionRegistry::new(store, None, None, None, std::time::Duration::from_secs(5), 4)),
            Arc::new(Fixed(default)),
            Arc::new(Marker("local")),
        )
    }

    async fn issued(i: &ApplianceVcIssuer) -> String {
        i.issue(IssueVcPayload::AgentIdentity(crate::identity::ssi::vc_issuer::AgentIdentity {
            identity_fields: std::borrow::Cow::Owned(std::collections::HashMap::new()),
            did: std::borrow::Cow::Borrowed("did:key:zAgent"),
            workload_binding: None,
            display_name: None,
        }))
        .await
        .expect("issue")
        .as_str()
        .expect("marker")
        .to_string()
    }

    /// No appliance override: unchanged behaviour, the local issuer signs.
    #[tokio::test]
    async fn without_an_appliance_default_the_local_issuer_signs() {
        assert_eq!(issued(&issuer(None).await).await, "local");
    }

    /// An explicit local default must not be mistaken for "no opinion".
    #[tokio::test]
    async fn an_appliance_default_of_local_signs_locally() {
        let local = SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Local),
            ..Default::default()
        };
        assert_eq!(issued(&issuer(Some(local)).await).await, "local");
    }

    async fn refused(i: &ApplianceVcIssuer) -> String {
        i.issue(IssueVcPayload::AgentIdentity(crate::identity::ssi::vc_issuer::AgentIdentity {
            identity_fields: std::borrow::Cow::Owned(std::collections::HashMap::new()),
            did: std::borrow::Cow::Borrowed("did:key:zAgent"),
            workload_binding: None,
            display_name: None,
        }))
        .await
        .expect_err("a chosen trust agent that cannot issue must not fall back to the local key")
        .to_string()
    }

    /// A VTA default naming no context or no connection cannot issue: the
    /// context is what determines the issuer DID, so there is nothing to issue
    /// *as*, and the gateway's own DID must not stand in for it.
    #[tokio::test]
    async fn a_vta_default_without_a_context_or_connection_is_refused() {
        for signing in [vta_signing(Some("vta-a"), None), vta_signing(None, Some("ctx"))] {
            let err = refused(&issuer(Some(signing)).await).await;
            assert!(err.contains("without a connection and a context"), "{err}");
        }
    }

    /// An unusable connection fails the issuance instead of signing locally.
    #[tokio::test]
    async fn an_unusable_connection_is_refused_instead_of_falling_back() {
        let signing = vta_signing(Some("does-not-exist"), Some("ctx"));
        let err = refused(&issuer(Some(signing)).await).await;
        assert!(err.contains("cannot be used"), "{err}");
    }
}

/// The positive path, against a **real** agent: with a dashboard connection as
/// the appliance default, the embedded credential is issued by the agent's
/// context rather than this process.
///
/// The unit tests above can only prove the fallbacks. This proves the thing the
/// feature exists for — that `[vta]` is no longer required for an injected
/// presentation to carry an agent-issued credential.
///
/// ```text
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID='did:webvh:...' \
/// VTA_LIVE_PARENT_CONTEXT=gwtest \
///   cargo test --bin agent-trust-gateway appliance_di::live_tests \
///     -- --ignored --test-threads=1
/// ```
#[cfg(test)]
mod live_tests {
    use super::tests::Fixed;
    use super::*;
    use crate::config::agent_surface::{SigningBackendKind, SurfaceSigningConfig};
    use crate::vta::connections::{
        FileSystemVtaConnectionStore, VtaConnection, VtaConnectionStatus, VtaConnectionStorage, VtaConnectionTransport,
    };

    const LIVE_SEED: [u8; 32] = [0x2a; 32];
    const CONTROL_SECRET_ID: &str = "vta-control-key-appliance-di";

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("set {name}; see the module docs"))
    }

    #[tokio::test]
    #[ignore = "requires a running VTA; see the module docs"]
    async fn a_dashboard_connection_issues_the_credential_through_the_agent() {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = env("VTA_LIVE_DID");
        let context = env("VTA_LIVE_PARENT_CONTEXT");
        let tmp = tempfile::tempdir().expect("tempdir");

        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                tmp.path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .expect("secrets store"),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "live control key".to_string(),
                secret_id: CONTROL_SECRET_ID.to_string(),
                description: None,
                value: LIVE_SEED
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                secret_type: "General".to_string(),
                tags: vec!["vta".to_string()],
            })
            .await
            .expect("store the control key");

        let store = Arc::new(
            FileSystemVtaConnectionStore::new(tmp.path().join("connections"))
                .await
                .expect("connection store"),
        );
        let now = chrono::Utc::now();
        store
            .create(VtaConnection {
                id: "appliance-di".to_string(),
                tenant_id: None,
                name: "Live agent".to_string(),
                description: None,
                enabled: true,
                transport: VtaConnectionTransport::Https,
                endpoint: url.clone(),
                vta_did: vta_did.clone(),
                default_context_id: Some(context.clone()),
                control_key_ref: Some(CONTROL_SECRET_ID.to_string()),
                control_did: None,
                control_key_state: Default::default(),
                status: VtaConnectionStatus::Connected,
                keys: Default::default(),
                pairing: crate::vta::pairing::PairingRecord {
                    state: crate::vta::pairing::PairingState::Connected,
                    pinned_vta_did: Some(vta_did.clone()),
                    ..Default::default()
                },
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("store the connection");

        let registry = Arc::new(VtaConnectionRegistry::new(
            store,
            Some(Arc::clone(&secrets)),
            None,
            None,
            std::time::Duration::from_secs(15),
            8,
        ));

        // A context must be able to **sign as itself** to issue: it needs a
        // DID and a designated issuer key. A context created by hand (`vta
        // context create`) has neither, and the agent refuses with "context
        // `x` has no DID, so it cannot sign as itself". Provisioning one the
        // way the gateway does is therefore part of the path under test, not
        // incidental setup.
        let client = registry
            .client("appliance-di")
            .await
            .expect("a usable connection");
        // Deliberately the **bare** context the operator made by hand: it has
        // no DID until the issuer gives it one, which is the gap being closed.
        let _ = &client;
        let provisioned = context.clone();

        // Exactly what the Settings picker writes.
        let appliance_default = SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Vta),
            connection_id: Some("appliance-di".to_string()),
            context_id: Some(
                provisioned
                    .as_str()
                    .to_string(),
            ),
            key_id: None,
        };

        struct NeverLocal;
        #[async_trait]
        impl VcIssuer for NeverLocal {
            async fn issue<'a>(
                &self,
                _payload: IssueVcPayload<'a>,
            ) -> Result<Value> {
                panic!("the local issuer must not be reached when an agent is the appliance default")
            }
        }

        let issuer = ApplianceVcIssuer::new(registry, Arc::new(Fixed(Some(appliance_default))), Arc::new(NeverLocal));

        let credential = issuer
            .issue(IssueVcPayload::AgentIdentity(crate::identity::ssi::vc_issuer::AgentIdentity {
                identity_fields: std::borrow::Cow::Owned(std::collections::HashMap::new()),
                did: std::borrow::Cow::Borrowed("did:key:z6MkappliancediTest"),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .expect("the agent must issue the credential");

        let issuer_did = credential
            .get("issuer")
            .and_then(|i| i.get("id").or(Some(i)))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        assert!(issuer_did.starts_with("did:"), "the credential must name an issuer: {credential}");
        assert!(!issuer_did.is_empty(), "issued by the agent context, not this process: {credential}");

        // The proof must come from the agent's context key, which is what
        // makes this different from local signing.
        let proof = credential
            .get("proof")
            .expect("the agent returns a Data Integrity proof");
        let vm = proof
            .get("verificationMethod")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(vm.starts_with("did:"), "the proof must name the agent's verification method: {proof}");
        eprintln!("APPLIANCE_DI issuer={issuer_did} vm={vm}");
    }
}

/// The fail-soft contract, which is what makes inferring a provisioner safe.
#[cfg(test)]
mod fallback_tests {
    use super::*;
    use crate::vta::agent_contexts::AgentKeyProvisioner;

    async fn registry() -> (Arc<VtaConnectionRegistry>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(tmp.path().join("c"))
                .await
                .expect("store"),
        );
        (Arc::new(VtaConnectionRegistry::new(store, None, None, None, std::time::Duration::from_secs(5), 4)), tmp)
    }

    fn provisioner(
        registry: &Arc<VtaConnectionRegistry>,
        default: Option<crate::config::agent_surface::SurfaceSigningConfig>,
        bootstrap_context: Option<&str>,
    ) -> ApplianceAgentProvisioner {
        ApplianceAgentProvisioner::new(
            Arc::clone(registry),
            Arc::new(tests::Fixed(default)),
            bootstrap_context.map(str::to_string),
        )
    }

    fn local() -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
        Some(crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
            ..Default::default()
        })
    }

    /// A gateway that signs with its own key, with or without a `[vta]` block
    /// behind a local choice, onboards agents as it always did: no attempt,
    /// no warning.
    #[tokio::test]
    async fn a_gateway_signing_with_its_own_key_mints_agent_keys_itself() {
        let (registry, _tmp) = registry().await;
        assert!(!provisioner(&registry, None, None).available(), "no trust agent at all");
        assert!(!provisioner(&registry, local(), None).available(), "its own key chosen");
        assert!(!provisioner(&registry, local(), Some("gw")).available(), "its own key chosen over [vta]");
    }

    /// Whatever trust agent signs for the gateway right now mints new agents'
    /// keys: the one Gateway signing names, else the `[vta]` block's.
    #[tokio::test]
    async fn new_agent_keys_follow_the_trust_agent_that_signs_now() {
        let (registry, _tmp) = registry().await;
        let bootstrap = crate::vta::connections::BOOTSTRAP_CONNECTION_ID.to_string();
        let target = |p: ApplianceAgentProvisioner| {
            p.target()
                .expect("a trust agent signs")
                .expect("it names a context")
        };

        assert_eq!(
            target(provisioner(&registry, None, Some("gw"))),
            (bootstrap.clone(), "gw".to_string()),
            "the [vta] block signs, whether or not it auto-provisions contexts"
        );
        assert_eq!(
            target(provisioner(&registry, Some(tests::vta_signing(Some("vta-b"), Some("ctx-b"))), Some("gw"))),
            ("vta-b".to_string(), "ctx-b".to_string()),
            "Gateway signing moved to another agent, so new keys go there"
        );
        assert_eq!(
            target(provisioner(&registry, Some(tests::vta_signing(None, None)), Some("gw"))),
            (bootstrap, "gw".to_string()),
            "a choice naming no connection is the [vta] block"
        );
    }

    /// A trust agent that signs but names nowhere to mint keys fails the
    /// onboarding with that reason, never a gateway-held key.
    #[tokio::test]
    async fn a_trust_agent_naming_no_context_refuses_to_onboard() {
        let (registry, _tmp) = registry().await;
        let p = provisioner(&registry, Some(tests::vta_signing(Some("vta-b"), None)), None);
        assert!(p.available(), "a trust agent signs, so the gateway mints no key itself");
        let err = p
            .provision("agent-1")
            .await
            .expect_err("nowhere to mint");
        assert!(format!("{err}").contains("no trust agent context"), "names the missing piece: {err}");
    }
}
