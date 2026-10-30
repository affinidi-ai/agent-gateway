//! The declarations and warnings a surface save reports.
//!
//! Each resolved Surface Variant (the base route and every enabled variant) gets its
//! declaration outcome and a dry run of its policy stack against failed callers. The
//! report is computed against the stores as they are now, so the save response is a
//! snapshot and `GET /v1/surfaces/{id}/declarations` recomputes it on read.

use serde::Serialize;
use tracing::warn;

use crate::config::NetworkConfig;
use crate::config::agent_surface::{AgentSurface, SurfaceProtocol};
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::policies::failed_caller_dry_run::{
    CaseOutcome, FailedCallerCase, MAX_DRY_RUN_VIEWS, PolicyPlanes, ResolvedView, dry_run_failed_callers,
};
use crate::source_auth::declaration::{
    Declaration, DeclarationOutcome, UnservableDeclaration, UnservableReason, access_point_resource_url,
    refuses_failed_callers_by_default, resolve_surface_declaration,
};
use crate::source_auth::errors::SourceAuthFailureKind;

/// The declarations and warnings of every resolved Surface Variant.
#[derive(Serialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct SurfaceReport {
    pub declarations: Vec<DeclarationEntry>,
    pub warnings: Vec<SurfaceWarning>,
}

/// The declaration outcome of one Surface Variant.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DeclarationEntry {
    /// The variant alias, or `null` for the base route.
    pub variant: Option<String>,
    pub outcome: &'static str,
    /// The reason code when the outcome is `strip` or `unservable`.
    pub reason: Option<&'static str>,
    /// The declared resource; for any other outcome, the resource the route's
    /// `protected_resource` names if it names one, else the suggested Access
    /// Point URL, else `null`.
    pub resource: Option<String>,
    /// The issuer the metadata, challenge and card advertise. Empty unless declaring.
    pub authorization_servers: Vec<String>,
    /// The scopes a token must grant, which the challenge names. Empty unless declaring.
    pub required_scopes: Vec<String>,
    /// The `scopes_supported` of the metadata. Empty unless declaring.
    pub scopes_supported: Vec<String>,
    /// The protected resource metadata URL. `null` unless declaring.
    pub metadata_url: Option<String>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    FailOpenPolicy,
    FailOpenUndetermined,
    PaymentBeforePolicy,
    DryRunSkipped,
    FabricOnlyDeclaration,
    ProtectedResourceDropped,
    AuthorizationServersStale,
    CardSchemeUnavailable,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SurfaceWarning {
    pub code: WarningCode,
    pub message: String,
    /// The field of the resolved surface the warning is about.
    pub path: String,
    /// The variant alias, or `null` for the base route.
    pub variant: Option<String>,
}

impl SurfaceWarning {
    fn new(
        code: WarningCode,
        message: String,
        path: &str,
        alias: Option<&str>,
    ) -> Self {
        Self {
            code,
            message,
            path: path.to_string(),
            variant: alias.map(str::to_string),
        }
    }

    /// A stored `protected_resource` the save kept for the client, then dropped
    /// because the edited Access Point no longer supports it.
    pub fn protected_resource_dropped(alias: Option<&str>) -> Self {
        Self::new(
            WarningCode::ProtectedResourceDropped,
            "The stored protected_resource no longer fits the edited caller authentication, so it was removed and \
             no protected resource metadata is published. The JWT Bearer method checks audiences only if the edit \
             set them."
                .to_string(),
            PROTECTED_RESOURCE_PATH,
            alias,
        )
    }
}

/// The stores a report reads.
pub struct ReportStores<'a> {
    pub strategies: Option<&'a dyn JwtVerificationStrategyStorage>,
    pub network: &'a NetworkConfig,
    pub planes: PolicyPlanes,
}

const POLICY_PATH: &str = "access_point.inbound_policy";
const TARGET_POLICY_PATH: &str = "target.policy";
const FABRIC_SAFE_DENY: &str = "Deny input.source_auth.method == \"failed\" in target.policy, or in a gateway policy that \
                                does not depend on input.a2a, so that callers arriving over Fabric are denied too.";
const PROTECTED_RESOURCE_PATH: &str = "access_point.caller_authentication.protected_resource";
const AUTHORIZATION_SERVERS_PATH: &str = "access_point.caller_authentication.protected_resource.authorization_servers";
const STRATEGY_PATH: &str = "access_point.caller_authentication.methods[0].jwt_verification_strategy_id";

/// Compute the report for a surface record.
pub async fn surface_report(
    surface: &AgentSurface,
    stores: &ReportStores<'_>,
) -> SurfaceReport {
    let views = resolved_views(surface);
    let mut outcomes = Vec::with_capacity(views.len());
    for (alias, view) in &views {
        outcomes.push(declaration_outcome(view, alias.as_deref(), stores).await);
    }
    let dry_runs = dry_run_failed_callers(&views, &outcomes, &stores.planes).await;
    let mut report = SurfaceReport::default();
    for (((alias, view), outcome), cases) in views
        .into_iter()
        .zip(outcomes)
        .zip(dry_runs)
    {
        let alias_ref = alias.as_deref();
        report
            .warnings
            .extend(declaration_warnings(&view, &outcome, alias_ref, stores.network));
        if !refuses_failed_callers_by_default(&outcome) {
            report
                .warnings
                .extend(match &cases {
                    Some(cases) => dry_run_warnings(&view, cases, alias_ref),
                    None => vec![dry_run_skipped(alias_ref)],
                });
        }
        report
            .declarations
            .push(DeclarationEntry::new(&view, alias, &outcome, stores.network));
    }
    report
}

impl DeclarationEntry {
    /// The entry for one resolved Surface Variant's outcome.
    pub fn new(
        view: &AgentSurface,
        alias: Option<String>,
        outcome: &DeclarationOutcome,
        network: &NetworkConfig,
    ) -> Self {
        let declared = match outcome {
            DeclarationOutcome::Declare(declaration) => Some(declaration),
            _ => None,
        };
        Self {
            resource: match declared {
                Some(declaration) => Some(declaration.resource.clone()),
                None => view
                    .protected_resource()
                    .and_then(|configured| {
                        configured
                            .for_variant(alias.as_deref())
                            .ok()
                    })
                    .map(|served| served.resource)
                    .or_else(|| access_point_resource_url(view, alias.as_deref(), network)),
            },
            outcome: outcome.label(),
            reason: outcome.reason_code(),
            authorization_servers: declared
                .map(|declaration| {
                    declaration
                        .authorization_servers
                        .clone()
                })
                .unwrap_or_default(),
            required_scopes: declared
                .map(|declaration| {
                    declaration
                        .required_scopes
                        .clone()
                })
                .unwrap_or_default(),
            scopes_supported: declared
                .map(|declaration| {
                    declaration
                        .advertised_scopes
                        .clone()
                })
                .unwrap_or_default(),
            metadata_url: declared
                .and_then(|declaration| {
                    declaration
                        .metadata_url()
                        .ok()
                })
                .map(|url| url.to_string()),
            variant: alias,
        }
    }
}

/// The base route and every enabled variant, resolved. A view that does not
/// resolve is left out; save validation refuses such a record.
fn resolved_views(surface: &AgentSurface) -> Vec<ResolvedView> {
    let base = surface
        .resolve_variant(None)
        .ok()
        .map(|view| (None, view));
    let variants = surface
        .variants
        .iter()
        .filter(|variant| variant.enabled)
        .filter_map(|variant| {
            surface
                .resolve_variant(Some(&variant.alias))
                .ok()
                .map(|view| (Some(variant.alias.clone()), view))
        });
    base.into_iter()
        .chain(variants)
        .collect()
}

/// The outcome the request path resolves for the view. A strategy store
/// failure answers callers `503` there, so it reports as unservable.
async fn declaration_outcome(
    view: &AgentSurface,
    alias: Option<&str>,
    stores: &ReportStores<'_>,
) -> DeclarationOutcome {
    resolve_surface_declaration(view, alias, stores.strategies, stores.network)
        .await
        .unwrap_or_else(|error| {
            warn!(surface_id = %view.surface_id, error = %error, "Strategy lookup failed while reporting a surface declaration");
            DeclarationOutcome::Unservable(UnservableDeclaration::new(
                UnservableReason::StrategyStoreUnavailable,
                "the JWT verification strategy could not be read",
            ))
        })
}

/// Whether HTTP callers cannot reach the Access Point: its listen address names
/// no listener of this gateway, so the gateway mounts no route for it and only
/// Fabric reaches it.
fn reached_only_over_fabric(
    view: &AgentSurface,
    network: &NetworkConfig,
) -> bool {
    network
        .map_url_to_port(view.listen_address())
        .is_none()
}

fn declaration_warnings(
    view: &AgentSurface,
    outcome: &DeclarationOutcome,
    alias: Option<&str>,
    network: &NetworkConfig,
) -> Vec<SurfaceWarning> {
    let mut warnings = Vec::new();
    if let DeclarationOutcome::Declare(declaration) = outcome {
        warnings.extend(stale_authorization_servers(view, declaration, alias));
        if matches!(view.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2)
            && declaration.pin.is_none()
        {
            warnings.push(SurfaceWarning::new(
                WarningCode::CardSchemeUnavailable,
                "The agent card names no security scheme: the JWT verification strategy has no pinned authorization \
                 server matching its expected_issuer and key set. Run Discover on the strategy."
                    .to_string(),
                STRATEGY_PATH,
                alias,
            ));
        }
    }
    if matches!(outcome, DeclarationOutcome::Declare(_) | DeclarationOutcome::Unservable(_))
        && reached_only_over_fabric(view, network)
    {
        warnings.push(SurfaceWarning::new(
            WarningCode::FabricOnlyDeclaration,
            "The Access Point declares OAuth protection, but its listen address names no listener of this gateway, \
             so callers reach it only over Fabric. Over Fabric this gateway publishes no protected resource \
             metadata and refuses a failed caller without naming any, and it accepts only a credential the sending \
             gateway injects for this resource; only the sending gateway challenges its callers."
                .to_string(),
            "access_point.listen_address",
            alias,
        ));
    }
    warnings
}

/// A stored `authorization_servers` that no longer names the issuer the
/// strategy trusts, which the gateway advertises instead. Any later save of the
/// surface that keeps the stored list is refused, including one that does not
/// send it, until the list names that issuer or is removed.
fn stale_authorization_servers(
    view: &AgentSurface,
    declaration: &Declaration,
    alias: Option<&str>,
) -> Option<SurfaceWarning> {
    let stored = view
        .protected_resource()?
        .authorization_servers
        .as_ref()
        .filter(|stored| **stored != declaration.authorization_servers)?;
    let issuer = declaration
        .authorization_servers
        .first()
        .map_or("", String::as_str);
    Some(SurfaceWarning::new(
        WarningCode::AuthorizationServersStale,
        format!(
            "authorization_servers lists {stored:?} but the JWT verification strategy now trusts {issuer}; the \
             gateway advertises {issuer}. Send authorization_servers as [\"{issuer}\"] or omit it."
        ),
        AUTHORIZATION_SERVERS_PATH,
        alias,
    ))
}

fn takes_payment(view: &AgentSurface) -> bool {
    use crate::config::agent_surface::PaymentPolicy;
    match &view.target.payment_policy {
        Some(PaymentPolicy::X402(config)) => config.enabled,
        Some(PaymentPolicy::Mpp(config)) => config.enabled,
        None => false,
    }
}

fn kind_name(kind: SourceAuthFailureKind) -> &'static str {
    match kind {
        SourceAuthFailureKind::Missing => "missing",
        SourceAuthFailureKind::Invalid => "invalid",
        SourceAuthFailureKind::InsufficientScope => "insufficient_scope",
    }
}

fn describe(case: &FailedCallerCase) -> String {
    match case.method {
        Some(method) => format!("kind {} on {method}", kind_name(case.kind)),
        None => format!("kind {}", kind_name(case.kind)),
    }
}

fn dry_run_skipped(alias: Option<&str>) -> SurfaceWarning {
    SurfaceWarning::new(
        WarningCode::DryRunSkipped,
        format!(
            "The failed-caller dry run checks the first {MAX_DRY_RUN_VIEWS} routes with caller authentication, so \
             this variant was not checked"
        ),
        POLICY_PATH,
        alias,
    )
}

fn dry_run_warnings(
    view: &AgentSurface,
    cases: &[FailedCallerCase],
    alias: Option<&str>,
) -> Vec<SurfaceWarning> {
    let with = |outcome| -> Vec<&FailedCallerCase> {
        cases
            .iter()
            .filter(|case| case.outcome == outcome)
            .collect()
    };
    let mut warnings = Vec::new();
    let admitted = with(CaseOutcome::Admitted);
    let admitted_over_fabric = with(CaseOutcome::AdmittedOverFabric);
    if let Some(first) = admitted.first() {
        warnings.push(SurfaceWarning::new(
            WarningCode::FailOpenPolicy,
            format!(
                "No policy denies a caller whose authentication failed ({}; {} of {} checked cases). {FABRIC_SAFE_DENY}",
                describe(first),
                admitted.len(),
                cases.len()
            ),
            POLICY_PATH,
            alias,
        ));
    } else if let Some(first) = admitted_over_fabric.first() {
        warnings.push(SurfaceWarning::new(
            WarningCode::FailOpenPolicy,
            format!(
                "Only the inbound policy, or a gateway policy that reads input.a2a, denies a caller whose \
                 authentication failed ({}; {} of {} checked cases). A gateway receiving the call over Fabric runs \
                 neither, so it admits that caller. {FABRIC_SAFE_DENY}",
                describe(first),
                admitted_over_fabric.len(),
                cases.len()
            ),
            TARGET_POLICY_PATH,
            alias,
        ));
    }
    let undetermined = with(CaseOutcome::Undetermined);
    if let Some(first) = undetermined.first() {
        warnings.push(SurfaceWarning::new(
            WarningCode::FailOpenUndetermined,
            format!(
                "A policy is undefined or fails to evaluate for a caller whose authentication failed ({}; {} of {} \
                 checked cases), so it cannot be determined that such callers are denied",
                describe(first),
                undetermined.len(),
                cases.len()
            ),
            POLICY_PATH,
            alias,
        ));
    }
    if takes_payment(view)
        && cases
            .iter()
            .any(|case| case.outcome == CaseOutcome::DeniedBySurfacePolicy)
    {
        warnings.push(SurfaceWarning::new(
            WarningCode::PaymentBeforePolicy,
            "The surface takes payment before its surface policy runs, and only surface policy denies failed \
             callers, so a failed caller can be asked to pay before it is denied. Deny failed callers in a gateway \
             policy (package gateway.policy) to refuse them first."
                .to_string(),
            "target.payment_policy",
            alias,
        ));
    }
    warnings
}

#[cfg(test)]
pub(crate) mod tests {
    use async_trait::async_trait;
    use serde_json::{Value, json};

    use super::*;
    use crate::jwt_bearer::models::{AuthorizationServerMetadata, JwksSource, JwtVerificationStrategy};
    use crate::policies::global_policy::tests::{gw_def, store_with};
    use crate::policies::policy_definitions::PolicyType;

    const ORIGIN: &str = "https://gw.example";
    const ISSUER: &str = "https://as.example/";
    const JWKS: &str = "https://as.example/jwks.json";
    const DENY_FAILED: &str =
        "package surface.policy\ndefault allow := true\nallow := false if input.source_auth.method == \"failed\"\n";

    /// A read-only strategy store holding one strategy.
    pub(crate) struct OneStrategy(pub(crate) JwtVerificationStrategy);

    #[async_trait]
    impl JwtVerificationStrategyStorage for OneStrategy {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("read-only")
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            Ok((self.0.id == id).then(|| self.0.clone()))
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            Ok(vec![self.0.clone()])
        }
        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("read-only")
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("read-only")
        }
    }

    struct BrokenStore;

    #[async_trait]
    impl JwtVerificationStrategyStorage for BrokenStore {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("unavailable")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            anyhow::bail!("unavailable")
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            anyhow::bail!("unavailable")
        }
        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("unavailable")
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("unavailable")
        }
    }

    fn strategy(pinned: bool) -> OneStrategy {
        OneStrategy(JwtVerificationStrategy {
            id: "strategy-1".into(),
            name: "as".into(),
            expected_issuer: ISSUER.into(),
            jwks_source: JwksSource::Remote { jwks_uri: JWKS.into() },
            authorization_server: pinned.then(|| AuthorizationServerMetadata {
                issuer: ISSUER.into(),
                metadata_url: "https://as.example/.well-known/oauth-authorization-server".into(),
                token_endpoint: "https://as.example/oauth2/token".into(),
                jwks_uri: JWKS.into(),
            }),
            ..Default::default()
        })
    }

    fn network() -> NetworkConfig {
        serde_json::from_value(json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "fallback.example", "external_origin": "https://fallback.example" },
            "integration": { "types": [], "categories": [] },
            "listeners": [{
                "id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443,
                "protocol": "https", "external_urls": [ORIGIN], "listener_type": "inbound"
            }],
            "routes": {},
        }))
        .expect("network config")
    }

    fn jwt_method(audiences: &[&str]) -> Value {
        json!({
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "strategy-1",
            "audiences": audiences,
            "required_scopes": ["agent.invoke"],
        })
    }

    /// An A2A surface whose `target.policy`, which both the direct path and Fabric
    /// receive run, is `policy`.
    fn surface(
        methods: Vec<Value>,
        policy: Option<&str>,
        variants: Value,
    ) -> AgentSurface {
        let mut access_point = json!({"listen_address": ORIGIN, "route": "/agent", "protocol": "a2a"});
        if !methods.is_empty() {
            access_point["caller_authentication"] = json!({"methods": methods});
        }
        let mut target = json!({"endpoint": "https://agent.internal"});
        if let Some(id) = policy {
            target["policy"] = json!({"policy_definition_id": id});
        }
        serde_json::from_value(json!({
            "surface_id": "surface-1", "name": "agent",
            "access_point": access_point,
            "target": target,
            "variants": variants,
        }))
        .expect("surface")
    }

    /// `view` with a `protected_resource` naming its Access Point URL.
    fn declares(mut view: AgentSurface) -> AgentSurface {
        view.access_point
            .caller_authentication
            .as_mut()
            .expect("caller authentication")
            .protected_resource =
            Some(serde_json::from_value(json!({"resource": format!("{ORIGIN}/agent")})).expect("protected resource"));
        view
    }

    /// A JWT Bearer Access Point with `required_scopes` and no `protected_resource`.
    fn undeclared(policy: Option<&str>) -> AgentSurface {
        surface(vec![jwt_method(&[])], policy, json!([]))
    }

    fn declaring(policy: Option<&str>) -> AgentSurface {
        declares(undeclared(policy))
    }

    fn variant(
        alias: &str,
        enabled: bool,
        overrides: Value,
    ) -> Value {
        json!({"id": format!("v-{alias}"), "alias": alias, "name": alias, "description": "", "enabled": enabled,
            "overrides": overrides})
    }

    async fn report_with(
        surface: &AgentSurface,
        strategies: &dyn JwtVerificationStrategyStorage,
    ) -> SurfaceReport {
        let mut deny = gw_def("deny", DENY_FAILED);
        deny.policy_type = PolicyType::AgentSurface;
        let definitions = store_with(vec![deny]).await;
        let network = network();
        let stores = ReportStores {
            strategies: Some(strategies),
            network: &network,
            planes: PolicyPlanes {
                definitions: Some(definitions),
                ..Default::default()
            },
        };
        surface_report(surface, &stores).await
    }

    async fn report(
        surface: &AgentSurface,
        strategy: &OneStrategy,
    ) -> SurfaceReport {
        report_with(surface, strategy).await
    }

    fn codes(report: &SurfaceReport) -> Vec<(WarningCode, Option<&str>)> {
        report
            .warnings
            .iter()
            .map(|warning| (warning.code, warning.variant.as_deref()))
            .collect()
    }

    /// The entry of an outcome other than `declare`, which carries no advertised values.
    fn entry(
        variant: Option<&str>,
        outcome: &'static str,
        reason: Option<&'static str>,
        resource: Option<String>,
    ) -> DeclarationEntry {
        DeclarationEntry {
            variant: variant.map(str::to_string),
            outcome,
            reason,
            resource,
            authorization_servers: Vec::new(),
            required_scopes: Vec::new(),
            scopes_supported: Vec::new(),
            metadata_url: None,
        }
    }

    fn declared_entry(
        variant: Option<&str>,
        route: &str,
    ) -> DeclarationEntry {
        DeclarationEntry {
            variant: variant.map(str::to_string),
            outcome: "declare",
            reason: None,
            resource: Some(format!("{ORIGIN}{route}")),
            authorization_servers: vec![ISSUER.to_string()],
            required_scopes: vec!["agent.invoke".to_string()],
            scopes_supported: vec!["agent.invoke".to_string()],
            metadata_url: Some(format!("{ORIGIN}/.well-known/oauth-protected-resource{route}")),
        }
    }

    #[tokio::test]
    async fn test_report_declares_per_variant_and_reports_no_fail_open_on_declaring_views() {
        let surface = declares(surface(
            vec![jwt_method(&[])],
            None,
            json!([
                variant("beta", true, json!({"access_point": {"inbound_policy": {"policy_definition_id": "deny"}}})),
                variant("off", false, json!({})),
            ]),
        ));
        let saved = report(&surface, &strategy(true)).await;

        assert_eq!(
            saved.declarations,
            vec![declared_entry(None, "/agent"), declared_entry(Some("beta"), "/agent$beta")]
        );
        assert!(
            saved.warnings.is_empty(),
            "a declaring view refuses failed callers before policy, so no policy can let one through: {:?}",
            saved.warnings
        );
    }

    #[tokio::test]
    async fn test_report_warns_where_failed_callers_get_through_a_view_that_does_not_declare() {
        let saved = report(&undeclared(None), &strategy(true)).await;

        assert_eq!(saved.declarations[0].outcome, "strip");
        assert_eq!(saved.declarations[0].reason, Some("not_declared"));
        assert_eq!(codes(&saved), vec![(WarningCode::FailOpenPolicy, None)]);
        let fail_open = &saved.warnings[0];
        assert_eq!(fail_open.path, "access_point.inbound_policy");
        assert!(
            fail_open
                .message
                .contains("kind missing on message/send"),
            "{}",
            fail_open.message
        );
        assert!(
            fail_open
                .message
                .contains("in target.policy, or in a gateway policy that does not depend on input.a2a"),
            "the advice names a deny Fabric receive also runs: {}",
            fail_open.message
        );
        assert!(
            fail_open
                .message
                .contains("36 of 36"),
            "{}",
            fail_open.message
        );
    }

    #[tokio::test]
    async fn test_report_warns_when_only_the_inbound_policy_denies_failed_callers() {
        let mut inbound_only = undeclared(None);
        inbound_only
            .access_point
            .inbound_policy = Some(serde_json::from_value(json!({"policy_definition_id": "deny"})).expect("policy"));
        let saved = report(&inbound_only, &strategy(true)).await;

        assert_eq!(codes(&saved), vec![(WarningCode::FailOpenPolicy, None)]);
        let fabric = &saved.warnings[0];
        assert_eq!(fabric.path, "target.policy");
        assert!(
            fabric
                .message
                .contains("over Fabric"),
            "{}",
            fabric.message
        );
        assert!(
            fabric
                .message
                .contains("kind missing on message/send; 36 of 36"),
            "{}",
            fabric.message
        );

        let declared = report(&declares(inbound_only), &strategy(true)).await;
        assert_eq!(declared.declarations[0].outcome, "declare");
        assert!(
            declared.warnings.is_empty(),
            "a declaring view refuses failed callers before policy on both paths: {:?}",
            declared.warnings
        );

        let covered = report(&undeclared(Some("deny")), &strategy(true)).await;
        assert!(
            covered.warnings.is_empty(),
            "target.policy denies failed callers on the direct path and over Fabric: {:?}",
            covered.warnings
        );
    }

    #[tokio::test]
    async fn test_report_names_the_strip_reason_for_a_jwt_bearer_access_point() {
        let not_declared = report(&undeclared(Some("deny")), &strategy(true)).await;
        assert_eq!(
            not_declared.declarations,
            vec![entry(None, "strip", Some("not_declared"), Some(format!("{ORIGIN}/agent")))],
            "the resource is the suggested Access Point URL"
        );
        assert!(
            not_declared
                .warnings
                .is_empty(),
            "{:?}",
            not_declared.warnings
        );

        let unread = report_with(&undeclared(Some("deny")), &BrokenStore).await;
        assert_eq!(
            unread.declarations, not_declared.declarations,
            "an Access Point without protected_resource never reads the strategy store"
        );

        let open = report(&undeclared(None), &strategy(true)).await;
        assert_eq!(codes(&open), vec![(WarningCode::FailOpenPolicy, None)], "nothing beyond fail_open_policy");
    }

    #[tokio::test]
    async fn test_report_names_a_forwarding_method_unservable_with_protected_resource_and_not_declared_without() {
        let mut method = jwt_method(&[]);
        method["forward_header"] = json!(true);
        let forwarding = surface(vec![method], Some("deny"), json!([]));

        let without = report(&forwarding, &strategy(true)).await;
        assert_eq!(
            without.declarations,
            vec![entry(None, "strip", Some("not_declared"), Some(format!("{ORIGIN}/agent")))]
        );
        assert!(without.warnings.is_empty(), "{:?}", without.warnings);

        let with = report(&declares(forwarding), &strategy(true)).await;
        assert_eq!(
            with.declarations,
            vec![entry(
                None,
                "unservable",
                Some("incompatible_caller_authentication"),
                Some(format!("{ORIGIN}/agent"))
            )],
            "the resource is the one protected_resource names"
        );
    }

    #[tokio::test]
    async fn test_report_has_no_declaration_warning_for_other_methods_or_no_authentication() {
        let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "X-Key"},
            "secret_id": "KEYS"});
        let other = report(&surface(vec![api_key], Some("deny"), json!([])), &strategy(true)).await;
        assert_eq!(other.declarations[0].outcome, "strip");
        assert_eq!(other.declarations[0].reason, Some("not_declared"));
        assert!(other.warnings.is_empty(), "{:?}", other.warnings);

        let open = report(&surface(vec![], None, json!([])), &strategy(true)).await;
        assert_eq!(open.declarations[0].outcome, "pass_through");
        assert_eq!(open.declarations[0].reason, None);
        assert!(open.warnings.is_empty(), "{:?}", open.warnings);
    }

    #[tokio::test]
    async fn test_report_warns_when_only_surface_policy_stands_between_a_failed_caller_and_payment() {
        let enabled = |on: bool| -> Option<crate::config::agent_surface::PaymentPolicy> {
            Some(serde_json::from_value(json!({"type": "x402", "enabled": on})).expect("payment policy"))
        };
        let mut paid = undeclared(Some("deny"));
        paid.target.payment_policy = enabled(true);

        let taken = report(&paid, &strategy(true)).await;
        assert_eq!(codes(&taken), vec![(WarningCode::PaymentBeforePolicy, None)]);
        assert_eq!(taken.warnings[0].path, "target.payment_policy");

        let declared = report(&declares(paid.clone()), &strategy(true)).await;
        assert!(declared.warnings.is_empty(), "a declaring view refuses before payment: {:?}", declared.warnings);

        paid.target.payment_policy = enabled(false);
        let disabled = report(&paid, &strategy(true)).await;
        assert!(disabled.warnings.is_empty(), "{:?}", disabled.warnings);
    }

    #[tokio::test]
    async fn test_report_warns_when_the_policy_cannot_be_evaluated() {
        let missing_policy = undeclared(Some("missing"));
        let undetermined = report(&missing_policy, &strategy(true)).await;
        assert_eq!(codes(&undetermined), vec![(WarningCode::FailOpenUndetermined, None)]);

        let declared = report(&declares(missing_policy), &strategy(true)).await;
        assert!(declared.warnings.is_empty(), "{:?}", declared.warnings);
    }

    #[tokio::test]
    async fn test_report_warns_for_a_variant_past_the_dry_run_limit() {
        let variants = (0..MAX_DRY_RUN_VIEWS)
            .map(|index| variant(&format!("v{index}"), true, json!({})))
            .collect();
        let surface = surface(vec![jwt_method(&[])], Some("deny"), Value::Array(variants));

        let saved = report(&surface, &strategy(true)).await;

        assert_eq!(saved.declarations.len(), MAX_DRY_RUN_VIEWS + 1, "every variant is still reported");
        let skipped: Vec<&SurfaceWarning> = saved
            .warnings
            .iter()
            .filter(|warning| warning.code == WarningCode::DryRunSkipped)
            .collect();
        let last = format!("v{}", MAX_DRY_RUN_VIEWS - 1);
        assert_eq!(
            skipped
                .iter()
                .map(|warning| warning.variant.as_deref())
                .collect::<Vec<_>>(),
            vec![Some(last.as_str())],
            "the base route and the first variants fill the limit"
        );
        assert_eq!(skipped[0].path, "access_point.inbound_policy");
        assert_eq!(serde_json::to_value(skipped[0].code).expect("json"), json!("dry_run_skipped"));
        assert!(
            !saved
                .warnings
                .iter()
                .any(|warning| matches!(warning.code, WarningCode::FailOpenPolicy | WarningCode::FailOpenUndetermined)),
            "{:?}",
            saved.warnings
        );
    }

    #[tokio::test]
    async fn test_report_warns_when_a_declaring_access_point_is_reached_only_over_fabric() {
        let mut unmounted = declaring(Some("deny"));
        unmounted
            .access_point
            .listen_address = "0.0.0.0:8443".into();
        let fabric_only = report(&unmounted, &strategy(true)).await;

        assert_eq!(
            fabric_only.declarations,
            vec![declared_entry(None, "/agent")],
            "the bind address names the listener"
        );
        assert_eq!(codes(&fabric_only), vec![(WarningCode::FabricOnlyDeclaration, None)]);
        assert_eq!(fabric_only.warnings[0].path, "access_point.listen_address");

        let mounted = report(&declaring(Some("deny")), &strategy(true)).await;
        assert!(mounted.warnings.is_empty(), "{:?}", mounted.warnings);

        let mut not_declaring = undeclared(Some("deny"));
        not_declaring
            .access_point
            .listen_address = "0.0.0.0:8443".into();
        let not_declaring = report(&not_declaring, &strategy(true)).await;
        assert_eq!(not_declaring.declarations[0].reason, Some("not_declared"));
        assert!(
            not_declaring
                .warnings
                .is_empty(),
            "{:?}",
            not_declaring.warnings
        );
    }

    #[tokio::test]
    async fn test_report_counts_an_unreadable_strategy_store_as_unservable() {
        let unreadable = report_with(&declaring(Some("deny")), &BrokenStore).await;
        assert_eq!(
            unreadable.declarations,
            vec![entry(None, "unservable", Some("strategy_store_unavailable"), Some(format!("{ORIGIN}/agent")))]
        );
    }

    /// An Access Point at `route` whose one method is `method` and whose
    /// `protected_resource` is `protected`.
    fn explicit(
        protocol: &str,
        route: &str,
        method: Value,
        protected: Value,
        variants: Value,
    ) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "surface-1", "name": "agent",
            "access_point": {"listen_address": ORIGIN, "route": route, "protocol": protocol,
                "caller_authentication": {"methods": [method], "protected_resource": protected}},
            "target": {"endpoint": "https://agent.internal"},
            "variants": variants,
        }))
        .expect("surface")
    }

    #[tokio::test]
    async fn test_report_names_why_an_explicit_protected_resource_is_unservable() {
        let resource = json!({"resource": format!("{ORIGIN}/agent")});
        let on = |protocol: &str| explicit(protocol, "/agent", jwt_method(&[]), resource.clone(), json!([]));
        let mut elsewhere = strategy(true);
        elsewhere.0.id = "strategy-2".into();
        let mut did_issuer = strategy(false);
        did_issuer.0.expected_issuer = "did:web:as.example".into();
        for (case, view, store, expected) in [
            ("mcp declares", on("mcp"), strategy(true), ("declare", None)),
            ("a2a declares", on("a2a"), strategy(true), ("declare", None)),
            (
                "the strategy's issuer is listed",
                explicit(
                    "mcp",
                    "/agent",
                    jwt_method(&[]),
                    json!({"resource": format!("{ORIGIN}/agent"), "authorization_servers": [ISSUER]}),
                    json!([]),
                ),
                strategy(true),
                ("declare", None),
            ),
            ("didcomm", on("didcomm"), strategy(true), ("unservable", Some("unsupported_protocol"))),
            (
                "no authorization server",
                explicit(
                    "mcp",
                    "/agent",
                    jwt_method(&[]),
                    json!({"resource": format!("{ORIGIN}/agent"), "authorization_servers": []}),
                    json!([]),
                ),
                strategy(true),
                ("unservable", Some("invalid_protected_resource")),
            ),
            (
                "audiences listed",
                explicit("mcp", "/agent", jwt_method(&[&format!("{ORIGIN}/agent")]), resource.clone(), json!([])),
                strategy(true),
                ("unservable", Some("incompatible_caller_authentication")),
            ),
            (
                "another origin",
                explicit(
                    "mcp",
                    "/agent",
                    jwt_method(&[]),
                    json!({"resource": "https://other.example/agent"}),
                    json!([]),
                ),
                strategy(true),
                ("unservable", Some("resource_mismatch")),
            ),
            ("strategy missing", on("a2a"), elsewhere, ("unservable", Some("strategy_unavailable"))),
            ("did issuer", on("mcp"), did_issuer, ("unservable", Some("issuer_not_advertisable"))),
        ] {
            let reported = report(&view, &store).await;
            assert_eq!((reported.declarations[0].outcome, reported.declarations[0].reason), expected, "{case}");
        }

        let root = explicit(
            "mcp",
            "/",
            jwt_method(&[]),
            json!({"resource": format!("{ORIGIN}/")}),
            json!([variant("beta", true, json!({}))]),
        );
        let reported = report(&root, &strategy(true)).await;
        let outcomes: Vec<_> = reported
            .declarations
            .iter()
            .map(|entry| (entry.variant.as_deref(), entry.outcome, entry.reason))
            .collect();
        assert_eq!(
            outcomes,
            vec![(None, "declare", None), (Some("beta"), "unservable", Some("root_variant_resource"))]
        );
    }

    #[tokio::test]
    async fn test_report_warns_when_a_declaring_a2a_card_has_no_pinned_server() {
        for protocol in ["a2a", "ap2"] {
            let card = explicit(
                protocol,
                "/agent",
                jwt_method(&[]),
                json!({"resource": format!("{ORIGIN}/agent")}),
                json!([]),
            );

            let unpinned = report(&card, &strategy(false)).await;
            assert_eq!(unpinned.declarations, vec![declared_entry(None, "/agent")], "{protocol}");
            assert_eq!(codes(&unpinned), vec![(WarningCode::CardSchemeUnavailable, None)], "{protocol}");
            assert_eq!(
                unpinned.warnings[0].path,
                "access_point.caller_authentication.methods[0].jwt_verification_strategy_id"
            );
            assert_eq!(
                unpinned.warnings[0].message,
                "The agent card names no security scheme: the JWT verification strategy has no pinned authorization \
                 server matching its expected_issuer and key set. Run Discover on the strategy."
            );

            let mut mismatched = strategy(true);
            if let Some(pin) = mismatched
                .0
                .authorization_server
                .as_mut()
            {
                pin.issuer = "https://other-as.example/".into();
            }
            let mismatched = report(&card, &mismatched).await;
            assert_eq!(
                codes(&mismatched),
                vec![(WarningCode::CardSchemeUnavailable, None)],
                "{protocol}: a pin for another issuer is no pin"
            );

            let pinned = report(&card, &strategy(true)).await;
            assert!(pinned.warnings.is_empty(), "{protocol}: {:?}", pinned.warnings);
        }

        let mcp = explicit("mcp", "/agent", jwt_method(&[]), json!({"resource": format!("{ORIGIN}/agent")}), json!([]));
        let unpinned = report(&mcp, &strategy(false)).await;
        assert_eq!(unpinned.declarations[0].outcome, "declare");
        assert!(unpinned.warnings.is_empty(), "an MCP Access Point has no agent card: {:?}", unpinned.warnings);
    }

    #[tokio::test]
    async fn test_report_warns_when_stored_authorization_servers_differ_from_the_strategy_issuer() {
        let listing = |servers: Value| {
            explicit(
                "mcp",
                "/agent",
                jwt_method(&[]),
                json!({"resource": format!("{ORIGIN}/agent"), "authorization_servers": servers}),
                json!([]),
            )
        };

        let stale = report(&listing(json!(["https://old.example/"])), &strategy(true)).await;
        assert_eq!(stale.declarations, vec![declared_entry(None, "/agent")], "the stored list is never advertised");
        assert_eq!(codes(&stale), vec![(WarningCode::AuthorizationServersStale, None)]);
        assert_eq!(
            stale.warnings[0].path,
            "access_point.caller_authentication.protected_resource.authorization_servers"
        );
        assert_eq!(
            stale.warnings[0].message,
            "authorization_servers lists [\"https://old.example/\"] but the JWT verification strategy now trusts \
             https://as.example/; the gateway advertises https://as.example/. Send authorization_servers as \
             [\"https://as.example/\"] or omit it."
        );

        let current = report(&listing(json!([ISSUER])), &strategy(true)).await;
        assert!(current.warnings.is_empty(), "{:?}", current.warnings);

        let omitted = report(&declaring(Some("deny")), &strategy(true)).await;
        assert!(omitted.warnings.is_empty(), "{:?}", omitted.warnings);
    }

    #[test]
    fn test_dropped_protected_resource_warning_names_the_setting_and_variant() {
        let dropped = SurfaceWarning::protected_resource_dropped(Some("beta"));
        assert_eq!(dropped.code, WarningCode::ProtectedResourceDropped);
        assert_eq!(dropped.path, "access_point.caller_authentication.protected_resource");
        assert_eq!(dropped.variant.as_deref(), Some("beta"));
        assert_eq!(SurfaceWarning::protected_resource_dropped(None).variant, None);
    }

    #[test]
    fn test_report_serializes_with_the_documented_field_names() {
        let report = SurfaceReport {
            declarations: vec![
                declared_entry(None, "/agent"),
                entry(Some("beta"), "strip", Some("not_declared"), None),
            ],
            warnings: vec![SurfaceWarning {
                code: WarningCode::FailOpenUndetermined,
                message: "m".into(),
                path: "p".into(),
                variant: Some("beta".into()),
            }],
        };
        assert_eq!(
            serde_json::to_value(&report).expect("json"),
            json!({
                "declarations": [
                    {"variant": null, "outcome": "declare", "reason": null, "resource": format!("{ORIGIN}/agent"),
                     "authorization_servers": [ISSUER], "required_scopes": ["agent.invoke"],
                     "scopes_supported": ["agent.invoke"],
                     "metadata_url": format!("{ORIGIN}/.well-known/oauth-protected-resource/agent")},
                    {"variant": "beta", "outcome": "strip", "reason": "not_declared", "resource": null,
                     "authorization_servers": [], "required_scopes": [], "scopes_supported": [], "metadata_url": null},
                ],
                "warnings": [{"code": "fail_open_undetermined", "message": "m", "path": "p", "variant": "beta"}],
            })
        );

        let every = [
            WarningCode::FailOpenPolicy,
            WarningCode::FailOpenUndetermined,
            WarningCode::PaymentBeforePolicy,
            WarningCode::DryRunSkipped,
            WarningCode::FabricOnlyDeclaration,
            WarningCode::ProtectedResourceDropped,
            WarningCode::AuthorizationServersStale,
            WarningCode::CardSchemeUnavailable,
        ];
        for code in every {
            match code {
                WarningCode::FailOpenPolicy
                | WarningCode::FailOpenUndetermined
                | WarningCode::PaymentBeforePolicy
                | WarningCode::DryRunSkipped
                | WarningCode::FabricOnlyDeclaration
                | WarningCode::ProtectedResourceDropped
                | WarningCode::AuthorizationServersStale
                | WarningCode::CardSchemeUnavailable => {}
            }
        }
        let names = serde_json::to_value(every).expect("json");
        assert_eq!(
            names,
            json!([
                "fail_open_policy",
                "fail_open_undetermined",
                "payment_before_policy",
                "dry_run_skipped",
                "fabric_only_declaration",
                "protected_resource_dropped",
                "authorization_servers_stale",
                "card_scheme_unavailable",
            ]),
            "the match above lists every code, so a removed code such as declaration_stripped or \
             additional_audiences cannot be serialized"
        );
    }
}
