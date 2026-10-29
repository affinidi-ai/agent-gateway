//! The declarations and warnings a surface save reports.
//!
//! Each resolved Surface Variant (the base route and every enabled variant) gets its
//! declaration outcome and a dry run of its policy stack against failed callers. The
//! report is computed against the stores as they are now, so the save response is a
//! snapshot and `GET /v1/surfaces/{id}/declarations` recomputes it on read.

use serde::Serialize;
use tracing::warn;

use crate::config::NetworkConfig;
use crate::config::agent_surface::AgentSurface;
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::jwt_bearer::models::JwtBearerAuthConfig;
use crate::policies::failed_caller_dry_run::{
    CaseOutcome, FailedCallerCase, MAX_DRY_RUN_VIEWS, PolicyPlanes, ResolvedView, dry_run_failed_callers,
};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::declaration::{
    DeclarationOutcome, UnservableDeclaration, UnservableReason, access_point_resource_url,
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
    /// The Access Point URL, when the Access Point has one.
    pub resource: Option<String>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    FailOpenPolicy,
    FailOpenUndetermined,
    PaymentBeforePolicy,
    DeclarationStripped,
    AdditionalAudiences,
    DryRunSkipped,
    FabricOnlyDeclaration,
    ProtectedResourceDropped,
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
const CALLER_AUTHENTICATION_PATH: &str = "access_point.caller_authentication";
const PROTECTED_RESOURCE_PATH: &str = "access_point.caller_authentication.protected_resource";

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
        Self {
            resource: match outcome {
                DeclarationOutcome::Declare(declaration) => Some(declaration.resource.clone()),
                _ => access_point_resource_url(view, alias.as_deref(), network),
            },
            outcome: outcome.label(),
            reason: outcome.reason_code(),
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

fn jwt_bearer_methods(view: &AgentSurface) -> impl Iterator<Item = &JwtBearerAuthConfig> {
    view.access_point
        .caller_authentication
        .iter()
        .flat_map(|authentication| authentication.methods.iter())
        .filter_map(|method| match method {
            SourceAuthConfig::JwtBearer(config) => Some(config),
            _ => None,
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
    match outcome {
        DeclarationOutcome::Strip(reason)
            if jwt_bearer_methods(view)
                .next()
                .is_some() =>
        {
            warnings.push(SurfaceWarning::new(
                WarningCode::DeclarationStripped,
                format!(
                    "The Access Point does not declare its OAuth protection on the agent card or in protected \
                     resource metadata: {}",
                    reason.code()
                ),
                CALLER_AUTHENTICATION_PATH,
                alias,
            ));
        }
        DeclarationOutcome::Declare(declaration) => {
            let extra = jwt_bearer_methods(view)
                .flat_map(|config| config.audiences.iter())
                .filter(|audience| **audience != declaration.resource)
                .count();
            if extra > 0 {
                warnings.push(SurfaceWarning::new(
                    WarningCode::AdditionalAudiences,
                    format!(
                        "audiences lists {extra} value(s) besides the Access Point URL. This route declares, so a \
                         caller's token must name the Access Point URL as its audience and the other values are \
                         ignored here"
                    ),
                    "access_point.caller_authentication.methods[0].audiences",
                    alias,
                ));
            }
        }
        DeclarationOutcome::Strip(_) | DeclarationOutcome::PassThrough | DeclarationOutcome::Unservable(_) => {}
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
mod tests {
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

    struct OneStrategy(JwtVerificationStrategy);

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

    /// A surface whose `target.policy`, which both the direct path and Fabric receive
    /// run, is `policy`.
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

    fn declaring(policy: Option<&str>) -> AgentSurface {
        surface(vec![jwt_method(&[&format!("{ORIGIN}/agent")])], policy, json!([]))
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

    #[tokio::test]
    async fn test_report_declares_per_variant_and_reports_no_fail_open_on_declaring_views() {
        let surface = surface(
            vec![jwt_method(&[&format!("{ORIGIN}/agent"), &format!("{ORIGIN}/agent$beta")])],
            None,
            json!([
                variant("beta", true, json!({"access_point": {"inbound_policy": {"policy_definition_id": "deny"}}})),
                variant("off", false, json!({})),
            ]),
        );
        let saved = report(&surface, &strategy(true)).await;

        assert_eq!(
            saved.declarations,
            vec![
                DeclarationEntry {
                    variant: None,
                    outcome: "declare",
                    reason: None,
                    resource: Some(format!("{ORIGIN}/agent")),
                },
                DeclarationEntry {
                    variant: Some("beta".into()),
                    outcome: "declare",
                    reason: None,
                    resource: Some(format!("{ORIGIN}/agent$beta")),
                },
            ]
        );
        assert_eq!(
            codes(&saved),
            vec![(WarningCode::AdditionalAudiences, None), (WarningCode::AdditionalAudiences, Some("beta"))],
            "a declaring view refuses failed callers before policy, so no policy can let one through"
        );
        let audiences = &saved.warnings[0];
        assert_eq!(audiences.path, "access_point.caller_authentication.methods[0].audiences");
        assert!(
            audiences
                .message
                .starts_with("audiences lists 1 value(s)"),
            "{}",
            audiences.message
        );
        assert!(
            audiences
                .message
                .contains("ignored"),
            "{}",
            audiences.message
        );
        assert!(
            !audiences
                .message
                .contains("also accepted"),
            "{}",
            audiences.message
        );
    }

    #[tokio::test]
    async fn test_report_warns_where_failed_callers_get_through_a_view_that_does_not_declare() {
        let open = declaring(None);
        let saved = report(&open, &strategy(false)).await;

        assert_eq!(saved.declarations[0].outcome, "strip");
        assert_eq!(codes(&saved), vec![(WarningCode::DeclarationStripped, None), (WarningCode::FailOpenPolicy, None)]);
        let fail_open = &saved.warnings[1];
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
        let mut inbound_only = declaring(None);
        inbound_only
            .access_point
            .inbound_policy = Some(serde_json::from_value(json!({"policy_definition_id": "deny"})).expect("policy"));
        let saved = report(&inbound_only, &strategy(false)).await;

        assert_eq!(codes(&saved), vec![(WarningCode::DeclarationStripped, None), (WarningCode::FailOpenPolicy, None)]);
        let fabric = &saved.warnings[1];
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

        let declared = report(&inbound_only, &strategy(true)).await;
        assert!(
            declared
                .warnings
                .iter()
                .all(|warning| warning.code != WarningCode::FailOpenPolicy),
            "a declaring view refuses failed callers before policy on both paths: {:?}",
            declared.warnings
        );

        let covered = report(&declaring(Some("deny")), &strategy(false)).await;
        assert_eq!(
            codes(&covered),
            vec![(WarningCode::DeclarationStripped, None)],
            "target.policy denies failed callers on the direct path and over Fabric"
        );
    }

    #[tokio::test]
    async fn test_report_names_the_strip_reason_for_a_jwt_bearer_access_point() {
        let stripped = report(&declaring(Some("deny")), &strategy(false)).await;
        assert_eq!(
            stripped.declarations,
            vec![DeclarationEntry {
                variant: None,
                outcome: "strip",
                reason: Some("not_pinned"),
                resource: Some(format!("{ORIGIN}/agent")),
            }]
        );
        assert_eq!(codes(&stripped), vec![(WarningCode::DeclarationStripped, None)]);
        assert_eq!(stripped.warnings[0].path, "access_point.caller_authentication");
        assert!(
            stripped.warnings[0]
                .message
                .ends_with("not_pinned"),
            "{}",
            stripped.warnings[0].message
        );
    }

    #[tokio::test]
    async fn test_report_names_forwards_caller_token_when_the_method_forwards_the_token() {
        let mut method = jwt_method(&[&format!("{ORIGIN}/agent")]);
        method["forward_header"] = json!(true);
        let forwarding = report(&surface(vec![method], Some("deny"), json!([])), &strategy(true)).await;

        assert_eq!(forwarding.declarations[0].outcome, "strip");
        assert_eq!(forwarding.declarations[0].reason, Some("forwards_caller_token"));
        assert_eq!(codes(&forwarding), vec![(WarningCode::DeclarationStripped, None)]);
        assert!(
            forwarding.warnings[0]
                .message
                .ends_with("forwards_caller_token"),
            "{}",
            forwarding.warnings[0].message
        );
    }

    #[tokio::test]
    async fn test_report_has_no_declaration_warning_for_other_methods_or_no_authentication() {
        let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "X-Key"},
            "secret_id": "KEYS"});
        let other = report(&surface(vec![api_key], Some("deny"), json!([])), &strategy(true)).await;
        assert_eq!(other.declarations[0].reason, Some("method_not_declarable"));
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
        let mut paid = declaring(Some("deny"));
        paid.target.payment_policy = enabled(true);

        let taken = report(&paid, &strategy(false)).await;
        assert_eq!(
            codes(&taken),
            vec![(WarningCode::DeclarationStripped, None), (WarningCode::PaymentBeforePolicy, None)]
        );
        assert_eq!(taken.warnings[1].path, "target.payment_policy");

        let declared = report(&paid, &strategy(true)).await;
        assert!(declared.warnings.is_empty(), "a declaring view refuses before payment: {:?}", declared.warnings);

        paid.target.payment_policy = enabled(false);
        let disabled = report(&paid, &strategy(false)).await;
        assert_eq!(codes(&disabled), vec![(WarningCode::DeclarationStripped, None)]);
    }

    #[tokio::test]
    async fn test_report_warns_when_the_policy_cannot_be_evaluated() {
        let missing_policy = declaring(Some("missing"));
        let undetermined = report(&missing_policy, &strategy(false)).await;
        assert_eq!(
            codes(&undetermined),
            vec![(WarningCode::DeclarationStripped, None), (WarningCode::FailOpenUndetermined, None)]
        );

        let declared = report(&missing_policy, &strategy(true)).await;
        assert!(declared.warnings.is_empty(), "{:?}", declared.warnings);
    }

    #[tokio::test]
    async fn test_report_warns_for_a_variant_past_the_dry_run_limit() {
        let variants = (0..MAX_DRY_RUN_VIEWS)
            .map(|index| variant(&format!("v{index}"), true, json!({})))
            .collect();
        let surface = surface(vec![jwt_method(&[])], Some("deny"), Value::Array(variants));

        let saved = report(&surface, &strategy(true)).await;

        assert_eq!(saved.declarations.len(), MAX_DRY_RUN_VIEWS + 1, "every variant is still declared");
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

        assert_eq!(fabric_only.declarations[0].outcome, "declare");
        assert_eq!(codes(&fabric_only), vec![(WarningCode::FabricOnlyDeclaration, None)]);
        assert_eq!(fabric_only.warnings[0].path, "access_point.listen_address");

        let mounted = report(&declaring(Some("deny")), &strategy(true)).await;
        assert!(mounted.warnings.is_empty(), "{:?}", mounted.warnings);

        let mut stripped = declaring(Some("deny"));
        stripped
            .access_point
            .listen_address = "0.0.0.0:8443".into();
        let not_declaring = report(&stripped, &strategy(false)).await;
        assert_eq!(codes(&not_declaring), vec![(WarningCode::DeclarationStripped, None)]);
    }

    #[tokio::test]
    async fn test_report_counts_an_unreadable_strategy_store_as_unservable() {
        let unreadable = report_with(&declaring(Some("deny")), &BrokenStore).await;
        assert_eq!(
            unreadable.declarations,
            vec![DeclarationEntry {
                variant: None,
                outcome: "unservable",
                reason: Some("strategy_store_unavailable"),
                resource: Some(format!("{ORIGIN}/agent")),
            }]
        );
    }

    /// An MCP Access Point at `route` whose one method is `method` and whose
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
        let resource = json!({"resource": format!("{ORIGIN}/agent"), "authorization_servers": [ISSUER]});
        for (case, surface, expected) in [
            ("declares", explicit("mcp", "/agent", jwt_method(&[]), resource.clone(), json!([])), ("declare", None)),
            (
                "not MCP",
                explicit("a2a", "/agent", jwt_method(&[]), resource.clone(), json!([])),
                ("unservable", Some("not_mcp")),
            ),
            (
                "no authorization server",
                explicit(
                    "mcp",
                    "/agent",
                    jwt_method(&[]),
                    json!({"resource": format!("{ORIGIN}/agent"), "authorization_servers": []}),
                    json!([]),
                ),
                ("unservable", Some("invalid_protected_resource")),
            ),
            (
                "audiences listed",
                explicit("mcp", "/agent", jwt_method(&[&format!("{ORIGIN}/agent")]), resource.clone(), json!([])),
                ("unservable", Some("incompatible_caller_authentication")),
            ),
            (
                "another origin",
                explicit(
                    "mcp",
                    "/agent",
                    jwt_method(&[]),
                    json!({"resource": "https://other.example/agent", "authorization_servers": [ISSUER]}),
                    json!([]),
                ),
                ("unservable", Some("resource_mismatch")),
            ),
        ] {
            let reported = report(&surface, &strategy(true)).await;
            assert_eq!((reported.declarations[0].outcome, reported.declarations[0].reason), expected, "{case}");
        }

        let root = explicit(
            "mcp",
            "/",
            jwt_method(&[]),
            json!({"resource": format!("{ORIGIN}/"), "authorization_servers": [ISSUER]}),
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
            declarations: vec![DeclarationEntry {
                variant: None,
                outcome: "strip",
                reason: Some("not_pinned"),
                resource: None,
            }],
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
                "declarations": [{"variant": null, "outcome": "strip", "reason": "not_pinned", "resource": null}],
                "warnings": [{"code": "fail_open_undetermined", "message": "m", "path": "p", "variant": "beta"}],
            })
        );
        assert_eq!(
            serde_json::to_value([WarningCode::FabricOnlyDeclaration, WarningCode::ProtectedResourceDropped])
                .expect("json"),
            json!(["fabric_only_declaration", "protected_resource_dropped"])
        );
    }
}
