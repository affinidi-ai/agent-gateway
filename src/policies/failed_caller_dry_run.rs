//! Dry run of the policy planes against a caller whose source authentication failed.
//!
//! An Access Point that declares refuses a failed caller with its challenge whatever
//! policy allows, as [`refuses_failed_callers_by_default`] decides. Any other Access
//! Point publishes the failure to policy instead of refusing the request, so it admits
//! failed callers unless some plane denies them. The dry run evaluates the effective
//! stack of one resolved Surface Variant with synthetic `Failed` inputs, one per failure
//! kind and protocol method, and reports which plane, if any, denies each one. A case
//! denied on the direct path is also run through the planes Fabric receive evaluates,
//! which skip the inbound policy and give gateway policy no `input.a2a`. It is a
//! heuristic over a fixed method set: a policy that branches on anything else can still
//! admit a failed caller.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::error;

use crate::config::agent_surface::{AgentSurface, SurfaceProtocol};
use crate::policies::global_policy::{GlobalPolicyManager, PLANE_AGENT_SURFACE, PLANE_GATEWAY};
use crate::policies::{FileSystemPolicyDefinitionStore, GatewayPolicyManager, OpaEngine, PlaneVerdict};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::declaration::{DeclarationOutcome, refuses_failed_callers_by_default};
use crate::source_auth::errors::SourceAuthFailureKind;
use crate::surface_context::{A2aContext, McpContext, PolicyInput, SourceAuthContext};

/// A2A methods checked, as `(v0.3 spelling, v1.0 spelling)`.
const A2A_METHODS: &[(&str, &str)] = &[
    ("message/send", "SendMessage"),
    ("message/stream", "SendStreamingMessage"),
    ("tasks/get", "GetTask"),
    ("tasks/cancel", "CancelTask"),
    ("tasks/resubscribe", "SubscribeToTask"),
    ("agent/getAuthenticatedExtendedCard", "GetExtendedAgentCard"),
];

const MCP_METHODS: &[&str] = &["initialize", "tools/list", "tools/call", "resources/read", "prompts/get"];

/// The policy planes a request meets, read as they are now.
#[derive(Clone, Default)]
pub struct PolicyPlanes {
    pub global: Option<Arc<GlobalPolicyManager>>,
    pub gateway: Option<Arc<GatewayPolicyManager>>,
    pub definitions: Option<Arc<FileSystemPolicyDefinitionStore>>,
}

/// How the effective stack treats one synthetic failed caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseOutcome {
    /// The Access Point declares, so it answers with its challenge before surface
    /// policy, AP2 and payment, whatever any plane allows.
    RefusedBeforePolicy,
    /// The appliance-wide or this gateway's gateway policy denies it, before payment.
    DeniedByGatewayPolicy,
    /// Only a surface-level plane denies it, after payment.
    DeniedBySurfacePolicy,
    /// Every plane allows it.
    Admitted,
    /// A plane the direct path runs denies it, but every plane Fabric receive runs
    /// admits it: Fabric receive skips the inbound policy and gives gateway policy no
    /// `input.a2a`.
    AdmittedOverFabric,
    /// No plane denies it and at least one cannot be evaluated.
    Undetermined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedCallerCase {
    pub kind: SourceAuthFailureKind,
    /// The protocol method, spelled as the accepted version spells it; `None` for a
    /// protocol without a method set.
    pub method: Option<&'static str>,
    pub outcome: CaseOutcome,
}

/// A resolved Surface Variant: its alias (`None` for the base route) and its view.
pub type ResolvedView = (Option<String>, AgentSurface);

/// The most views with caller authentication one dry run evaluates. Each view costs a
/// policy evaluation per plane member for every pair of failure kind and method, and the
/// number of variants a surface has is not otherwise bounded.
pub const MAX_DRY_RUN_VIEWS: usize = 16;

/// Run the dry run for each resolved Surface Variant and return the cases of each, in
/// order: none for a view without caller authentication, and `None` for a view with
/// caller authentication past the first [`MAX_DRY_RUN_VIEWS`], which is not evaluated.
/// `declarations` holds the declaration outcome of each view at the same index; a view
/// without one is treated as not declaring. Each surface policy definition is compiled
/// once, and compiling and evaluating run on the blocking pool.
pub async fn dry_run_failed_callers(
    views: &[ResolvedView],
    declarations: &[DeclarationOutcome],
    planes: &PolicyPlanes,
) -> Vec<Option<Vec<FailedCallerCase>>> {
    let mut authenticated = 0;
    let checked: Vec<bool> = views
        .iter()
        .map(|(_, view)| {
            if view.source_auth().is_none() {
                return true;
            }
            authenticated += 1;
            authenticated <= MAX_DRY_RUN_VIEWS
        })
        .collect();
    let selected: Vec<(ResolvedView, bool)> = views
        .iter()
        .enumerate()
        .zip(&checked)
        .filter(|(_, checked)| **checked)
        .map(|((index, view), _)| {
            let refuses = declarations
                .get(index)
                .is_some_and(refuses_failed_callers_by_default);
            (view.clone(), refuses)
        })
        .collect();
    let mut evaluated = evaluate_views(selected, planes)
        .await
        .into_iter();
    checked
        .into_iter()
        .map(|checked| {
            if checked {
                evaluated.next()
            } else {
                None
            }
        })
        .collect()
}

async fn evaluate_views(
    views: Vec<(ResolvedView, bool)>,
    planes: &PolicyPlanes,
) -> Vec<Vec<FailedCallerCase>> {
    let sources = surface_policy_sources(&views, planes.definitions.as_deref()).await;
    let count = views.len();
    let planes = planes.clone();
    let evaluation = tokio::task::spawn_blocking(move || {
        let compiled: HashMap<String, Option<OpaEngine>> = sources
            .into_iter()
            .map(|(id, source)| {
                let engine = source.and_then(|source| compile(&id, &source));
                (id, engine)
            })
            .collect();
        views
            .iter()
            .map(|((alias, view), refuses)| evaluate_view(view, alias.as_deref(), *refuses, &planes, &compiled))
            .collect::<Vec<_>>()
    });
    match evaluation.await {
        Ok(cases) => cases,
        Err(join_error) if join_error.is_panic() => std::panic::resume_unwind(join_error.into_panic()),
        Err(join_error) => {
            error!(error = %join_error, "Failed-caller dry run was cancelled");
            vec![Vec::new(); count]
        }
    }
}

fn evaluate_view(
    view: &AgentSurface,
    variant_alias: Option<&str>,
    refuses_by_default: bool,
    planes: &PolicyPlanes,
    compiled: &HashMap<String, Option<OpaEngine>>,
) -> Vec<FailedCallerCase> {
    let Some(method) = view.source_auth() else {
        return Vec::new();
    };
    let direct_engines = engines_for(compiled, surface_policy_ids(view));
    let fabric_engines = engines_for(
        compiled,
        view.opa_policy_definition_id()
            .into_iter(),
    );
    let gateway_id = planes
        .gateway
        .as_deref()
        .and_then(GatewayPolicyManager::get_self_gateway_id);
    let stack = Stack {
        planes,
        gateway_id: gateway_id.as_deref(),
    };

    let mut cases = Vec::new();
    for kind in failure_kinds(method) {
        for protocol_method in protocol_methods(view) {
            let outcome = if refuses_by_default {
                CaseOutcome::RefusedBeforePolicy
            } else {
                let input = |with_a2a| {
                    synthetic_input(view, variant_alias, method.method_tag(), kind, protocol_method, with_a2a)
                };
                let direct = input(true);
                match stack.outcome(&direct, &direct, &direct_engines) {
                    CaseOutcome::DeniedByGatewayPolicy | CaseOutcome::DeniedBySurfacePolicy
                        if stack.outcome(&input(false), &direct, &fabric_engines) == CaseOutcome::Admitted =>
                    {
                        CaseOutcome::AdmittedOverFabric
                    }
                    outcome => outcome,
                }
            };
            cases.push(FailedCallerCase {
                kind,
                method: protocol_method,
                outcome,
            });
        }
    }
    cases
}

fn engines_for<'c, 'v>(
    compiled: &'c HashMap<String, Option<OpaEngine>>,
    ids: impl Iterator<Item = &'v str>,
) -> Vec<Option<&'c OpaEngine>> {
    ids.map(|id| {
        compiled
            .get(id)
            .and_then(Option::as_ref)
    })
    .collect()
}

/// The gateway and surface planes one path evaluates.
struct Stack<'a> {
    planes: &'a PolicyPlanes,
    gateway_id: Option<&'a str>,
}

impl Stack<'_> {
    /// How the appliance-wide and per-gateway gateway policy, given `gateway_input`,
    /// then the appliance-wide surface plane and `surface_engines`, given
    /// `surface_input`, treat one case.
    fn outcome(
        &self,
        gateway_input: &str,
        surface_input: &str,
        surface_engines: &[Option<&OpaEngine>],
    ) -> CaseOutcome {
        let global = self.planes.global.as_deref();
        let gateway = PlaneVerdict::all([
            global.map_or(PlaneVerdict::Allow, |global| global.verdict(PLANE_GATEWAY, gateway_input)),
            match (self.planes.gateway.as_deref(), self.gateway_id) {
                (Some(manager), Some(id)) => manager.verdict(id, gateway_input),
                _ => PlaneVerdict::Allow,
            },
        ]);
        let surface = PlaneVerdict::all(
            std::iter::once(
                global.map_or(PlaneVerdict::Allow, |global| global.verdict(PLANE_AGENT_SURFACE, surface_input)),
            )
            .chain(
                surface_engines
                    .iter()
                    .map(|engine| engine.map_or(PlaneVerdict::Undetermined, |engine| engine.verdict(surface_input))),
            ),
        );
        match (gateway, surface) {
            (PlaneVerdict::Deny, _) => CaseOutcome::DeniedByGatewayPolicy,
            (_, PlaneVerdict::Deny) => CaseOutcome::DeniedBySurfacePolicy,
            (PlaneVerdict::Allow, PlaneVerdict::Allow) => CaseOutcome::Admitted,
            _ => CaseOutcome::Undetermined,
        }
    }
}

fn surface_policy_ids(view: &AgentSurface) -> impl Iterator<Item = &str> {
    [view.inbound_opa_policy_definition_id(), view.opa_policy_definition_id()]
        .into_iter()
        .flatten()
}

/// The current Rego of every surface policy the views that reach policy reference,
/// read once per definition id; `None` when the definition is missing or empty.
async fn surface_policy_sources(
    views: &[(ResolvedView, bool)],
    definitions: Option<&FileSystemPolicyDefinitionStore>,
) -> HashMap<String, Option<String>> {
    let mut sources = HashMap::new();
    for ((_, view), refuses) in views {
        if *refuses {
            continue;
        }
        for id in surface_policy_ids(view) {
            if sources.contains_key(id) {
                continue;
            }
            let source = match definitions {
                Some(store) => store
                    .get(id)
                    .await
                    .map(|definition| definition.policy)
                    .filter(|policy| !policy.trim().is_empty()),
                None => None,
            };
            sources.insert(id.to_string(), source);
        }
    }
    sources
}

/// A surface policy compiled from its definition, or `None` when it does not
/// compile; the request path then denies.
fn compile(
    definition_id: &str,
    source: &str,
) -> Option<OpaEngine> {
    let engine = OpaEngine::new();
    engine
        .load_policy(definition_id, source)
        .ok()?;
    Some(engine)
}

fn failure_kinds(method: &SourceAuthConfig) -> Vec<SourceAuthFailureKind> {
    let mut kinds = vec![SourceAuthFailureKind::Missing, SourceAuthFailureKind::Invalid];
    if let SourceAuthConfig::JwtBearer(config) = method
        && !config
            .required_scopes
            .is_empty()
    {
        kinds.push(SourceAuthFailureKind::InsufficientScope);
    }
    kinds
}

fn protocol_methods(view: &AgentSurface) -> Vec<Option<&'static str>> {
    match view.access_point.protocol {
        SurfaceProtocol::A2a | SurfaceProtocol::Ap2 => {
            let versions = view
                .a2a_settings()
                .accepted_versions;
            let spellings = versions
                .iter()
                .filter_map(|version| match *version {
                    crate::a2a::version::VERSION_0_3 => Some(false),
                    crate::a2a::version::VERSION_1_0 => Some(true),
                    _ => None,
                });
            spellings
                .flat_map(|pascal| {
                    A2A_METHODS
                        .iter()
                        .map(move |(slash, pascal_name)| {
                            Some(if pascal {
                                *pascal_name
                            } else {
                                *slash
                            })
                        })
                })
                .collect()
        }
        SurfaceProtocol::Mcp => MCP_METHODS
            .iter()
            .map(|method| Some(*method))
            .collect(),
        SurfaceProtocol::DIDComm => vec![None],
    }
}

/// The input a `POST` to the view's Access Point URL gives policy for one case. On
/// an A2A or AP2 view `with_a2a` sets `input.a2a`, which Fabric receive leaves out of
/// gateway policy input.
fn synthetic_input(
    view: &AgentSurface,
    variant_alias: Option<&str>,
    attempted_method: &str,
    kind: SourceAuthFailureKind,
    protocol_method: Option<&str>,
    with_a2a: bool,
) -> String {
    let mut input =
        PolicyInput::new("POST", "/", HashMap::new(), "inbound", None, None, Some(view.surface_id.clone()), &view.name);
    input.set_variant_alias(variant_alias);
    let reason = match kind {
        SourceAuthFailureKind::Missing => "Missing credential",
        SourceAuthFailureKind::Invalid => "Invalid credential",
        SourceAuthFailureKind::InsufficientScope => "Insufficient scope",
    };
    input.source_auth = Some(SourceAuthContext::Failed {
        attempted_method: attempted_method.to_string(),
        kind,
        reason: reason.to_string(),
    });
    match view.access_point.protocol {
        SurfaceProtocol::A2a | SurfaceProtocol::Ap2 => {
            if with_a2a {
                input.a2a = Some(A2aContext::new(protocol_method.map(str::to_string), None));
            }
        }
        SurfaceProtocol::Mcp => {
            input.mcp = protocol_method.map(|method| McpContext {
                method: method.to_string(),
                ..Default::default()
            });
        }
        SurfaceProtocol::DIDComm => {}
    }
    serde_json::to_string(&input).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::policies::global_policy::tests::{gw_def, store_with};
    use crate::policies::global_policy::{GlobalAssignment, GlobalPolicyAssignments};
    use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};
    use crate::source_auth::declaration::{Declaration, StripReason};

    const DENY_FAILED: &str =
        "package surface.policy\ndefault allow := true\nallow := false if input.source_auth.method == \"failed\"\n";
    const DENY_FAILED_SEND_ONLY: &str = "package surface.policy\ndefault allow := true\nallow := false if {\n  input.source_auth.method == \"failed\"\n  input.a2a.method == \"SendMessage\"\n}\n";
    const UNDEFINED: &str = "package surface.policy\nallow if input.source_auth.method == \"jwt_bearer\"\n";
    const ERRORS: &str =
        "package surface.policy\nallow := true if input.source_auth\nallow := false if input.source_auth\n";
    const ALLOW_ALL: &str = "package surface.policy\ndefault allow := true\n";

    fn surface_def(
        id: &str,
        rego: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            policy_type: PolicyType::AgentSurface,
            ..gw_def(id, rego)
        }
    }

    fn jwt_method(required_scopes: &[&str]) -> Value {
        json!({
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "strategy-1",
            "audiences": ["https://gw.example/agent"],
            "required_scopes": required_scopes,
        })
    }

    /// A surface whose `target.policy`, which both the direct path and Fabric receive
    /// run, is `policy`.
    fn surface(
        protocol: &str,
        methods: Vec<Value>,
        policy: Option<&str>,
    ) -> AgentSurface {
        let mut access_point = json!({"listen_address": "0.0.0.0:8443", "route": "/agent", "protocol": protocol});
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
        }))
        .expect("surface")
    }

    fn a2a(policy: Option<&str>) -> AgentSurface {
        surface("a2a", vec![jwt_method(&["agent.invoke"])], policy)
    }

    fn with_inbound_policy(
        mut view: AgentSurface,
        id: &str,
    ) -> AgentSurface {
        view.access_point
            .inbound_policy =
            Some(serde_json::from_value(json!({"policy_definition_id": id})).expect("inbound policy"));
        view
    }

    fn declares() -> DeclarationOutcome {
        DeclarationOutcome::Declare(Declaration {
            resource: "https://gw.example/agent".to_string(),
            authorization_servers: vec!["https://issuer.example".to_string()],
            pin: None,
            required_scopes: vec!["agent.invoke".to_string()],
            advertised_scopes: vec!["agent.invoke".to_string()],
        })
    }

    async fn definitions(definitions: &[(&str, &str)]) -> PolicyPlanes {
        let store = store_with(
            definitions
                .iter()
                .map(|(id, rego)| surface_def(id, rego))
                .collect(),
        )
        .await;
        PolicyPlanes {
            definitions: Some(store),
            ..Default::default()
        }
    }

    async fn run(
        view: &AgentSurface,
        definitions_of: &[(&str, &str)],
    ) -> Vec<FailedCallerCase> {
        cases_of(view, DeclarationOutcome::PassThrough, &definitions(definitions_of).await).await
    }

    async fn cases_of(
        view: &AgentSurface,
        declaration: DeclarationOutcome,
        planes: &PolicyPlanes,
    ) -> Vec<FailedCallerCase> {
        dry_run_failed_callers(&[(None, view.clone())], &[declaration], planes)
            .await
            .remove(0)
            .expect("a single view is within the limit")
    }

    fn outcomes(cases: &[FailedCallerCase]) -> Vec<CaseOutcome> {
        let mut outcomes: Vec<CaseOutcome> = cases
            .iter()
            .map(|case| case.outcome)
            .collect();
        outcomes.dedup();
        outcomes
    }

    async fn gateway_denying_failed_callers() -> GatewayPolicyManager {
        gateway_denying(&DENY_FAILED.replace("surface.policy", "gateway.policy")).await
    }

    async fn gateway_denying(rego: &str) -> GatewayPolicyManager {
        use crate::gateways::types::{
            Gateway, GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType,
        };
        let gateway_policy = GatewayPolicyManager::new();
        let gateway = Gateway {
            id: "self".to_string(),
            tenant_id: None,
            name: "self".to_string(),
            description: String::new(),
            did: "did:example:self".to_string(),
            issuer_did: None,
            issuer_did_source: None,
            trusted_issuer_dids: Vec::new(),
            gateway_type: GatewayType::SelfGateway,
            status: GatewayStatus::Active,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            exposure_mode: None,
            opa_policy_config: Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: rego.to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        };
        gateway_policy
            .update_gateway_policy(&gateway)
            .await
            .expect("gateway policy");
        gateway_policy
    }

    #[tokio::test]
    async fn test_dry_run_covers_every_kind_and_method_of_both_a2a_versions() {
        let cases = run(&a2a(Some("deny")), &[("deny", DENY_FAILED)]).await;
        assert_eq!(cases.len(), 3 * 12);
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedBySurfacePolicy]);
        let methods: Vec<&str> = cases
            .iter()
            .filter(|case| case.kind == SourceAuthFailureKind::InsufficientScope)
            .filter_map(|case| case.method)
            .collect();
        assert!(methods.contains(&"message/send") && methods.contains(&"SendMessage"), "{methods:?}");
        assert!(methods.contains(&"agent/getAuthenticatedExtendedCard"), "{methods:?}");
    }

    #[tokio::test]
    async fn test_dry_run_without_required_scopes_skips_the_scope_kind() {
        let view = surface("a2a", vec![jwt_method(&[])], Some("deny"));
        let cases = run(&view, &[("deny", DENY_FAILED)]).await;
        assert_eq!(cases.len(), 2 * 12);
        assert!(
            cases
                .iter()
                .all(|case| case.kind != SourceAuthFailureKind::InsufficientScope)
        );
    }

    #[tokio::test]
    async fn test_dry_run_spells_methods_as_the_accepted_version_does() {
        let mut view = a2a(Some("deny"));
        view.access_point.a2a = Some(serde_json::from_value(json!({"accepted_versions": ["0.3"]})).expect("a2a"));
        let cases = run(&view, &[("deny", DENY_FAILED)]).await;
        assert_eq!(cases.len(), 3 * 6);
        assert!(cases.iter().all(|case| {
            case.method
                .is_some_and(|method| method.contains('/'))
        }));
    }

    #[tokio::test]
    async fn test_dry_run_finds_a_method_the_policy_forgets() {
        let cases = run(&a2a(Some("send-only")), &[("send-only", DENY_FAILED_SEND_ONLY)]).await;
        let admitted: Vec<Option<&str>> = cases
            .iter()
            .filter(|case| case.outcome == CaseOutcome::Admitted)
            .map(|case| case.method)
            .collect();
        assert_eq!(admitted.len(), 3 * 11);
        assert!(admitted.contains(&Some("SendStreamingMessage")));
        assert!(!admitted.contains(&Some("SendMessage")));
    }

    #[tokio::test]
    async fn test_dry_run_with_no_policy_admits_every_case() {
        let cases = run(&a2a(None), &[]).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::Admitted]);
        let cases = run(&a2a(Some("allow")), &[("allow", ALLOW_ALL)]).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::Admitted]);
    }

    #[tokio::test]
    async fn test_dry_run_reports_undefined_erroring_or_missing_policy_as_undetermined() {
        for (definitions, label) in [
            (vec![("p", UNDEFINED)], "undefined allow"),
            (vec![("p", ERRORS)], "conflicting values"),
            (vec![("p", "package surface.policy\nallow if {")], "does not compile"),
            (vec![], "missing definition"),
        ] {
            let cases = run(&a2a(Some("p")), &definitions).await;
            assert_eq!(outcomes(&cases), vec![CaseOutcome::Undetermined], "{label}");
        }
    }

    #[tokio::test]
    async fn test_dry_run_a_deny_anywhere_beats_an_undetermined_plane() {
        let view = with_inbound_policy(a2a(Some("deny")), "undefined");
        let cases = run(&view, &[("undefined", UNDEFINED), ("deny", DENY_FAILED)]).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedBySurfacePolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_an_inbound_policy_deny_admits_failed_callers_over_fabric() {
        for protocol in ["a2a", "mcp"] {
            let view = with_inbound_policy(surface(protocol, vec![jwt_method(&[])], None), "deny");
            let cases = run(&view, &[("deny", DENY_FAILED)]).await;
            assert!(!cases.is_empty(), "{protocol}");
            assert_eq!(
                outcomes(&cases),
                vec![CaseOutcome::AdmittedOverFabric],
                "{protocol}: Fabric receive does not run the inbound policy"
            );
        }

        let both = with_inbound_policy(a2a(Some("deny")), "deny");
        let cases = run(&both, &[("deny", DENY_FAILED)]).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedBySurfacePolicy], "target.policy denies on both paths");
    }

    #[tokio::test]
    async fn test_dry_run_a_gateway_deny_keyed_on_the_a2a_method_admits_failed_callers_over_fabric() {
        let keyed_on_a2a = "package gateway.policy\ndefault allow := true\nallow := false if {\n  input.source_auth.method == \"failed\"\n  input.a2a.method_canonical\n}\n";
        let planes = PolicyPlanes {
            gateway: Some(Arc::new(gateway_denying(keyed_on_a2a).await)),
            ..Default::default()
        };
        let cases = cases_of(&a2a(None), DeclarationOutcome::PassThrough, &planes).await;
        assert_eq!(
            outcomes(&cases),
            vec![CaseOutcome::AdmittedOverFabric],
            "Fabric receive gives gateway policy no input.a2a"
        );

        let planes = PolicyPlanes {
            gateway: Some(Arc::new(gateway_denying_failed_callers().await)),
            ..Default::default()
        };
        let cases = cases_of(&a2a(None), DeclarationOutcome::PassThrough, &planes).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedByGatewayPolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_gateway_policy_denies_before_payment() {
        let planes = PolicyPlanes {
            gateway: Some(Arc::new(gateway_denying_failed_callers().await)),
            ..definitions(&[("deny", DENY_FAILED)]).await
        };
        let cases = cases_of(&a2a(Some("deny")), DeclarationOutcome::PassThrough, &planes).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedByGatewayPolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_reads_the_appliance_wide_surface_plane() {
        let store = store_with(vec![surface_def("global-deny", DENY_FAILED)]).await;
        let global = GlobalPolicyManager::new();
        global.set_policy_definition_store(store.clone());
        let mut assignments = GlobalPolicyAssignments::default();
        assignments
            .assignments
            .insert(
                PLANE_AGENT_SURFACE.to_string(),
                vec![GlobalAssignment {
                    policy_id: "global-deny".to_string(),
                    monitor_only: false,
                }],
            );
        global
            .refresh(&assignments)
            .await;
        let planes = PolicyPlanes {
            global: Some(Arc::new(global)),
            definitions: Some(store),
            ..Default::default()
        };
        let cases = cases_of(&a2a(None), DeclarationOutcome::PassThrough, &planes).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::DeniedBySurfacePolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_mcp_uses_the_mcp_method_set() {
        let view = surface(
            "mcp",
            vec![
                json!({"type": "api_key", "extraction": {"source": "http_header", "field": "X-Key"}, "secret_id": "KEYS"}),
            ],
            None,
        );
        let cases = run(&view, &[]).await;
        let methods: Vec<Option<&str>> = cases
            .iter()
            .map(|case| case.method)
            .collect();
        assert_eq!(cases.len(), 2 * 5);
        assert!(methods.contains(&Some("tools/call")) && methods.contains(&Some("initialize")));
    }

    #[tokio::test]
    async fn test_dry_run_a_declaring_access_point_refuses_every_case_before_policy() {
        let planes = definitions(&[("allow", ALLOW_ALL)]).await;
        let cases = cases_of(&a2a(Some("allow")), declares(), &planes).await;
        assert_eq!(cases.len(), 3 * 12, "every kind and method is still reported");
        assert_eq!(outcomes(&cases), vec![CaseOutcome::RefusedBeforePolicy]);

        let mcp = surface("mcp", vec![jwt_method(&["tools.call"])], None);
        let cases = cases_of(&mcp, declares(), &planes).await;
        assert_eq!(cases.len(), 3 * 5);
        assert_eq!(outcomes(&cases), vec![CaseOutcome::RefusedBeforePolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_a_declaring_access_point_answers_with_its_challenge_whatever_gateway_policy_says() {
        let planes = PolicyPlanes {
            gateway: Some(Arc::new(gateway_denying_failed_callers().await)),
            ..Default::default()
        };
        let cases = cases_of(&a2a(None), declares(), &planes).await;
        assert_eq!(outcomes(&cases), vec![CaseOutcome::RefusedBeforePolicy]);
    }

    #[tokio::test]
    async fn test_dry_run_an_access_point_that_does_not_declare_defers_to_policy() {
        let planes = definitions(&[]).await;
        for declaration in [
            DeclarationOutcome::PassThrough,
            DeclarationOutcome::Strip(StripReason::ForwardsCallerToken),
            DeclarationOutcome::Unservable("no external URL".to_string()),
        ] {
            let label = declaration.label();
            let cases = cases_of(&a2a(None), declaration, &planes).await;
            assert_eq!(outcomes(&cases), vec![CaseOutcome::Admitted], "{label}");
        }
    }

    #[tokio::test]
    async fn test_dry_run_reports_every_view_in_order_from_shared_definitions() {
        let planes = definitions(&[("deny", DENY_FAILED)]).await;
        let views = [
            (None, a2a(Some("deny"))),
            (Some("open".to_string()), surface("a2a", vec![], Some("deny"))),
            (Some("again".to_string()), a2a(Some("deny"))),
            (Some("loose".to_string()), a2a(None)),
            (Some("declared".to_string()), a2a(None)),
            (Some("unlisted".to_string()), a2a(None)),
        ];
        let declarations = [
            DeclarationOutcome::PassThrough,
            DeclarationOutcome::PassThrough,
            DeclarationOutcome::PassThrough,
            DeclarationOutcome::PassThrough,
            declares(),
        ];
        let reports: Vec<Vec<FailedCallerCase>> = dry_run_failed_callers(&views, &declarations, &planes)
            .await
            .into_iter()
            .map(|cases| cases.expect("every view is within the limit"))
            .collect();
        assert_eq!(reports.len(), 6);
        assert_eq!(outcomes(&reports[0]), vec![CaseOutcome::DeniedBySurfacePolicy]);
        assert!(reports[1].is_empty());
        assert_eq!(outcomes(&reports[2]), vec![CaseOutcome::DeniedBySurfacePolicy]);
        assert_eq!(outcomes(&reports[3]), vec![CaseOutcome::Admitted]);
        assert_eq!(outcomes(&reports[4]), vec![CaseOutcome::RefusedBeforePolicy]);
        assert_eq!(
            outcomes(&reports[5]),
            vec![CaseOutcome::Admitted],
            "a view without a declaration outcome is treated as not declaring"
        );
    }

    #[tokio::test]
    async fn test_dry_run_checks_at_most_the_view_limit_of_authenticated_views() {
        let planes = definitions(&[("deny", DENY_FAILED)]).await;
        let mut views: Vec<ResolvedView> = (0..MAX_DRY_RUN_VIEWS + 2)
            .map(|index| (Some(format!("v{index}")), a2a(Some("deny"))))
            .collect();
        views.push((Some("open".to_string()), surface("a2a", vec![], None)));

        let reports = dry_run_failed_callers(&views, &[], &planes).await;

        assert_eq!(reports.len(), MAX_DRY_RUN_VIEWS + 3);
        for cases in &reports[..MAX_DRY_RUN_VIEWS] {
            let cases = cases
                .as_deref()
                .expect("a view within the limit is checked");
            assert_eq!(outcomes(cases), vec![CaseOutcome::DeniedBySurfacePolicy]);
        }
        assert_eq!(reports[MAX_DRY_RUN_VIEWS], None, "the first view past the limit is not checked");
        assert_eq!(reports[MAX_DRY_RUN_VIEWS + 1], None);
        assert_eq!(
            reports[MAX_DRY_RUN_VIEWS + 2],
            Some(Vec::new()),
            "a view without caller authentication has nothing to check and does not count"
        );
    }

    #[tokio::test]
    async fn test_dry_run_skips_a_view_without_caller_authentication() {
        assert!(
            run(&surface("a2a", vec![], None), &[])
                .await
                .is_empty()
        );
    }

    #[test]
    fn test_synthetic_input_publishes_a_failed_caller_on_the_variant_route() {
        let input: Value = serde_json::from_str(&synthetic_input(
            &a2a(None),
            Some("beta"),
            "jwt_bearer",
            SourceAuthFailureKind::InsufficientScope,
            Some("SendMessage"),
            true,
        ))
        .expect("json");
        assert_eq!(input["source_auth"]["method"], "failed");
        assert_eq!(input["source_auth"]["attempted_method"], "jwt_bearer");
        assert_eq!(input["source_auth"]["kind"], "insufficient_scope");
        assert_eq!(input["http"]["path"], "/");
        assert_eq!(input["channel"]["variant_alias"], "beta");
        assert_eq!(input["a2a"]["method"], "SendMessage");
        assert_eq!(input["a2a"]["method_canonical"], "message/send");
        assert!(
            input
                .get("mcp")
                .is_none_or(Value::is_null),
            "an A2A view publishes no MCP method"
        );

        let fabric_gateway: Value = serde_json::from_str(&synthetic_input(
            &a2a(None),
            Some("beta"),
            "jwt_bearer",
            SourceAuthFailureKind::InsufficientScope,
            Some("SendMessage"),
            false,
        ))
        .expect("json");
        assert!(
            fabric_gateway
                .get("a2a")
                .is_none_or(Value::is_null),
            "the gateway input of Fabric receive has no A2A method"
        );
        assert_eq!(fabric_gateway["source_auth"], input["source_auth"]);
    }

    #[test]
    fn test_synthetic_input_publishes_the_mcp_method_on_an_mcp_view() {
        let view = surface("mcp", vec![jwt_method(&[])], None);
        let input: Value = serde_json::from_str(&synthetic_input(
            &view,
            None,
            "jwt_bearer",
            SourceAuthFailureKind::Missing,
            Some("tools/call"),
            false,
        ))
        .expect("json");
        assert_eq!(input["source_auth"]["kind"], "missing");
        assert_eq!(input["mcp"]["method"], "tools/call");
        assert!(
            input
                .get("a2a")
                .is_none_or(Value::is_null)
        );
        assert!(input["channel"]["variant_alias"].is_null());
    }
}
