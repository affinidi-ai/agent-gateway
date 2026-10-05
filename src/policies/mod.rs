pub mod agent_context;
pub mod circuit_breaker;
pub mod gateway_manager;
pub mod global_policy;
pub mod mcp_tool_gating;
pub mod opa;
pub mod policy_definitions;
pub mod rate_limiter;
pub mod surface_manager;

use std::borrow::Cow;

/// Rego package name every gateway-scope policy must declare (`package gateway.policy`).
/// Used as the audit `policy_id` for gateway-scope decisions and as the query root
/// (`data.gateway.policy.allow`).
pub const GATEWAY_POLICY_PACKAGE: &str = "gateway.policy";

/// Canonical Rego package name for agent-surface-scope policies (`package
/// surface.policy`). Used as the surface-scope audit `policy_id` label and the
/// single query root (`data.surface.policy.allow`). A legacy `package
/// channel.policy` declaration authored before the rename is rewritten to this
/// package by the policy store's startup migration pass (see
/// [`migrate_legacy_surface_package`]), so the runtime only ever evaluates
/// `surface.policy` — there is no `channel.policy` query fallback.
pub const SURFACE_POLICY_PACKAGE: &str = "surface.policy";

/// Legacy Rego package that agent-surface policies declared before the
/// `channel.policy` → `surface.policy` rename. Retained only so the startup
/// storage migration ([`migrate_legacy_surface_package`]) can recognise and
/// rewrite it; no code path evaluates it directly.
pub const LEGACY_SURFACE_POLICY_PACKAGE: &str = "channel.policy";

/// Rewrite a legacy `package channel.policy` declaration to the canonical
/// `package surface.policy`, returning the input unchanged when it declares no
/// legacy package.
///
/// This is the startup storage migration for agent-surface policies. It is applied
/// once per stored definition by the policy store's startup migration pass (see
/// [`policy_definitions::FileSystemPolicyDefinitionStore::migrate_legacy_packages`]),
/// which re-saves each rewritten definition through the store's normal `save`
/// path. Every policy the OPA engine later compiles is read from that
/// already-migrated store, so no read-time or `data.channel.policy` query fallback
/// is needed.
///
/// The declaration is located by [`policy_definitions::declared_package_span`] (the
/// same parser the write-time scope check uses), so only the leading `package`
/// name is rewritten — the policy body is preserved verbatim and a stray
/// `channel.policy` mention in a preceding comment is never touched.
pub fn migrate_legacy_surface_package(policy: &str) -> Cow<'_, str> {
    if let Some((offset, name)) = policy_definitions::declared_package_span(policy)
        && name == LEGACY_SURFACE_POLICY_PACKAGE
    {
        let end = offset + LEGACY_SURFACE_POLICY_PACKAGE.len();
        let mut migrated = String::with_capacity(policy.len() + SURFACE_POLICY_PACKAGE.len());
        migrated.push_str(&policy[..offset]);
        migrated.push_str(SURFACE_POLICY_PACKAGE);
        migrated.push_str(&policy[end..]);
        return Cow::Owned(migrated);
    }
    Cow::Borrowed(policy)
}

/// Substring of the Regorus error raised when a boolean query resolves to no
/// value — i.e. the queried package/rule is not declared by the loaded module.
///
/// The fail-closed handling for a wrong-package / missing-`allow` policy keys on
/// this text (see `opa::eval_surface_decision` and
/// `GatewayPolicyManager::evaluate_policy_decision`). It is therefore **coupled
/// to the Regorus error wording** for the pinned version in `Cargo.toml`: if a
/// Regorus upgrade rewords it, that "no value" case would fall through to an
/// opaque engine error instead of an actionable deny. The
/// `regorus_no_value_marker_matches_live_error` canary asserts this constant
/// against the raw Regorus error directly (and the
/// `unknown_package_policy_is_denied_not_ignored` /
/// `wrong_package_gateway_policy_fails_closed` tests exercise the behavior), so
/// a wording change breaks the canary first and points straight here — update
/// this constant when bumping Regorus if that test fails.
pub const REGORUS_QUERY_NO_VALUE_MARKER: &str = "did not produce any values";

pub use agent_context::{build_agent_context, build_agent_context_for_protocol};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerError};
pub use gateway_manager::GatewayPolicyManager;
pub use global_policy::{FileSystemGlobalPolicyStore, GlobalPolicyAssignments, GlobalPolicyManager};
pub use mcp_tool_gating::CompiledMcpToolGating;
pub use opa::OpaEngine;
pub use opa::PolicyDecision;
pub use policy_definitions::{FileSystemPolicyDefinitionStore, PolicyAttestation};
pub use rate_limiter::{RateLimitConfig, RateLimitError, RateLimiter};
pub use surface_manager::SurfacePolicyManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_channel_package_to_surface() {
        let migrated = migrate_legacy_surface_package("package channel.policy\n\ndefault allow = false\n");
        assert_eq!(migrated, "package surface.policy\n\ndefault allow = false\n");
    }

    #[test]
    fn migration_preserves_leading_comments_and_whitespace() {
        let migrated =
            migrate_legacy_surface_package("# legacy policy\n\n  package channel.policy\ndefault allow = true");
        assert_eq!(migrated, "# legacy policy\n\n  package surface.policy\ndefault allow = true");
    }

    #[test]
    fn migration_only_rewrites_the_package_declaration_not_the_body() {
        // A `channel.policy` string in the body (e.g. a comment or rule) must not
        // be rewritten — only the leading package declaration.
        let src = "package channel.policy\n\n# note: replaces channel.policy\nallow if { true }\n";
        let migrated = migrate_legacy_surface_package(src);
        assert_eq!(migrated, "package surface.policy\n\n# note: replaces channel.policy\nallow if { true }\n");
    }

    #[test]
    fn migration_ignores_channel_policy_in_a_preceding_comment() {
        // A comment mentioning the legacy package before the real declaration must
        // not be mistaken for the package line.
        let src = "# migrated away from channel.policy\npackage surface.policy\ndefault allow = true\n";
        let migrated = migrate_legacy_surface_package(src);
        assert_eq!(migrated, src, "already-canonical policy must be returned unchanged");
        assert!(matches!(migrated, std::borrow::Cow::Borrowed(_)), "no-op must not allocate");
    }

    #[test]
    fn migration_is_a_noop_for_non_legacy_packages() {
        for src in [
            "package surface.policy\ndefault allow = true",
            "package gateway.policy\ndefault allow = true",
            "package authz.custom\ndefault allow = true",
            "",
            "   \n",
            "default allow = true",
        ] {
            let migrated = migrate_legacy_surface_package(src);
            assert_eq!(migrated, src);
            assert!(matches!(migrated, std::borrow::Cow::Borrowed(_)), "no-op must not allocate for: {src:?}");
        }
    }
}
