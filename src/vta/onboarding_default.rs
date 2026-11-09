//! What a gateway signs with when nobody has said.
//!
//! A gateway keeps signing with its local issuer key unless an operator opts
//! into the bundled agent or connects their own. Nothing is inferred from the
//! state of the disk: a rebuilt volume or a sidecar that happens to be down
//! must never change which backend signs.
//!
//! ## The reversibility invariant
//!
//! Resolving a default **never** migrates, rewrites or deletes a key. It only
//! decides which backend new signatures use. Per-surface migration stays
//! opt-in (VTA-19) with both keys published (VTA-17), so switching back is
//! always possible and nothing ever becomes unverifiable.

use serde::{Deserialize, Serialize};

use crate::config::vta::{VtaConfig, VtaMode};

/// The appliance-wide signing default, as an operator writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultBackend {
    /// The in-process issuer key, for now. The default; the bundled agent
    /// is an explicit opt-in.
    #[default]
    Auto,
    /// Always the in-process issuer key, whatever the install looks like.
    LegacyLocal,
    /// Always the bundled sidecar.
    Bundled,
}

/// What the appliance will actually sign with, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultResolution {
    /// `local` or `bundled`.
    pub backend: &'static str,
    /// Operator-facing explanation. Surfaced in the advanced settings so the
    /// answer to "why is it signing with this?" never requires reading code.
    pub reason: String,
    /// Whether an operator (or a fleet config) chose this explicitly, as
    /// opposed to it being inferred.
    pub explicit: bool,
    /// Set when the chosen backend could not be used and the gateway fell back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_from: Option<&'static str>,
}

impl DefaultResolution {
    fn local(
        reason: impl Into<String>,
        explicit: bool,
    ) -> Self {
        Self {
            backend: "local",
            reason: reason.into(),
            explicit,
            fallback_from: None,
        }
    }

    fn bundled(
        reason: impl Into<String>,
        explicit: bool,
    ) -> Self {
        Self {
            backend: "bundled",
            reason: reason.into(),
            explicit,
            fallback_from: None,
        }
    }
}

/// Resolve the appliance default.
///
/// An explicitly enabled `[vta]` block always wins: the operator has already
/// said what they want, and a default that could override it would be a
/// default that changes configured behaviour.
pub fn resolve(config: &VtaConfig) -> DefaultResolution {
    if config.enabled {
        let backend = if config.mode == VtaMode::Bundled {
            "bundled trust agent"
        } else {
            "configured agent"
        };
        return DefaultResolution {
            backend: if config.mode == VtaMode::Bundled {
                "bundled"
            } else {
                "vta"
            },
            reason: format!("the [vta] block is enabled, so this appliance signs through its {backend}"),
            explicit: true,
            fallback_from: None,
        };
    }

    match config.default_backend {
        DefaultBackend::Auto => DefaultResolution::local(
            "this gateway signs with its own local issuer key; connect an agent to change that",
            false,
        ),
        DefaultBackend::LegacyLocal => {
            DefaultResolution::local("`default_backend = \"legacy_local\"` was set explicitly", true)
        }
        DefaultBackend::Bundled => {
            DefaultResolution::bundled("`default_backend = \"bundled\"` was set explicitly", true)
        }
    }
}

/// Fold in whether the chosen backend is actually usable.
///
/// A bundled agent that did not come up must not block onboarding, and must
/// not be papered over either. Only an explicit `bundled` choice can reach
/// this, and the fallback is reported in the resolution rather than silent.
pub fn with_availability(
    resolved: DefaultResolution,
    bundled_available: bool,
) -> DefaultResolution {
    if resolved.backend != "bundled" || bundled_available {
        return resolved;
    }
    DefaultResolution {
        backend: "local",
        reason: "the bundled agent is not available, so this gateway is signing with its own local key; \
                 start the agent or connect your own to change that"
            .to_string(),
        explicit: resolved.explicit,
        fallback_from: Some("bundled"),
    }
}

/// Fold in how the bundled bootstrap actually went.
///
/// - Connected, or no bootstrap at all: nothing changes.
/// - Not connected, and **never** connected: the sidecar has signed nothing, so
///   the gateway falls back to its local key and says so. Onboarding is not
///   blocked.
/// - Not connected, but **once** connected: tokens were already issued under
///   the sidecar's key, so signing with a different key would change the issuer
///   under callers' feet. The backend stays `bundled`, signing is refused, and
///   the reason says what to do.
pub fn with_bundled_bootstrap(
    resolved: DefaultResolution,
    status: Option<&crate::vta::bundled::BootstrapStatus>,
) -> DefaultResolution {
    use crate::vta::bundled::BootstrapState;

    let Some(status) = status.filter(|s| s.state != BootstrapState::Connected) else {
        return resolved;
    };
    let detail = status
        .detail
        .as_deref()
        .map(|d| format!(" ({d})"))
        .unwrap_or_default();
    if status.previously_connected {
        return DefaultResolution {
            backend: "bundled",
            reason: format!(
                "the bundled agent is {}{detail}, so signing is refused rather than switching issuer key: {}",
                status.state.label(),
                status.advice
            ),
            explicit: true,
            fallback_from: None,
        };
    }
    DefaultResolution {
        backend: "local",
        reason: format!(
            "the bundled agent is {}{detail}, so this gateway is signing with its own local key: {}",
            status.state.label(),
            status.advice
        ),
        explicit: true,
        fallback_from: Some("bundled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled() -> VtaConfig {
        VtaConfig::default()
    }

    fn enabled(mode: VtaMode) -> VtaConfig {
        VtaConfig {
            enabled: true,
            mode,
            base_url: Some("https://vta.example".to_string()),
            vta_did: Some("did:webvh:vta.example".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("k1".to_string()),
            ..VtaConfig::default()
        }
    }

    #[test]
    fn the_reason_for_an_enabled_block_names_what_signs() {
        assert_eq!(
            resolve(&enabled(VtaMode::Bundled)).reason,
            "the [vta] block is enabled, so this appliance signs through its bundled trust agent"
        );
        assert_eq!(
            resolve(&enabled(VtaMode::Appliance)).reason,
            "the [vta] block is enabled, so this appliance signs through its configured agent"
        );
    }

    #[test]
    fn auto_signs_with_the_local_key_and_asks_nothing() {
        let resolved = resolve(&disabled());
        assert_eq!(resolved.backend, "local");
        assert!(!resolved.explicit, "nobody was asked");
        assert!(
            resolved
                .fallback_from
                .is_none(),
            "nothing failed; this is the intended outcome"
        );
        assert!(
            resolved
                .reason
                .contains("local issuer key"),
            "the reason must be operator-readable: {}",
            resolved.reason
        );
    }

    #[test]
    fn an_explicit_default_is_honoured() {
        let local = resolve(&VtaConfig {
            default_backend: DefaultBackend::LegacyLocal,
            ..disabled()
        });
        assert_eq!(local.backend, "local");
        assert!(local.explicit, "a configured value is an explicit choice");

        let bundled = resolve(&explicit_bundled());
        assert_eq!(bundled.backend, "bundled");
        assert!(bundled.explicit);
    }

    /// Fleet and IaC installs must never need the dashboard, so the default is
    /// expressible in config alone.
    #[test]
    fn the_default_is_settable_from_config() {
        let cfg: VtaConfig = toml::from_str("default_backend = \"bundled\"").expect("parse");
        assert_eq!(cfg.default_backend, DefaultBackend::Bundled);
        assert_eq!(resolve(&cfg).backend, "bundled");

        let bare: VtaConfig = toml::from_str("").expect("parse");
        assert_eq!(bare.default_backend, DefaultBackend::Auto);
        assert_eq!(resolve(&bare).backend, "local", "absent means the local key, never the bundled agent");
    }

    /// A default that could override configured behaviour would not be a
    /// default.
    #[test]
    fn an_enabled_vta_block_always_wins_over_any_default() {
        for backend in [DefaultBackend::Auto, DefaultBackend::LegacyLocal, DefaultBackend::Bundled] {
            let cfg = VtaConfig {
                default_backend: backend,
                ..enabled(VtaMode::Appliance)
            };
            let resolved = resolve(&cfg);
            assert_eq!(resolved.backend, "vta", "the configured agent must win over `{backend:?}`");
            assert!(resolved.explicit);
        }

        assert_eq!(resolve(&enabled(VtaMode::Bundled)).backend, "bundled");
    }

    // ---- safe fallback ----------------------------------------------------

    fn explicit_bundled() -> VtaConfig {
        VtaConfig {
            default_backend: DefaultBackend::Bundled,
            ..disabled()
        }
    }

    #[test]
    fn an_unavailable_bundled_agent_does_not_block_onboarding() {
        let resolved = with_availability(resolve(&explicit_bundled()), false);

        assert_eq!(resolved.backend, "local");
        assert_eq!(resolved.fallback_from, Some("bundled"));
        assert!(resolved.explicit, "the operator's choice is still reported as explicit");
        assert!(
            resolved
                .reason
                .contains("not available"),
            "the state must be clearly reported: {}",
            resolved.reason
        );
        assert!(
            resolved
                .reason
                .contains("start the agent"),
            "the reason must be actionable: {}",
            resolved.reason
        );
    }

    #[test]
    fn availability_only_affects_a_bundled_choice() {
        let local = resolve(&disabled());
        assert_eq!(with_availability(local.clone(), false), local, "a local default has nothing to fall back from");

        let bundled = resolve(&explicit_bundled());
        assert_eq!(with_availability(bundled.clone(), true), bundled, "an available agent is used as chosen");
    }

    fn bootstrap_status(
        state: crate::vta::bundled::BootstrapState,
        previously_connected: bool,
    ) -> crate::vta::bundled::BootstrapStatus {
        crate::vta::bundled::BootstrapStatus {
            state,
            advice: state.advice(),
            detail: None,
            vta_did: None,
            control_did: None,
            context_id: "gateway".to_string(),
            bootstrapped_at: None,
            previously_connected,
            signing_key_id: None,
            signing_key_public: None,
            owner: "unclaimed",
        }
    }

    #[test]
    fn a_connected_or_absent_bootstrap_changes_nothing() {
        use crate::vta::bundled::BootstrapState;
        let resolved = DefaultResolution::bundled("explicit", true);
        assert_eq!(with_bundled_bootstrap(resolved.clone(), None), resolved);
        let connected = bootstrap_status(BootstrapState::Connected, true);
        assert_eq!(with_bundled_bootstrap(resolved.clone(), Some(&connected)), resolved);
    }

    #[test]
    fn a_bootstrap_that_never_connected_falls_back_to_local_and_says_why() {
        use crate::vta::bundled::BootstrapState;
        let status = bootstrap_status(BootstrapState::WaitingForVta, false);

        let resolution = with_bundled_bootstrap(DefaultResolution::bundled("explicit", true), Some(&status));

        assert_eq!(resolution.backend, "local");
        assert_eq!(resolution.fallback_from, Some("bundled"));
        assert!(
            resolution
                .reason
                .contains("waiting for the trust agent"),
            "{}",
            resolution.reason
        );
        assert!(
            !resolution
                .reason
                .contains("WaitingForVta"),
            "an operator should not read an internal name: {}",
            resolution.reason
        );
        assert!(
            resolution
                .reason
                .contains("start the bundled trust agent"),
            "{}",
            resolution.reason
        );
    }

    #[test]
    fn a_bootstrap_that_was_connected_never_falls_back_to_a_different_issuer_key() {
        use crate::vta::bundled::BootstrapState;
        for state in [
            BootstrapState::Revoked,
            BootstrapState::VtaLost,
            BootstrapState::VtaReplaced,
            BootstrapState::WaitingForVta,
        ] {
            let status = bootstrap_status(state, true);

            let resolution = with_bundled_bootstrap(DefaultResolution::bundled("explicit", true), Some(&status));

            assert_eq!(resolution.backend, "bundled", "{state:?} must not switch to local");
            assert!(
                resolution
                    .fallback_from
                    .is_none(),
                "{state:?}"
            );
            assert!(
                resolution
                    .reason
                    .contains("refused"),
                "{}",
                resolution.reason
            );
        }
    }
}
