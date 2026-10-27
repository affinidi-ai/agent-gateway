//! What a gateway signs with when nobody has said.
//!
//! A new install must ask nothing about keys or agents: it picks a working
//! default and just works. An **existing** install must change nothing at all
//! — upgrading is not consent, and the key it has been signing with is the key
//! it keeps signing with until an operator opts in.
//!
//! Those two requirements point in opposite directions, so the distinction is
//! made explicitly rather than inferred from config that looks the same in
//! both cases.
//!
//! ## How "existing install" is detected
//!
//! By the presence of a local issuer key on disk. That is the honest signal:
//! the key exists precisely because this gateway has already been signing with
//! it, and anything it signed is verifiable against it. A fresh install has
//! nothing to preserve, so it is free to take the better default.
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
    /// Decide from the install: bundled for a new one, local for an existing
    /// one. The default, because it is the only value that is right for both.
    #[default]
    Auto,
    /// Always the in-process issuer key, whatever the install looks like.
    LegacyLocal,
    /// Always the bundled sidecar.
    Bundled,
}

/// Whether this gateway has signed anything before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallKind {
    /// No local issuer key on disk — nothing to preserve.
    Fresh,
    /// A local issuer key already exists, so something may already have been
    /// signed with it.
    Existing,
}

impl InstallKind {
    /// Classify from whether a local issuer key is already present.
    pub fn from_local_key_present(present: bool) -> Self {
        if present {
            Self::Existing
        } else {
            Self::Fresh
        }
    }
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
pub fn resolve(
    config: &VtaConfig,
    install: InstallKind,
) -> DefaultResolution {
    if config.enabled {
        let backend = if config.mode == VtaMode::Bundled {
            "bundled"
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

    match (config.default_backend, install) {
        (DefaultBackend::LegacyLocal, _) => {
            DefaultResolution::local("`default_backend = \"legacy_local\"` was set explicitly", true)
        }
        (DefaultBackend::Bundled, _) => {
            DefaultResolution::bundled("`default_backend = \"bundled\"` was set explicitly", true)
        }
        // Upgrading is not consent. An existing install keeps signing with the
        // key it already signed with, and nothing is migrated.
        (DefaultBackend::Auto, InstallKind::Existing) => DefaultResolution::local(
            "this gateway already has a local issuer key, so it keeps using it; connect an agent to change that",
            false,
        ),
        (DefaultBackend::Auto, InstallKind::Fresh) => DefaultResolution::bundled(
            "a new install defaults to the bundled agent, so there is nothing to set up",
            false,
        ),
    }
}

/// Fold in whether the chosen backend is actually usable.
///
/// A bundled agent that did not come up must not block onboarding, and must
/// not be papered over either. Falling back to the **local** key is safe here
/// precisely because this path is only reachable on a fresh install or an
/// explicit choice: there is no older key whose artifacts would stop
/// verifying, so nothing signs with a key an operator would not expect.
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

    // ---- the two install shapes ------------------------------------------

    #[test]
    fn a_fresh_install_needs_no_questions_and_gets_the_bundled_agent() {
        let resolved = resolve(&disabled(), InstallKind::Fresh);
        assert_eq!(resolved.backend, "bundled");
        assert!(!resolved.explicit, "nobody was asked");
        assert!(
            resolved
                .reason
                .contains("new install"),
            "the reason must be operator-readable: {}",
            resolved.reason
        );
    }

    /// Upgrading is not consent: the key this gateway already signed with is
    /// the key it keeps signing with.
    #[test]
    fn an_existing_install_keeps_its_local_key_with_no_behaviour_change() {
        let resolved = resolve(&disabled(), InstallKind::Existing);
        assert_eq!(resolved.backend, "local");
        assert!(!resolved.explicit);
        assert!(
            resolved
                .reason
                .contains("already has a local issuer key"),
            "unexpected reason: {}",
            resolved.reason
        );
        assert!(
            resolved
                .fallback_from
                .is_none(),
            "nothing failed; this is the intended outcome"
        );
    }

    #[test]
    fn the_install_kind_follows_the_presence_of_a_local_key() {
        assert_eq!(InstallKind::from_local_key_present(true), InstallKind::Existing);
        assert_eq!(InstallKind::from_local_key_present(false), InstallKind::Fresh);
    }

    // ---- explicit configuration wins -------------------------------------

    #[test]
    fn an_explicit_default_is_honoured_on_both_install_shapes() {
        for install in [InstallKind::Fresh, InstallKind::Existing] {
            let local = resolve(
                &VtaConfig {
                    default_backend: DefaultBackend::LegacyLocal,
                    ..disabled()
                },
                install,
            );
            assert_eq!(local.backend, "local");
            assert!(local.explicit, "a configured value is an explicit choice");

            let bundled = resolve(
                &VtaConfig {
                    default_backend: DefaultBackend::Bundled,
                    ..disabled()
                },
                install,
            );
            assert_eq!(bundled.backend, "bundled");
            assert!(bundled.explicit);
        }
    }

    /// Fleet and IaC installs must never need the dashboard, so the default is
    /// expressible in config alone.
    #[test]
    fn the_default_is_settable_from_config() {
        let cfg: VtaConfig = toml::from_str("default_backend = \"bundled\"").expect("parse");
        assert_eq!(cfg.default_backend, DefaultBackend::Bundled);
        assert_eq!(resolve(&cfg, InstallKind::Existing).backend, "bundled");

        // Absent means `auto`, which is the only value right for both shapes.
        let bare: VtaConfig = toml::from_str("").expect("parse");
        assert_eq!(bare.default_backend, DefaultBackend::Auto);
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
            let resolved = resolve(&cfg, InstallKind::Existing);
            assert_eq!(resolved.backend, "vta", "the configured agent must win over `{backend:?}`");
            assert!(resolved.explicit);
        }

        let bundled = resolve(&enabled(VtaMode::Bundled), InstallKind::Fresh);
        assert_eq!(bundled.backend, "bundled");
    }

    // ---- safe fallback ----------------------------------------------------

    #[test]
    fn an_unavailable_bundled_agent_does_not_block_onboarding() {
        let resolved = with_availability(resolve(&disabled(), InstallKind::Fresh), false);

        // Onboarding completes: there is a usable answer, not an error.
        assert_eq!(resolved.backend, "local");
        // And it is reported, not papered over.
        assert_eq!(resolved.fallback_from, Some("bundled"));
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
        let local = resolve(&disabled(), InstallKind::Existing);
        assert_eq!(with_availability(local.clone(), false), local, "a local default has nothing to fall back from");

        let bundled = resolve(&disabled(), InstallKind::Fresh);
        assert_eq!(with_availability(bundled.clone(), true), bundled, "an available agent is used as chosen");
    }

    /// The fallback is only ever to the local key, and only where no older key
    /// exists — so nothing signs with a key an operator would not expect.
    #[test]
    fn the_fallback_never_reaches_an_existing_install_implicitly() {
        let resolved = resolve(&disabled(), InstallKind::Existing);
        assert_eq!(resolved.backend, "local", "an existing install never auto-selects bundled, so it cannot fall back");
    }
}
