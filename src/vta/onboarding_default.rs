//! What a gateway signs with when nobody has said.
//!
//! A gateway keeps signing with its own issuer key unless an operator connects
//! a trust agent. Nothing is inferred from the state of the disk: a rebuilt
//! volume or an agent that happens to be down must never change which backend
//! signs.
//!
//! ## The reversibility invariant
//!
//! Resolving a default **never** migrates, rewrites or deletes a key. It only
//! decides which backend new signatures use. Per-surface migration stays
//! opt-in with both keys published, so switching back is always possible and
//! nothing ever becomes unverifiable.

use serde::{Deserialize, Serialize};

use crate::config::vta::VtaConfig;

/// The appliance-wide signing default, as an operator writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultBackend {
    /// The gateway's own issuer key. The default.
    #[default]
    Auto,
    /// Always the gateway's own issuer key, whatever the install looks like.
    LegacyLocal,
}

/// What the appliance will actually sign with, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultResolution {
    /// `local` or `vta`.
    pub backend: &'static str,
    /// Operator-facing explanation. Surfaced in the advanced settings so the
    /// answer to "why is it signing with this?" never requires reading code.
    pub reason: String,
    /// Whether an operator (or a fleet config) chose this explicitly, as
    /// opposed to it being inferred.
    pub explicit: bool,
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
        return DefaultResolution {
            backend: "vta",
            reason: "the [vta] block is enabled, so this appliance signs through its configured agent".to_string(),
            explicit: true,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled() -> VtaConfig {
        VtaConfig::default()
    }

    fn enabled() -> VtaConfig {
        VtaConfig {
            enabled: true,
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
            resolve(&enabled()).reason,
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
    }

    /// Fleet and IaC installs must never need the dashboard, so the default is
    /// expressible in config alone.
    #[test]
    fn the_default_is_settable_from_config() {
        let cfg: VtaConfig = toml::from_str("default_backend = \"legacy_local\"").expect("parse");
        assert_eq!(cfg.default_backend, DefaultBackend::LegacyLocal);
        assert_eq!(resolve(&cfg).backend, "local");

        let bare: VtaConfig = toml::from_str("").expect("parse");
        assert_eq!(bare.default_backend, DefaultBackend::Auto);
        assert_eq!(resolve(&bare).backend, "local", "absent means the local key");
    }

    #[test]
    fn a_retired_default_backend_is_refused_rather_than_ignored() {
        assert!(toml::from_str::<VtaConfig>("default_backend = \"bundled\"").is_err());
    }

    /// A default that could override configured behaviour would not be a
    /// default.
    #[test]
    fn an_enabled_vta_block_always_wins_over_any_default() {
        for backend in [DefaultBackend::Auto, DefaultBackend::LegacyLocal] {
            let cfg = VtaConfig {
                default_backend: backend,
                ..enabled()
            };
            let resolved = resolve(&cfg);
            assert_eq!(resolved.backend, "vta", "the configured agent must win over `{backend:?}`");
            assert!(resolved.explicit);
        }
    }
}
