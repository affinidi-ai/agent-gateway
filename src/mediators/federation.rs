//! The `mediator_federation` dashboard feature flag.
//!
//! Off by default. While off, `connect-via-oob` refuses `acceptor_mediator_id`.
//! While on, the acceptor may home its permanent connection point on its own
//! mediator. The flag does not change how messages are sent: a send is
//! forwarded through the sender's own mediator whenever the recipient is on
//! another one. Read per request from settings, like `ap2_experimental`.

use std::collections::HashMap;

pub const FLAG_MEDIATOR_FEDERATION: &str = "mediator_federation";

/// Absent means disabled.
pub fn federation_enabled_from_flags(feature_flags: Option<&HashMap<String, bool>>) -> bool {
    feature_flags
        .and_then(|flags| {
            flags
                .get(FLAG_MEDIATOR_FEDERATION)
                .copied()
        })
        .unwrap_or(false)
}

/// Whether per-gateway mediator federation is enabled. False when settings
/// are unavailable.
pub fn mediator_federation_enabled() -> bool {
    crate::storage::settings_store::global_settings()
        .map(|settings| federation_enabled_from_flags(Some(&settings.feature_flags)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_is_off_unless_the_flag_is_explicitly_true() {
        assert!(!federation_enabled_from_flags(None));
        assert!(!federation_enabled_from_flags(Some(&HashMap::new())));
        assert!(!federation_enabled_from_flags(Some(&HashMap::from([(FLAG_MEDIATOR_FEDERATION.to_string(), false)]))));
        assert!(federation_enabled_from_flags(Some(&HashMap::from([(FLAG_MEDIATOR_FEDERATION.to_string(), true)]))));
    }
}
