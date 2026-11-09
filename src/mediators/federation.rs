//! The `mediator_federation` dashboard feature flag.
//!
//! Off by default. While off, `connect-via-oob` refuses `acceptor_mediator_id`.
//! While on, the acceptor may home its permanent connection point on its own
//! mediator. The flag does not change how messages are sent: a send is
//! forwarded through the sender's own mediator whenever the recipient is on
//! another one. Read per request from the system settings, like `ap2_experimental`.

pub const FLAG_MEDIATOR_FEDERATION: &str = "mediator_federation";

/// Whether per-gateway mediator federation is enabled. False when settings
/// are unavailable.
pub fn mediator_federation_enabled() -> bool {
    crate::storage::settings_store::system_flag_enabled(FLAG_MEDIATOR_FEDERATION)
}
