//! Keeping the VTA off the data plane.
//!
//! A bundled VTA sidecar sits on loopback or a private compose network — the
//! same address space a surface is legitimately allowed to forward to. That
//! makes it reachable, in principle, as an ordinary MCP/A2A/surface upstream,
//! which would let a caller drive the agent that holds this gateway's signing
//! keys through the proxy pipeline. The VTA is a **control-plane** dependency
//! and must never be addressable from the data plane.
//!
//! Attacker-influenceable targets are already refused by
//! [`crate::egress::EgressPolicy::Strict`], which blocks loopback and RFC 1918.
//! The gap this module closes is the **forward leg**, which deliberately allows
//! those ranges so an operator-configured surface can reach a localhost
//! sidecar — exactly the shape a bundled VTA has.
//!
//! ## Why origin-level, and why a reservation rather than a range
//!
//! Matching is on `(host, port)`: path and scheme are ignored, because
//! `/trust-tasks` and `/` are the same service and an http/https downgrade is
//! not a different agent. Blocking by *range* instead would also block every
//! legitimate localhost sidecar an operator runs, so only the endpoints the
//! gateway itself was configured with are reserved.

use std::collections::BTreeSet;
use std::sync::RwLock;

use url::Url;

/// Origins the gateway talks to as a VTA, and therefore refuses to proxy to.
///
/// Populated once at startup from operator bootstrap config and the stored
/// connection records — never from request input, so it cannot be poisoned by
/// a caller into blocking a legitimate upstream.
static RESERVED: RwLock<BTreeSet<String>> = RwLock::new(BTreeSet::new());

/// Canonical `(host, port)` key for an endpoint, or `None` when it names no
/// host (a unix socket path, a relative URL).
fn origin_key(raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = url
        .host_str()?
        .to_ascii_lowercase();
    // A missing port means the scheme default; normalising it here is what
    // makes `http://vta` and `http://vta:80` the same reservation.
    let port = url
        .port_or_known_default()
        .unwrap_or(0);
    Some(format!("{host}:{port}"))
}

/// Reserve `endpoint` as a VTA address. Idempotent; a non-URL or hostless
/// endpoint (unix socket) is ignored, because there is nothing a proxy target
/// could name it by.
pub fn reserve(endpoint: &str) {
    let Some(key) = origin_key(endpoint) else {
        return;
    };
    if let Ok(mut reserved) = RESERVED.write() {
        reserved.insert(key);
    }
}

/// Whether `raw` points at a reserved VTA origin.
///
/// A poisoned lock yields `true`: refusing a forward is recoverable, letting
/// one through to the key-holding agent is not.
pub fn is_reserved(raw: &str) -> bool {
    let Some(key) = origin_key(raw) else {
        return false;
    };
    match RESERVED.read() {
        Ok(reserved) => reserved.contains(&key),
        Err(_) => true,
    }
}

/// Refuse `raw` if it names a VTA. The message is deliberately explicit about
/// *why*, because an operator who typed the sidecar address into a surface
/// needs to understand it is not a configuration mistake they can work around.
pub fn assert_not_vta(raw: &str) -> Result<(), String> {
    if is_reserved(raw) {
        return Err("this address belongs to a Verifiable Trust Agent this gateway signs with; \
             a VTA is a control-plane dependency and cannot be used as a proxy target"
            .to_string());
    }
    Ok(())
}

/// Every reserved origin, for diagnostics.
pub fn reserved_origins() -> Vec<String> {
    RESERVED
        .read()
        .map(|reserved| {
            reserved
                .iter()
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn clear_reservations() {
    if let Ok(mut reserved) = RESERVED.write() {
        reserved.clear();
    }
}

/// `RESERVED` is process-wide, so every test that writes it — here and in
/// `egress` — must hold this.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// `RESERVED` is process-wide, so these tests must not interleave.
    use super::TEST_LOCK as LOCK;

    #[test]
    fn a_reserved_sidecar_cannot_be_named_as_a_proxy_target() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("http://127.0.0.1:3000");

        // The whole origin is off-limits, whatever path or scheme is used to
        // dress it up — `/trust-tasks` and `/` are the same service.
        for attempt in [
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:3000/trust-tasks",
            "https://127.0.0.1:3000/trust-tasks",
            "http://127.0.0.1:3000/../anything",
        ] {
            assert!(is_reserved(attempt), "`{attempt}` reached the VTA");
            let err = assert_not_vta(attempt).expect_err("must be refused");
            assert!(err.contains("Verifiable Trust Agent"), "unexpected error: {err}");
        }

        clear_reservations();
    }

    #[test]
    fn an_unrelated_localhost_sidecar_is_untouched() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("http://127.0.0.1:3000");

        // Reserving a *range* would break every legitimate localhost upstream,
        // so only the configured VTA origin is refused.
        for allowed in ["http://127.0.0.1:8080/mcp", "http://localhost:3000/mcp", "https://upstream.example/a2a"] {
            assert!(!is_reserved(allowed), "`{allowed}` was wrongly refused");
            assert_not_vta(allowed).expect("an unrelated upstream must still work");
        }

        clear_reservations();
    }

    #[test]
    fn the_default_port_is_normalised_so_it_cannot_be_dodged() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("https://vta.internal");

        assert!(is_reserved("https://vta.internal:443/trust-tasks"), "an explicit default port dodged the block");
        assert!(is_reserved("https://VTA.INTERNAL/trust-tasks"), "case dodged the block");
        // A different port is a different service.
        assert!(!is_reserved("https://vta.internal:8443/trust-tasks"));

        clear_reservations();
    }

    #[test]
    fn hostless_and_unparseable_endpoints_reserve_nothing() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("/var/run/vta.sock");
        reserve("not a url");
        reserve("");
        assert!(
            reserved_origins().is_empty(),
            "a unix socket has no origin a proxy target could name: {:?}",
            reserved_origins()
        );
        clear_reservations();
    }

    #[test]
    fn reservation_is_idempotent_and_reported() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("http://127.0.0.1:3000");
        reserve("http://127.0.0.1:3000/trust-tasks");
        reserve("http://vta:3000");

        assert_eq!(reserved_origins(), vec!["127.0.0.1:3000".to_string(), "vta:3000".to_string()]);
        clear_reservations();
    }
}
