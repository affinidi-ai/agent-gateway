//! Keeping the VTA off the data plane.
//!
//! A trust agent can sit on loopback or a private network — the same address
//! space a surface is legitimately allowed to forward to. That makes it
//! reachable, in principle, as an ordinary MCP/A2A/surface upstream,
//! which would let a caller drive the agent that holds this gateway's signing
//! keys through the proxy pipeline. The VTA is a **control-plane** dependency
//! and must never be addressable from the data plane.
//!
//! Attacker-influenceable targets are already refused by
//! [`crate::egress::EgressPolicy::Strict`], which blocks loopback and RFC 1918.
//! The gap this module closes is the **forward leg**, which deliberately allows
//! those ranges so an operator-configured surface can reach a localhost
//! service — exactly the shape a co-located VTA has.
//!
//! ## Why origin-level, and why a reservation rather than a range
//!
//! Matching is on `(host, port)`: path and scheme are ignored, because
//! `/trust-tasks` and `/` are the same service and an http/https downgrade is
//! not a different agent. Blocking by *range* instead would also block every
//! legitimate localhost service an operator runs, so only the endpoints the
//! gateway itself was configured with are reserved.
//!
//! ## Which connection records reserve their endpoint
//!
//! The `[vta]` block's address is reserved for the life of the process. A
//! stored connection reserves its endpoint once it has been verified (it is
//! `connected` or `degraded`), enabled or not, and stops reserving it when it is
//! deleted, revoked or pointed elsewhere and no other such record uses the
//! origin. An unverified record has proved nothing about its endpoint, so it
//! cannot take an arbitrary upstream off the data plane.

use std::collections::BTreeSet;
use std::sync::RwLock;

use url::Url;

/// Origins the gateway talks to as a VTA, and therefore refuses to proxy to.
///
/// Populated from operator bootstrap config — never from request input, so it
/// cannot be poisoned by a caller into blocking a legitimate upstream.
static RESERVED: RwLock<BTreeSet<String>> = RwLock::new(BTreeSet::new());

/// Origins of the verified connection records, replaced as a whole by
/// [`sync_connection_reservations`].
static CONNECTION_ORIGINS: RwLock<BTreeSet<String>> = RwLock::new(BTreeSet::new());

/// Serialises [`sync_connection_reservations`], so a slower sync cannot write
/// back a listing older than one already applied.
static SYNC: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The host part of the key of every name this host answers to.
const LOCAL_HOST: &str = "loopback";

/// Canonical `(host, port)` key for an endpoint, or `None` when it names no
/// host (a unix socket path, a relative URL). Every name of this host itself
/// (`localhost`, a loopback or unspecified address) is one host, so a trust
/// agent reserved at one of them is reserved at all of them.
pub fn origin_key(raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = match url.host()? {
        url::Host::Domain(domain) => {
            let domain = domain
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain == "localhost" || domain.ends_with(".localhost") {
                LOCAL_HOST.to_string()
            } else {
                domain
            }
        }
        url::Host::Ipv4(ip) if ip.is_loopback() || ip.is_unspecified() => LOCAL_HOST.to_string(),
        url::Host::Ipv6(ip)
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified()) =>
        {
            LOCAL_HOST.to_string()
        }
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => format!("[{ip}]"),
    };
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
    if !recording() {
        return;
    }
    let Some(key) = origin_key(endpoint) else {
        return;
    };
    if let Ok(mut reserved) = RESERVED.write() {
        reserved.insert(key);
    }
}

/// Reserve the endpoint of a connection the gateway is about to sign through.
/// Held until a [`sync_connection_reservations`] finds no verified record
/// using it.
pub fn reserve_connection(endpoint: &str) {
    if !recording() {
        return;
    }
    let Some(key) = origin_key(endpoint) else {
        return;
    };
    if let Ok(mut origins) = CONNECTION_ORIGINS.write() {
        origins.insert(key);
    }
}

/// Whether `connection` takes its endpoint off the data plane: it has been
/// verified against the trust agent at that address.
pub fn reserves_endpoint(connection: &crate::vta::connections::VtaConnection) -> bool {
    use crate::vta::pairing::PairingState;
    matches!(connection.pairing.state, PairingState::Connected | PairingState::Degraded)
}

/// Recompute the connection reservations from the stored records, releasing
/// any origin no verified record uses. A store that cannot be listed leaves
/// the current reservations in place.
pub async fn sync_connection_reservations(store: &dyn crate::vta::connections::VtaConnectionStorage) {
    let _guard = SYNC.lock().await;
    let connections = match store.list().await {
        Ok(connections) => connections,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list VTA connections; their endpoint reservations are unchanged");
            return;
        }
    };
    let origins: BTreeSet<String> = connections
        .iter()
        .filter(|connection| reserves_endpoint(connection))
        .filter_map(|connection| origin_key(&connection.endpoint))
        .collect();
    if !recording() {
        return;
    }
    if let Ok(mut current) = CONNECTION_ORIGINS.write() {
        *current = origins;
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
    [&RESERVED, &CONNECTION_ORIGINS]
        .iter()
        .any(|set| match set.read() {
            Ok(reserved) => reserved.contains(&key),
            Err(_) => true,
        })
}

/// Refuse `raw` if it names a VTA. The message is deliberately explicit about
/// *why*, because an operator who typed the trust agent address into a surface
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
    let mut origins = BTreeSet::new();
    for set in [&RESERVED, &CONNECTION_ORIGINS] {
        if let Ok(reserved) = set.read() {
            origins.extend(reserved.iter().cloned());
        }
    }
    origins.into_iter().collect()
}

#[cfg(test)]
pub(crate) fn clear_reservations() {
    for set in [&RESERVED, &CONNECTION_ORIGINS] {
        if let Ok(mut reserved) = set.write() {
            reserved.clear();
        }
    }
}

/// Whether reservations are recorded. Always, except in unit tests: there the
/// reservations are process-wide while each test's mock trust agent listens on
/// a loopback port another test may be given next, so only a test that holds
/// [`TEST_LOCK`] records them, on its own thread, and they are cleared when it
/// lets go.
#[cfg(not(test))]
fn recording() -> bool {
    true
}

#[cfg(test)]
thread_local! {
    static RECORDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn recording() -> bool {
    RECORDING.with(std::cell::Cell::get)
}

/// The lock a test that checks reservations holds: it records them on the
/// holding thread only, and clears them before and after.
#[cfg(test)]
pub(crate) struct ReservationTestLock(std::sync::Mutex<()>);

#[cfg(test)]
pub(crate) struct RecordingReservations<'a>(#[allow(dead_code)] std::sync::MutexGuard<'a, ()>);

#[cfg(test)]
impl ReservationTestLock {
    pub(crate) fn lock(&self) -> Result<RecordingReservations<'_>, std::convert::Infallible> {
        let guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_reservations();
        RECORDING.with(|recording| recording.set(true));
        Ok(RecordingReservations(guard))
    }
}

#[cfg(test)]
impl Drop for RecordingReservations<'_> {
    fn drop(&mut self) {
        RECORDING.with(|recording| recording.set(false));
        clear_reservations();
    }
}

/// `RESERVED` is process-wide, so every test that writes it — here and in
/// `egress` — must hold this.
#[cfg(test)]
pub(crate) static TEST_LOCK: ReservationTestLock = ReservationTestLock(std::sync::Mutex::new(()));

#[cfg(test)]
mod tests {
    use super::*;

    /// `RESERVED` is process-wide, so these tests must not interleave.
    use super::TEST_LOCK as LOCK;

    #[test]
    fn a_reserved_trust_agent_cannot_be_named_as_a_proxy_target() {
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
    fn an_unrelated_localhost_service_is_untouched() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("http://127.0.0.1:3000");

        // Reserving a *range* would break every legitimate localhost upstream,
        // so only the configured VTA origin is refused.
        for allowed in ["http://127.0.0.1:8080/mcp", "http://localhost:3001/mcp", "https://upstream.example/a2a"] {
            assert!(!is_reserved(allowed), "`{allowed}` was wrongly refused");
            assert_not_vta(allowed).expect("an unrelated upstream must still work");
        }

        clear_reservations();
    }

    #[test]
    fn another_name_of_this_host_cannot_reach_a_reserved_local_agent() {
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("http://127.0.0.1:3000");

        for attempt in [
            "http://localhost:3000/mcp",
            "http://LOCALHOST.:3000/mcp",
            "http://agent.localhost:3000/mcp",
            "http://127.0.0.2:3000/mcp",
            "http://0.0.0.0:3000/mcp",
            "http://[::1]:3000/mcp",
            "http://[::ffff:127.0.0.1]:3000/mcp",
        ] {
            assert!(is_reserved(attempt), "`{attempt}` reached the local trust agent");
        }
        assert!(!is_reserved("http://10.0.0.1:3000/mcp"), "another host is another service");

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

        assert_eq!(reserved_origins(), vec!["loopback:3000".to_string(), "vta:3000".to_string()]);
        clear_reservations();
    }

    fn record(
        id: &str,
        endpoint: &str,
        state: crate::vta::pairing::PairingState,
    ) -> crate::vta::connections::VtaConnection {
        let now = chrono::Utc::now();
        crate::vta::connections::VtaConnection {
            id: id.to_string(),
            tenant_id: None,
            name: id.to_string(),
            description: None,
            enabled: true,
            transport: Default::default(),
            endpoint: endpoint.to_string(),
            vta_did: "did:webvh:vta.example".to_string(),
            default_context_id: None,
            control_key_ref: Some("key".to_string()),
            control_did: None,
            control_key_state: Default::default(),
            status: Default::default(),
            keys: Default::default(),
            pairing: crate::vta::pairing::PairingRecord { state, ..Default::default() },
            created_at: now,
            updated_at: now,
            retired_at: None,
        }
    }

    #[test]
    fn only_verified_connections_reserve_and_an_origin_is_released_once_nothing_uses_it() {
        use crate::vta::connections::{FileSystemVtaConnectionStore, VtaConnectionStorage};
        use crate::vta::pairing::PairingState;
        let _guard = LOCK.lock().unwrap();
        clear_reservations();
        reserve("https://bootstrap.vta:8443");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = runtime
            .block_on(FileSystemVtaConnectionStore::new(dir.path().to_path_buf()))
            .unwrap();
        for connection in [
            record("draft", "https://upstream.example", PairingState::Draft),
            record("a", "https://vta.example", PairingState::Connected),
            record("b", "https://vta.example/other", PairingState::Degraded),
        ] {
            runtime
                .block_on(store.create(connection))
                .unwrap();
        }

        runtime.block_on(sync_connection_reservations(&store));
        assert!(!is_reserved("https://upstream.example/mcp"), "an unverified record reserved its endpoint");
        assert!(is_reserved("https://vta.example/trust-tasks"));

        runtime
            .block_on(store.delete("a"))
            .unwrap();
        runtime.block_on(sync_connection_reservations(&store));
        assert!(is_reserved("https://vta.example/trust-tasks"), "another verified record still uses the origin");

        runtime
            .block_on(store.update(record("b", "https://vta.example/other", PairingState::Revoked)))
            .unwrap();
        runtime.block_on(sync_connection_reservations(&store));
        assert!(!is_reserved("https://vta.example/trust-tasks"), "a revoked record kept its origin reserved");
        assert!(is_reserved("https://bootstrap.vta:8443"), "the [vta] block's address is never released");

        clear_reservations();
    }
}
