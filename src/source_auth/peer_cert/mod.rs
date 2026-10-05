//! Inbound peer-certificate capture for mTLS source authentication.
//!
//! Two paths can populate [`PeerCertInfo`] on a request:
//!
//! * **Forwarded** ([`forwarded`]): an upstream TLS-terminating proxy
//!   forwards the client cert in an HTTP header. Honoured only when the
//!   immediate peer IP is in the configured trusted-proxies list. Pure
//!   tower layer — no listener changes required.
//! * **Direct** ([`direct`]): the gateway terminates TLS itself and
//!   captures the peer cert from the rustls server connection during
//!   the handshake via [`direct::PeerCertAcceptor`].
//!
//! The middleware ([`crate::source_auth::middleware`]) treats the two
//! paths identically; per-channel `MtlsAuthConfig::allow_forwarded`
//! decides whether `Forwarded` is acceptable on that channel.

pub mod direct;
pub mod forwarded;

pub use direct::{PeerCertAcceptor, load_inbound_client_auth, promote_direct_peer_cert};
pub use forwarded::forwarded_peer_cert;
