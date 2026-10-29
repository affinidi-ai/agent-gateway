//! State management for proxy handlers

pub mod multi_channel;
pub mod outbound;
pub mod proxy;

pub use multi_channel::{ActiveVariant, MultiSurfaceProxyState};
pub use outbound::{OutboundProxyState, OutboundSurfaceState};
pub use proxy::{ProxyState, SurfaceInfo};
