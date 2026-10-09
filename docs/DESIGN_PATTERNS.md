# Internal Rust Design Patterns

Source-development guidance for contributors. For product architecture, use the hosted
[Agent Gateway architecture](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/concepts/architecture/).

This page records recurring implementation patterns and current type or method names. Product
behavior belongs in the topic-specific architecture documents.

## Shared runtime state

`MultiSurfaceProxyState.channels` is an `Arc<RwLock<Vec<SurfaceInfo>>>`. Request handling takes a
read lock to resolve a surface, while `SurfaceTaskManager::reload_single_channel` builds a
replacement `SurfaceInfo` and swaps it under a short write lock. Build expensive derived state
before acquiring the write lock whenever possible.

DashMap-backed filesystem stores use a separate serialized reconciliation path. Their shared
per-store refresh lock prevents overlapping scans from applying snapshots out of order.

## RAII connection accounting

[`ConnectionGuard`](../src/server/connection_guard.rs) owns active-connection accounting for a
request. Normal completion calls `ConnectionGuard::decrement`; `Drop` schedules best-effort cleanup
when an early return or abnormal disconnect bypasses that call. New request paths should retain the
guard for the full lifetime of the counted operation. A streamed response (SSE passthrough, legacy
`GET /sse`, the Streamable HTTP notification stream and modern MCP streams) moves its guard into the
response body, so the connection stays counted until the body ends or the client drops it. Active
connection counts are not reset on idle, so a quiet long-lived stream stays visible.

## Storage traits and composites

[`MetricsBackend`](../src/metrics/backends/types.rs) defines `persist`, `load`, and `name`.
[`MultiBackend`](../src/metrics/backends/multi.rs) composes configured implementations: persistence
runs across all backends and logs an individual backend failure, while loading returns the first
non-empty snapshot. Callers depend on the trait rather than backend-specific behavior.

## Weak callbacks from owned tasks

`ConnectionPointListenerManager` uses `Arc::new_cyclic` and
`ConnectionPointListenerManager::with_self_ref_and_channel` to give listener tasks a `Weak<Self>`
callback. A task upgrades the weak reference immediately before use. Do not retain a strong manager
reference inside a task owned by that manager, because it would prevent shutdown cleanup.

## One-shot state publication

`SurfaceTaskManager::reload_channels` creates a Tokio `oneshot` for each inbound port listener and
passes its sender to `run_port_server`. The child publishes its `Arc<MultiSurfaceProxyState>` once;
the manager stores the received state for later single-surface updates. Use this pattern when a
spawned owner must publish one initialized value, rather than introducing a shared mutable slot.

## Batched metrics persistence

`MetricsStore::start_periodic_save` batches dirty in-memory metrics into periodic backend writes.
Mutation paths mark the store dirty; the periodic task persists a snapshot instead of writing on
every request. Shutdown paths are responsible for their explicit final flush.

## Builder-style optional dependencies

`ConnectionPointListenerManager::new` establishes required dependencies, and methods such as
`with_gateway_store`, `with_pending_connection_store`, `with_bootstrap_config`,
`with_network_config`, `with_mediator_store`, and `with_notification_store` attach optional
subsystems. Keep required dependencies in the constructor and use these methods only where absence
has a defined behavior.

## Atomic lifecycle gates

Long-lived listener managers use `listeners_active: Arc<AtomicBool>` to prevent new listener work
while the appliance is Standby. The atomic is a fast admission gate, not ownership
or completion tracking; shutdown still drains or aborts the relevant tasks through their lifecycle
manager.

Appliance readiness uses the generation-fenced state in `src/server/mode.rs`, not the listener
boolean.
