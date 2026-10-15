# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` is the canonical rule file for this repository. It is imported below, so its
rules (changelog fragments, no pushes, docs in sync, no history comments) apply to every
change. Do not copy its content here; update `AGENTS.md` instead.

@AGENTS.md

## Claude-specific notes

- Nested `AGENTS.md` files are not loaded automatically. Before editing anything under
  `www/default/`, read [`www/default/AGENTS.md`](www/default/AGENTS.md); UI changes must
  update it in the same change.
- Before touching the request path, read [`ARCHITECTURE.md`](ARCHITECTURE.md). It is the
  authority on pipeline stage order (inbound, outbound, Fabric) and on the invariants.
- Use the terms in [`CONTEXT.md`](CONTEXT.md) (Agent Surface, Access Point, Target,
  Transit Point, Trust Check, Fabric) in code, docs, and Gherkin.

## Big picture

- One Rust binary (`agent-gateway`, edition 2024, Rust 1.95+) plus a React dashboard
  (`www/default/`) served by the same process. No database: a DashMap cache is
  authoritative at runtime, persisted as JSON under `_storage/`.
- Two planes: the management plane (REST API under `/api/v1/…` plus dashboard, on the
  bootstrap TLS port) and the data plane (listeners from `gateway.json`, one per Agent
  Surface Access Point or Transit Point).
- Startup: `src/main.rs` loads the bootstrap TOML and surfaces, then
  `server::run_axum_proxy` (`src/server/orchestrator.rs`) wires stores, connection
  points, routers, and listeners.
- Inbound pipeline: `src/proxy/handler.rs`. Outbound pipeline:
  `src/proxy/outbound_handler.rs`. Fabric send: `src/proxy/fabric_forward.rs`; receive:
  `src/gateways/connection_points/message_processor.rs`.
- Policy is Regorus (in-process Rego) in `src/policies/`. Policy input types live in
  `src/surface_context/`. All outbound HTTP goes through the DNS-pinning SSRF guard in
  `src/egress.rs`.
- ts-rs exports TypeScript bindings into `www/default/src/generated/` (tracked) when Rust
  tests run, so a Rust type change can produce frontend diffs.

## Running tests

Run `make config-test` once (certs and keys) before calling `cargo test` directly.

| Goal | Command |
| --- | --- |
| Compile check of tests | `cargo test --no-run` |
| One module or test by name | `cargo test --bin agent-gateway '<name filter>'` |
| Component tests | `cargo test --bin agent-gateway component_tests` |
| Policy engine tests | `make test-policies` |
| Single-gateway BDD (Cucumber) | `cargo test --test surface_bdd` |
| Gateway-to-gateway BDD (needs Docker) | `make gw-e2e` (`G2G_BDD_PARALLELISM=1` to debug) |
| Frontend unit tests (Jest) | `make npm-test` |
| Dashboard Playwright tests | `make ui-test` |

BDD features live in `tests/features/{surface,g2g}/`; `scripts/bdd-gherkin.py` lists
existing steps. [`docs/development/TESTING.md`](docs/development/TESTING.md) says which
test layer a change belongs in.
