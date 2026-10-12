# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

[`AGENTS.md`](AGENTS.md) is the canonical source of project rules, architecture and workflow,
including the mandatory `.changelog/wip/<branch>.yaml` fragment and the never-push rule. It is
imported below so its content loads with this file; do not duplicate it here.

@AGENTS.md

For dashboard work under `www/default/`, also follow [`www/default/AGENTS.md`](www/default/AGENTS.md).

## Commands

Run `make help` for the full target list. The ones used most:

| Task | Command |
| --- | --- |
| Fast compile check | `make check` |
| Build backend and frontend | `make dev` |
| Run locally (builds www + cargo) | `make run-debug` (`x=<name>` for a named instance) |
| All Rust tests | `make test` (`test=<name>` filters) |
| Tests for one module | `cargo test --bin agent-gateway '<module name>'` |
| Frontend unit tests | `make npm-test` |
| Playwright UI tests | `make ui-test` |
| Lint everything (fmt check, Clippy, ESLint, ShellCheck) | `make lint` |
| Format Rust and frontend | `make fmt` |
| Local CI preflight | `make ci` |
| MCP conformance | `make mcp-conformance` |

`make test`, `make ui-test` and the other test targets depend on `config-test`, which prepares
the certificates and keys the tests need. Run it once before invoking `cargo test` directly.
