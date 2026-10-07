# MCP conformance harness

Runs the published MCP conformance suite against Agent Trust Gateway, scored
against the suite's frozen `2026-07-28` requirement set, then runs the checks
the suite does not make and a legacy `2024-11-05` compatibility check. The
gateway-side contract (which paths it covers, what the baselines mean) is in
[docs/MCP_METADATA.md](../../docs/MCP_METADATA.md#conformance-harness).

## Running it

```sh
make mcp-conformance                    # both phases
make mcp-conformance ARGS=--unit-tests  # also the full binary test suite
make mcp-conformance-legacy             # legacy compatibility checks only
./scripts/mcp-conformance/run.sh --help
```

Requires Node >= 20.18.1 with npm, git and openssl. Cargo is needed for builds,
for `--unit-tests` and for the `fabric` target, not for a run whose binaries are
all passed in or, with `--skip-build`, already built. The `fabric` target also
needs a running Docker daemon. The first run needs the npm registry and GitHub;
later runs reuse the caches under `target/mcp-conformance/`. Both `npm ci`
installs pass `--include=dev`, so `NODE_ENV=production` or npm `omit=dev` does
not drop the suite or `tsx`.

A run that uses Cargo refuses to start while `RUSTFLAGS` or
`CARGO_ENCODED_RUSTFLAGS` is set. Cargo would use either in place of the
rustflags in `.cargo/config.toml`. The harness does not clear them itself,
because that would drop flags you set on purpose: unset them, or pass prebuilt
binaries without `--unit-tests`.

| Option | Effect |
| --- | --- |
| `--skip-build` | Use the existing binary instead of building it; a missing one stops the run in preflight |
| `--binary PATH` | Gateway binary for the modern phase; the `fabric` target builds its own through Cargo |
| `--legacy-binary PATH` | Gateway binary for the legacy phase (CI passes the `build:rust` artifact) |
| `--only LIST` | Comma-separated, non-empty subset of `direct,access-point,transit,owned-proxy,proxy-surface,fabric,legacy` |
| `--unit-tests` | Run the full binary test suite before the suite; when `--only` selects no modern target the tests do not run and the summary shows a `WARN` line |

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCP_CONFORMANCE_PORT_BASE` | `18760` | First local port; the harness uses base+0, +1, +2, +10, +11, +20 and +21 (the `fabric` gateways take free ports) |
| `MCP_CONFORMANCE_REFERENCE_REPO` | GitHub `modelcontextprotocol/conformance` | Git URL or mirror holding the pinned reference commit |

Exit codes: `0` pass, `1` failure, `2` invalid options or precondition not met
(another run in progress, missing tool, `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`
set when Cargo runs, a binary path that is not an executable file, port in use,
binary that does not admit `2026-07-28`), `3` the pinned suite or reference server could
not be fetched, `130` interrupted (SIGINT), `143` terminated (SIGTERM).

## What a run does

1. **Preflight.** Takes the lock `target/mcp-conformance/.lock`, then checks
   the tools, that Cargo will not see `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`,
   the Node version, the binaries it will not build and that every port is
   free. Runs share `target/mcp-conformance/` and this directory's
   `node_modules` whatever their `MCP_CONFORMANCE_PORT_BASE`, so a second run
   while one is in progress exits `2` without touching it; a different port
   base does not allow one. A lock left by a killed run is replaced once its PID
   no longer runs the harness. A port in use also stops the run, including one
   taken after preflight: each step checks its ports again before starting the
   process that listens on them and fails if that process has exited once they
   accept connections. The harness never stops a process it did not start. The
   previous run's outputs are removed only after every check passes.
2. **Pinned dependencies.** `npm ci` here installs the exact suite version in
   `package-lock.json`. The reference server is fetched by commit into
   `target/mcp-conformance/reference/`, verified with `git rev-parse`, and
   installed from its own lockfile.
3. **Fixtures.** Starts the reference server (`everything-server.ts`),
   `fixture.mjs`, the REST backend of the gateway-owned MCP Proxy, and
   `shim.mjs`, the upstream the forwarding targets use. The reference
   server's `subscriptions/listen` response deviates from the specification
   twice, and the gateway rightly refuses both: it is newline-delimited JSON
   under `application/json`, where Streamable HTTP carries a multi-message
   response as `text/event-stream`; and it tags messages with the request id
   as a string (`"7"` for id `7`), where `io.modelcontextprotocol/subscriptionId`
   is a `RequestId` equal to the request's id. The shim re-frames that one
   response as SSE, one `message` event per line, restores the tag to the
   request's typed id, and passes everything else through unchanged, so the
   subscription checks reach the gateway. The `direct` target still talks to
   the reference server itself.
4. **Modern phase.** Builds the gateway (`cargo build`, target dir `target/`),
   writes a fresh env with `env.mjs`, starts the gateway and probes it: a
   `-32022` answer means the binary does not admit `2026-07-28`. Then runs the
   suite per target, `check-results.mjs`, `compat.mjs admitted` and
   `compat.mjs legacy`. The `fabric` target runs `fabric.feature` through the
   g2g BDD runner (`cargo test --test g2g_bdd`): two gateways
   paired over a managed mediator in Docker, an Access Point on gateway 1
   whose Target is `fabric://` gateway 2, and a surface on gateway 2 that
   forwards to the shim. A step in the scenario runs the suite against gateway
   1, so the requests cross the Fabric as framed streams.
5. **Legacy phase.** Starts the same binary on another fresh env and runs
   `compat.mjs rejected` (every endpoint answers the unmodelled `2025-11-25`
   with `-32022` and a `supported` list offering `2024-11-05`) and
   `compat.mjs legacy`. `compat.mjs admitted`, in the modern phase, requires
   every endpoint, `legacy-surface` included, to admit `2026-07-28`.

`env.mjs` builds everything from scratch under `target/mcp-conformance/env/`:
`config.toml` from the binary's own `--generate-bootstrap`, a certificate from
`scripts/certs/generate-cert.sh`, a `gateway.json` derived from
`config/examples/gateway.example.json`, and the surfaces and MCP Proxy below.
The backup encryption key is generated with `openssl rand -hex 32` when the
gateway starts and exists only in its environment.

| Target | Endpoint | Suite run | Baseline |
| --- | --- | --- | --- |
| `direct` | The reference server itself | Full `2026-07-28` requirement set | `direct.yaml` |
| `access-point` | Access Point `/conformance/mcp` forwarding to the reference server through the shim | Full requirement set | `forwarding.yaml` |
| `transit` | Transit Point `/transit/conformance-mcp` on the outbound listener | Full requirement set | `forwarding.yaml` |
| `owned-proxy` | Standalone MCP Proxy `/owned/api` over the REST fixture | `tools-list`, `tools-call-simple-text`, `caching` | `owned.yaml` |
| `proxy-surface` | Access Point `/conformance/owned-mcp` with Target `proxy://conformance-owned` | Same subset | `owned.yaml` |
| `fabric` | Access Point on gateway 1 with Target `fabric://` gateway 2, whose surface forwards to the reference server through the shim | Full requirement set | `fabric.yaml` |
| `legacy-surface` | Access Point `/conformance/legacy-mcp` whose stored record deliberately still carries the retired `mcp_protocol_mode: 'legacy'`, which is ignored | `compat.mjs` only | |

Outputs, all under the ignored `target/mcp-conformance/`:

| Path | Contents |
| --- | --- |
| `run/summary.txt` | One line per step and the overall result |
| `run/logs/` | Build, npm, gateway, fixture, suite and check logs; `g2g-fabric.log` is the `fabric` target's BDD run |
| `run/results/<target>/` | The suite's `checks.json` per scenario |
| `env/<modern\|legacy>/` | The generated gateway envs and `targets.json` |

## Checks beyond the suite

- `check-results.mjs`: every target has a result for each scenario it ran; the
  Access Point, Transit Point and Fabric Access Point report the same
  `ttlMs`/`cacheScope` as the reference server does directly; owned `tools-call-simple-text` results carry
  the fixture's text and are not tool errors. The suite only asks for non-empty
  text, which even a tool error satisfies. Caching parity needs `direct` and
  `access-point`, `transit` or `fabric`; with a narrower `--only` the summary shows it as
  `SKIP`.
- `compat.mjs legacy`: a `2024-11-05` session (`initialize`,
  `notifications/initialized`, `tools/list`, `tools/call`) returns the same
  results through `access-point`, `transit` and `legacy-surface` as directly,
  and the owned endpoints return the fixture's text with equal results.
- `compat.mjs admitted` / `rejected`: which endpoints admit `2026-07-28` in each
  build, with `-32022`, `supported: ["2024-11-05"]` and the request id echoed
  where it is rejected.

Streamed frame counts are not compared between targets: how the reference
server frames and times streamed messages is fixture behaviour, not gateway
behaviour.

## Maintaining the baselines

`expected-failures/*.yaml` list `<scenario>:<check-id>` entries, each with a
one-line reason comment above it. The suite fails a run on any failure or
warning that is not listed and on a listed check that now passes, so a fixed
failure must be removed from its baseline in the same change. Check ids are in
`run/results/<target>/server-<scenario>-*/checks.json`. Never list a gateway
defect to make a run pass; fix the gateway instead.

## Updating the pins

- **Suite.** Change the exact version in `package.json`, run
  `npm install --package-lock-only` here and commit both files. Requirement
  sets exist only on the prerelease line, so keep an exact prerelease pin.
- **Reference server.** Change `REFERENCE_SHA` in `run.sh`; the next run
  fetches that commit. Pick the commit the suite version was released from.
- Re-run `make mcp-conformance`, then update the baselines from the results.
