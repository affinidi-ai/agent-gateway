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
make mcp-conformance ARGS=--report      # report only: every scenario, open gaps listed
make mcp-conformance-legacy             # legacy compatibility checks only
./scripts/mcp-conformance/run.sh --help
```

Requires Node >= 22 with npm, git and openssl. Cargo is needed for builds,
for `--unit-tests` and for the `fabric` target, not for a run whose binaries are
all passed in or, with `--skip-build`, already built. The `fabric` target also
needs a running Docker daemon. The first run needs the npm registry and GitHub;
later runs reuse the caches under `target/mcp-conformance/`. Both `npm ci`
installs pass `--include=dev`, so `NODE_ENV=production` or npm `omit=dev` does
not drop the suite or `tsx`.

A run that uses Cargo refuses to start while `RUSTFLAGS` or
`CARGO_ENCODED_RUSTFLAGS` is set. Cargo would use either in place of the
rustflags in `.cargo/config.toml`. The harness does not clear them itself,
because that would drop flags you set on purpose: unset them, or pass a
prebuilt binary without `--unit-tests`.

| Option | Effect |
| --- | --- |
| `--skip-build` | Use the existing binary instead of building it; a missing one stops the run in preflight |
| `--binary PATH` | Gateway binary for the modern and legacy phases; the `fabric` target builds its own through Cargo |
| `--only LIST` | Comma-separated, non-empty subset of `direct,access-point,transit,owned-proxy,proxy-surface,fabric,client,legacy` |
| `--unit-tests` | Run the full binary test suite before the suite; when `--only` selects no modern target the tests do not run and the summary shows a `WARN` line |
| `--report` | Report only: run every scenario the suite has against each selected target, ignore the suite's verdicts and the baselines, and write the open gaps to `run/gaps.md`. See [Report-only mode](#report-only-mode) |

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCP_CONFORMANCE_PORT_BASE` | `18760` | First local port; the harness uses base+0, +1, +2, +10, +11, +20 and +21, and +30 and +31 when the `client` target runs (the `fabric` gateways and the client adapter take free ports) |
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
   subscription checks reach the gateway. The shim's own tests
   (every `*.test.mjs` here, found the way `npm test` in this directory finds them) run before it starts. The
   `direct` target still talks to the reference server itself.
4. **Modern phase.** Builds the gateway (`cargo build`, target dir `target/`),
   writes a fresh env with `env.mjs`, starts the gateway and probes it: a
   `-32022` answer means the binary does not admit `2026-07-28`. A normal
   run always probes, since its compat checks need every gateway endpoint to
   admit the version; only a `--report` run that selects nothing but `direct`
   and `fabric`, which use neither that Access Point nor this gateway's modern
   admission, skips the probe. Then runs the
   suite per target, `check-results.mjs`, `compat.mjs admitted` and
   `compat.mjs legacy`. The `fabric` target runs `fabric.feature` through the
   g2g BDD runner (`cargo test --test g2g_bdd`): two gateways
   paired over a managed mediator in Docker, an Access Point on gateway 1
   whose Target is `fabric://` gateway 2, and a surface on gateway 2 that
   forwards to the shim. A step in the scenario runs the suite against gateway
   1, so the requests cross the Fabric as framed streams.
5. **Client phase** (the `client` target). Runs the suite's `client` command,
   which starts its own server for each scenario and spawns
   `client-driver.mjs` with that server's URL. The driver runs the suite's
   reference client (`everything-client.ts` of the pinned checkout, whose root
   packages are installed with `npm ci --ignore-scripts`) twice per scenario:
   at the suite's server, and through a gateway it starts on a fresh
   env whose Target is that server, both through `client-shim.mjs` so the two
   runs send the same requests. `client-parity.mjs` requires the same
   suite verdict (the suite's exit status of each scenario run, which can be a
   failure without a failed check) and the same checks with the same statuses
   both ways, and `tools_call`, `request-metadata`,
   `sep-2322-client-request-state` and `json-schema-2020-12-preservation` to
   pass through the gateway: a passing verdict and no failed or warned check. The
   reference client has no handler for the other four scenarios, so they fail
   the same way on both sides. Between the reference client and the gateway
   sits `client-shim.mjs`, on the direct run as well: the reference client omits
   the `Mcp-Method` and `Mcp-Name` headers and sometimes the `Accept` list,
   which the gateway rightly rejects on a modern request, so the adapter adds
   them to requests that carry `MCP-Protocol-Version` and passes everything
   else through. `http-standard-headers` and `http-custom-headers` therefore
   check headers the shim fills in: they measure neither the gateway nor the
   client.
   The suite ends a client that outlives its timeout with a signal; the driver
   then kills the gateway and reference client it started, and the run stops
   if a gateway is still listening after a scenario. The suite splits its
   `--command` on spaces, so the driver's path reaches it through the
   environment (`MCP_CONFORMANCE_DRIVER_SCRIPT`) and a checkout path with a space
   works. A driver that cannot run a scenario at all, for instance because its
   gateway does not start, exits `70` and writes
   `run/logs/client-gateway/harness-failure.txt`; the suite sees only a failed
   client, so the harness reads that file and stops with a failure, in a report-only
   run too, rather than counting the scenario as a verdict or a gap.
   Last, `auth/client-credentials-jwt` runs through the gateway only:
   `client-auth.mjs` follows the suite server's `401` challenge to the token
   endpoint, writes a credential provider and its secrets into the env and
   binds the provider to the Target, and the gateway signs the assertion,
   fetches the token and attaches it. The driver follows and stores only URLs
   on the origin of the suite's server or on loopback, and writes the secrets
   with mode `0600` in a `0700` directory.
6. **Legacy phase.** Starts the same binary on another fresh env and runs
   `compat.mjs rejected` (every endpoint answers the unmodelled `2099-01-01`
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
| `client` | Access Point `/conformance/mcp` of a gateway started per scenario, forwarding to the suite's own server | The eight `2026-07-28` client scenarios that need no authorization, compared with a direct run; `auth/client-credentials-jwt` through the gateway only. See [What the client target covers](#what-the-client-target-covers) | None: `client-parity.mjs` compares the eight with the direct run |
| `legacy-surface` | Access Point `/conformance/legacy-mcp` whose stored record deliberately still carries the retired `mcp_protocol_mode: 'legacy'`, which is ignored | `compat.mjs` only | |

Outputs, all under the ignored `target/mcp-conformance/`:

| Path | Contents |
| --- | --- |
| `run/summary.txt` | One line per step and the overall result; see [Reading a suite line](#reading-a-suite-line) |
| `run/gaps.md` | Written by `--report` only: per target, each failed or warned check with its scenario, check id, status and the suite's message |
| `run/report/` | Written by `--report` only: per target, the scenarios the suite marked failed |
| `run/logs/` | Build, npm, gateway, fixture, suite and check logs; `g2g-fabric.log` is the `fabric` target's BDD run |
| `run/results/<target>/` | The suite's `checks.json` per scenario; the `client` target writes `client-direct/` and `client-gateway/` |
| `env/<modern\|legacy>/` | The generated gateway envs and `targets.json` |
| `env/client/<scenario>/` | The env of the gateway started for one client scenario |
| `run/logs/client-gateway/gateway-<scenario>.log` | The log of that gateway, kept with the other run logs |
| `run/logs/client-gateway/harness-failure.txt` | Written only when the driver could not run a scenario (exit `70`); the harness fails when it exists |
| `run/logs/client-<direct\|gateway>.verdicts` | The suite's verdict (`pass` or `fail`) of each client scenario run, which `client-parity.mjs` compares |

### What the client target covers

| Scenarios | Run | Why |
| --- | --- | --- |
| The eight `2026-07-28` client scenarios that need no authorization | Directly and through the gateway, with the same suite verdict and checks required both ways | The reference client and the shim are the same in both runs, so a difference is the gateway's. The two header scenarios check headers the shim fills in, so they do not measure the gateway or the client |
| `auth/client-credentials-jwt` | Through the gateway only, counted on its own summary line | In the gateway run the gateway, not the reference client, signs the assertion and fetches the token. Run directly, the reference client does the exchange itself and exits with an error against this server's modern-wire `initialize`, so the two runs test different clients and a comparison would not measure the gateway |
| `auth/client-credentials-basic` | Not run: a known gap | An `oauth2_client_credentials` provider sends the client secret in the form body and the scenario requires HTTP Basic. `--report` lists it, and it can be reproduced by hand (below) |
| The other `auth/*` client scenarios (discovery, scope step-up, token-endpoint authentication methods, pre-registration, `iss`, offline access, DPoP, enterprise-managed authorization, workload identity federation) | Not run | They test an MCP client's own OAuth behaviour, such as an authorization-code flow, discovery at request time or a token issued outside the gateway. Target authentication does none of that, so the gateway has nothing to measure. `--report` lists them as gaps of the `client` target |

### Reading a suite line

Each suite line of the summary counts checks, from the `checks.json` files the
suite saved:

```text
PASS  suite direct: 50 scenarios run; 147 passed; 1 expected failure(s); 42 unscored failure(s)
```

The `client` target shows one such line for the eight parity scenarios and one
for `auth/client-credentials-jwt`.

- **passed**: checks with status `SUCCESS`.
- **expected failure(s)**: failed or warned checks of scored scenarios that the
  target's baseline lists. On the `client` line they are the failed checks of
  the scenarios that may fail, as long as they fail the same way without the
  gateway.
- **unscored failure(s)**: failed or warned checks of scenarios the suite runs
  but the requirement set does not score (its `not_scored` list, such as every
  `tasks-*` scenario). The suite never fails a run on them and no baseline
  covers them, so this count is the only place a normal run shows them.
- **unexpected failure(s)**: shown only when there are some, on a `FAIL` line.
  The suite log named on that line lists each one.

The counts do not change the exit code. The numbers differ from the suite's own
`Total:` line, which counts failures and leaves warnings out.

### Report-only mode

`--report` answers "what does the gateway not do yet", where a normal run
answers "did anything regress". It combines with `--only`.

```sh
make mcp-conformance ARGS="--report"
make mcp-conformance ARGS="--report --only client"
```

| Target | Scenarios in a report-only run |
| --- | --- |
| `direct`, `access-point`, `transit`, `owned-proxy`, `proxy-surface` | Every scenario of `conformance list --server`, one at a time, including the ones outside the `2026-07-28` requirement set and, for the owned targets, outside their tool subset |
| `client` | Every scenario of `conformance list --client`, one at a time, through the gateway only. This includes every `auth/*` scenario, the ones the normal run leaves out among them |
| `fabric` | Every scenario of `conformance list --server`, as for the other server targets, without the requirement set or the baseline: the BDD step runs `report-cli.sh` in place of the suite's command |
| `authorization` | Every scenario of `conformance list --authorization`, against the gateway's modern listener, which is not an authorization server. Run with the modern phase only, and never in a normal run |
| `legacy` | None: it runs no suite scenario, so `--report` leaves it out. `--report --only legacy` exits `2` |

A scenario that applies to `2026-07-28`, or that is an extension, runs on the
`2026-07-28` wire, as in a normal run. A scenario of older revisions only, such
as `server-initialize`, runs at its own revision.

The run ignores the suite's exit status and the baselines, and does not run
`check-results.mjs`, `client-parity.mjs` or `compat.mjs` (apart from the modern probe). It exits `0` however
many gaps it finds. A failed probe does not stop it: the summary shows an
`INFO` line and `run/gaps.md` a `Harness notes` section, and the scenarios
still run. It still exits non-zero when the harness itself fails: a
build error, a gateway or fixture that does not start, a client scenario whose
driver could not start its gateway, a port in use, a gateway
still listening after its client scenario ended, a suite `list` command that
fails (the scenario list is read in full before any scenario runs, so a list
that stops partway is not a short report), or a target for which the
suite ran no scenario or saved no result.

`run/gaps.md` has one section per target with the number of passed checks and
one table row per failed or warned check. A scenario the suite failed without a
failed check, for instance because the client exited with an error, gets a row
with `-` as its check. The summary repeats the totals:

```text
INFO  report client: 115 passed; 81 open gap(s)
INFO  report: the open gaps are in target/mcp-conformance/run/gaps.md
```

The file takes the suite's message of a check and never its `details`, and
Bearer and DPoP values (whatever their length), Basic values that look
generated, JWTs, PEM blocks and the values of fields whose name contains
`secret`, `token`, `password`, `key`, `assertion`, `authorization`, `cookie`,
`credential` or `signature` in a message are replaced with `[redacted]`. A
field that names an endpoint, URL, type or method of a credential keeps its
value. A gap of the
`client` target is not always the gateway's: the reference client has no
handler for some scenarios and fails them without the gateway too, which only
the normal run's parity check tells apart.

### Reproducing a client scenario by hand

After a run, with the fixtures stopped, one scenario can be run again from the
repository root. `auth/client-credentials-basic` is the known gap: the gateway
sends the client secret in the form body, and the scenario requires HTTP Basic.
A `--report` run lists it in `run/gaps.md` with every other open gap.

```sh
MCP_CONFORMANCE_DRIVER_MODE=gateway \
MCP_CONFORMANCE_DRIVER_REFERENCE="$PWD/target/mcp-conformance/reference" \
MCP_CONFORMANCE_DRIVER_BINARY="$PWD/target/debug/agent-gateway" \
MCP_CONFORMANCE_DRIVER_WORK="$PWD/target/mcp-conformance/env/client" \
MCP_CONFORMANCE_DRIVER_LOGS="$PWD/target/mcp-conformance/run/logs/client-gateway" \
MCP_CONFORMANCE_DRIVER_SCRIPT="$PWD/scripts/mcp-conformance/client-driver.mjs" \
MCP_CONFORMANCE_DRIVER_INBOUND_PORT=18790 MCP_CONFORMANCE_DRIVER_OUTBOUND_PORT=18791 \
MCP_CONFORMANCE_DRIVER_FIXTURE_URL=http://127.0.0.1:18761 \
scripts/mcp-conformance/node_modules/.bin/conformance client \
  --scenario auth/client-credentials-basic --spec-version 2026-07-28 --force \
  --command 'node "$MCP_CONFORMANCE_DRIVER_SCRIPT"'
```

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
