# A2A conformance harness

Runs the A2A project's conformance suite, the
[A2A TCK](https://github.com/a2aproject/a2a-tck), against the suite's own test
agent directly and through Agent Trust Gateway, and scores each gateway entry
point on how its results differ from the direct run. The gateway-side contract
(what is covered and what the baselines record) is in
[docs/PROTOCOLS.md](../../docs/PROTOCOLS.md#a2a-conformance-harness).

## Running it

```sh
make a2a-conformance                     # A2A 1.0 suite
make a2a-conformance-legacy              # A2A 0.3 suite
make a2a-conformance ARGS=--report       # list every difference, exit 0
make a2a-conformance ARGS="--only transit --skip-build"
./scripts/a2a-conformance/run.sh --help
```

Requires git, openssl and Python: 3.15 or later for the 1.0 suite, 3.13 or 3.14
for the 0.3 suite. The 1.0 suite also needs a C++ compiler when `uv` has to
build `grpcio`, as the first run does (see
[What is pinned](#what-is-pinned)). Cargo is needed unless
`--skip-build` or `--binary` names a built gateway. The first run needs GitHub
and PyPI; later runs reuse the checkouts and virtual environments under
`target/a2a-conformance/`. Nothing is installed outside that directory; pip and
uv keep their download caches where they usually do.

Some of the caller's variables would change what is tested, so the run sets
them itself. Every variable whose name starts with `PYTHON` (`PYTHONPATH`,
`PYTHONHOME`, `PYTHONSAFEPATH` and the rest) is unset; the suite gets only the
`PYTHONPATH` that holds the harness plugins. `127.0.0.1` and `localhost` are
added to `NO_PROXY` and `no_proxy`, which both end up with the entries of
both, so a proxy set in the environment is used for the fetches and never for
the requests the run makes on loopback; a value of `*` is kept as it is. The
1.0 suite's packages go into its own environment whatever `UV_PROJECT` or
`UV_PROJECT_ENVIRONMENT` say. Other `UV_*` and `PIP_*` settings, such as an
index mirror, still apply.

| Option | Effect |
| --- | --- |
| `--a2a-version VERSION` | Suite to run: `1.0` (default) or `0.3` |
| `--skip-build` | Use the existing binary instead of building it; a missing one stops the run in preflight |
| `--binary PATH` | Gateway binary to test |
| `--only LIST` | Comma-separated, non-empty subset of `access-point,access-point-full,transit,a2a-proxy`; the direct run always happens |
| `--report` | Write every difference to `gaps.md` in the run directory and exit `0` whatever the baselines say; results or a baseline that cannot be read still fail the run |

| Variable | Default | Purpose |
| --- | --- | --- |
| `A2A_CONFORMANCE_PORT_BASE` | `18860` | First local port. The 1.0 suite uses base+0, +1, +2, +10 and +11; the 0.3 suite base+20, +22, +30 and +31 |
| `A2A_CONFORMANCE_TCK_REPO` | GitHub `a2aproject/a2a-tck` | Git URL or mirror holding the pinned commits |
| `A2A_CONFORMANCE_PYTHON` | `python3.15`, then `python3` | Interpreter for the 1.0 suite. When set, it is the only one tried; a missing or unsuitable one stops the run in preflight. A cached virtual environment built with another interpreter is rebuilt |
| `A2A_CONFORMANCE_LEGACY_PYTHON` | `python3.14`, `python3.13`, then `python3` | Interpreter for the 0.3 suite, with the same rule |

Exit codes: `0` pass, `1` failure, `2` invalid options or precondition not met
(another run in progress, missing tool or Python, `RUSTFLAGS` or
`CARGO_ENCODED_RUSTFLAGS` set when Cargo runs, a binary path that is not an
executable file, port in use), `3` the pinned suite or its packages could not
be fetched, `129` hung up (SIGHUP, such as a closed terminal), `130` interrupted
(SIGINT), `143` terminated (SIGTERM).

## What is pinned

| | A2A 1.0 | A2A 0.3 |
| --- | --- | --- |
| Suite | `a2a-tck` at `5e6f37c2d38eb3d7684686243c34d365c83df49b` (`main`) | `a2a-tck` at `917352a0f63e8c1ed728507e7d2e0d0f8d291b04` (branch `0.3.x`) |
| Suite packages | The suite's own `uv.lock`, installed by `uv` 0.13.10 | `legacy-suite-requirements.txt` (the branch has no lockfile) |
| Test agent | The suite's generated `sut/a2a-python/sut_agent.py` | The suite's bundled `python-sut/tck_core_agent` |
| Test agent packages | `agent-requirements.txt` (`a2a-sdk` 1.3.1) | `legacy-agent-requirements.txt` (`a2a-sdk` 0.3.26) |

The 1.0 suite is not installed as a package: pytest runs from its checkout,
so its build backend, which the lock does not pin, never runs. Two of the
packages its lock installs, `grpcio` and `markupsafe`, are there as source
archives only, so `uv` builds them from those locked, hashed sources; `grpcio`
is what needs the C++ compiler. What they build with is not in the lock:
`uv` takes the newest `setuptools` (both) and `wheel` (`grpcio`) on the index,
and the `cython` version `grpcio` itself names.

The suite is fetched by commit and verified with `git rev-parse`. The 1.0
suite runs `tests/compatibility/`, as its `run_tck.py` does. The 0.3 suite runs
the two categories that decide compliance, `mandatory` and `capabilities`.
Both run on the JSON-RPC binding only, the one binding the gateway serves.

## What a run does

1. **Preflight.** Takes the lock `target/a2a-conformance/.lock`, then checks
   the tools, the Python version, the binary it will not build and that every
   port is free. Runs share `target/a2a-conformance/`, so a second run while
   one is in progress exits `2`, whatever its port base or suite. A lock left
   by a killed run is replaced once its PID no longer runs the harness. The
   harness never stops a process it did not start. The previous run's outputs
   are removed only after every check passes.
2. **Self-tests.** `test_check_results.py` runs first: the scoring has to be
   right before it scores anything.
3. **Pinned dependencies.** Fetches the suite, restores its checkout to the
   pinned commit with nothing else in it, and installs the suite's packages and
   the test agent's packages into their own virtual environments.
4. **Direct run.** Starts the test agent on loopback and runs the suite
   against it. This is the reference for the forwarding targets.
5. **Gateway targets.** Builds the gateway, writes a fresh env with `env.py`,
   starts the gateway, waits for its health endpoint, and runs the suite once
   per target. The surfaces accept A2A `1.0` for the 1.0 suite, and `0.3` and
   `1.0` for the 0.3 suite. That is the default of a forwarding surface. For
   the A2A proxy surface it is a stored setting the gateway keeps for an older
   surface: the admin API creates a new A2A proxy surface with `1.0` only,
   which the 0.3 suite could not call at all.
6. **Score.** `check_results.py` compares every target with the direct run and
   the baselines.

`env.py` builds everything from scratch under `target/a2a-conformance/`:
`config.toml` from the binary's own `--generate-bootstrap`, a certificate from
`scripts/certs/generate-cert.sh`, a `gateway.json` derived from
`config/examples/gateway.example.json`, and the records below. Every Access
Point is public (`access_point.public: true`) and the Transit Point admits
unauthenticated callers, because the suite sends no credentials. The backup
encryption key is generated with `openssl rand -hex 32` when the gateway starts
and exists only in its environment.

| Target | Endpoint | Scored |
| --- | --- | --- |
| `direct` | The test agent itself | On its own failures |
| `access-point` | A2A Access Point `/conformance/a2a` forwarding to the test agent, `validation: envelope` | Against `direct` |
| `access-point-full` | A2A Access Point `/conformance/a2a-full`, same agent, `validation: full` | Against `direct` |
| `transit` | A2A Transit Point `/transit/conformance-a2a` on the outbound listener, same agent | Against `direct` |
| `a2a-proxy` | A2A Access Point `/conformance/a2a-proxy` whose Target is the gateway-owned A2A proxy over `directline.py` | On its own failures |

Outputs, all under the ignored `target/a2a-conformance/`; the 0.3 suite writes
to `run-0.3/` and `env-0.3/`:

| Path | Contents |
| --- | --- |
| `run/summary.txt` | One line per step and the overall result |
| `run/gaps.md` | With `--report`: every difference per target, with the suite's message and the baseline's cause |
| `run/logs/` | Build, install, gateway, test agent, suite and scoring logs |
| `run/results/<target>/` | The suite's JUnit report (and, for 1.0, its compatibility and HTML reports) and `probes.json` |
| `env/` | The generated gateway env and `targets.json` |

## How a target is scored

The suite's test agent fails some checks with no gateway in front of it, so a
forwarding target is not scored on what fails. It is scored on what changes:

- **Agents** (`direct`, `a2a-proxy`): every failure must be listed in the
  target's baseline, and the number of passing tests must equal its `passed`,
  so a test that stops running or starts being skipped fails the run. The
  count includes the two probes below. A pass lost and a pass gained in the
  same run cancel out and are not seen.
- **Forwarding targets** (`access-point`, `access-point-full`, `transit`):
  every test whose outcome differs from the direct run must be listed, with
  that outcome. A test that fails in both is the agent's and does not count.

Outcomes are `pass`, `fail`, `skip` and `xfail` (a SHOULD-level check the suite
reports without failing its run). A test that passes directly and is skipped
through the gateway is a difference: the suite skips a test when the call it
depends on did not work. The run also fails on a listed entry that no longer
applies, so a baseline cannot keep an entry the gateway has outgrown.

`probes.py` adds two checks the suite does not make, scored the same way:

- `harness.entry_point::accepts_trailing_slash`: the interface URL answers
  JSON-RPC with and without a trailing slash.
- `harness.agent_card::interfaces_are_served`: every interface the agent card
  lists answers in the binding it names.

## Baselines

`expected/<version>/<target>.toml`. Each entry names one `test` or several
`tests`, the `outcome`, and the `reason`: the cause, not a restatement of the
failure. An outcome that depends on timing is a list. An agent's baseline lists
failures only and sets `passed`, the number of tests that pass; the run fails
until it is updated when that number changes in either direction.

```toml
[[expected]]
tests = [
    "jsonrpc.test_sse_streaming.TestSseSubscribeToTask::test_subscribe_first_event_is_task",
]
outcome = "skip"
reason = "A Transit Point buffers an A2A event stream until the agent closes it ..."
```

When a run fails on an unlisted test, find the cause before listing it: run
with `--report`, read `gaps.md` and the suite log, and reproduce the request by
hand against the env in `target/a2a-conformance/env/`. A gateway change that
removes a difference must remove its entry in the same change.

## Where the harness adapts the suite

The suite and its test agents run unchanged. Five small adapters sit around
them, each for one reason:

- `agent.py` and `agent_legacy.py` start the test agents on `127.0.0.1` only.
  The agents themselves listen on every interface.
- `agent_legacy.py` also gives the 0.3 agent its port and card URL (it has
  port 9999 written in) and lets it read SDK fields by their camelCase names,
  which `a2a-sdk` 0.3 no longer offers; without that every request to it ends
  in an internal error.
- `plugins/tck_plugin.py` (`--strip-trailing-slash`, `transit` target only) sends
  JSON-RPC to the interface URL as the agent card gives it. The 1.0 suite
  always appends `/`, which a Transit Point answers with 404, so every test
  would fail for that one reason. The trailing-slash probe keeps that failure
  visible as a single entry.
- `plugins/tck_plugin_legacy.py` makes the 0.3 suite look for the agent card under the
  URL it was given. That suite otherwise asks the root of the host, where a
  gateway surface, served under a path, has no card.
- `plugins/tck_loopback.py` narrows the webhook receiver both suites start
  for their push notification tests to `127.0.0.1`. The suites bind it on
  every interface, and start it even for a test that then skips itself.

`directline.py` stands in for the Direct Line service behind the A2A proxy. It
answers every text with one text reply, so the suite's checks that need a
task, an artifact or a stream cannot pass on the `a2a-proxy` target; its
baseline marks those entries "Not a finding".

## Updating a pin

Change the commit in `run.sh` (and the package files, with `pip freeze` from a
fresh environment, when the test agent's SDK moves), run with `--report`, and
bring the baselines in line with what the report shows.
