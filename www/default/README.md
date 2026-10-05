# Agent Gateway Dashboard

The React frontend for Agent Gateway. It is the operator interface: surfaces, policies,
secrets, connections, and live traffic.

This is the **current** dashboard shipped to users, not a legacy build.

For the rules a change has to follow, see [`AGENTS.md`](AGENTS.md). For the backend, see
[`ARCHITECTURE.md`](../../ARCHITECTURE.md).

![The Agent Gateway dashboard in use: totals for agent identities, surfaces, connections, and latency, a chart of connections over time, the split of traffic between two surfaces, and identity connections by surface](../../docs/assets/diagrams/screenshot-dashboard-activity.jpg)

## Stack

| Concern | Choice |
| --- | --- |
| Framework | React 18 with TypeScript |
| Build | Create React App through CRACO (`craco build`) |
| Routing | React Router 6 |
| Components | React Bootstrap, over the dashboard's own CSS |
| Charts | Chart.js through `react-chartjs-2` |
| Tests | Jest via `craco test`, plus Playwright in [`ui-tests/`](../../ui-tests/) |

The package is named `agent-gateway-management`.

## Layout

| Path | Holds |
| --- | --- |
| `src/pages/` | One entry per route, 80 of them. A page with owned sections, hooks, or helpers gets a folder rather than a single file. |
| `src/components/` | Shared building blocks. `components/shared/` is the reusable set. |
| `src/context/` | Cross-page state: `AppContext`, `PermissionsContext` |
| `src/hooks/` | Shared hooks |
| `src/utils/` | Helpers that are not React-specific |
| `src/generated/` | TypeScript types generated from the Rust source. Do not edit. |
| `src/api.ts` | The management API client, around 1,350 lines |
| `src/types.ts` | Hand-written types that have no Rust counterpart |
| `src/routes.ts` | Route table |
| `src/dashboard.css` | The dashboard's visual language, including the dark theme |

The Surface Builder is the most involved part of the dashboard, and the one most of the
rules in [`AGENTS.md`](AGENTS.md#surface-builder) apply to:

![The Surface Builder canvas for an A2A surface named Booking Agent: a human and a calling agent reach the Access Point at gateway.example.com, pass through Rate Limit, Identity, and Policy elements to the managed agent, which reaches its external target, with the element palette on the left](../../docs/assets/diagrams/screenshot-surface-builder.jpg)

## Talking to the backend

Every call goes through `src/api.ts` to the management API under `/api/v1/…`. Add new
calls there rather than calling `fetch` from a page.

**In development**, `npm start` runs the CRA dev server and proxies `/api` to the backend
through [`src/setupProxy.js`](src/setupProxy.js). The target is
`REACT_APP_BACKEND_URL`, defaulting to `https://localhost:8443`, with certificate
verification off so the local self-signed certificate works. WebSocket upgrades are
proxied too, which is what the live traffic view needs.

**In production**, there is no proxy. The gateway binary serves the built assets itself
with `ServeDir` and falls back to `index.html` for client-side routes
([`src/proxy/server.rs`](../../src/proxy/server.rs)), so the dashboard and the API share
an origin.

## Generated types

`src/generated/` is written from the Rust types by the
[`ts-rs`](https://github.com/Aleph-Alpha/ts-rs) export macros. Those macros run **during
`cargo test`**, not during a frontend build:

```bash
cargo test --bin agent-gateway
```

The output is committed, so a changed Rust type shows up as a diff in
`www/default/src/generated/`. If a generated type looks stale, run the Rust tests rather
than editing the file. A type declared with `#[cfg_attr(test, ts(export, …))]` in
[`src/config/`](../../src/config/) lands here.

## Running it

From the repository root, the usual path starts the backend and the dashboard together:

```bash
make run-debug
```

To run the dashboard on its own against a backend that is already up:

```bash
cd www/default
npm install
npm start
```

See [`docs/development/DEVELOPMENT.md`](../../docs/development/DEVELOPMENT.md) for the
standalone frontend target and the named-instance workflow.

## Checks

```bash
npm run lint
npm run lint:fix
npm run format
npm run test -- --watchAll=false
```

`CONTRIBUTING.md` requires `npx prettier --write src && npm run lint` before a pull
request that touches this directory.

## Test identifiers

Every interactive element carries a `data-testid`, consumed by the Playwright specs in
[`ui-tests/specs/`](../../ui-tests/specs/). The naming convention is in
[`AGENTS.md`](AGENTS.md#test-identifiers) and
[`ui-tests/README.md`](../../ui-tests/README.md).

## Related

- [`AGENTS.md`](AGENTS.md): the working rules and page-specific requirements.
- [`../../docs/development/TESTING.md`](../../docs/development/TESTING.md): the four test layers.
- [`../../docs/RBAC.md`](../../docs/RBAC.md): the permissions the dashboard reads.
