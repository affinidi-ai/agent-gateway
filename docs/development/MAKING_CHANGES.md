# Making Changes

Recipes for the changes that come up repeatedly, organised by what you want to do rather
than by the subsystem it lands in.

Each recipe lists the files to touch in order, and names an existing example to read
first. Read the example: it is more reliable than this page, which describes the shape
rather than the detail.

Before starting, read [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for the request path and
[`CONTEXT.md`](../../CONTEXT.md) for the vocabulary. Every change needs a changelog
fragment and tests; see [`CONTRIBUTING.md`](../../CONTRIBUTING.md) and
[`TESTING.md`](TESTING.md).

## Add a source authentication method

How the gateway proves who an inbound caller is. Currently five: JWT bearer, API key, API
key provider, DID Auth, and mTLS.

**Read first:** `ApiKeyAuthConfig` in
[`src/source_auth/models.rs`](../../src/source_auth/models.rs). It is the smallest
complete example.

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/source_auth/models.rs` | Add a variant to `SourceAuthConfig` with its config struct. The serde tag is the operator-facing name. |
| 2 | `src/source_auth/models.rs` | Add validation, and defaults through `#[serde(default = "…")]` with a named function rather than a literal. |
| 3 | `src/source_auth/` | Add the module implementing the check. It returns an `AuthenticatedIdentity`. |
| 4 | `src/source_auth/middleware.rs` | Add the arm to the dispatch `match` around line 176. The compiler finds this for you. |
| 5 | `src/surface_context/` | If policies should see anything new, add it to `SourceAuthContext`. |
| 6 | `www/default/src/` | Add the configuration UI, following [`www/default/AGENTS.md`](../../www/default/AGENTS.md). |
| 7 | `docs/SOURCE_AUTH.md` | Document the method, its fields, and its defaults. |

**Watch for:** whether a DID derived from this method counts as verified in policy input.
Only credentials bound to the request itself qualify. See
[`SOURCE_AUTH.md`](../SOURCE_AUTH.md#managed-identity) and
[`POLICY.md`](../POLICY.md#caller-identity-verification-in-policy-input).

## Add a management API endpoint

**Read first:** the `/v1/config/reload` registration in
[`src/identity/router.rs`](../../src/identity/router.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/rbac/mod.rs` | Add a `Feature` variant and its key in `Feature::as_str`. There are 73; follow the `<area>View` / `<area>Edit` / `<area>Delete` naming. |
| 2 | `src/rbac/mod.rs` | Give the key its default role in `RbacConfig::default()`. A key missing from the map is denied to every role, administrators included. |
| 3 | `config/examples/rbac.example.json` | Add the key with the same role, so the example shows it. |
| 4 | `src/identity/handlers/` | Write the handler. |
| 5 | `src/identity/router.rs` | Register the route with `.layer(require_feature(s.clone(), r.clone(), Feature::YourFeature))`. A route without this layer is unprotected. |
| 6 | `src/access_tokens/` | If the route touches a tenant-ownable record, check the resource pattern. Enforcement is fail-closed for unknown nested paths. |
| 7 | `src/auth_manager/permissions.rs` | If the dashboard uses the feature, add its key to `get_permissions`. |
| 8 | `www/default/src/api.ts` | Add the client call. Do not call `fetch` from a page. |
| 9 | `docs/RBAC.md` | Describe the new permission if it changes the authorization contract. |

**Watch for:** the permissions endpoint contract in [`RBAC.md`](../RBAC.md). The dashboard
hides controls based on it, so a feature missing there is invisible rather than refused.

## Add a stored record type

State is a DashMap cache over JSON files. There is no migration system; a new field must
deserialize from records written before it existed.

**Read first:** [`src/surfaces/store.rs`](../../src/surfaces/store.rs) and its filesystem
implementation.

| Order | File | Change |
| --- | --- | --- |
| 1 | your module | Define the type and implement `StorableEntity` from [`src/storage/filesystem.rs`](../../src/storage/filesystem.rs). `id()` becomes the filename. |
| 2 | your module | Define the store trait, then implement `StorageBackend<T>` for the filesystem. |
| 3 | `src/config/types.rs` | Add the path to `StoragePaths`. |
| 4 | `src/config/bootstrap.rs` | Resolve it relative to the config directory, next to the others. |
| 5 | `config/examples/config.example.toml` | Add it under `[storage_paths]`. |
| 6 | `src/server/orchestrator.rs` | Open the store during startup and pass it where it is needed. |
| 7 | `src/server/orchestrator.rs` | Register a counter in `register_resource_limit_counters` if the record should be limited. |
| 8 | `config/examples/limits.example.json` | Add the limit, with its operator-facing `name` and `description`. |

**Watch for:**

- Give every new field `#[serde(default)]`, or loading an existing record fails.
- `StorableEntity::migrate_raw_json` is the hook for renaming or removing a field. It runs
  on the raw JSON before deserialization.
- `on_load` is the hook for normalising after deserialization.
- A record that should be tenant-ownable needs an optional `tenant_id`; absent means
  appliance-global. See [`ACCESS_TOKENS.md`](../ACCESS_TOKENS.md#tenant-ownership).

## Add a field to policy input

Anything a Rego policy can read lives in `PolicyInput`.

**Read first:** [`src/surface_context/mod.rs`](../../src/surface_context/mod.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/surface_context/mod.rs` | Add the field to the relevant context struct, or add a new context to `PolicyInput`. |
| 2 | `src/proxy/handler.rs` | Populate it on the inbound path. |
| 3 | `src/proxy/outbound_handler.rs` | Populate it on the outbound path, or state why it is inbound-only. |
| 4 | `docs/POLICY.md` | Document the field and its possible values. |

**Watch for:** the two paths are separate code. A field added to only one is a silent gap,
because a policy reading a missing value in Rego gets `undefined` rather than an error.

## Add a protocol

The largest change shape. `SurfaceProtocol` currently has four variants: A2A, AP2, MCP,
DIDComm.

**Read first:** [`src/mcp/`](../../src/mcp/), which is the most complete non-default
implementation.

| Order | Area | Change |
| --- | --- | --- |
| 1 | `src/config/agent_surface.rs` | Add the `SurfaceProtocol` variant. The `ts-rs` export keeps the TypeScript in step; run `cargo test --bin agent-gateway` to regenerate. |
| 2 | `src/<protocol>/` | Add the module: wire format, validation, and metadata handling. |
| 3 | `src/protocols/extensions.rs` | Extend the protocol-agnostic helpers if extension inspection or metadata injection apply. |
| 4 | `src/proxy/protocol_router.rs` | Route requests to it. |
| 5 | `src/proxy/handler.rs` | Place validation before generic classification, as MCP does. |
| 6 | `src/surface_context/` | Add a context struct so policies can see protocol-specific fields. |
| 7 | `src/config/bootstrap.rs` | Add a `[<protocol>]` section for revision defaults and timeouts. |
| 8 | `www/default/src/` | Add the Surface Builder support. |
| 9 | `docs/PROTOCOLS.md` | Record the supported revisions and the exact limitations. |

**Watch for:**

- Gate anything experimental behind a feature flag that is off by default, and reject with
  a clear status code when off. AP2 is the precedent; see
  [`PROTOCOLS.md`](../PROTOCOLS.md#ap2-limitation).
- Fabric receive is a separate leg. A protocol reachable over `fabric://` needs validation
  there too, in
  [`src/gateways/connection_points/message_processor.rs`](../../src/gateways/connection_points/message_processor.rs).
- Decide whether tool-gating or an equivalent applies, and whether the default is allow or
  deny. The policy planes fail closed, so it should be deny.

## Add a dashboard page

**Read first:** an existing page folder under `www/default/src/pages/`, and
[`www/default/README.md`](../../www/default/README.md).

| Order | File | Change |
| --- | --- | --- |
| 1 | `www/default/src/api.ts` | Add the API calls. |
| 2 | `www/default/src/pages/<Name>/` | Add the page. Keep the entry file orchestration-focused and put owned logic in sections, hooks, and helpers beside it. |
| 3 | `www/default/src/routes.ts` | Register the route. |
| 4 | the page | Give every interactive element a `data-testid` following the convention. |
| 5 | `ui-tests/specs/` | Add a spec. |
| 6 | `www/default/AGENTS.md` | Record any page-specific requirement that a future change must preserve. |

**Watch for:** gate controls on the permissions from `PermissionsContext`. A view-only user
should see the data and not the mutating controls.

## Add an outbound call

Any new call the gateway makes to an address an operator or a payload can influence.

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/egress.rs` | Send through the shared guard. It vets the target, resolves DNS once, and pins the request to that address with redirects disabled. |
| 2 | `docs/POLICY.md` | Add the sink to the egress table. |

**Watch for:** do not build a `reqwest::Client` directly for a target that is not a fixed
compile-time constant. The pin-once primitive exists because a hostname that passes a
static check can still resolve to an internal address on the next lookup. See
[`POLICY.md`](../POLICY.md#egress-and-ssrf-controls).

## Related

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): the map this page assumes.
- [`TESTING.md`](TESTING.md): which test layer each change belongs in.
