# MCP Metadata Compatibility

Trust Gateway supports canonical MCP metadata and the historical Affinidi
metadata format. This is a metadata migration, not a protocol-era bridge.
`2024-11-05` and `2026-07-28` are both active and advertised on every MCP
endpoint: Access Points, Transit Points, standalone MCP Proxies and Fabric
framed streams. A revision the gateway does not model is rejected with HTTP
`400`, JSON-RPC `-32022`, `data.requested` echoing it, and `data.supported`
listing the revisions the path admits.

The accepted and advertised revisions are resolved per transport path
(`McpPathKind`: direct Access Point, gateway-owned Proxy, Transit Point, Fabric
receive, Fabric send), not from one appliance-wide value. Every path admits
`2026-07-28`, and one path can be returned to legacy-only without affecting the
others. Tests pin each path's posture, that a path never advertises a revision
it will not accept, and that returning one path to legacy-only leaves the rest
unchanged.

On Fabric, `2026-07-28` travels only as framed streams (`proxy::fabric_stream`),
whose local capabilities advertise request streams and subscriptions; the
buffered Fabric forward stays legacy-only. The published MCP conformance suite
measures these paths; [Conformance Harness](#conformance-harness) describes
how it runs.

## Output Preference

An Agent Surface accepts the optional field:

```json
{
  "mcp_legacy_metadata_output": "canonical"
}
```

| Value | Behavior |
| --- | --- |
| Missing or `compatibility` | Preserve each existing legacy writer's location and historical Affinidi URL keys. |
| `canonical` | Write request/notification metadata to `params._meta` and successful result metadata to `result._meta`, using legal Affinidi aliases. |

The setting is surface-wide. All variants inherit it, including complete
snapshots; it is not a variant override. It applies to that surface's MCP
Transit Points even if the Access Point uses another protocol. A2A/AP2 output
is unchanged. The effective surface configuration is captured for the request
and does not change halfway through a response after a hot reload.

The metadata preference cannot disable wire validation or activate modern MCP.
Helpers supplied with an explicitly validated modern classification always use
canonical output, independently of the legacy preference.

### Existing Writer Locations

Compatibility does not mean forcing every legacy writer to the root:

| Writer | Compatibility | Canonical |
| --- | --- | --- |
| Direct/Fabric request custom metadata | `params._meta` | `params._meta` |
| Transit Point request custom metadata and credential VP | Top-level `_meta` | `params._meta` |
| Inbound identity-binding VP | `params._meta` when `params` exists; otherwise top-level | `params._meta` |
| Protocol-native did:webvh identity | Top-level `_meta` | `params._meta` |
| Delegated credential metadata | `params._meta` | `params._meta` |
| Successful response metadata and credential VP | `result._meta` | `result._meta` |

Both official MCP schemas put request and notification metadata in
`params._meta`. Top-level request metadata is an Affinidi compatibility shape,
not standard legacy MCP.

## Modern MCP Admission

After the HTTP security and size checks below, every MCP endpoint admits
`2026-07-28` alongside `2024-11-05` on direct Access Points, gateway-owned
Proxies, Transit Points and, as framed streams, both Fabric paths. There is no
per-endpoint opt-out. No initialize exchange, session identifier, or
metadata-output preference changes which revisions an endpoint admits.

The gateway forwards an admitted modern request and validates the answer as a
modern result, which needs `resultType` and, for lists, cache hints. A
legacy-only upstream's answer fails that check, so the modern caller gets HTTP
`502`, while `2024-11-05` callers on the same endpoint are unaffected.

**Compatibility note.** `mcp_protocol_mode` is no longer a setting. Stored
records and API payloads for surfaces, Transit Points and MCP Proxies that
still carry it, with any value, load and are accepted; the value is ignored,
never returned, and dropped the next time the record is saved.

A surface, Transit Point or MCP Proxy that never sets `mcp_http` is stored
exactly as a release without that field wrote it, so an upgrade rewrites no
records. To roll back to such a release, first PATCH `mcp_http` to `null` on
every surface that sets it, replace each Transit Point array (base and
variant) with records that omit it, and verify the GET readback. Older
binaries reject the field on a surface and skip that whole surface at load; on
Transit Points and standalone MCP Proxies they ignore it and drop it the next
time they save the record. No older binary
enforces `mcp_http.authorization`: clearing `mcp_http` removes that requirement
from a surface's Access Point and from each Transit Point, and a Transit Point
or MCP Proxy that still carries it is served without it. Protect every endpoint
that relies on it another way, or disable it, before downgrading.

Admitted modern Transit requests do not use the legacy base-surface fallback
when a requested variant is absent, disabled or has a broken default reference.
Unknown aliases return a correlated `404`; disabled or misconfigured defaults
return `503`, before Target work. Fabric Open likewise rejects a named alias
that is absent even when the variant catalog is empty. Legacy resolution is
unchanged.

The Access Point router applies the same rule on an empty variant catalog,
where generic resolution returns the base surface. Legacy requests keep that
fallback; an admitted modern request carrying an unknown alias returns a
correlated `404`, and a surface whose `default_variant_id` no longer matches a
variant returns `503`, both before Target work. Non-empty catalogs keep their
existing router-level alias and disabled-variant errors for both eras.

Resolved Access Point, Transit Point and Fabric request snapshots retain the
selected stable variant ID separately from the materialized surface, whose
variant catalog is cleared. Credential preparation and protected continuations
use that retained ID for named and default variants. Signed handler fixtures
verify variant-specific resource audiences, base-audience rejection on named
routes, successful protected retries and quiet subscription cancellation.
The Access Point and Fabric retry fixtures assert the retained variant ID and
resource in the encrypted continuation binding. Full Access Point router and
encrypted cross-gateway authorization conformance remain separate checks.

Outbound listeners retain the original surface catalog in live shared state;
only identity-engine compilation uses the default-resolved snapshot. Named
Transit routes use `/outbound{surface-route}$alias/{transit-point}` or
`{listen_path}$alias` on a custom mount, with `%24` accepted in place of `$`.
Both spellings select the same variant and strip the route and variant suffix
before forwarding the remaining path. Listener fixtures cover default and
named Targets and root and nested forwarding; shared-state tests cover catalog
preservation through reloads.
Signed custom-path subscription fixtures additionally check variant-specific
metadata and challenges, base-audience rejection, credential forwarding and
quiet cancellation. Route-shape changes still require listener rebuilding.

## HTTP Endpoint Admission

Optional `mcp_http` config belongs on each MCP surface, Transit Point, and
standalone MCP Proxy. It is inherited with the Access Point by surface
variants, not from the Access Point to Transit Points. Surface POST uses the
supplied value; PUT retains an omitted or null value, including matching
Transit Points in the base and variant catalogs by stable IDs; merge PATCH
removes the Access Point value with null. To clear a Transit Point value
through RFC 7396, replace its points array with records without that field,
since arrays merge wholesale. Explicit `{}` restores default HTTP settings.
`authorization` is preserved on its own: a PUT that sends an `mcp_http` block
without it leaves the stored requirement in place, because an unrelated edit
must not silently unauthenticate the endpoint.
Removing it takes a PATCH that sets `mcp_http.authorization` (or `mcp_http`) to
`null`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `allowed_origins` | `[]` | Additional exact serialized HTTP(S) origins, without paths, wildcards or credentials. |
| `max_request_bytes` | `1048576` | Maximum decoded request body size before protocol parsing. |
| `max_header_bytes` | `16384` | Sum of header-name bytes, value bytes and four framing bytes per field. |
| `max_accept_ranges` | `32` | Maximum nonempty parsed Accept media ranges across repeated fields. |
| `max_response_bytes` | `1048576` | Maximum modern JSON response or normalized SSE event bytes. |
| `max_chunk_bytes` | `262144` | Maximum modern upstream response chunk bytes. |
| `stream_idle_timeout_secs` | `60` | Maximum wait for nonempty upstream response bytes. A forwarded `subscriptions/listen` stream is quiet between notifications, so it is bounded by `stream_max_lifetime_secs` instead. |
| `stream_max_lifetime_secs` | `3600` | Maximum modern response read lifetime. |
| `authorization` | Absent | Resource Server token requirement; see [MCP Resource Authorization](#mcp-resource-authorization). |

Numeric limits must be nonzero. These are project limits, not MCP constants.
Stream timeouts require idle <= maximum lifetime <= 86400 seconds. Modern
upstream header acquisition uses the resolved network request timeout (30
seconds when absent), separately from response-stream deadlines. Modern direct
calls are not automatically retried after an ambiguous failure.
Non-MCP endpoints reject the config. Every setting applies to every MCP
endpoint, whichever revision a request carries, so `2024-11-05` clients also
receive `403` (Origin), `431` (header budget) or `413` (body limit, 1 MiB by
default). Size the limits and allowlist browser origins for each endpoint. The
configured public HTTP(S) listener origins and explicit allowlist are trusted;
a public endpoint given as a bare listen address (for example `0.0.0.0:8443`)
names no HTTP(S) origin and adds nothing to the allowlist. Any other public
endpoint that is not an HTTP(S) origin, such as a URL missing its scheme, also
adds nothing and is logged once as a warning. Request
Host/Forwarded headers and CORS do not grant Origin authority. A framed Fabric
stream receiver independently uses its stored Access Point URL and allowlist, so
a browser Origin carried on a framed stream must be allowlisted on the
receiving surface too. A buffered Fabric `ForwardRequest` receiver does not
check the forwarded Origin, because the sending gateway already checked it
against its own surface; header and body limits still apply, and the forwarded
Origin still counts toward the header budget. A framed request the receiver refuses this way is
answered on the stream with the same status and JSON-RPC error a direct endpoint
returns, so the caller gets `403`, not a timeout. Missing Origin is
allowed for non-browser callers. Present `null`, duplicate, malformed, or
untrusted Origins return HTTP `403`. These checks also apply to legacy POSTs.

Each mounted entry point resolves accepted and advertised revisions from its
own transport path: the Access Point router uses the direct Access Point
policy, the outbound listener the Transit Point policy, and framed Fabric
receive the Fabric receive policy. An Access Point or Transit Point whose
Target is `fabric://` is further limited to the Fabric send policy, so a
modern request that leg cannot carry returns HTTP `400` / `-32022` at
admission, before payment, policy or consent work. Buffered Fabric
`ForwardRequest` messages are legacy-only; modern MCP crosses Fabric only as
framed streams.

Direct Access Points, MCP Transit Points, and standalone MCP proxy POSTs bound
body reads before parsing. Oversized bodies return `413`; oversized headers
return `431`. Fabric receives an already decoded message and checks these
limits independently before Target dispatch. A malformed HTTP security header
in the Fabric JSON envelope is rejected rather than silently dropped.

The shared admission order is header budget, Origin, body budget, the existing
MCP wire validator, then the admitted modern message's media contract. Standard
mirror/version errors therefore retain their existing ordering. Modern request
fixtures require exactly one `application/json` Content-Type with UTF-8 when
a charset is supplied, and explicit positive-quality `application/json` and
`text/event-stream` Accept ranges. MIME parameters, quoted commas and repeated
Accept fields are parsed; wildcards alone do not satisfy MCP's two-type
requirement. An explicit zero quality cannot be overridden by a duplicate or
wildcard. Malformed Accept values return `400`, unavailable representations
`406`, and unsupported Content-Type `415`. These media checks apply only to
admitted modern messages. Notifications do not inherit request-only
Accept requirements; extension notification acceptance is a separate dispatch
decision.

GET/DELETE with an explicit single
`MCP-Protocol-Version: 2026-07-28` return `405` with `Allow: POST`, even with an
attached legacy session ID. Unmarked or legacy-version GET/DELETE retain the
existing route behavior, including legacy GET-SSE. This rule applies to direct
Access Points, Transit Points, standalone proxies, and Fabric receive.

Standalone proxy POSTs run the same raw-body wire validator before legacy SSE
session lookup, so an attached session ID cannot bypass a modern rejection.
Legacy initialize results, JSON/SSE responses, and accepted notification
statuses retain their existing behavior.

## Keys And Read Compatibility

Canonical MCP output uses these aliases. Existing constants and A2A/AP2 URL
envelopes retain their original values.

| Historical Affinidi URL | Canonical MCP key |
| --- | --- |
| `https://fabric.affinidi.io/extensions/agent-identity-credential/v1` | `io.affinidi.fabric/agent-identity-credential` |
| `https://fabric.affinidi.io/extensions/agent-identity-binding/v1` | `io.affinidi.fabric/agent-identity-binding` |
| `https://fabric.affinidi.io/extensions/trust-registry` | `io.affinidi.fabric/trust-registry` |
| `https://fabric.affinidi.io/extensions/agent-identity/v1` | `io.affinidi.fabric/agent-identity` |
| `https://fabric.affinidi.io/extensions/custom-metadata/v1` | `io.affinidi.fabric/custom-metadata` |

The final two aliases recognize those envelopes when present; they do not
introduce an additional identity or custom-metadata feature. Valid unprefixed
keys such as `agentIdentity`, `serverIdentity`, `didwebvhIdentity`, `tenant`,
and `progressToken` are not automatically renamed. A prefix is optional for
ordinary MCP metadata keys.

The [MCP metadata key grammar](https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta)
allows an empty name, including an empty unprefixed key. This is intentional,
not a requirement to invent a vendor prefix for every key.

- Readers prefer the canonical container, with historical metadata retained
  as an explicit compatibility input. Ordinary canonical values win over
  duplicate ordinary top-level values; nonconflicting split metadata is kept.
- Equal recognized aliases are deduplicated. Conflicting identity/owned values
  across aliases or locations are rejected, not chosen by map order.
- A present malformed canonical metadata container never falls back to root
  metadata. Malformed caller metadata returns HTTP `400` / `-32602` with a
  recoverable string/integer request ID.
- Canonical output migrates the envelope, removes the old root metadata, and
  emits one spelling per recognized alias. Unknown third-party URL keys are
  not guessed or renamed; canonical output rejects invalid key syntax.
- Only envelope keys are migrated. Tool arguments, schemas, signed VC/VP
  contents, proof strings, identity fields, and continuation state are not
  rewritten. Metadata-free legacy payloads are left unchanged.

The historical read fallback has no automatic removal date. Removing it or
changing the default requires a separate migration decision. It cannot provide
missing modern protocol version/capability fields or make an invalid modern
request valid.

## Recorded Decisions

These choices are deliberate and are not open questions.

| Decision | Choice |
| --- | --- |
| Top-level `_meta` reads | Retained indefinitely as an Affinidi compatibility extension, not MCP behavior. Canonical output still migrates the envelope. |
| Unmarked requests | A request carrying no modern metadata and no mirrored method/name headers keeps the local compatibility path. That path is a retained Affinidi behavior; it is not evidence of an established legacy session, and it never makes an invalid modern request valid. |
| Intermediate revisions | Only `2024-11-05` and `2026-07-28` are modelled. `2025-03-26`, `2025-06-18` and `2025-11-25` are rejected with `-32022` listing the versions actually supported; semantics are never inferred by comparing date strings. A legacy `initialize` that asks for a revision the endpoint does not serve (an intermediate revision, or `2026-07-28`, which has no handshake) is forwarded asking for the newest legacy revision the endpoint serves, `2024-11-05`, on direct Access Points, Transit Points and Fabric receive, so the upstream cannot settle a session whose later requests would be rejected. Gateway-owned MCP Proxies already answer `initialize` with `2024-11-05`. This applies to `2025-03-26` clients too, although that revision sends no `MCP-Protocol-Version` header and their later requests are never refused: the upstream answers `2024-11-05`, and such a client continues on it, without `2025-03-26` features, or ends the session. |
| OAuth roles | Per surface, the gateway is the Resource Server, and the Authorization Server only through the opt-in `sts.mcp_issuer` profile. No browser-facing authorization-code or PKCE endpoint is offered, so authorization server metadata advertises only the token-exchange and JWT-bearer ID-JAG grants the profile implements. |
| Conformance scoring | The published MCP conformance suite is scored only against its frozen `2026-07-28` requirement set, matching the modelled revisions. The frozen `2025-11-25` set is permanently out of scope and is never a release gate. |

## Ownership And Verification

Operator metadata cannot overwrite MCP-reserved prefixes, `progressToken`,
`traceparent`, `tracestate`, `baggage`, or known gateway identity/trust fields
and their aliases. Prefix reservation checks the second label: `dev.mcp/`
and `org.modelcontextprotocol.api/` are reserved, while `com.example.mcp/`
is not reserved by that rule. Single-label prefixes such as `mcp/` and
`modelcontextprotocol/`, or those names in the first label, are not reserved
by the specification's second-label rule. Reserved protocol values are preserved
without assuming their shape; preserved tracing strings are not newly trusted
or used for tracing by this migration.

Checks apply at surface creation/update across all resolved variants. The
request boundary rechecks only the selected, already-resolved surface snapshot
for loaded configuration; it does not clone and revalidate unrelated variants.
Invalid configured metadata is not silently skipped. Configured raw-identity removal and delegated-token
destinations cannot target protected keys. These protections apply in both
output modes; `compatibility` is not a security bypass.

Presented MCP binding and credential VPs are verified once at admission, before
forwarding, using the existing signature, credential lifetime, holder/subject,
and issuer checks. The extraction audit is emitted at that admission boundary,
not again when a later stage consumes the verified context. An outer `did` must agree with the verified holder. Missing
or invalid proof is rejected with the existing HTTP `422` identity-problem
response, never forwarded as gateway-issued identity. On Fabric receive, the
issuer must be one of the sending connection's issuers: the paired gateway's
attested issuer DID or an issuer DID the operator trusts for that connection
(see "Peer issuer DIDs" in `AGENTS.md`); a caller-supplied HTTP header is not a
substitute.
The verified context is reused so a challenge is not consumed twice.

Extracting declaration data for policy is not cryptographic verification.
Verified identity provenance remains separate. Configured raw identity payloads
still follow the existing schema-based identity-resolution flow. Source bearer
credentials remain stripped under the existing forwarding rules.

## Custom Metadata And Results

`Meta`, `Headers`, and `Both` retain their meanings. Secret/runtime value helpers
are resolved using the existing resolver. A namespaced key containing `/` is
valid for `Meta` but cannot be converted blindly to an `X-Gateway-*` header.
`Headers`/`Both` require a valid HTTP header name and string value; use `Meta`
for keys that have no valid existing header representation.

Enabled custom metadata is required processing, including in the default
`compatibility` mode. A failed secret/runtime value-helper lookup blocks the
request or response instead of silently omitting configured metadata. On the
direct HTTP path, request injection failure returns `500` before forwarding;
response injection failure returns `502` rather than the upstream success.
The shared writer extends the Transit Point's existing fail-closed behavior to
direct and Fabric injection. This is an availability change from their older
best-effort writers, not a canonical-only setting. Validate helper references
and secret-store access before upgrading; monitor injection failures during
rollout. Compatibility output does not restore best-effort injection.

Canonical output also rejects malformed or nonconforming upstream metadata
with `502` instead of returning a partially normalized response. Audit upstream
keys before opting in; historical unknown URL keys are not automatically renamed.

Results preserve `resultType`, arbitrary extension result types, tool-level
`isError`, unknown fields, schemas, pagination, content blocks, and cache hints.
Canonical legacy output does not add modern protocol fields. No new VP or
operator enrichment is added to `input_required` or unknown nonfinal result
types; existing metadata, `inputRequests`, and opaque `requestState` survive.
This is a local enrichment decision, not an MCP prohibition on interim metadata.
JSON-RPC errors do not gain `resultType`, `params`, or successful result objects.

A cacheable modern result keeps the upstream's `ttlMs` and `cacheScope` unless
the gateway makes it caller-specific; it then becomes private with zero TTL.
That happens when gateway or operator metadata is written into the result
(custom metadata also sets `Cache-Control: private, no-store`), and when the
result is authorized or filtered per caller: on the direct Access Point by a
surface or variant OPA policy, MCP tool gating or a response policy; on a
Transit Point by its tool gating, response policy or response extension rules.
Gateway-level OPA only admits requests, so on its own it leaves the hints
unchanged. There is no gateway response cache. Existing legacy SSE behavior is
retained; the buffered legacy Fabric forward still reduces SSE to its final
JSON response, while modern MCP crosses Fabric as live framed streams.

## Policy Context

The shared policy builder can carry the following fields from a validated
modern request into `input.mcp`:

| Field | Source | Presence |
| --- | --- | --- |
| `protocol_version` | Admitted protocol version | Validated modern messages only |
| `client_capabilities` | Admitted `params._meta` declaration | Required on modern requests; optional on notifications |
| `client_info` | Admitted `params._meta` declaration | Only when supplied |

Legacy policy input still has `input.mcp`, built from the request body rather
than a validated modern message: `method`, `tool_name` for `tools/call`, and raw
`params`. All three fields above are absent from it, including when a caller
supplies only the supported legacy version header. The direct Access Point and
Fabric receive both build it, so a Fabric-received legacy request gets the same
`input.mcp` as a direct one. Existing legacy method/name extraction and reduced
per-tool policy objects keep their shapes.
Modern context preserves the exact method, raw params and arbitrary extension
declarations. Known modern tool, resource and prompt requests also expose the
corresponding `tool_name`, `resource_uri` or `prompt_name` field. Modern
notifications do not need a fabricated request ID or client capability object.

Direct, Transit Point, Fabric send and independent Fabric receive policy
builders carry the admitted snapshot rather than re-reading protocol metadata
from an enriched body. The receiver validates for itself. Gateway and surface
policies, Trust Check templates, tool gating and specialized MCP tool policies
receive the modern declarations; per-tool list filtering keeps those
declarations while setting the evaluated tool name. No legacy session supplies
capabilities to modern context.

Capabilities are self-reported support declarations, not authentication or
authorization evidence. `client_info` is display/debug data and must not
establish identity, tenancy or access. Verified caller context stays in the
existing source-auth and identity fields. For example, a unit/component Rego
fixture may combine a verified caller with the declared protocol:

```rego
package surface.policy

default allow = false

allow if {
  input.source_auth.method == "api_key"
  input.source_auth.key_name == "trusted-client"
  input.mcp.protocol_version == "2026-07-28"
}
```

A policy sees a modern `protocol_version` only for admitted `2026-07-28`
requests; unmodelled revisions are rejected before policy or forwarding. Test
fixtures use an explicit local version policy, never a production bypass.

### Common Modern Message Helpers

The modern helper layer validates common response envelopes, request
IDs, result types, basic continuation fields and cache hints without stripping
method-specific or vendor fields. It distinguishes strict modern results from
compatibility reads: an absent `resultType` is interpreted as `complete` only
for compatibility reads, never added to an upstream result to claim modern
support. Gateway-owned complete-response construction supplies `resultType`
and conservative `ttlMs: 0` / `cacheScope: private` defaults for cacheable
methods. Nonfinal results cannot be relabeled as completed responses.

Forwarded modern notifications have a separate response path: acceptance is
HTTP `202` with an empty body, while rejection preserves an HTTP error status
and an optional bounded JSON-RPC error without an `id`. Other success statuses,
unexpected bodies on `202`, and response envelopes with IDs are rejected.
Notification responses skip result enrichment, discovery rewriting and
continuation finalization, retain the shared byte and idle limits, and never
mint session headers. Tests cover direct forwarding, independent signed Fabric
receive, and Transit Point HTTP/Fabric response adapters. This is transport
support for extension notifications, not a new core notification feature;
gateway-owned dispatch still rejects notification methods it does not implement.

Modern request metadata validates optional `io.modelcontextprotocol/logLevel`
against the defined logging levels and `progressToken` as a string or number.
Invalid values return correlated HTTP `400` / `-32602`; legacy classification
is unchanged. The request SSE adapter requires the current request's valid
logging opt-in, a defined notification level, present log data and an optional
string logger. Progress notifications require the matching typed token, numeric
progress and optional numeric total/string message. Notification metadata must
be an object. Valid extension methods and fields pass through unchanged, and
request notifications never acquire subscription IDs or result enrichment.

Required client-capability checks produce HTTP `400` / `-32021`, retaining the
request ID and the exact `data.requiredCapabilities` object. The checks use only
the current request. Implicit form elicitation does not imply URL-mode support;
extension settings remain opaque and are not merged or interpreted by a generic
subset matcher. Extension availability requires declarations from both peers.
The gateway originates no extension traffic, so on forwarding paths it does not
enforce a client's extension declaration: an extension request is forwarded
whether or not the client declared the extension, with the declaration
unchanged, and the upstream decides.

The project-authored [common-result fixtures](../tests/fixtures/mcp/2026-07-28.json)
pin their source schema revision, immutable commit and digest. They are a
preservation regression set, not the full method-specific conformance suite.
No network access is needed during their tests.

### Owned Modern Dispatch

Standalone MCP Proxies and surface-backed `proxy://` targets have a modern
dispatcher for `server/discover`, `tools/list`, `tools/call`, and streaming
`subscriptions/listen`, reached by admitted modern requests. Discovery
advertises tools with `listChanged: true` and the accepted endpoint versions,
with `resultType: complete`, private zero-TTL cache hints, and server
information in `result._meta.io.modelcontextprotocol/serverInfo`. Unsupported
methods and notifications
return HTTP `404` / `-32601`; they never enter legacy session handling.

Owned tool catalogs are name-sorted and retain the available title,
description, annotations, input schema and output schema. Modern REST execution
reuses the OpenAPI library's parameter extraction and validation and returns
structured JSON results, text or image content, and `isError` for HTTP failures.
Argument failures are `400` / `-32602` before network execution;
execution failures remain error tool results. Catalog locks are released
before the REST call. Surface-backed dispatch runs after the shared request
gates and credential preparation, with surface timeout/circuit-breaker
controls and the common modern final-response pipeline. Standalone inbound
headers are used for mirror validation, not as REST Target credentials.

The OpenAPI library rebuilds parameter schemas and can drop extension
annotations. Modern catalog construction restores request-body and
path/operation parameter schemas from the stored OpenAPI source, matching
parameters by original name and location. `flatten_post_params` is confined to
this owned REST adapter. Modern flattening rejects colliding parameter names,
optional bodies with required children, and body-level constraints that cannot
be preserved. Simple object flattening retains additional-property semantics
and validates mirrors against the public flat arguments before REST wrapping.
Legacy schema conversion is unchanged.

Modern catalogs compile advertised input and JSON output schemas with the
existing Draft 2020-12 validator and an offline-only retriever. Calls validate
the public arguments before REST parameter extraction; successful JSON results
that violate the output schema become tool errors without structured content.
Source constraints and vendor fields survive conversion, and a bounded set of
transitively referenced OpenAPI component schemas remains available at its
original local pointers. Explicit schema resources retain their `$id`, `$defs`
and reference scope. Unresolvable external references are never fetched or
advertised as enforceable tools.

For Proxies whose source schemas the legacy OpenAPI converter cannot load, the
Proxy registers with a modern-only catalog instead of failing: a separate modern routing catalog uses the library only for
operation and parameter mapping; original schemas remain authoritative for
modern validation. That routing catalog is never used by legacy calls, and
discovery omits legacy support when no legacy catalog exists. `2024-11-05`
clients of such a Proxy get `500`, so its create and update responses carry a
`warnings` entry naming the converter error. Both catalogs
are published as one snapshot after a successful build; a failed reload keeps
the previous snapshot and removal drops both. Tests cover conditional input
constraints, nested component references, scoped local definitions, output
constraints, truthful discovery and failed-reload preservation. This does not
establish fidelity for every OpenAPI or JSON Schema composition.

The modern-only REST adapter uses the shared no-redirect HTTP client. Redirects
fail before a second endpoint is contacted; response content length, chunks,
headers and accumulated bytes are bounded by the endpoint limits, and an
oversized stream is dropped without waiting for EOF. URL path parameters are
encoded as segments and cannot replace the configured authority. Tool arguments
cannot override prepared Target credentials or protected transport headers.
Catalog construction and execution select the same OpenAPI request media type;
JSON, URL-encoded forms, text and multipart uploads use maintained encoders,
with multipart fully bounded before sending. Request-body and parameter
references are resolved only within the stored OpenAPI document with a fixed
depth bound, never fetched over the network. Tests cover a real redirect
destination, oversized streaming responses, credential conflicts, path escaping,
images, forms and an actual owned multipart call. These checks do not
establish full offline schema fidelity or complete client-security
conformance, and the conformance harness scores owned endpoints only on the
tool subset listed under [Conformance Harness](#conformance-harness).

### Forwarding Discovery

Forwarding endpoints constrain `server/discover` through the shared JSON/SSE
response adapter. Supported versions are intersected with the resolved
endpoint's version policy; a response that does not include the requested
modern version is rejected. Capabilities are limited to the path's implemented
features, preserving the upstream settings of retained capabilities. Unknown
capability and extension claims are not advertised without explicit path
support. Upstream server information, icons, instructions and other result
fields remain unchanged. No network reference or icon fetching occurs.

The supported versions a forwarded discovery result delivers to the client are
remembered for its endpoint: the surface, the Access Point variant or Transit
Point alias, and the Target. A `-32601` discovery error marks the endpoint as
legacy-only; any other error, or a result the gateway rejects, records nothing.
Entries replace earlier ones, expire after five minutes and are capped at 1024
endpoints. A later `-32022` from that endpoint lists only the remembered
versions, keeping the path's versions when nothing is remembered or nothing
would remain. Only the advertised list changes: admission is unaffected and the
upstream is never contacted to build the error. Discovery on the direct Access
Point is constrained by the same version policy that admitted the request.

Fabric responses carry the selected peer's negotiated support in an internal
HTTP response extension, not a caller-controlled header. Discovery on both
Fabric ends is restricted by that agreement, including the separate subscription
capability. An absent agreement cannot imply support. Any changed discovery
result becomes private and immediately stale (`ttlMs: 0`); HTTP responses use
`Cache-Control: no-store`. There is no gateway response cache or automatic
legacy-to-modern bridge.

### Modern Subscriptions

The shared subscription state machine accepts the exact `notifications`
filter fields: `toolsListChanged`, `promptsListChanged`,
`resourcesListChanged`, and `resourceSubscriptions`. Filters must be objects
with boolean flags and at most 128 resource URI strings, each at most 4096
bytes. Shared HTTP admission validates filters after wire and media checks;
malformed filters return `400` / `-32602`. On an endpoint that does not admit
`2026-07-28`, the `-32022` version rejection takes precedence.

Each stream requires `notifications/subscriptions/acknowledged` first, carrying
only a subset of requested filters. Every subscription notification retains the
original string or integer request ID in
`params._meta.io.modelcontextprotocol/subscriptionId`. Unacknowledged,
unrequested, miscorrelated or duplicate-acknowledgement events fail closed.
Progress and logging belong to their originating request stream, never to a
subscription. A graceful final result carries `resultType: complete` and the
same subscription ID in `result._meta`; it bypasses application-result
enrichment. A successful subscription cannot be returned as a single JSON
response without the SSE acknowledgement.

Owned subscriptions acknowledge only requested tools-list changes. A bounded
catalog hub allows 128 live subscriptions, at most 16 per proxy, with independent
stream identifiers even when callers reuse JSON-RPC IDs. Successful persisted
proxy changes coalesce into tools-list notifications. Disable, removal,
ownership, routing or security-setting changes close existing subscriptions.
Request-time catalog construction does not emit change events. Unsupported or
empty filters receive an empty acknowledgement followed by graceful completion.
The owned producer also completes at its configured lifetime and frees its
registration on body drop.

Direct, Transit, standalone and Fabric subscription responses retain an access
revision captured before request setup. Persisted surface changes, policy
refresh/removal, API-key revoke/rotate/delete, JWT strategy mutations/reload,
credential-provider mutations and explicit vault revocation conservatively
invalidate existing subscriptions appliance-wide. Policy, strategy and provider
mutations signal at both start and finish; vault revocation signals inside its
cancellation-safe mutation task. Reads do not invalidate access. Streams close
without waiting for upstream activity and must reconnect through current checks.
Verified JWT expiry and Transit-token expiry can only shorten the configured
lifetime.

Access Points, Transit Points and independent Fabric receivers additionally
capture the configured vault's uncached durable revocation epoch before
credential evaluation and recheck it once per second, including while upstream
is quiet. The check has a one-second timeout and closes the stream on a changed
epoch, unavailable or corrupt state. An initial failure returns a correlated
HTTP `503` before dispatch; vault adapters that cannot provide a revision fail
closed. Local-filesystem tests revoke in a separate process with the local watch
signal disconnected and verify quiet-stream closure, read stability and corrupt
state handling. This does not establish remote-filesystem visibility. Other
credential kinds, cross-process configuration notifications, external token
revocation and full resource-policy revalidation are not verified.

An isolated signed Access Point handler fixture verifies missing, wrong-audience,
insufficient-scope and expired Resource Server tokens stop before the subscription
Target. The successful path forwards only the verified delegated credential,
retains the subscription ID and emits no legacy session header. Recompiling a
real surface policy from allow to deny closes its quiet stream and denies a new
subscription; restoring allow permits a new connection. Explicit vault revocation
also closes the upstream stream and denies reconnect without verified consent.
This is direct-handler coverage, not proof of every Transit Point or Fabric
authorization and lifecycle path.

A separate signed Fabric-receiver fixture verifies subscriptions against the
receiver's own resource audience and scopes, independent of sender admission.
Missing, expired, ingress-audience and insufficient-scope tokens never reach its
quiet Target. The valid path uses a verified agent presentation and delegated
credential, preserves the subscription ID, closes on vault revocation and denies
reconnect without consent. It invokes the receiving pipeline directly with a
test-local policy; complete encrypted-route authorization remains a separate
check.

The full Transit Point handler has a corresponding signed subscription fixture
on an A2A parent with an MCP Transit Point. Its own resource
audience/scopes and token expiry are enforced before Target work, ingress tokens
and session headers are stripped, and only the verified delegated credential
is forwarded. The managed agent has a registered signing key for the existing
presentation stage. Revocation closes quiet upstream work and denies reconnect.
Both handler and admission step receive an explicit test policy. With Transit
tokens required, admitted
modern requests additionally require exactly one token, a configured validator,
the current surface ID, an allowed Transit Point, a nonempty token ID and strict
issue/expiry times. This modern-only check runs after protocol admission and
before identity/Target work; legacy validation keeps its existing behavior.
The fixture rejects cross-surface, wrong-point, duplicate and expired tokens,
and verifies a quiet subscription closes at Transit-token expiry and rejects
reuse. Named and custom-path variants have signed handler coverage; full
encrypted-route authorization conformance remains separate.

Fabric requires both request-stream and subscription capabilities. Composed
tests cover acknowledgement, catalog changes, graceful results and quiet
downstream cancellation across both registries. After a validated final result,
the MCP adapter explicitly releases the Fabric response lease to its listener
driver and waits for the terminal handshake. The driver accepts only the exact
End boundary, sends EndAck and reports completion; extra data, a missing End,
deadline, listener loss or downstream cancellation fails the handoff. Ordinary
body drops never request successful completion.

Resource updates may name sub-resources of an acknowledged resource. The shared
filter accepts an exact parsed URI, a hierarchical child at a path-segment
boundary, or a fragment of the same resource when the subscription did not name
a fragment. Scheme, authority, user information and query must match; siblings,
changed queries and other authorities remain excluded. An explicit fragment or
opaque URI requires exact parsed equality. Updates retain the 4096-byte URI
limit and reject control characters. This matching is not an authorization
grant: resource access and lifetime checks still apply independently. Opaque
provider-specific sub-resource relationships and negotiated extension
notifications are not verified.

### Protected Continuations

`mcp::continuations` provides gateway-owned protected continuations. The
direct, Transit Point and Fabric receive modern request branches use this
service for gateway-originated consent (MRTR), which needs both
`[mcp.continuations]` in the bootstrap config (below) and `sts.mcp_issuer`
(see [MCP Resource Authorization](#mcp-resource-authorization)). A modern
request to an endpoint that has `outbound_credentials` while
`[mcp.continuations]` is not configured fails with HTTP `503`, JSON-RPC
`-32603` ("MCP credential service unavailable"); there is no legacy consent
fallback. Full cross-gateway delivery and callback conformance is not verified.
The separate modern
consent connect/callback routes reuse the existing Credential Provider and JWT
verification strategy stores to verify provider-issued OIDC identity tokens.
The async storage contract distinguishes unavailable storage, conflicts,
binding mismatches, expiry and capacity failures; a storage error never means
that consent was granted or that a request was safely replayed.

Records carry a random UUID, binding digest, issue/expiry times, monotonic
revision, retry round and phase. Pending input/consent can become ready or
denied. Only ready records can be claimed for dispatch; claimed records can
be consumed but never rearmed. Pending retries atomically rotate their round
and protected state without extending expiry. The maximum TTL is 900 seconds
and at most eight rounds are represented. Old-round state and repeated retry
request IDs are rejected. A client elicitation `accept` does not make a record
ready; readiness requires a separately verified consent/token outcome.

The embedded implementation uses bounded atomic process-local state and loses
outstanding continuations on restart. It is for single-active deployments,
not replica-safe storage. The DynamoDB implementation uses strongly consistent
GetItem, create-if-absent PutItem and conditional UpdateItem checking binding,
revision, round, phase, issue time and logical expiry. It reuses the repository's
`PK`/`SK` convention, both `McpContinuation#<deployment>:<uuid>`. A provisioned
table needs string PK/SK attributes and TTL on the numeric `expires_at` field;
application expiry is enforced regardless of asynchronous DynamoDB TTL deletion.
The runtime role requires `dynamodb:GetItem`, `dynamodb:PutItem`, and
`dynamodb:UpdateItem` on that table. The adapter does not provision infrastructure
or silently fall back to memory.

Client-visible state always uses AES-256-GCM, independently of optional disk
encryption. The existing encryption helper now supports associated data while
legacy callers keep empty-AAD compatibility. Continuation AAD binds purpose,
format version, deployment and key ID. A dedicated key ring has at most four
zeroizing keys, explicit issue/decrypt windows and a previous-key overlap of
at most the maximum continuation TTL. Missing, expired or unknown keys fail
closed. Plaintext claims are bounded to 32 KiB and encoded state to 64 KiB;
no plaintext fallback is accepted.

Claims bind the authenticated principal, authorization digest, tenant when
applicable, surface, variant, route role, canonical resource, credential
provider, agent DID, user identity hash, required scopes, method and argument
digest. JCS canonicalization uses
`serde_json_canonicalizer`, avoiding the older optional `serde_jcs` library's
arbitrary-precision-number panic without changing its existing consumers.
The request digest covers method and root params except `_meta`,
`inputResponses` and `requestState`; nested fields with those names remain
business inputs. Nonfinite or unsafe integer values, excessive nesting and
large parameter trees are rejected. Integration must derive authorization and
resource bindings from verified/configured inputs, not client declarations.

The service seals state before creating its record, validates current request
bindings before lookup, claims atomically before dispatch and restores the
original opaque upstream `requestState`/`inputResponses` only for the claimed
operation. It never interprets that upstream state as a gateway token. This
is not exactly-once execution for arbitrary upstream services: an ambiguous
dispatch failure remains claimed and is not automatically retried.

On consent-enabled direct paths, an authenticated continuation kind separates
gateway consent from a forwarded upstream continuation. The gateway wraps an
upstream `input_required` result in its own protected state, retaining the
upstream state verbatim and the upstream's requested input keys. A retry first
authenticates the outer wrapper, then selects its bound provider and validates
the current request context. It restores only the requested upstream responses;
unknown keys are ignored, even when a key resembles a gateway consent key.
If renewed gateway consent interrupts that retry, the restored upstream state
and responses are protected inside the new consent ticket. Transparent paths
without gateway consent continue to forward upstream state unchanged.

Direct modern consent runs after current source authorization, managed identity,
Trust Check and policy/tool gates, before local or delegated payment and Target
dispatch. Legacy payment order is unchanged. Direct modern policy evaluation
therefore precedes payment settlement and does not see a settled payment context.
Continuation claims precede payment verification as well as Target calls. Direct
and sending Access Points, and independent Fabric receive, inspect local payment
requirements first: a ready
continuation with no applicable payment credential returns the local challenge
without claiming it or activating staged consent. Repeated unpaid checks leave
the retry usable; a later paid retry still needs the atomic claim. Failed or
ambiguous payment processing never rearms a claimed continuation. Delegated
payment challenges and real payment-rail conformance are not verified. Both
JSON and SSE use a separate
terminal-response finalizer for continuation wrapping/consumption; application
enrichment remains complete-only, and subscription completion bypasses both.
The direct handler test supplies explicit internal admission dependencies. It
checks pending
consent before unavailable delegated payment, changed-policy rejection,
delegated-token injection without the caller bearer, JSON/SSE upstream-state
restoration and one Target call under concurrent retries. A local x402 fixture
also checks repeated HTTP 402 responses followed by one successful paid retry
and one conflict, with exactly one Target invocation; it uses mock verification
and no settlement and does not establish external payment-rail conformance.

Only the credential argument consumed by the active local paywall is excluded
from the continuation's business-argument digest: `payment_signature` for x402
or `payment_credential` for MPP. Other arguments, nested fields, and credentials
for disabled, unmatched or delegated paywalls remain bound. Successful modern
payment processing removes the consumed header and argument, including a second
argument copy when a header supplied the credential. x402 receipts use the
configured response header; MPP receipts use `Payment-Receipt`. Receipt absence
does not undo successful credential consumption. Legacy processing is unchanged.

Successful local payment on a consent-enabled modern path is retained as
authenticated evidence inside the encrypted continuation. Evidence records the
payment rail, optional receipt, verification time and expiry; receipt bytes are
bounded to 16 KiB and validity to the continuation's maximum lifetime. A later
round must validate the same authorization, surface, provider, route and
business arguments and win its own atomic claim before reusing the evidence.
The local processor rechecks expiry and rail and returns the original receipt
without another payment verification or settlement. Evidence expiry is never
extended by a new upstream round or renewed consent, and descendant state is
also capped to the previous operation's remaining lifetime. Direct and isolated
receiver JSON/SSE tests use a real local transaction store and mock verification
to assert one payment record across two rounds, identical receipts, and no
additional payment or Target call on replay. This is not external payment-rail,
full two-gateway, or distributed payment-store conformance.

The delegated-payment hop strips an endpoint-bound Resource Server bearer as
well as any configured source-auth credential; ingress authorization does not
authorize a separate payment resource. Payment headers remain available to the
delegate. For admitted modern requests, delegated HTTP 402 responses are
`no-store`; the retired payment codes `-32042` and `-32043` are mapped to the
gateway application codes `1001` (payment required) and `1002` (payment rejected)
with the caller's request ID and preserved challenge data and headers. Unknown
upstream codes and legacy response bodies remain unchanged. The existing remote
allow/challenge/deny contract does not establish that a challenged or timed-out
payment had no side effects, so a claimed delegated operation is never rearmed.
Safe delegated retries and cross-round remote payment reuse are not provided.

Transit Point preparation runs at the existing post-policy credential step.
It uses the independently verified endpoint resource token, resolved agent DID
and Transit Point alias, including the effective variant resource. The existing
JWT strategy store and continuation service are wired at startup and listener
rebuild. Prepared delegated headers are applied after caller-header filtering
and Target authentication, rather than stored in the incoming-header map.
JSON/SSE response finalization uses the same protected continuation service.
The admitted-step regression verifies source authentication, pending consent,
route/resource binding, delegated credential delivery to a real Target,
upstream-state restoration and replay rejection. Full routed callback and
authenticated Fabric delivery conformance remain required.

Fabric receive uses the same preparation after receiver-owned resource
authorization, verified agent-presentation admission and surface/tool policy
checks. Modern payment follows consent preparation; legacy ordering stays
unchanged. Its continuation binds the authenticated sending peer as well as
the receiving surface, variant, principal and resource. Prepared credentials
replace Target credentials only after caller-header filtering. Modern receiving
payment uses the shared local processor with receiver-owned configuration and
headers, including argument-carried credentials and case-insensitive header
names. x402 and MPP receipt headers and continuation finalization are shared by
JSON and SSE.
An isolated receiver regression uses a real signed agent presentation and
receiver-issued resource token, rejects a token for the ingress resource,
requires consent before Target calls, rejects a changed peer, and permits one
Target call under concurrent retries. It also covers repeated unpaid challenges,
header- and argument-carried x402 payment, receipt preservation and removal of
consumed credentials before the Target, using mock verification without
settlement. This fixture enters the receiver with
explicit test-local admission; it is not a managed-mediator or encrypted-frame
delivery test.

The sending Access Point also prepares modern consent after its Fabric policy
and tool gates, before mirroring, local/delegated payment or remote dispatch.
Its `fabric_send` continuation role binds the selected remote peer and is
distinct from the receiver's `fabric` role. Prepared credentials are added
after source-token stripping; they must authorize the receiving resource,
never reuse the ingress bearer. The sender wraps a remote `input_required`
response with its own state when local consent is configured, preserving the
remote state as opaque data. Sender-side wiring and receipt preservation still
require full two-gateway and managed-mediator conformance.

`claim_delegation` leaves pending consent pending even when an ordinary vault
record matches the agent/user/provider and scopes. Only a verified callback
stages a credential and marks its parent ready. A ready retry checks that
continuation's staged credential, binding, expiry, scopes and vault checkpoint,
wins the atomic dispatch claim, then activates the credential under the vault
mutation lock. Missing or revoked staged credentials deny the continuation;
activation failure never rearms a claimed operation. Two-store-instance tests
cover visibility and single-use activation, not remote-filesystem conformance.

Activated modern credentials carry optional server-side `consent_identity`
provenance containing the verified principal and provider/strategy digests.
Legacy callbacks and older records leave it absent. Modern request preparation
requires that provenance, the agent/user/provider identity, current scopes and
expiry before reusing a credential. Changed provider or strategy configuration
requires new consent. Expired verified credentials use the coordinated refresh
path when the provider permits refresh; otherwise new consent is required.

Modern preparation owns every configured credential binding, including bindings
skipped by their tool filter, so no modern method falls back to legacy consent.
Verified credentials can be reused on discovery, list, subscription and extension
methods. Only `tools/call`, `prompts/get` and `resources/read` can initiate or
resume gateway consent; other methods fail authorization when consent is needed.
API-key providers resolve required secrets without browser consent. Machine-token
providers use bounded, no-redirect client-credentials grants with the configured
HTTPS `resource` and exact effective scopes. Their expiring bearer credentials
use a separate provider-configuration-bound vault identity, never a legacy
machine-token cache entry. Missing secrets, rejected grants and persistence
failures stop dispatch; provider resource changes invalidate the modern cache.
Service-only bindings leave opaque upstream continuation state unchanged.

Applicable modern credential bindings must use distinct injection destinations:
HTTP header names compare case-insensitively, while canonical MCP metadata keys
compare exactly. Conflicts, reserved or malformed metadata keys, invalid header
names and formats without `{value}` fail before credential fetching or consent.
Credential values are bounded to 32 KiB and rejected on CR/LF or invalid header
bytes rather than sanitized. Prepared credential headers are marked sensitive,
and final header construction rejects duplicates defensively.

The file vault serializes mutations with an advisory lock, with cancellable
nonblocking acquisition bounded to five seconds, and atomically replaces
records. Once acquired, the lock moves into an owned mutation task; cancelling
the caller cannot release it before an outstanding filesystem write or delete
finishes. Waiting for the lock is still cancellable, and provider network calls
never hold it. A cancelled mutation can finish durably without returning a
result; its outcome must not be assumed absent or automatically retried.
Its consent upsert preserves the composite credential's ID;
refresh updates compare the stored version and owner before writing. A stale
refresh or usage update cannot recreate a revoked record, and rejected refresh
writes stop forwarding. Modern-provenance credentials use a durable refresh
claim under `refresh_claims`, keyed by credential ID and pinned to its version,
refresh-token digest and revocation checkpoint. Only one instance claims a
refresh; the filesystem lock is released before provider network work.
Publication rechecks the claim and current credential/checkpoint under the
same lock. Any concurrent revocation or replacement prevents publication.
Legacy requests using a modern-provenance credential honor the same claim;
ordinary legacy credentials retain their existing refresh path.

Refresh claims have a 45-second completion deadline and are not automatically
rearmed after a crash, cancellation or ambiguous provider response. A competing
request receives a temporary service-unavailable response while refresh is in
progress; an uncertain claim later requires new consent. Successful publication
updates the credential atomically and removes the claim. Provider refresh calls
are bounded to 30 seconds and 64 KiB, use the existing no-redirect external
client, send the configured upstream `resource` and existing scopes, and require
a valid expiring bearer credential without scope widening. Modern callers
recheck provider and strategy snapshots before publication. A provider
`invalid_grant` requires new consent; provider response bodies are not logged.
Tests with independent file-store instances and a held real provider response
prove one refresh call and no publication after revocation. A separate four-process
vault test races refresh claims, revokes the credential while the winner is
paused, and kills a claim owner abruptly. Restarted instances observe revocation
or an uncertain claim, never a newly reusable rotating refresh token. A paused
storage test cancels an update's caller and verifies that the lock stays held
until the write finishes before revocation can proceed.

The shared filesystem atomic writer uses exclusive UUID-named temporary files,
flushes and syncs their contents before rename, and syncs the parent directory
after rename on Unix. Entity deletion also syncs its parent directory on Unix.
I/O and sync failures propagate, except that a directory sync the filesystem
reports as unsupported (`EINVAL`, `ENOTSUP`/`EOPNOTSUPP` or `ENOSYS`) is logged
once as a warning and skipped, because the rename or deletion has already
happened. Ordinary failed writes remove their temporary file, while a crash may
leave an ignored `.tmp` file. These local guarantees and
tests do not establish remote-filesystem lock/visibility semantics, storage
hardware power-loss behavior or multi-host deployment conformance.

Modern callback credentials are staged separately under `mcp_consent` and are
invisible to ordinary vault lookup, listing and refresh. Staging is capped at
100,000 live records, with expired or invalidated rows removed on subsequent
staging or access. Protected callback state captures the current composite
credential version and a vault-wide revocation epoch. Any token or user
revocation rotates that epoch before deletion, conservatively invalidating
all outstanding consent attempts, including attempts with no existing token.
Credential replacement or refresh also invalidates a stale checkpoint.
Cancellation or a crash between staging and readiness leaves only an unusable
staged row. Activation and revocation serialize on the same filesystem lock;
if activation wins first, a later revocation removes the active credential.
These guarantees do not imply cancellation of an already-authorized dispatch.

The `consent` helper produces request-local URL-mode
`input_required` results only for a declared `elicitation.url` capability.
Each input key derives from the continuation UUID. Retry parsing reads only
that key, ignores unknown keys, rejects legacy response envelopes and inline
credential content, and persists decline/cancel as denial before any vault
read. Acceptance never establishes readiness. Results contain neither legacy
session identifiers nor cache hints or application identity enrichment.

URL mode is for third-party credential consent, not authorization of an MCP
client to this gateway. A modern connect/callback flow must verify that the
person opening the URL is the initiating authenticated caller; protected URL
state alone does not prove that identity. The existing public OAuth callback
does not establish this check and must not be treated as modern consent
authority without it. URL construction accepts HTTPS or loopback-development
HTTP and rejects userinfo and fragments, but does not itself establish user
identity or authorize a callback.

Consent-connect, consent-callback and MCP retry state have separate AEAD
purposes. A ticket binds the parent continuation, provider configuration
digest, resolved surface and identity-strategy digests, current authorization
context, exact callback URL and expiry; callback state additionally protects
the PKCE verifier and vault checkpoint. Substituting one
kind of state for another fails authentication. Callback setup is
create-if-absent, and callback consumption is claimed atomically before
provider exchange. A denied, expired or dispatched parent prevents new
callback work. The parent still requires a fresh vault check before MCP
dispatch; a callback claim is not proof that provider credentials exist.

The modern callback foundations live separately from the unchanged legacy
OAuth callback. When the continuation runtime, STS profile and existing
source-auth verification stores are
configured, `/mcp-consent/connect/{provider-id}` and
`/mcp-consent/callback/{provider-id}` are registered. The provider references an
existing JWT verification strategy through `consent_identity_strategy_id`.
Create/update enforce provider type, HTTPS issuer/resource, tenant-compatible
references and PAT resource scope; the reference participates in ownership
impact and reassignment. Connect and callback reject changed surface, provider
or strategy snapshots. No dashboard account, account-link registry or browser
copy of the MCP bearer is required or treated as proof of the consent user.

The provider authorization request adds `openid` and a ticket-bound nonce.
The callback requires an ID token verified by the existing `JwtBearerVerifier`
against that strategy's issuer and keys, the provider client audience, expiry,
issue time, nonce and authorized-party claim when applicable. Its verified
issuer/subject is mapped through the STS profile's deterministic subject
binding and must match the initiating MCP principal and user hash. Matching
email, bare subject, a different pairwise subject, client acceptance or copied
callback state cannot satisfy this check. Providers unable to prove the same
identity fail explicitly. A supplied authorization-response `iss` must equal
the configured issuer. Provider error responses persist denial; callback work
is single-use before exchanging the code, and failed identity proof never
stages credentials. Current source authorization and policy must run again
on the MCP retry.

Modern provider preparation uses the optional credential-provider `resource`
field, distinct from the gateway's own MCP resource. It must be a canonical
HTTPS URI; create/update validate it and omitted updates preserve it. Modern
authorization and token requests bind that resource, exact callback, scopes
and S256 PKCE. Provider additional parameters cannot override reserved OAuth
parameters. The token response is bounded to 64 KiB and 30 seconds; provider
error bodies and credentials are never included in the consent response.
Legacy providers without the new resource/strategy settings retain their
existing legacy behavior. Releases without these fields ignore `resource` and
`consent_identity_strategy_id` and drop them the next time they save the
provider. In-process callback-route tests use a real isolated token endpoint
and signed ID tokens, covering same-user success, wrong-user rejection,
configuration changes, provider denial, PKCE and single-use exchange.
Full cross-gateway and routed callback integration, distributed coverage, and
provider/redirect conformance remain required.

Startup-only `[mcp.continuations]` settings in the bootstrap TOML explicitly
select a deployment namespace, TTL, active key, key ring and storage backend.
Omission disables the continuation runtime, so modern gateway consent is
unavailable (see above). The selected key is loaded from
the existing Secrets store by record ID; its value must be 64 hex characters
encoding a nonzero 32-byte key. Each key declares numeric Unix-second
`not_before`, `seal_until` and `open_until` times. Startup rejects missing or
invalid key material and an active key unable to cover the configured TTL.
Keys are loaded once; a coordinated restart is required to install rotation
changes, and existing IDs/material must remain available during their overlap.
Embedded storage loses outstanding requests on restart; DynamoDB retains them.

```toml
[mcp.continuations]
deployment = "gateway-example"
ttl_secs = 300
active_key = "current"
max_pending_per_principal = 64

[[mcp.continuations.keys]]
id = "current"
secret_id = "existing-secret-record-id"
not_before = 1789516800
seal_until = 1792108800
open_until = 1792109700

[mcp.continuations.storage]
backend = "embedded"
capacity = 1024
```

The dates above are examples, not defaults; operators must choose current
rotation windows. For DynamoDB use `backend = "dynamodb"` and a `table` name
instead of `capacity`. The client uses bootstrap `aws_region`/`aws_profile`
and the AWS credential chain. Startup makes a ten-second-bounded consistent
read probe; it does not provision the table or prove write permissions.
`max_pending_per_principal` (default 64) caps the continuations one caller
(deployment, tenant and principal) may have issued and not yet expired; past
it, the caller gets `429` and other callers are unaffected. It is counted per
process, so with DynamoDB each replica applies it separately; with the
embedded backend it must not exceed `capacity`.
Unknown backends, bad limits and failed probes never fall back to memory.
These settings initialize storage and keys only; they do not change which
revisions an endpoint admits.

Replica-consistent credential storage and refresh locking are not verified,
and end-to-end MRTR admission/dispatch coverage is incomplete.
Offline DynamoDB tests inspect real SDK calls against an isolated HTTP fixture.
The opt-in `dynamodb_continuations_enforce_claims_across_processes` test additionally
uses a real loopback-only DynamoDB-compatible service, a disposable table and four
child processes. It asserts one continuation claim and one MCP ID-JAG redemption,
persisted replay rejection, namespace/issuer isolation, expiry and fail-closed
behavior after table deletion. Any loopback DynamoDB-compatible service, such
as LocalStack, can serve it. The test does not prove deployed IAM, DynamoDB
durability or end-to-end replica consent.
The default suite intentionally skips this test. Run it explicitly with:

```sh
ATG_MCP_DYNAMO_ENDPOINT=http://127.0.0.1:4566 \
  cargo test --locked --bin agent-gateway \
  dynamodb_continuations_enforce_claims_across_processes -- --ignored
```

The endpoint must be a numeric loopback HTTP address. The test uses fixture
credentials, creates only its own `mcp-conformance-*` table, and removes that
table on completion or assertion failure. It never provisions remote resources.

### MCP Resource Authorization

An opt-in `sts.mcp_issuer` in the network configuration adds an HTTPS issuer
profile to the existing STS. Existing `/oauth2/token` and DID-issued flows
remain unchanged. The issuer must exactly match a configured inbound public
origin and the root or `/api` identity mount followed by `/oauth2/mcp`:

```json
{
  "sts": {
    "mcp_issuer": { "issuer": "https://gateway.example/api/oauth2/mcp" },
    "mcp_replay": { "backend": "embedded", "capacity": 100000 }
  }
}
```

That profile serves tokens at `/api/oauth2/mcp/token`, the existing gateway
public signing keys at `/api/oauth2/mcp/jwks.json`, and discovery at
`/.well-known/oauth-authorization-server/api/oauth2/mcp`. The configured
issuer controls every advertised URL; Host and forwarding headers cannot
change them. Metadata advertises only token exchange and JWT-bearer ID-JAG
redemption with pre-registered confidential clients. There is no hosted browser
login, authorization-code grant, authorization endpoint, PKCE authorization
endpoint, dynamic registration, or refresh-token grant. Authorization-code-only
MCP clients remain unsupported. The profile does not yet advertise the full
enterprise-managed authorization extension.

The new token endpoint bounds form bodies to 64 KiB, at most 32 parameters,
128-byte names and 32 KiB values. Duplicate parameters, repeated Authorization
headers and conflicting client authentication methods are rejected. JWT or
ID-token subjects require a verified issuer, nonempty subject, future expiry
and an explicit client subject-audience allowlist. Actor assertions receive
the same audience and expiry checks. Token exchange rejects a subject or actor
whose JOSE `typ` is `oauth-id-jag+jwt`, compared as a media type, whatever
token type the client declares, so a grant is consumed only through single-use
JWT-bearer redemption. It also rejects any subject or actor the gateway signed
itself, under its DID or this profile issuer, so only external identity
assertions are exchanged. The client must explicitly allow the
requested canonical HTTPS resource and every requested scope; legacy empty
allowlists do not grant unrestricted access through this profile.

Every profile request requires `resource`. Access-token requests may omit
`audience` or repeat the same resource. ID-JAG issuance instead uses the HTTPS
AS issuer as `aud` and separately stores `resource` in the signed grant.
Redemption checks the same client, exact resource and grant scope ceiling
before consuming it. Issued access tokens have JOSE `typ: at+jwt`, the profile
issuer, resource audience, delegated actor and bounded expiry. The existing
signer, client registry, Trust Check, policy, throttle and auditing are reused;
profile policy inputs additionally expose `input.sts.resource` and
`input.sts.issuer`. Issuance does not extend beyond assertion expiry, including
time spent in asynchronous policy preparation.

Profile subjects derived from external assertions are namespaced by the
verified issuer and subject: `urn:affinidi:mcp:subject:<SHA-256(JCS([iss,sub]))>`.
Two trusted issuers using the same `sub` therefore cannot share a resource or
delegation identity. Already-local profile subjects remain stable through
ID-JAG redemption. Existing DID-issued endpoints keep their original subject
semantics. Any browser-session linkage must map to this authoritative profile
identity explicitly, never by email or unqualified subject matching.

Profile replay protection is separate from the legacy synchronous fallback.
`sts.mcp_replay` selects bounded embedded storage (default capacity 100000,
single active process) or `{ "backend": "dynamodb", "table": "..." }`.
Keys bind the profile issuer, grant issuer and token ID. DynamoDB uses an
atomic conditional PutItem under `StsMcpReplay#<digest>` PK/SK and numeric
`expires_at`; grant TTL is at most 900 seconds. Configure TTL cleanup and
grant `dynamodb:PutItem` on the table. Failed or timed-out writes fail closed,
never fall back to memory. Real DynamoDB multi-replica and IAM conformance
remain required; a default process-local backend is not restart-safe replay
protection.

An MCP Access Point, independent Transit Point or standalone MCP Proxy opts
into Resource Server enforcement with `mcp_http.authorization`:

```json
{
  "mcp_http": {
    "authorization": {
      "resource": "https://gateway.example/smoke",
      "scopes": ["read"]
    }
  }
}
```

The resource must match its configured public listener origin and route.
Saving a surface or standalone Proxy checks this against the stored network
configuration and returns `400` when a declared resource is not the
endpoint's own, or when another stored surface or Proxy, enabled or not,
already serves it. Changing a route or Proxy path therefore also needs a new
`resource`. Surfaces loaded at startup or on reload are checked only at
request time, where a mismatched resource fails closed with `503`. Explicit
surface aliases receive distinct `$alias` resource URIs; Transit
aliases occur in the surface portion of the outbound path. A custom Transit
mount appends `$alias` to its configured resource path, and `%24` requests use
that same canonical audience. Authentication and protected-resource metadata
share this derivation; a token for the base resource cannot authorize a named
variant. Access Point
authorization is an alternative to legacy `source_auth`; combining them is
rejected. Transit-token requirements remain independent. Protection applies
to all requests on the opted-in endpoint, not only modern-shaped requests,
so removing modern metadata cannot bypass it. Unconfigured endpoints retain
existing authentication behavior.

Resource checks require one Authorization Bearer token with an EdDSA signature
from the configured gateway keys, `typ: at+jwt`, exact issuer, resource audience,
nonempty subject, valid expiry/not-before, and required scopes. Missing or
invalid tokens return `401`; insufficient scope returns `403` and the complete
required scope set; missing verification/configuration returns `503`, not a
login challenge. The verified caller feeds policy and subscription expiry.
Caller bearer tokens are stripped before forwarding to HTTP, owned REST
adapters, mirrors or Fabric. Fabric receive independently enforces its local
surface's resource contract; authenticated Fabric transport alone does not
grant resource access. A separately protected remote resource needs its own
audience-bound credential, never the ingress caller token.

Protected-resource metadata is read from live endpoint configuration at
`/.well-known/oauth-protected-resource/<endpoint-path>`, with `no-store`.
The root document exists only for a configured root resource, never an
arbitrary surface. Documents include the exact resource, one configured AS
issuer, header-only bearer support and configured scopes. Unknown, disabled
or ambiguous resources are not advertised as usable. Challenges use these
absolute metadata URLs. Component coverage exercises real STS exchange,
metadata, missing/insufficient/cross-resource tokens and bearer stripping on
Access Points, Transit Points and standalone Proxies; Fabric negative coverage
proves unavailable receiver authority cannot be bypassed. Complete positive
Fabric authorization, distributed replay and lifecycle conformance are not
verified. These opt-in OAuth settings do not change which revisions an
endpoint admits.

### Tool Parameter Headers

`mcp::tool_headers::ToolHeaderBindings` compiles `x-mcp-header` annotations for
owned modern tools. Names must be nonempty HTTP field-name tokens and unique
case-insensitively within a tool. Annotations must lie on exact property paths
reachable through `properties` alone and declare string, integer or boolean
types. Annotations under references, arrays, composition or conditional schema
locations invalidate that tool; example/default/const instance data is not
mistaken for a schema. No remote reference is fetched.

The compiler is bounded to 8192 schema nodes, depth 64, 128 bindings, and
128 bytes per annotation name. Invalid tools are excluded individually from
the modern catalog and cannot be called. Missing, duplicate, malformed or
mismatched recognized headers return HTTP `400` / `-32020` with the request ID,
before Target execution. Null and absent arguments omit the header. Unknown
parameter mirrors are ignored by this validator; transparent MCP forwarding
must preserve them.

The gateway's role differs by path. Forwarding paths — direct Access Points and
Transit Points — are transparent proxies: they validate the standard mirrored
headers and forward `Mcp-Method`, `Mcp-Name` and every `Mcp-Param-*` unchanged,
leaving parameter mirrors to the upstream that owns the tool schema
(`modern_routing_headers_reach_the_upstream` in `src/proxy/handler.rs`;
`modern_transit_consent_binds_its_resource_and_preserves_delegated_credentials`
in `src/proxy/outbound_handler.rs`). Fabric carries modern MCP only as framed
streams, which preserve repeated request headers; the receiving gateway
validates the standard mirrored headers again.
Gateway-owned MCP Proxies are the server, so they validate recognized mirrors
against their own schemas as above. The gateway never synthesizes
`Mcp-Param-*` headers, because it holds no client-side tool schema state.

Encoding shares the existing `Mcp-Name` Base64 sentinel rules. Only complete,
case-sensitive sentinel pairs are decoded, once. Padded strings, control
characters, non-ASCII text and literal sentinel-shaped strings are encoded.
Integer mirrors are compared as exact decimals rather than floating point,
accepting representations such as `42.0` for `42` while enforcing the
JavaScript safe-integer bounds. Boolean mirrors use lowercase values. Neither
annotations nor mirrored values establish authentication or tenant authority.

### Bounded SSE Decoder

The modern transport foundation uses `eventsource-stream` behind an adapter
with explicit nonzero event and source-chunk byte limits. It retains at most
one bounded source chunk and one bounded event, and feeds the parser in small
pieces. Cross-chunk state normalizes CR/LF line endings and removes only the
initial UTF-8 BOM; valid split UTF-8 code points remain intact. An ignored
initial empty line keeps BOM handling in the adapter rather than invoking the
dependency's separate first-string BOM handling. The event limit counts the
normalized frame bytes, including field lines and delimiters, not just data.

SSE field interpretation stays in the library, including ignored unknown
fields, repeated field updates and multiline data. Oversized chunks/events
and malformed encoding are errors. A partial event at EOF is not synthesized
as a complete event. Dropping the decoder drops its upstream stream immediately,
including while that stream is quiet; there is no detached reader task.

The shared JSON/request-stream adapter validates correlated responses, preserves progress
and permitted logging notifications, rejects independent server requests and
subscription events on ordinary request streams, and invokes the supplied response rewrite only for a
complete result. It revalidates rewritten output, stops after the first RPC
response, and does not treat an incomplete upstream close as success. Its Axum
response body owns the upstream stream, sends comment keepalives, preserves
status and safe repeated headers, removes hop-by-hop/session/resumption
headers, and sets `Cache-Control: no-store` and `X-Accel-Buffering: no`.

The complete-result callback is asynchronous and one-shot. JSON responses can
carry newly produced headers; an SSE callback cannot mutate already-sent
headers and fails closed on an unexpected change. Request-level payment receipt
headers are established before the stream starts and retain repeated values.
Result-only metadata is not injected into protocol errors, `input_required`, or
task results. Configurations that produce new result-only HTTP headers during
SSE completion remain an integration limitation; metadata-only output works.

Direct and Transit Point response paths have modern branches for admitted
modern requests. They reuse existing final-result policy/metadata processing;
Transit Point tests also verify tool filtering and private/zero-TTL cache hints
in JSON and SSE. Response-body observers record completion, failure or
disconnect exactly once, with no detached reader. A real TCP adapter test
verifies progress before completion and cancellation while the upstream stream
is quiet. Empty chunks do not keep an idle stream alive. The conformance
harness exercises the direct, Transit Point and owned branches on their mounted
routes (see [Conformance Harness](#conformance-harness)). Fabric streams modern
responses through the framed transport and receiving branch described below.
Legacy SSE behavior is unchanged.

### Framed Fabric Transport

The additive DIDComm message types under
`https://affinidi.com/atm/forward-stream/1.0/` are `frame`,
`capabilities-query`, and `capabilities-disclose`. Existing `ForwardRequest`
and `ForwardResponse` messages retain their buffered, legacy-only contract.
Local stream capabilities advertise request streams and subscriptions; any
active MCP surface admits a framed modern request.

Capability offers and disclosures are nonce-correlated and bound to the
authenticated peer, recipient, Connection Point and live listener generation.
An Open frame identifies its offer, surface and optional variant separately.
Incoming preparation requires an active configured peer, permitted surface,
active MCP surface, an envelope `expires_time` that is present, in the
future and at most one hour ahead (as for a `forward-request`), unexpired
deadline and negotiated limits. It retains
the resolved surface snapshot for the request lifetime. Every request still
runs the receiver's independent wire, identity and policy checks; peer
capabilities do not establish caller authorization.

The listener answers a capability query only from a registered, active peer
gateway, read from its in-memory gateway store; any other sender's query is
dropped before it creates an offer, because the offer table is shared by every
peer. An Open that preparation refuses, or that times out in admission, is
answered with an `Error` frame when it comes from an active peer on this
listener, so the sending gateway fails at once instead of waiting for its
response deadline. The frame says why:

| Code | Refusal | Sender |
| --- | --- | --- |
| `stale_offer` | The Open names no live capability offer, for example after the receiver restarted or the offer expired | Drops its agreement, so the next request negotiates again |
| `legacy_only` | Sent by an older peer whose surface does not admit modern MCP | Answers the caller as a legacy-only endpoint would: `400` / `-32022` listing `2024-11-05` |
| `unavailable` | Anything else: route, exposure, tenant, limits, envelope times, admission timeout | Keeps its agreement and answers `502` |

Only a stale offer makes the sender negotiate again, so a route the peer
refuses does not make every request query its capabilities and fill the
receiver's offer table, which every peer shares. A repeated Open for a stream
that is still open is not answered, because the `Error` would end that stream.
A receiver bounds an Open's deadline by its own `stream_max_lifetime_secs`
rather than refusing a later one, so a peer with a longer lifetime or a clock
ahead of the receiver's still gets a stream. The deadline bounds only how long
the stream runs. The Open's replay record lasts until the Open could no longer
be admitted, the earlier of its envelope's expiry and its capability offer's
expiry (at most 5 minutes), and a repeated Open of a stream still running is
refused by that stream's registration. Replay records therefore do not
accumulate for the sender's full stream lifetime.

An isolated Open-admission fixture uses the real filesystem surface resolver,
listener stamping and capability exchange with an explicit test-local version
policy. It verifies resolved variant snapshots, repeated headers, active remote
peer and exposure checks, Origin/deadline/byte limits, listener replacement and
replay protection. Rejected Opens do not consume replay slots; accepted Opens
remain protected after their leases drop. The same isolated fixture runs an
admitted Open through chunked upload, independent receiving-pipeline validation,
a real loopback Target and framed JSON/SSE delivery with EndAck. Missing
capabilities, duplicate mirrored headers, empty uploads and a legacy-only
receiver version policy stop before Target execution. SSE progress arrives
before the Target is released to finish; cancellation drops quiet upstream
work and final results preserve extension metadata. Runtime dependencies are
passed explicitly to the owning receiver, never enabled through a test
environment switch. The conformance harness `fabric` target covers the full
sending route over an encrypted Docker mediator.

Frames preserve repeated HTTP headers and raw request bytes. Request and
response streams have independent cumulative byte credits, sequence numbers
and terminal byte counts. Credits acknowledge consumed frame boundaries, not
merely received bytes. A response sender seals its final sequence/byte boundary
before sending End and waits for an authenticated EndAck with that exact
boundary, including for empty responses. Byte credit alone never completes a
sealed response. Terminal acknowledgements use the same peer, recipient,
Connection Point, listener-generation and thread binding as other control frames;
valid duplicates are harmless, invalid boundaries fail closed. Bounded
reordering and duplicate suppression reject
overlaps, gaps, forged credits and false completion. Both directions are
reserved before upload; accepted Open IDs remain replay-protected while the
same Open could still be admitted (its envelope's or its offer's expiry,
whichever is earlier) and while the stream is registered, including across
listener replacement. Capacity exhaustion fails closed rather than evicting
active replay records.

A capability query is admitted like a `forward-request` too: its envelope
`expires_time` is required and validated, and its `(sender DID, message id)`
pair is remembered in the Fabric seen set until it expires. A replayed query is
therefore refused, both while it is live and after, and can never recreate an
expired offer, so an Open bound to that offer stays refused once its replay
record ends. The sending gateway gives a query a 300 s envelope lifetime.

Current local bounds are 48 KiB per serialized frame, 16 KiB per decoded chunk,
16 KiB of headers, a 1 MiB credit window and 64 outstanding frames. The registry
allows 128 streams per direction, with 8 per peer and 16 per surface; replay records
are additionally bounded, at 512 per allowed stream. See [Framed Fabric limits](#framed-fabric-limits). Capability negotiation intersects supported features
and byte limits. Both send and receive registrations retain that immutable
agreement and check every frame against it; senders split at the smaller peer
chunk limit. The DIDComm sender checks the actual encrypted payload against
`a2a.fabric_stream_max_envelope_bytes` before sending. The setting is optional.
When set it must be from 65536 to 1048576 bytes and no larger than
`a2a.sdk_inbound_cache_bytes`. When unset the limit is 131072 bytes, or the SDK
inbound cache size when that is smaller, and no range check applies, so a
bootstrap config without the setting loads whatever its cache size; generated
bootstrap configs omit it. Operators must align this budget with their
mediator's envelope limit; real mediator overhead and throughput remain
conformance requirements, not an assumption established by the unit tests.

The DIDComm frame sender (`DidCommFrameSink`) packs every stream frame, from
Open through data, credit, End and EndAck to Cancel and Error, for the peer and
sends it the same way `pack_and_send_message` sends capability queries,
disclosures and buffered Fabric messages, so framed streams reach exactly the
peers that legacy Fabric forwarding reaches. The envelope check above measures
the packed frame. Every frame carries `created_time` and `expires_time`; an
Open expires at its request deadline (capped by
`sent_envelope_lifetime_secs`) because the receiver admits it through the same
envelope replay check as a `forward-request`, and other frames carry the capped
maximum lifetime.

The receiving task owns upload assembly, Target execution and framed response
delivery. Declared length and endpoint body limits are checked before Target
execution. Cancel, deadline and listener loss release both directions and drop
quiet Target work. The modern receiver reuses the shared JSON/SSE adapter and
existing complete-result metadata/tool filtering, without legacy session reuse
or SSE fallback. Its response body is owned, not cloned or drained into a
legacy response envelope. Final-only header changes during SSE remain
fail-closed. Stream tasks belong to the listener's task set.

Direct Access Points and independent MCP Transit Points use the modern
forwarding entry point after their request gates and credential
preparation. It resolves an active configured peer, obtains a nonce-correlated
capability agreement with a bounded wait, and schedules its outgoing driver on
the current listener's bounded queue. Dropping the HTTP response, including
before headers arrive, signals the driver to cancel the remote stream. Normal
EOF uses a distinct completion signal and does not send a spurious Cancel.
Listener replacement rejects queued work from the old generation.

The listener keeps its SDK message-pickup future alive across outgoing-queue
events. The SDK registers a pending pickup with its WebSocket task; dropping
that future to schedule unrelated work can abandon the request and lose an
incoming frame. Only a completed pickup starts the next pickup operation.
While a received message waits for a dispatch slot, the next pickup does not
start, but queued outgoing stream drivers are still scheduled.

Streamed complete results re-enter each sending endpoint's existing response
policy, filtering and metadata processing. The receiver also dispatches modern
surface-backed `proxy://` calls through the owned dispatcher after preparation,
then through its common response pipeline. Response observers track completion,
failure or disconnect rather than recording success at final-result processing;
upstream header waits and stream lifetimes have separate deadlines. For framed
receiver responses, the metrics callback belongs to the transport send and runs
once after EndAck, failure or cancellation. It counts peer-acknowledged bytes,
never merely read or queued bytes, and does not mark local EOF as delivery.
Unsent responses still release their callback and connection guard on drop.
This establishes consumption by the authenticated gateway peer, not receipt by
the final HTTP client. Direct and Transit adapters preserve the explicit MCP
completion handle so a final SSE result can finish its End handshake without
a spurious Cancel. Focused tests cover partial delivery, missing acknowledgements,
forged terminal controls, empty responses and cancellation during the End wait.

Focused tests cover a composed two-registry exchange larger than its credit
window, byte/header preservation, early progress, malformed or oversized
frames, replay, timeouts and quiet cancellation. Receiver JSON/SSE fixtures
exercise the actual adapter with explicit validated modern requests. The
conformance harness `fabric` target runs the complete route between two
gateways over one Docker mediator; it runs locally, not in CI. Framed streams
are not supported across mediator federation, where each gateway uses its own
mediator.

The opt-in `modern_fabric_sender_negotiates_over_encrypted_mediator` test runs
against a disposable local messaging mediator. In it, two real SDK clients
generate separate identities, authenticate to the mediator, negotiate
capabilities and exchange authcrypted frames. The sender uses the real gateway
store and listener index; the receiver resolves a persisted variant and calls a
loopback Target through its ordinary pipeline. JSON and SSE results preserve
extension metadata, progress crosses the mediator before the final result is
released, and caller disconnect cancels quiet Target work. The same fixture
verifies concurrent subscriptions with equal numeric request IDs and different
filters, all four core update types including hierarchical sub-resources,
string subscription IDs, empty acknowledgements, graceful completion and
rejection of unacknowledged updates. Cancelling one quiet stream leaves the
other stream active. Subscription results bypass ordinary enrichment and
continuation finalization. The fixture uses two in-process runtimes with
explicit test-local policies, not two gateway binaries or the complete
production listener loop. End-to-end Access Point/Transit Point authorization,
subscription revocation through every route, envelope-limit/load tests and
multi-process route conformance remain required.

This ignored test requires `ATG_MCP_FABRIC_MEDIATOR_DID` and, for a non-peer DID,
`ATG_MCP_FABRIC_MEDIATOR_DOCUMENT` containing its public DID document. All service
endpoints must be loopback HTTP/WebSocket URLs. Provision a disposable mediator
with the repository's G2G setup script and remove its stack and generated keys
afterward. Run the check explicitly:

```sh
RUST_MIN_STACK=8388608 RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' \
  cargo test --locked --bin agent-gateway \
  modern_fabric_sender_negotiates_over_encrypted_mediator -- --ignored
```

#### Framed Fabric limits

These limits apply to modern MCP over Fabric framed streams and to modern
listens. They are constants unless noted, and they are counted per gateway
process.

| Limit | Value | Past it |
|---|---|---|
| Framed streams per peer | 8, counted apart for streams a peer opened here and streams this gateway opened to it, across all surfaces | The Open is refused. The sending caller gets `502` "Modern Fabric transport is unavailable" on an Access Point and `UpstreamConnectionFailed` on a Transit Point, not `429` |
| Framed streams per surface | 16 inbound per local surface (shared by every peer); outbound counted per peer channel | As above |
| Framed streams in total | 128 per direction | As above |
| Stream progress | `stream_idle_timeout_secs` (default 60 s) bounds an upload and the Credit and EndAck waits while frames are outstanding; a quiet subscription has nothing outstanding and is not affected | The stream ends |
| Opens per peer | 50/s, burst 100, per listener | The Open is refused before any lookup |
| Capability queries per sender | 10/s, burst 20, per listener | The query is dropped |
| Refused Opens being answered | 16 at a time, off the listener's reader loop | Further refusals are not answered; the sender waits for its response deadline |
| `subscriptions/listen` per caller | 16 (the authenticated principal, or the client IP or peer DID when unauthenticated) | `429` |
| `subscriptions/listen` per surface | 256 across callers | `429` |
| Pending consent continuations per caller | 64 by default (`mcp.continuations.max_pending_per_principal`) | `429` for that caller only |

**A partner gateway can be locked out by its own listens.** A forwarded
`subscriptions/listen` holds its framed-stream slot for up to
`stream_max_lifetime_secs` (default 3600 s), and the progress timeout does not
end a quiet subscription. Eight listens from callers behind one partner
gateway therefore use up that peer's slots, and every other modern request
from that partner is refused with `502` until one ends. Two partners at eight
each fill a receiving surface's 16 slots. Because the per-peer cap applies
first over Fabric, the 16-per-caller listen limit cannot be reached there.

**Modern MCP is active on every MCP endpoint, so weigh shared state before
exposing a multi-tenant or internet-facing gateway.** Gateway-wide tables and
signals are shared across tenants and peers: subscription invalidation is
process-wide, the capability offer and Open replay tables have no per-peer or
per-tenant caps, and there are no per-tenant limits. Prefer single-tenant or
trusted deployments, or restrict who can reach MCP endpoints and which peers
are paired, until these are scoped. See [Fabric: modern MCP activation](FABRIC.md#modern-mcp-activation).

## Configuration Lifecycle

The field is managed through the surface API/config, not a dedicated canvas
control. The frontend API type recognizes it. Older dashboard clients can
continue saving surfaces without silently resetting the preference.

Tenant ownership and PAT resource-scope checks still apply to these writes.
PUT retains the stored `tenant_id`; changing the metadata format does not
reassign the surface to another tenant.

| Operation | Missing field | Explicit `null` | Explicit enum |
| --- | --- | --- | --- |
| POST | Compatibility default | Compatibility default | Use selected mode |
| PUT | Retain stored preference | Retain stored preference | Replace preference |
| RFC 7396 PATCH | Retain stored preference | Remove field; restore default | Replace preference |

Use `PATCH /v1/surfaces/{id}` with
`Content-Type: application/merge-patch+json` and the JSON object above to opt in.
The normal identity API mount may add `/api`. Use the existing authenticated
admin client and verify the GET readback. Updates persist and use the existing
hot-reload flow; no direct `_storage/` edits are required.

An in-flight request retains its admitted output preference even if an API
write persists a new preference while the upstream response is pending. The
current listener reload can wait for in-flight requests to finish; subsequent
requests use the updated preference after reload completes.

Deploy reader-capable gateways and update consumers before opting a surface
into canonical output. Revert to `compatibility` to roll back output on the new
binary. Before downgrading to an older binary, remove the field with PATCH
`null` and verify persistence: older `deny_unknown_fields` deserializers reject
the new field even when its value is `compatibility`. Do not discard surface or
identity data as part of rollback.

## Verification

Focused tests live in the shared metadata module, VP/identity readers and
writers, surface configuration tests, MCP component tests, and the independent
Fabric receive handler fixture. Signed `did:peer` fixtures exercise real SSI
verification offline, separately from the BDD test-auth verification bypass.

The surface and G2G `mcp_metadata_compatibility.feature` suites assert exact
locations, old-alias absence, caller outcomes, and collaborator effects.
The ordinary Rust suite also runs the isolated Fabric receive handler through
both output modes, asserting exact migration of historical request and response
metadata without the mediator environment gate. HTTP component tests exercise
PATCH-null persistence through a fresh filesystem-store load, rejected updates,
and response consistency during a signal-controlled in-flight reload. These
tests do not depend on the BDD test-auth bypass.
Run the managed-mediator G2G tests explicitly: the aggregate Cargo command can
skip that suite when its environment gate is not enabled.

## Conformance Harness

Modern MCP support is measured against the published MCP conformance suite's
frozen `2026-07-28` requirement set rather than a hand-written checklist.
`scripts/mcp-conformance/` runs it end to end; `make mcp-conformance` is the
entry point, and [its README](../scripts/mcp-conformance/README.md) covers
options, outputs and baseline maintenance.

**Pins.** The suite is `@modelcontextprotocol/conformance@0.2.0-alpha.11`,
pinned exactly with a lockfile, because requirement sets exist only on the
prerelease line and not on `latest`. The upstream is the suite's own reference
server (`examples/servers/typescript/everything-server.ts`) at commit
`7169291ec0b68eb370fddcd9947313ab0d5e4156`, fetched by commit, verified and
installed from its lockfile. Measuring that server directly and through the
gateway with the same suite attributes every difference to the gateway. The
scored scenario list comes from
`npx @modelcontextprotocol/conformance@0.2.0-alpha.11 list --requirements 2026-07-28`.

**Binary.** Both phases run the ordinary gateway binary, each on its own
generated env. The modern phase first probes that the Access Point admits
`2026-07-28`; every gateway endpoint admits it. Fabric is
measured through a two-gateway topology (the `fabric` target below).

| Target | Endpoint | Scenarios | Baseline |
| --- | --- | --- | --- |
| `direct` | The reference server, without the gateway | Full requirement set | `direct.yaml` |
| `access-point` | Access Point forwarding to the reference server | Full requirement set | `forwarding.yaml` |
| `transit` | Transit Point on the outbound listener, same upstream | Full requirement set | `forwarding.yaml` |
| `owned-proxy` | Standalone MCP Proxy over an OpenAPI REST fixture | `tools-list`, `tools-call-simple-text`, `caching` | `owned.yaml` |
| `proxy-surface` | Access Point whose Target is that Proxy (`proxy://`) | Same subset | `owned.yaml` |
| `fabric` | Access Point on gateway 1 whose Target is `fabric://` gateway 2, whose surface forwards to the reference server | Full requirement set | `fabric.yaml` |

Only the forwarding targets show that the gateway does not alter messages in
transit. The owned targets run a subset because an OpenAPI-backed Proxy offers
tools only; the suite's content fixtures cannot come from a REST bridge.

**Baselines.** Each entry in `scripts/mcp-conformance/expected-failures/` names
one `<scenario>:<check-id>` with its reason. The suite fails a run on any other
failure or warning and on a listed check that now passes.

| Baseline | Entries | Reason |
| --- | --- | --- |
| `direct.yaml`, `forwarding.yaml`, `fabric.yaml` | `input-required-result-validate-input:sep-2322-validate-input-responses` | The reference server accepts an `inputResponses` value that is not an object, a SHOULD-level warning the gateway forwards unchanged. |
| `owned.yaml` | `caching:sep-2549-{prompts-list,resources-list,resources-templates-list}-caching-hints` | The Proxy offers tools only, so those lists return `-32601`. |

The forwarding targets reach the reference server through
`scripts/mcp-conformance/shim.mjs`. The reference server's `subscriptions/listen`
response deviates from the specification twice, and the gateway refuses both:
it streams newline-delimited JSON under `application/json`, where Streamable HTTP
carries a multi-message response as `text/event-stream`; and it tags messages
with the request id as a string, where `io.modelcontextprotocol/subscriptionId`
is a `RequestId` equal to the request's id. The shim re-frames that one response
as SSE and restores the typed id, so the subscription checks run against the
gateway and pass; `forwarding.yaml` lists no subscription checks.

`server-stateless:sep-2575-server-unsupported-version-error` is deliberately not
listed: a forwarding endpoint's `-32022` must advertise only the versions the
upstream's discovery delivered (see [Forwarding Discovery](#forwarding-discovery)).
Scenarios the suite reports but never scores, including every `tasks-*`
extension scenario, are not gates; this matches owned discovery not advertising
the Tasks extension.

**Checks the suite does not make.** `check-results.mjs` requires a result for
every scenario each target ran; requires the Access Point, Transit Point and
Fabric Access Point to report the same `ttlMs` and `cacheScope` as the reference server does directly,
which holds on surfaces without caller-scoped policies (see
[Custom Metadata And Results](#custom-metadata-and-results)); and requires owned
`tools-call-simple-text` results to carry the REST fixture's text without
`isError`, because the suite accepts any non-empty text, including a tool error.
Streamed frame counts are not compared: how the reference server frames and
times streamed messages is fixture behaviour.

**Legacy compatibility.** `compat.mjs` runs a `2024-11-05` client session
(`initialize`, `notifications/initialized`, `tools/list`, `tools/call`) in
both phases. The Access Point, Transit Point and the `legacy-surface` Access
Point, whose stored record deliberately still carries the retired
`mcp_protocol_mode: "legacy"`, must return the same results as the reference
server directly, and the standalone and `proxy://` owned endpoints must return
the fixture's text with equal results. In the modern phase every endpoint,
`legacy-surface` included, must admit `2026-07-28`. In the legacy phase every
endpoint must answer the unmodelled `2025-11-25` with HTTP `400`, `-32022`, a
`supported` list that includes `2024-11-05` and not the requested revision, and
the request id echoed.

**Running.** `make mcp-conformance` runs both phases, `ARGS=--unit-tests` also
runs the full binary test suite, and `make mcp-conformance-legacy` runs only
the legacy-phase compatibility checks.
Run outputs stay under the ignored `target/mcp-conformance/`. Exit codes are `0`
pass, `1` failure, `2` invalid options or precondition not met, `3` dependency
fetch failure, `130` interrupted (SIGINT) and `143` terminated (SIGTERM).

**CI.** The `test:mcp-conformance` job runs only when the pipeline variable
`MCP_CONFORMANCE` is `"true"` (default `"false"`). It runs the harness with
`--unit-tests`, passes the `build:rust` binary to both phases, leaves out the
`fabric` target, keeps the summary, logs and results as artifacts, and
tolerates only exit code `3`. It caches only the pinned reference checkout and
the npm cache, compiles the unit tests through the runner's sccache with
`CARGO_INCREMENTAL=0`, installs
git, openssl and CA certificates only when the image lacks them, and times out
after 90 minutes.
Scheduled pipelines are excluded by the workflow rules, so running it on a
schedule also needs that rule relaxed.

**Fabric.** The suite speaks HTTP to one URL, so the `fabric` target puts that
URL in front of a Fabric route. `scripts/mcp-conformance/fabric.feature` runs
through the g2g BDD runner: two gateways paired over a
managed mediator in Docker, an Access Point on gateway 1 whose Target is
`fabric://` gateway 2, and a surface on gateway 2 forwarding to the shim.
A step runs the suite against gateway 1, so every request crosses both Fabric
paths as a framed stream. Gateway 2 allowlists gateway 1's origins, because a
framed stream receiver checks a forwarded Origin against its own allowlist (see
[HTTP Endpoint Admission](#http-endpoint-admission)). The feature sits outside
`tests/features/g2g`, so `make gw-e2e` does not run it, and the CI job leaves
the target out because it has no Docker daemon. A `make gw-e2e` scenario
checks that an unmodelled revision is rejected before it enters the Fabric.

## Implementation Invariants

Engineering invariants for the modern MCP work, kept with the MCP contract.

### Admission, transports and owned dispatch

MCP policy builders carry optional `protocol_version`, `client_capabilities`, and `client_info` from the admitted modern classification through direct, Transit Point, Fabric, Trust Check and per-tool policy inputs. Legacy serialized input stays unchanged. Modern methods and raw params remain extensible; client declarations never establish authenticated identity. Modern context reaches policy only for admitted modern requests; explicit unit/component fixtures and the conformance harness described below exercise it. See `docs/MCP_METADATA.md` for the policy contract.

Every MCP endpoint (Agent Surface, Transit Point, standalone MCP Proxy, Fabric framed stream) admits and advertises `2026-07-28` alongside `2024-11-05`; `mcp_legacy_metadata_output` remains independent. `mcp_protocol_mode` is retired: `RetiredSetting` (`src/config/types.rs`, used as `AgentSurface::_retired_protocol_mode`) accepts any stored or submitted value under `deny_unknown_fields`, discards it and never serializes it, and Transit Points and MCP Proxies ignore the field. `mcp_http`'s Origin, header and body limits apply to every MCP endpoint and every revision, except that buffered Fabric `ForwardRequest` receive skips the Origin allowlist check (`EndpointHttpPolicy::without_origin_check`) because the sending gateway already checked it; the forwarded Origin still counts toward the header budget. Records that do not set `mcp_http` save byte-identically to releases without it: `component_tests::mcp_record_compat` loads and re-saves surface, MCP Proxy, vault token and credential provider fixtures (`tests/fixtures/records/`) written by such a release. Before downgrading, PATCH `mcp_http` to `null` on every surface and rewrite Transit Point arrays without it: older binaries skip a surface that carries it (`AgentSurface` is `deny_unknown_fields`) and silently ignore, then drop on save, the field on Transit Points and MCP Proxies. No older binary enforces `mcp_http.authorization`: clearing `mcp_http` removes it from surfaces and Transit Points, and a Transit Point or MCP Proxy that keeps it is served without it, so protect or disable every endpoint that relies on it before downgrading (see `docs/MCP_METADATA.md`). Accepted/advertised revisions resolve **per transport path** (`McpPathKind` in `src/mcp/request_validation.rs`: `DirectAccessPoint`, `OwnedProxy`, `TransitPoint`, `FabricReceive`, `FabricSend`) via `runtime_policy_for`, not from one appliance-wide constant, so one path can be returned to legacy-only without affecting Fabric or any other path. Every path admits `2026-07-28`, the Fabric legs as framed streams only. The mounted Access Point router, outbound Transit listener and framed Fabric receive each use their own path policy. `admission_policy_for_target` narrows a `fabric://` Access Point or Transit Point Target to the `FabricSend` policy, so a modern request that leg cannot carry gets `400` / `-32022` at admission, before payment, OPA or consent. Buffered Fabric `ForwardRequest` receive is legacy-only; modern MCP crosses Fabric only as framed streams. Unit tests pin each path's posture, pin that a path never advertises a revision it will not admit, and pin that returning one path to legacy-only leaves the others admitting modern; tests that send `2026-07-28` through a live entry point branch on that path's `runtime_policy_for`, and tests that only need a rejected revision use the unmodelled `2025-11-25`. `no_mcp_surface_scenario_is_a_draft_while_modern_mcp_is_admitted` fails the unit tests if any `tests/features/surface/mcp_*.feature` file contains `@wip` while a path admits modern.

The MCP conformance harness (`scripts/mcp-conformance/`, `make mcp-conformance`) runs the published suite (`@modelcontextprotocol/conformance`, pinned exactly by its lockfile, frozen `2026-07-28` requirement set) against the ordinary gateway binary, used for both phases: the pinned reference server directly, an Access Point and Transit Point forwarding to it, an owned MCP Proxy standalone and behind `proxy://` (`tools-list`, `tools-call-simple-text` and `caching` only), and a `fabric` target: `scripts/mcp-conformance/fabric.feature` through the g2g BDD runner (Docker mediator), an Access Point on gateway 1 targeting `fabric://` gateway 2, which forwards to the reference server; the suite runs from a step. Expected failures live in `scripts/mcp-conformance/expected-failures/*.yaml`, one `<scenario>:<check-id>` with a one-line reason each; the suite fails a run on an unlisted failure or warning and on a listed check that passes, so remove an entry in the change that fixes it and never list a gateway defect. `check-results.mjs` adds caching parity with the reference server, real owned tool results and result completeness; `compat.mjs` checks a `2024-11-05` session on every endpoint in both phases, `2026-07-28` admission on every endpoint (including `legacy-surface`, whose record still carries the retired `mcp_protocol_mode`) in the modern phase, and `-32022` for the unmodelled `2025-11-25` with a `supported` list offering `2024-11-05` on every endpoint in the legacy phase. Envs are generated under the ignored `target/mcp-conformance/` from `--generate-bootstrap`, a generated certificate and an `openssl rand` backup key held only in the gateway's environment; nothing is copied from `envs/`. The `test:mcp-conformance` CI job runs only when `MCP_CONFORMANCE` is `"true"`, passes the `build:rust` binary to both phases and tolerates only exit `3` (dependency fetch failure). Modern MCP crosses Fabric only as framed streams; the CI job leaves out the `fabric` target (no Docker daemon). See `docs/MCP_METADATA.md` (Conformance Harness).

`mcp_http` holds endpoint-local `allowed_origins`, `max_request_bytes` (default 1 MiB), `max_header_bytes` (16 KiB), `max_accept_ranges` (32), the modern response bounds below, and an optional `authorization`. `mcp_http.authorization` (Resource Server tokens; see the STS section) and the Origin, size and response settings apply to every MCP endpoint and every revision; Origin and size checks run through `mcp::modern_http::EndpointHttpPolicy`. A public endpoint given as a bare listen address has no HTTP(S) origin and adds nothing to the Origin allowlist. Direct, Transit Point, standalone proxy POST, and independent Fabric receive paths use the shared admission wrapper. Origin authority comes only from configured public listener origins and exact allowlisted origins, never request forwarding headers or CORS; missing Origin is allowed, invalid present Origin is `403`. Body/header budgets return `413`/`431`. The existing wire validator precedes modern media checks and rejects every revision the path does not admit. Standalone proxy raw-body validation runs before legacy session lookup. See `docs/MCP_METADATA.md` for defaults, errors and lifecycle semantics.

GET/DELETE with an explicit `2026-07-28` version return `405` / `Allow: POST` without consulting a legacy session; unmarked legacy routes remain unchanged. Modern response config additionally bounds JSON/SSE events (`max_response_bytes`, 1 MiB), source chunks (`max_chunk_bytes`, 256 KiB), idle time (60s) and lifetime (3600s; maximum 86400s). Direct/Transit modern response branches use the shared bounded adapter and existing complete-result processing, skip legacy fallback/session synthesis, and keep metrics/cleanup on response-body lifetime. Admitted modern requests on Access Points and Transit Points reach these branches; unit tests use explicit admitted fixtures, and the conformance harness exercises them on the mounted routes. Real TCP adapter tests cover incremental progress and quiet upstream cancellation. Result-only header production after SSE has started remains fail-closed, never silently dropped or injected into nonfinal results.

Owned modern MCP dispatch (`mcp_proxies/handlers.rs`) handles discovery, deterministic tool catalogs and tool calls behind the `OwnedProxy` version policy, which admits `2026-07-28` for every Proxy and surface. Standalone dispatch precedes legacy sessions; modern surface-backed `proxy://` dispatch follows the shared request gates and feeds the common final-response path. Catalogs preserve available schemas/annotations and calls preserve structured results; tools are cloned before execution so catalog locks do not span network work. `mcp::tool_headers` validates bounded, properties-only `x-mcp-header` annotations and exact mirrored values, using the shared Base64 rules and exact safe-integer comparisons. Invalid tools are individually excluded; header mismatches return `400` / `-32020` before execution. Modern schema construction restores OpenAPI source schemas lost by the library and rejects unsafe flattening. The modern-only `mcp_proxies::modern_rest` adapter retains library parameter extraction/validation while using no-redirect, byte-bounded HTTP, authority-preserving path encoding, protected Target headers and bounded JSON/form/text/multipart encoding. Catalogs and execution select the same media type and only resolve bounded local OpenAPI references. Legacy conversion and execution remain unchanged. Full schema fidelity and complete client-security conformance are not verified, and the conformance harness scores owned endpoints only on its tool subset; see `docs/MCP_METADATA.md`.

`proxy::fabric_stream` is the additive framed Fabric transport that carries modern MCP between gateways: nonce-bound capability offers, authcrypt peer/recipient/Connection Point/listener-generation/thread binding, bounded bidirectional credits and reordering, Open replay protection and listener-owned receiving and outgoing tasks. Typed input preserves bytes, repeated headers and resolved variant snapshots through independent receiver admission. Direct and Transit senders use the negotiated transport after request gates; both ends reuse JSON/SSE and complete-result processing, including receiver-owned `proxy://` dispatch. Every frame observes its registered negotiated limits; dropping an HTTP body signals cancellation even while quiet, while normal EOF reports completion separately. Framed response sends require an exact peer-bound EndAck after sealing their final byte/sequence boundary, including empty responses; byte credit alone is not completion. Transport-owned metrics report only peer-acknowledged bytes and release connection guards on success, failure or drop. After a validated MCP final result, Direct and Transit adapters explicitly hand the response lease to the listener driver for a bounded End handshake; ordinary body drops still cancel. Peer consumption is not final HTTP-client delivery. Legacy ForwardRequest/ForwardResponse stay buffered. `a2a.fabric_stream_max_envelope_bytes` bounds actual encrypted payloads before sending; it is optional and range checked (64 KiB to 1 MiB, within `a2a.sdk_inbound_cache_bytes`) only when set, and `A2aConfig::stream_envelope_limit` otherwise uses 128 KiB capped at the SDK cache, so configs without it load whatever their cache size. `DidCommFrameSink` packs and sends every frame like `pack_and_send_message`, stamping `created_time`/`expires_time` so the receiver checks an Open's envelope times as it checks a `forward-request`'s (`envelope_replay::validate_envelope_times`); the Open's replay record is kept by the stream registry. Local capabilities advertise request streams and subscriptions; any active MCP surface admits a framed modern request; a `legacy_only` refusal comes only from older peers that do not admit modern MCP. The conformance harness `fabric` target covers the complete route over one Docker mediator; framed streams are not supported across mediator federation, where each gateway uses its own mediator. See `docs/MCP_METADATA.md`.

Owned modern catalogs validate their advertised source input and JSON output schemas offline as Draft 2020-12, retain bounded transitive component references and explicitly scoped local definitions, and reject invalid successful results as tool errors. A Proxy whose schemas legacy conversion cannot load registers a modern-only routing catalog instead of failing; that projection never validates or executes legacy calls. Discovery reflects catalog availability. Legacy and modern catalogs publish as one snapshot after successful construction, and failed reloads preserve the prior snapshot. Do not treat these focused checks as proof of all schema or route conformance.

Modern notification forwarding accepts only an empty HTTP `202` or an HTTP error with an optional bounded ID-less JSON-RPC error. Notification responses bypass result enrichment and continuation finalization, preserve byte/deadline limits, and never create legacy sessions. Direct, independent receiver and Transit Point adapter tests cover this transport behavior; owned dispatch still rejects unimplemented notification methods.

The Fabric listener keeps its pending SDK pickup future alive across outgoing-queue events; cancelling and recreating it can abandon a registered pickup and lose frames. Connection-protocol messages and replies that complete an in-flight request (`ForwardResponse`, `GatewayIssuerResponse`, stream frames, queries and disclosures) dispatch inline (`dispatches_inline` in `ws_listener.rs`). Every other message needs one of the listener's `a2a.max_inflight_dispatches` slots (`dispatch_slot`): a `ForwardRequest` that finds none free is answered at once with a `503` `ForwardResponse` carrying `retry-after: 1`, and any other message waits for a slot through `ListenerGeneration::serve_outgoing_until`, which keeps spawning outgoing stream tasks meanwhile, so nothing is silently dropped at capacity. An explicit opt-in test verifies the real sender, persisted variant receiver, JSON/SSE progress and quiet cancellation through two SDK clients and a disposable local mediator. It also covers equal-ID concurrent subscriptions with independent filters, core resource/catalog updates, empty acknowledgements, graceful completion and unrequested-event rejection. It uses test-local runtime policies, not two gateway binaries or the complete production listener loop; full route authorization, subscription revocation and load conformance are not verified.

Modern admission validates optional request log levels and string/number progress tokens without changing legacy classification. Request-scoped SSE validates log and progress payloads against those request-local controls, rejects malformed metadata containers and subscription-only events, and preserves valid extension methods and fields. Log opt-in is never inherited from another request; these checks do not introduce gateway-owned logging or progress features.

### Discovery, subscriptions and variants

Modern MCP discovery and subscriptions run for admitted modern requests on Access Points, gateway-owned Proxies, Transit Points and Fabric framed streams. Forwarded discovery intersects endpoint versions and path capabilities, including the selected authenticated Fabric peer; changed results are private with zero TTL. `mcp::upstream_versions` remembers the versions each forwarded discovery delivered (legacy-only after `-32601`, nothing after other errors) per surface, Access Point variant or Transit Point alias, and Target, bounded to 1024 entries for 300 seconds; a later `-32022` from that endpoint advertises only the path's versions that are also remembered, keeping the full path list when nothing is remembered or none overlap, without changing admission or calling the upstream. Owned catalogs advertise tools-list changes and provide bounded, stream-local subscriptions. Acknowledgement precedes every requested notification, subscription IDs retain their string/integer type, and final subscription results bypass application enrichment. Resource updates match exact parsed URIs or hierarchical child/fragment relationships with unchanged scheme, authority and query; explicit fragments and opaque URIs require exact equality. Matching never grants resource access. Surface/policy/API-key lifecycle changes invalidate subscriptions conservatively appliance-wide; request-entry revisions and verified JWT/Transit expiry bound access lifetime. Provider-specific opaque sub-resources, other credential revocation, changes to a connection's trusted or attested issuers, cross-process changes and full route/mediator authorization and lifecycle conformance are not verified. See `docs/MCP_METADATA.md`; do not treat helper tests as proof of those.

JWT strategy mutations/reload, provider mutations and explicit vault revocation also invalidate local subscription lifetimes; vault invalidation remains inside the owned mutation task so cancellation cannot release it early. Reads do not invalidate access. Access Points, Transit Points and independent Fabric receivers capture the configured vault's durable revocation epoch before credential evaluation and recheck it every second, with a one-second read timeout even on quiet streams. Changed, corrupt or unavailable state closes the stream; initial read failure returns correlated `503`. Separate-process local-filesystem tests cover revocation without a local signal. Remote-filesystem visibility, other credential kinds, cross-process configuration changes and full resource-policy conformance remain required.

When a Transit Point requires a Transit token, admitted modern requests revalidate it after MCP admission: one header, configured validator, matching surface ID and permitted Transit Point, nonempty token ID, and strict issue/expiry times. Missing authority, duplicates, cross-surface tokens and expiry fail before identity or Target work. The subscription lifetime is capped to that token's expiry; reconnect must pass current checks. Legacy Transit-token validation is unchanged.

Resolved Access Point, Transit Point and Fabric requests retain their selected stable variant ID independently of the materialized surface's cleared catalog. Modern credential preparation and continuations use that retained ID, including defaults. Admitted modern Transit requests reject unknown, disabled and broken-default variants before Target work instead of using the legacy base fallback; Fabric Open also rejects absent named aliases in an empty catalog. The Access Point router carries an unresolved selection on an empty catalog and applies the same rule: legacy keeps the base fallback, while an admitted modern request returns `404` for an unknown alias or `503` for a broken `default_variant_id`. Named variant resource audiences remain distinct from base audiences. Outbound listeners retain the original catalog in shared state while compiling default identity engines, register named canonical and custom paths with `$alias` or `%24alias`, and strip variant routing syntax before forwarding. Custom Transit audiences append `$alias` to the configured resource path; authentication and metadata share the derivation. Real-listener and signed custom-path fixtures cover routing, metadata, audience rejection and quiet cancellation, but complete Access Point router and encrypted cross-gateway authorization still require conformance. Legacy resolution is unchanged.

### Resource Server, consent and credentials

The opt-in `sts.mcp_issuer` profile uses a configured HTTPS origin and root or `/api` identity mount ending `/oauth2/mcp`. It shares STS signing, clients, policy, Trust Check and throttling, preserves legacy DID endpoints, and implements managed token-exchange/ID-JAG grants only. Its forms reject duplicate parameters, token exchange rejects subject and actor tokens whose JOSE `typ` is the ID-JAG media type whatever type the client declares (`declares_id_jag_typ`) and any the gateway signed under its DID or the profile issuer, resources/scopes require explicit client allowlists, ID-JAG `aud` and `resource` stay distinct, and access tokens use `at+jwt`. `sts.mcp_replay` is bounded embedded or conditional DynamoDB storage without fallback. Endpoint-local `mcp_http.authorization` enforces resource tokens for all request eras, supplies path-specific metadata and `401`/`403` challenges, feeds verified policy identity, and strips bearer tokens before forwarding. Fabric receive must enforce its own resource independently. No new browser AS flow follows from these settings, and they do not change which revisions an endpoint admits; full route/distributed conformance is not verified.

MCP Resource Server alignment must reuse the existing `src/sts/` architecture. It adds no gateway-hosted browser login, authorization-code grant or PKCE authorization endpoint. Preserve existing DID-issued flows and do not claim compatibility with authorization-code-only clients. `mcp::continuations` provides bounded mandatory AEAD state, authorization/request and vault-identity/scope binding, atomic embedded and DynamoDB stores, monotonic retry rounds and single-use dispatch claims. URL elicitation requires the request-local capability, and decline/cancel persists denial. Modern third-party consent references an existing JWT strategy through `CredentialProvider.consent_identity_strategy_id`, with tenant/PAT and ownership-reference checks. The existing provider callback verifies a nonce-bound OIDC ID token's signature, issuer, client audience, expiry and deterministic issuer/subject match to the initiating STS principal; no account-link registry, email matching, new hosted login or browser-held MCP bearer establishes consent. Callback tickets bind current surface/provider/strategy snapshots. Verified credentials are staged invisibly to ordinary vault lookup, then activated only after a ready retry wins its single-use claim. A vault revocation epoch and composite credential version prevent stale publication across filesystem instances; any revocation conservatively invalidates outstanding staged consents. Client acceptance and legacy vault records never establish modern readiness. Modern gateway consent (MRTR) needs `[mcp.continuations]` in the bootstrap config and `sts.mcp_issuer`; a modern request to an endpoint with `outbound_credentials` while continuations are not configured fails with `503` / `-32603` ("MCP credential service unavailable"), never falling back to legacy consent. Full callback-route coverage, remote-filesystem conformance and distributed refresh coordination are not verified; see `docs/MCP_METADATA.md`.

The direct modern branch uses shared `proxy::credential_delegation::modern` preparation after current policy checks and before local/delegated payment. The Transit Point branch reuses it at the post-policy credential step, bound to that endpoint's independently verified resource token, agent DID and alias; prepared credentials are applied after caller-header filtering. Both require verified vault provenance, authenticate gateway continuation kinds, and protect opaque upstream state plus requested input keys without prefix-based ownership guesses. JSON/SSE terminal finalization wraps continuations separately from complete-only enrichment. Explicit test-local admission exercises direct forwarding and concurrent retries, while admitted Transit Point steps cover resource binding, credential delivery and replay. Payment retry/idempotency, distributed refresh coordination, full routed consent and Fabric consent conformance are not verified.

Fabric receive prepares modern consent after its own resource authorization, verified agent-presentation admission and policy gates, before payment and Target dispatch. Continuations additionally bind the authenticated sending peer; ingress-audience tokens do not authorize the receiver. An isolated signed-identity receiver test covers pending consent, delegated credential delivery, JSON/SSE upstream continuation restoration, cross-peer rejection and single-use concurrent retries. This does not establish encrypted-frame or managed-mediator conformance.

The sending Access Point uses a distinct `FabricSend` continuation role bound to the selected remote peer; modern consent precedes mirroring, payment and remote dispatch, with delegated credentials applied after caller-token stripping. Modern-provenance vault credentials use durable, version- and revocation-bound refresh claims across filesystem instances, including when a legacy request reaches the same credential. Provider refresh calls are bounded, resource-scoped and cannot widen scopes; publication rejects concurrent replacement/revocation. Ambiguous refreshes never automatically reuse the rotating token. Remote-filesystem, crash-durability, payment-retry and full two-gateway consent conformance are not verified.

Modern credential preparation owns all configured bindings, including tool-filtered skips, on every modern method. Only `tools/call`, `prompts/get` and `resources/read` may initiate or resume gateway consent; other methods reuse verified credentials or fail authorization without legacy elicitation. API-key and client-credentials providers resolve through the prepared injection path, fail closed on missing credentials, and require no browser identity strategy. Modern machine grants use bounded no-redirect requests, the configured resource and exact scopes, and a provider-configuration-bound cache distinct from legacy machine tokens. Service-only bindings preserve opaque upstream continuation state.

Modern credential destinations must be unambiguous before fetching credentials or issuing consent: headers compare case-insensitively, metadata uses canonical key validation, and custom formats must contain `{value}`. Reject conflicting destinations, malformed values and credentials over 32 KiB instead of silently sanitizing or overwriting them. Prepared headers remain sensitive.

Direct and sending Access Points and independent Fabric receive inspect local payment requirements before consuming a ready modern continuation. A no-credential challenge leaves the continuation and staged consent unclaimed; payment verification and Target dispatch still require the atomic claim. Failed or ambiguous payment processing never rearms an operation. Shared local processing uses each endpoint's own configuration and headers, removes consumed header and argument credentials, and preserves x402 versus MPP receipt names. Only the active local paywall's consumed argument is excluded from the continuation digest; business arguments, nested fields and other payment rails remain bound. Successful local payment on consent-enabled paths is retained as bounded, encrypted continuation evidence: later rounds revalidate authority and claim once before reusing the original receipt without another verification or settlement. Neither evidence nor descendant continuations extend the original expiry. Direct and isolated receiver JSON/SSE regressions assert one persisted mock x402 payment across rounds and no further work on replay. Delegated payment, external payment-rail and distributed payment-store conformance are not verified.

Delegated payment never forwards the ingress Resource Server bearer. Modern delegated HTTP 402 challenges force `no-store` and map only retired payment codes `-32042`/`-32043` to application codes `1001`/`1002`, retaining caller correlation and challenge data/headers. Unknown upstream errors and legacy bodies remain unchanged. The remote allow/challenge/deny contract does not prove absence of side effects; never rearm a claimed operation on a challenge or uncertain result.

Vault mutations keep their acquired file lock in an owned task until filesystem work completes, even if the caller is cancelled; lock acquisition remains cancellable and provider network calls stay outside it. A cancelled mutation may have committed and must not be assumed absent. The shared atomic writer uses exclusive UUID temporary files, file flush/sync before rename and Unix directory sync after rename/deletion; a directory sync the filesystem reports as unsupported is logged once and skipped, while other sync failures propagate. Four-process local tests cover refresh claim races, revocation and abrupt owner death; paused-write tests cover cancellation. Real loopback DynamoDB-compatible tests race continuation claims and ID-JAG redemption across four processes. These checks do not prove remote-filesystem, deployed IAM, hardware power-loss or complete multi-host consent conformance.
