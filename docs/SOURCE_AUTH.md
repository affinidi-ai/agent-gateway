# Source Authentication and Managed Identity

Revision-specific internals of how the gateway authenticates an inbound caller and how
it derives the managed agent's DID. These are separate concerns and the source keeps
them separate: source authentication proves who is calling, managed identity names the
agent the request is on behalf of.

Use the hosted [identity documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/concepts/identity/)
for product concepts. See [`POLICY.md`](POLICY.md#caller-identity-verification-in-policy-input)
for how a derived DID is graded in policy input, and [`FABRIC.md`](FABRIC.md#peer-issuer-dids)
for attribution on the fabric path.

Implemented in [`src/source_auth/`](../src/source_auth/) and
[`src/didauth/`](../src/didauth/).

## Source authentication

Configured on the Access Point as `caller_authentication.methods`. Each method is a
`SourceAuthConfig`
([`models.rs`](../src/source_auth/models.rs)), which has five variants.

| Method | Serialized tag | Validates |
| --- | --- | --- |
| JWT bearer | `jwt_bearer` | An inbound bearer token against a JWT verification strategy |
| API key | `api_key` | A key extracted from the request against the secrets store |
| API key provider | `api_key_provider` | A key extracted from the request against the API Key Provider |
| DID Auth | `did_auth` | A DID Auth session token |
| mTLS | `mtls` | A TLS client certificate |

`methods` is a list, but the inbound pipeline enforces only its first entry
([`AgentSurface::source_auth`](../src/config/agent_surface_accessors.rs)); later entries
are accepted and ignored.

A JWT bearer token is accepted only when it is signed with an RS256, RS384, RS512, ES256,
ES384 or EdDSA key from the strategy's key set, its `iss` equals the strategy's expected
issuer, it has an `exp` that has not passed and, when it has an `nbf`, that time has come,
each with 60 seconds of leeway. `aud` must name one of the method's `audiences`; an empty
list skips that check, except on a declaring Access Point, where `aud` must name the resource
of the route called. A method that lists `required_scopes` also needs a token that grants
each of them; see [Required scopes](#required-scopes).

An Access Point whose first method is JWT bearer can also publish RFC 9728 protected
resource metadata naming the authorization server that issues its tokens, and then refuses
callers with a challenge that points at it. It declares by itself from its pinned strategy and
`required_scopes`, and an MCP Access Point can also ask for it with
`caller_authentication.protected_resource`; see [Declaring an Access Point](#declaring-an-access-point).
See also
[`MCP_METADATA.md`](MCP_METADATA.md#authorization-server-discovery-for-caller-authentication),
and [Choosing How an MCP Access Point Checks Tokens](MCP_METADATA.md#choosing-how-an-mcp-access-point-checks-tokens)
for when to use the explicit setting instead of the gateway STS Resource Server path.

The gateway builds one source authentication middleware at startup. If its JWT
verification strategy store (`jwt_verification_strategies/`, next to the secrets storage
directory) cannot be opened, the gateway refuses to start and names that path, rather
than serving surfaces whose caller authentication would be skipped. A request, direct or
over Fabric, that reaches a surface with caller authentication configured while no middleware
is installed is refused with `500` rather than forwarded unauthenticated.

On an Access Point that does not declare, a missing or invalid credential, or a JWT short of
a required scope, does not refuse the request. That includes an mTLS certificate that lacks
the configured binding field. The request continues with no caller identity, and policy sees
`input.source_auth` as
`{"method": "failed", "attempted_method": ..., "kind": ..., "reason": ...}`, where `kind` is
`missing`, `invalid` or `insufficient_scope`. Only server-side errors,
such as missing configuration or an internal failure, block the request with `500`
([`errors.rs`](../src/source_auth/errors.rs)). Such a request is forwarded without the
surface's Target Authentication credential, or the A2A proxy's Direct Line secret, on each inbound
and Fabric forwarding path: direct inbound, `proxy://` MCP Targets, `a2a-proxy://` Targets,
Fabric send and Fabric receive. Transit Point listeners do not authenticate callers, so this
does not cover them. A surface that does not declare and must reject unauthenticated callers
therefore needs a policy that denies them:

```rego
package surface.policy

default allow := false

allow if not deny

deny if input.source_auth.method == "failed"
```

See [`POLICY.md`](POLICY.md#failed-caller-authentication).

A declaring Access Point, MCP or A2A, is the exception: it refuses a failed caller itself, with
`401` for a missing or invalid JWT and `403` for one short of a required scope, and the caller
never reaches the surface's policy or its Target. The refusal carries the discovery challenge on
a direct request and the realm-only refusal on the receiving gateway of a Fabric route. The
invariant is written once in [`AGENTS.md`](../AGENTS.md#architecture); see
[Caller challenge](#caller-challenge) and
[`MCP_METADATA.md`](MCP_METADATA.md#authorization-server-discovery-for-caller-authentication).

A surface whose JWT verification strategy no longer exists, for example because it was deleted
while the surface still references it, cannot authenticate any caller. The strategy is looked
up only after a token is found, so a request with no token is still a missing credential,
handled as above, while a request that presents one is refused with `500`. Deleting a strategy is not
refused while a surface uses it; the dashboard asks for confirmation first and lists the
surfaces whose Access Point or Surface Variants reference it.

### JWT bearer signing keys

A strategy with a remote `jwks_uri` has its JSON Web Key Set fetched and cached by
[`JwksClient`](../src/jwt_bearer/jwks.rs). Each node keeps its own cache.

| Behaviour | Rule |
| --- | --- |
| Cache key | One key set per strategy, used only while the strategy's `jwks_uri` and `updated_at` match the ones it was fetched for. A strategy edited on any node, through the API or on disk, is a cache miss once the node reads the edited record. |
| Eviction | Updating or deleting a strategy through the API evicts its key set. A standby that becomes Active drops every cached key set (see [Server mode](CONFIGURATION_RELOAD.md#server-mode)). |
| Lifetime | `Cache-Control: max-age`, clamped to between 60 seconds and 24 hours; 24 hours when the header is absent. |
| Unknown `kid` | A token whose `kid` is not in a fresh key set triggers at most one refetch per strategy every 60 seconds. Inside that window it fails as `Key not found for kid`, an invalid credential like any other. |
| Concurrency | Concurrent requests for one strategy share one fetch. |
| Fetch failure | The next fetch waits 10 seconds. When a refresh of an expired key set fails, the last good set keeps serving for up to one hour past its expiry; after that, or with no good set, the request is refused with `500`. |
| Limits | A response body over 64 KiB, more than 64 keys, a repeated `kid`, or a key without a `kid` in a set of several keys is a failed fetch. `POST /v1/jwt-verification-strategies/validate-jwks-uri` applies the same limits. |

The fetch is pinned to the vetted address under the cloud-metadata-only posture, with no
redirects ([`fetch.rs`](../src/jwt_bearer/fetch.rs); see
[`POLICY.md`](POLICY.md#other-pinned-egress-sinks)). A strategy with a static key set is never
fetched or cached. Each network fetch of a strategy's key set, successful or failed, is counted
by result in `agent_gateway_jwks_fetch_total`
([`OBSERVABILITY.md`](OBSERVABILITY.md#trust-plane-metrics)); a cache hit and the
`validate-jwks-uri` probe are not counted. A host that does not resolve fails as `blocked`, and
resolving it times out after 10 seconds as `unreachable`.

### Authorization server discovery

A strategy can pin its authorization server's metadata. Discovery runs through the shared
[authorization server metadata module](#authorization-server-metadata-module-developer-reference)
with `expected_issuer` as the issuer, so the document's `issuer` must equal it byte for byte,
trailing slash included, and name a `token_endpoint` and a `jwks_uri` that do not use a weaker
scheme than the issuer. The pin, `authorization_server`, holds `issuer`, `metadata_url` (the
document that answered), `token_endpoint` and `jwks_uri`. It does not change `jwks_source`,
and token verification does not read it.

| Request | Behaviour |
| --- | --- |
| `POST /v1/jwt-verification-strategies/discover` with `{"issuer": ...}` | Returns the metadata a save would pin, and stores nothing |
| Save with `discover_metadata: true` | Discovers and pins. If discovery fails, the save is refused with `422` and nothing is stored |
| Save with `discover_metadata: false` | Clears the pin |
| Save without `discover_metadata` | Keeps the pin, if any. When a pinned strategy's issuer or remote `jwks_uri` changed, discovers again. If that fails, or the caller is past the probe limit, the save still answers `200` and logs a warning; the old pin is kept only when its issuer still equals the expected issuer (only the remote `jwks_uri` changed) and is cleared otherwise. A tenant-scoped caller that moves the issuer to an `http` URL always has its pin cleared: the strict posture refuses the issuer as `invalid_url` before any request |

`POST /v1/jwt-verification-strategies/validate-jwks-uri` stays for strategies whose
`jwks_uri` is entered by hand; `discover` returns the discovered `jwks_uri` as well.

Both endpoints, and a save that discovers, make an outbound request on the caller's behalf, so
they share one set of rules ([`handlers.rs`](../src/jwt_bearer/handlers.rs)):

| Rule | Detail |
| --- | --- |
| Permission | `jwt_verification_strategies.edit` |
| Egress posture | The cloud-metadata-only posture (cloud metadata blocked; http, loopback and RFC 1918 allowed), and the strict posture for a tenant-scoped PAT, which also blocks loopback, RFC 1918, link-local and unique-local addresses. Under the strict posture discovery and `validate-jwks-uri` accept `https` only: an `http` issuer or JWKS URI fails with `invalid_url` before any lookup, and an `http` endpoint in the document makes it invalid. Each request is pinned to the vetted address unless a proxy is configured (see the module's [DNS limit](#authorization-server-metadata-module-developer-reference)), does not follow redirects, and reads at most 64 KiB. A discovery fetch has 10 seconds to resolve the host and 10 more for the request, and discovery makes up to three fetches for an issuer with a path and two for one without, so it takes at most 60 or 40 seconds. |
| Limit | Up to 10 probes per user at once, replenished at one every 6 seconds; past that, `429` with code `rate_limited`. A save that cannot re-discover because of the limit keeps its pin only when the issuer is unchanged, and clears it otherwise. |
| Errors | A fixed `code` and message, never the resolved address or the transport error. Discovery uses the [module's codes](#authorization-server-metadata-module-developer-reference): `invalid_url`, `blocked` (also a host name that does not resolve), `unreachable`, `http_status`, `too_large`, `invalid_document`, `issuer_mismatch`. `validate-jwks-uri` uses `invalid_url`, `blocked` (also a host name that does not resolve), `unreachable`, `http_error`, `too_large`, `invalid_document`. `discover` and saves answer `422`; `validate-jwks-uri` answers `400` with `valid: false`. |
| Audit | Each probe logs an `audit` event `jwt_verification_strategy.probe` with the probe kind (`discover`, `jwks_uri` or `save`), the caller, the tenant, the posture, the host and the result: `ok` or the failure code, which a failed probe also logs in a warning. The `discover` and `save` probes record the discovery codes, so a metadata server that answers outside 2xx is recorded as `http_status`. The `jwks_uri` probe records `http_error` for the same answer, so a rule that matches failed probes by result must match both. |

Every discovery is also counted in `agent_gateway_discovery_total`
([trust plane metrics](OBSERVABILITY.md#trust-plane-metrics)), and each strategy create, update
or delete records a `verification_strategy_changed` configuration event that says whether the
pin changed ([governance audit forwarding](OBSERVABILITY.md#governance-audit-forwarding)).

**Microsoft Entra.** Only tenant-specific authorities work, such as
`https://login.microsoftonline.com/<tenant id>/v2.0`. The multi-tenant authorities (`common`,
`organizations`) advertise `{tenantid}` in their issuer, which fails the exact match, and a
strategy whose `expected_issuer` contains `{` or `}` is refused with `400`: the gateway never
matches issuer templates.

**Other consumers of a strategy.** STS subject and ID-JAG verification ([`STS.md`](STS.md))
selects a strategy by `expected_issuer` and checks no audience; modern consent verifies the
provider's ID token against `consent_identity_strategy_id` with the client id as audience
([`MCP_METADATA.md`](MCP_METADATA.md)); credential providers reference a strategy only through
that field. None of them reads `authorization_server`, so a pin never changes which tokens
they accept. The field is left out of the stored record when unset, so a strategy saved before
the field existed keeps the digest that a consent record bound to it.

### Required scopes

A `jwt_bearer` method can list `required_scopes`. After the token verifies (signature, issuer,
expiry and audience), the Access Point reads the scopes it grants
([`access_token.rs`](../src/jwt_bearer/access_token.rs)) and checks them in
[`middleware.rs`](../src/source_auth/middleware.rs). The check is not part of token
validation, so STS, modern consent and credential providers are unaffected.

| Rule | Detail |
| --- | --- |
| Granted scopes | The first claim in the strategy's `scope_claims` (default `scope`, then `scp`) that the token carries decides. A string is split on spaces, an array of strings is used as is, and any other shape grants nothing. |
| Shortfall | A token that lacks any required scope is a failed caller of kind `insufficient_scope`, handed to policy like a missing or invalid token, except on a declaring Access Point, which refuses it with `403` (see [Caller challenge](#caller-challenge)). The `auth_failed` audit reason is `insufficient_scope`, and each shortfall is counted in `agent_gateway_scope_denied_total` ([`OBSERVABILITY.md`](OBSERVABILITY.md#trust-plane-metrics)). |
| Access tokens only | With `required_scopes` set, a token carrying `nonce` or `at_hash`, or whose JOSE `typ` header is present and is not `at+jwt`, `application/at+jwt` or `JWT` (case-insensitive), fails as `invalid`. A method without `required_scopes` keeps accepting such tokens. |
| Saving | Each entry must be an RFC 6749 scope token (`%x21 / %x23-5B / %x5D-7E`) of 1 to 128 characters, with at most 32 entries and no duplicates, on the base Access Point and on every Surface Variant. Otherwise the save is refused with `400`, and a configuration file is refused at startup. |

A strategy's `scope_claims` lists the claims read for granted scopes, in order: 1 to 8 names,
each 1 to 256 printable ASCII characters without spaces, none repeated, or the save is refused
with `400`. Microsoft Entra app-only tokens, for example, carry their permissions in `roles`.
A save that omits the field keeps the stored list, and one that sends `["scope", "scp"]`
stores the default as absent, so a strategy that never customises it keeps its stored record,
and the digest a consent record binds to it, unchanged. Only Access Points read it.

An ID token is signed by the same issuer as an access token, and its audience can be the
Access Point URL: any Google service account can mint a Google ID token for an audience it
chooses. Such a token carries no scope, so requiring a scope refuses it. An Access Point that
trusts a Google issuer, or any issuer that mints ID tokens for arbitrary audiences, needs
`required_scopes` or a policy on `client_id` or `subject`.

A verified caller's policy input carries `scopes` and `client_id` normalised across
providers, and the id and tenant of the strategy that verified the token; see
[`POLICY.md`](POLICY.md#jwt-bearer-caller-input).

Releases before this one ignore a method's `required_scopes` and a strategy's
`scope_claims` on every `jwt_bearer` Access Point, and drop them when they save the record.
After a rollback those Access Points accept tokens without the scope, ID tokens included,
with no warning, and the metadata keeps listing the scopes as supported. Before rolling back,
disable each Access Point that relies on `required_scopes`, or protect it with a surface
policy those releases can evaluate: one that checks the raw `scope` or `scp` claim in
`input.source_auth.claims`, since they publish neither `input.source_auth.scopes` nor the
`insufficient_scope` kind. Set `required_scopes` again after upgrading.

### Declaring an Access Point

An Access Point declares when it tells callers which authorization server to use: it publishes
protected resource metadata for the route called, binds the token audience to that route and
refuses a failed caller with a challenge that names the metadata. The request path resolves
the declaration once per request ([`declaration.rs`](../src/source_auth/declaration.rs)), and
the metadata, the audience binding, the caller challenge and a declaring A2A agent card
([`PROTOCOLS.md`](PROTOCOLS.md#agent-card-security)) are all projections of it. It has two
sources:

| Source | Applies to | Rule |
| --- | --- | --- |
| Explicit | An MCP Access Point | `caller_authentication.protected_resource` is present. Its fields and checks are in [`MCP_METADATA.md`](MCP_METADATA.md#authorization-server-discovery-for-caller-authentication). A setting the Access Point cannot serve answers `503`; it never falls back to the derived rule. |
| Derived | Any other Access Point, and an MCP one without the setting | Its only caller authentication method is `jwt_bearer` with `required_scopes`, and the strategy and the Access Point meet the conditions below. |

There is no setting that switches a derived declaration off: remove `required_scopes`. An
Access Point that uses neither source never declares. An explicit declaration needs no
`required_scopes` and never reads the strategy store; a derived one reads it only once its
method lists `required_scopes`.

A derived declaration strips when any condition below fails. The checks run in this order, and
the reason code ([`StripReason`](../src/source_auth/declaration.rs)) is the first that applies.
A stripped Access Point publishes no metadata, sends no challenge and adds no scheme to its
card, and handles failed callers as an Access Point that does not declare.

| Reason code | Strips when |
| --- | --- |
| `fabric_target` | The Access Point has no caller authentication and its Target is `fabric://` |
| `multiple_methods` | There is more than one caller authentication method |
| `method_not_declarable` | The only method is not `jwt_bearer` |
| `no_required_scopes` | `required_scopes` is empty |
| `root_variant` | The route called is a Surface Variant of an Access Point at `/`, which has no path of its own |
| `strategy_unavailable` | The strategy is missing, or the surface's tenant may not reference it |
| `static_jwks` | The strategy has static keys instead of a remote `jwks_uri` |
| `not_pinned` | The strategy pins no authorization server ([Authorization server discovery](#authorization-server-discovery)) |
| `pin_mismatch` | The pinned issuer differs from `expected_issuer`, or the pinned `jwks_uri` from the strategy's |
| `custom_token_header` | `token_header` is not `Authorization` or `token_scheme` is not `Bearer` (case-insensitive) |
| `forwards_caller_token` | `forward_header` is on |
| `no_access_point_url` | No listener matches, or the URL (the first `external_urls` entry of the listener its `listen_address` names, plus the route) is not a canonical `https` URL |
| `audience_missing` | `audiences` does not list that URL exactly |

`agent_gateway_card_security_total` also counts a `strip` with the reason `transit_point`: a
Transit Point card whose partner security and signatures the gateway removed because its
Access Point's cards are secured ([`PROTOCOLS.md`](PROTOCOLS.md#agent-card-security)). It is
never the outcome of a request.

On an explicit MCP declaration `forward_header` is refused with `400` on save and `503` at
request time instead of stripping, because the setting exists to switch the protection on.

The resource a derived declaration names is the Access Point URL above, with `$alias` for a
Surface Variant (`%24` is read as `$`). Each variant is resolved on its own, against its own
URL. An alias on a surface without variants selects nothing and is ignored: the base route
answers, directly or over Fabric, with the base route's declaration and challenge. On a declaring route `aud` must contain that resource: the accepted audience is the
resource of the route called, so a token issued for the base route does not open a variant and
an extra value in `audiences` is not accepted. A route that holds `$` or `%24` is refused with
`400` on save, because it would claim another surface's variant URL.

A declaring Access Point never sends the caller's token on, to the Target or over Fabric: it is
the resource the token was issued for, so a Target would receive a token not meant for it. A strategy store failure while
resolving a declaration that would otherwise declare answers `503` and never lets the caller
through.

### Protected resource metadata

A declaring Access Point publishes its declaration as RFC 9728 protected resource metadata, so
a client can find the authorization server from the Access Point URL alone. Every inbound
listener serves it at `/.well-known/oauth-protected-resource<path>`, where `<path>` is the
route, or `<route>$alias` for a Surface Variant, whether or not `sts.mcp_issuer` is set:

```json
{
  "resource": "https://gw.example/smoke",
  "authorization_servers": ["https://as.example/"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["agent.invoke"]
}
```

| Field | Value |
| --- | --- |
| `resource` | The resource of the route called, which `aud` must name |
| `authorization_servers` | The pinned issuer of a derived declaration, or the servers an explicit setting lists |
| `scopes_supported` | `required_scopes`, then the other scopes an explicit `protected_resource.scopes` advertises |

| Request | Answer |
| --- | --- |
| The path of a declaring Access Point or enabled Surface Variant | `200` with `Cache-Control: no-store` |
| Any other path, including one that strips | `404` |
| A path that two endpoints claim, a setting the Access Point cannot serve, or a strategy store failure | `503` |

The surface and its strategy are read on every request, so an edit to either changes the
document on the next request. The route, its CORS rule, the collision checks and the reserved
prefix are in
[`MCP_METADATA.md`](MCP_METADATA.md#authorization-server-discovery-for-caller-authentication).

### Caller challenge

On a declaring Access Point the gateway is the resource server, so a caller whose source
authentication failed is refused by the gateway, whatever policy would say. The refusal names
the protected resource metadata, so a client finds the authorization server from the refusal
alone (RFC 6750 and RFC 9728):

| Failure kind | Answer |
| --- | --- |
| `missing` | `401`, `WWW-Authenticate: Bearer resource_metadata="<metadata URL>"`, plus `scope="<required_scopes>"` when the method lists any |
| `invalid` | `401`, the same challenge with `error="invalid_token"` after `resource_metadata` |
| `insufficient_scope` | `403`, the same challenge with `error="insufficient_scope"` after `resource_metadata` |

`scope` lists `required_scopes` only, never the other scopes the metadata advertises. A
server-side error is never challenged: it answers `500`, or `503` when the Access Point can no
longer serve its declaration.

The refusal comes from one place for every stage
([`challenge.rs`](../src/source_auth/challenge.rs),
[`caller_denial.rs`](../src/proxy/caller_denial.rs)). The invariant, that a declaring Access
Point refuses a failed caller before AP2, payment and forwarding unless a stage admits it,
is written once in [`AGENTS.md`](../AGENTS.md#architecture). In request order:

| Stage | A failed caller on a declaring Access Point |
| --- | --- |
| Source authentication of an MCP Access Point | The challenge, before any policy |
| Appliance-wide and gateway policy | A caller either refuses gets the challenge in place of the stage's `403`; a caller they admit continues |
| Built-in default, on every other protocol, right after gateway policy | The challenge, before AP2 and payment and before the request reaches the Target or Fabric |
| Receiving gateway of a Fabric route | `401` or `403` with `realm="agent-gateway"` and no `resource_metadata`, before policy |

A caller that did not fail source authentication gets the refusing stage's `403` with no
challenge, on every stage. Outside MCP the body is the refusing stage's body (the built-in
default's detail is `Caller authentication failed`), with `Cache-Control: no-store`; an MCP
Access Point answers with a problem whose detail is fixed and never says why a token failed.
Every challenge the gateway builds carries the `GatewayChallenge` marker
([`protected_resource.rs`](../src/protocols/protected_resource.rs)), so the filter below keeps
it.

Only the sending gateway of a Fabric route declares and sends the challenge that names the
metadata. The receiving gateway has no use for `resource_metadata`: the sending gateway strips the caller's own token, so sending
the remote client to fetch one would only loop. It refuses a failed caller with the realm-only
answer, which the sending gateway then drops as a [relayed challenge](#relayed-challenges). See
[`FABRIC.md`](FABRIC.md#resource-server-across-the-fabric).

| Not a caller challenge | Answer |
| --- | --- |
| Rate limit | `429` |
| Payment | `402` with its `Payment` challenges; a `Bearer` challenge is never added to it |
| A `tools/call` that a policy refuses, and MCP tool gating | The JSON-RPC denial (HTTP `200`, code `-32001`) |
| Response policy, egress policy, server-side source authentication errors | Their own answers |

### Relayed challenges

When the Access Point declares, or the Target is a `fabric://` route, every
`WWW-Authenticate` challenge in the Target's response except `Payment` is removed before the
caller sees it ([`strip_relayed_challenges`](../src/source_auth/challenge.rs)). The gateway is
then the resource server, or the Target is another gateway answering the sending gateway's
credential, so `Bearer`, `DPoP`, `Basic` and the rest name an authorization the caller cannot
use through the gateway.

| Target response | Caller gets |
| --- | --- |
| A challenge the gateway built itself | Unchanged |
| A header value listing several challenges | Only its `Payment` challenges |
| A `401` left with no challenge | `502` with the detail `The target refused the gateway's authorization`: the Target refused the gateway's own credential, which the caller cannot fix, and a `401` without a challenge would send an OAuth or MCP client back to its own authorization server |
| Any other status | The same status, without the dropped challenges |
| A `401` that carried no challenge at all | Unchanged |

Each response that loses a challenge logs a warning naming the surface, the status, the
dropped schemes and whether it became `502`. Over the Fabric, the receiving gateway's own `401`
or `403` reaches the sending gateway as a relayed challenge, so the caller gets `502` or a
`403` without it. Every other Access Point passes the Target's challenges and status through
unchanged, including one whose `jwt_bearer` method forwards the caller's own token.

### mTLS

Two trust modes, in [`MtlsTrust`](../src/source_auth/models.rs):

| Mode | Behaviour |
| --- | --- |
| `Pinned { certificate_ids }` | Accepts only those exact certificates, matched by SHA-256 fingerprint of the stored leaf DER. No chain verification. References certificates whose `kind == ClientLeaf`. |
| `Ca { ca_certificate_ids, … }` | Verifies that the presented leaf chains to one of the configured CAs. References certificates whose `kind == Ca`, and can require the TLS Client extended key usage. |

The identity taken from the certificate is chosen by `MtlsIdentityBinding`. Every mode
except `Fingerprint` fails at runtime when the certificate does not carry the field.

| Binding | Takes |
| --- | --- |
| `fingerprint` | Lowercase hex SHA-256 of the leaf DER. Always available. |
| `subject_cn` | Subject Common Name |
| `dns_san` | First DNS SubjectAltName |
| `uri_san` | First URI SubjectAltName. SPIFFE IDs arrive through this mode. |
| `ip_san` | First IP SubjectAltName, rendered canonically |
| `subject_rdn { oid }` | An arbitrary RDN by OID from the Subject DN, for example UID as `0.9.2342.19200300.100.1.1` |

The certificate reaches the gateway either from a directly terminated TLS handshake or
forwarded as an XFCC header from a proxy listed in `tls.client_auth.trusted_proxies`.
An XFCC header from any other source is not trusted.

### DID Auth

A two-step ceremony: `POST /authenticate/challenge` issues a challenge, and
`POST /authenticate` accepts a JWS over it.

```mermaid
sequenceDiagram
    participant C as Caller
    participant G as Agent Gateway
    C->>G: POST /authenticate/challenge
    G-->>C: Challenge, valid 300 s by default
    Note over C: Signs the challenge as a JWS<br/>with its DID key, EdDSA by default
    C->>G: POST /authenticate with the JWS
    Note over G: Checks the DID against allowed_dids,<br/>and the iat against the permitted skew
    G-->>C: Session token, valid 86400 s by default
    C->>G: Later requests carry the session token
```

| Setting | Default | Notes |
| --- | --- | --- |
| `allowed_dids` | empty | Empty means any DID is accepted |
| `challenge_ttl_seconds` | 300 | Capped at 3600. A longer challenge widens the replay window. |
| `session_ttl_seconds` | 86400 | |
| `allowed_algorithms` | `["EdDSA"]` | The verifier recognises `EdDSA` and `ES256`; a value outside that set is rejected at validation time |

`IAT_SKEW_SECONDS` is 120 ([`verify.rs`](../src/didauth/verify.rs)). A JWS is rejected
when its `iat` is more than 120 seconds in the future. The backdating allowance is
wider, at 30 times that value.

Workload Binding supports `caller_source: did`, which tags the Workload Binding
presentation with `user_hash = SHA256(did)`.

### Authorization server metadata module (developer reference)

[`src/authz_metadata/`](../src/authz_metadata/) fetches and validates an authorization
server's metadata document and returns the issuer, the URL the document came from, the
`token_endpoint` and the `jwks_uri`. An issuer is acceptable only when it has no whitespace,
Unicode spaces such as a no-break space or a line separator included, and no control
character anywhere, leading, trailing or inside; the raw string is checked before it is
parsed, and a failure is `invalid_url` before any DNS lookup or request.
Let P be the issuer path with its trailing slashes removed. An origin issuer (empty P, with or
without a trailing slash) has two attempts, in this order: `{origin}/.well-known/oauth-authorization-server`
(RFC 8414), then `{origin}/.well-known/openid-configuration`. A path issuer has three: the
RFC 8414 URL with P inserted after the well-known name
(`{origin}/.well-known/oauth-authorization-server{P}`), the OpenID Connect URL with P inserted
(`{origin}/.well-known/openid-configuration{P}`), then the OpenID Connect URL with P appended
(`{origin}{P}/.well-known/openid-configuration`). The first acceptable document wins. The
`issuer` in the document must equal the requested issuer byte for byte. `token_endpoint` and
`jwks_uri` are both required, `jwks_uri` too although RFC 8414 makes it optional, because the
gateway validates JWT access tokens and needs the issuer's keys; a document without either is
`invalid_document`. Both must be absolute `http` or
`https` URLs of at most 2048 characters, with no whitespace, control characters,
credentials or fragment, not a cloud-metadata address, and not a weaker scheme than the
issuer: an `https` issuer with an `http` endpoint is an invalid document under every posture.
The schemes are compared as parsed, so their case does not matter.

| Limit | Value |
| --- | --- |
| Body size | 64 KiB (`MAX_METADATA_BYTES`), set per call by `DiscoveryOptions::max_bytes` |
| Timeout | 10 s, set per call by `DiscoveryOptions::timeout`, applied once to resolving the host and again to the HTTP request from connecting to reading the last byte. One fetch can take up to twice the timeout, and `discover` can make three fetches for a path issuer and two for an origin issuer, so up to six or four times the timeout in all |
| Redirects | Refused |
| DNS | The egress guard can resolve the host more than once; the connection is pinned to the addresses of the last, vetted resolution. An IPv6 literal host cannot be pinned and fails as `blocked`. Pinning does not hold when a proxy is configured: the HTTP client reads `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` (also in lower case) and, on macOS and Windows, the system proxy settings. The request then goes to the proxy, which resolves the host again and connects to an address nobody vetted, so address vetting and pinning no longer apply. This is true of the shared pinned egress clients until they call `.no_proxy()` |
| Status | Only a 2xx response is read |

The caller chooses an `EgressPosture`. `Strict` accepts `https` only: `get_bounded` and
`discover` refuse an `http` URL or an `http` issuer as `invalid_url` before any DNS lookup or
request, and an `http` `token_endpoint` or `jwks_uri` makes the document invalid. `Strict` also
blocks loopback, unspecified, RFC 1918, link-local and unique-local addresses.
`CloudMetadataOnly` accepts `http` and `https`, for operator-trusted callers such as a local
authorization server, and blocks only cloud-metadata addresses, allowing loopback and private
ranges. An `http` issuer, possible only under `CloudMetadataOnly`, may have `http` or `https`
endpoints. The posture
applies to the metadata URL at fetch time. It also applies to the discovered
`token_endpoint` and `jwks_uri` at parse time, where under `Strict` a literal IP host or a
`localhost` name in a blocked range makes the document invalid. A name that only resolves to
a private address cannot be known without DNS, so it passes parsing. The caller must therefore
fetch these URLs with `get_bounded`, or another pinned client, under the same posture, which
blocks such a name at fetch time. The JWT Bearer `JwksClient` fetches a strategy's key set
for verification (`get_key`) only under the cloud-metadata-only posture; only `fetch_jwks`,
used by `validate-jwks-uri`, takes the caller's posture. So a `jwks_uri` discovered under
`Strict` must not be handed to the verification cache; fetch it with `get_bounded` under
`Strict`.

A failure is a `DiscoveryError`. `failure()` returns the `DiscoveryFailure`, `code()` a
stable string, `message()` fixed text that is safe in an API response (it never carries a
resolved address or a transport error) and `detail()` text for logs only. The error's
`Display` output includes the detail, so it is for logs only too. Both `code()` and
`message()` reveal the kind of failure, for example that a host is blocked or unreachable, so
a caller that serves untrusted parties should log them and return one generic message
instead.

| `code()` | Meaning |
| --- | --- |
| `invalid_url` | The URL or issuer is not an absolute `http` or `https` URL without credentials (`https` only under `Strict`), the issuer has a query or fragment, or the issuer contains whitespace or control characters |
| `blocked` | The egress posture refused the URL or its resolved address, the host name did not resolve, or the host is an IPv6 literal |
| `unreachable` | Resolving the host timed out, the connection failed or timed out, or the body could not be read in time |
| `http_status` | The server answered with a status outside 2xx, including a redirect |
| `too_large` | The body exceeded the size limit |
| `invalid_document` | The body is not a JSON object, or a required field is missing or unacceptable, including an endpoint with a weaker scheme than the issuer or, under `Strict`, a non-`https` endpoint |
| `issuer_mismatch` | The document's `issuer` differs from the requested issuer |

`discover` tries the URLs in order and stops at once on `invalid_url`, `blocked` or
`unreachable`. Otherwise, when every attempt fails, it returns the most specific failure among
all of them, from least to most specific: `http_status`,
`too_large`, `invalid_document`, `issuer_mismatch`.

| Function | Use |
| --- | --- |
| `discover(issuer, posture, options)` | Fetches and validates, trying the URLs in order |
| `metadata_urls(issuer)` | Pure: the candidate URLs for an issuer, in order: two for an origin issuer, three for a path issuer |
| `validate_issuer(issuer, posture)` | Pure: the issuer checks `discover` makes before any request; protected resource metadata uses it for the authorization servers it advertises |
| `parse_metadata(body, issuer, metadata_url, posture)` | Pure: validates a document already in hand |
| `get_bounded(url, posture, options)` | The pinned, bounded GET, reusable for a JWKS fetch |

```rust
use crate::authz_metadata::{discover, DiscoveryOptions, EgressPosture};

match discover(issuer, EgressPosture::Strict, DiscoveryOptions::default()).await {
    Ok(metadata) => use_endpoints(&metadata.token_endpoint, &metadata.jwks_uri),
    Err(error) => {
        tracing::warn!(code = error.code(), detail = error.detail(), "discovery failed");
        respond_with("The authorization server could not be reached");
    }
}
```

The module has no metrics, audit or storage coupling and no tenancy or strategy types in its
signatures, so callers record outcomes themselves from `code()`.

## Managed identity

A rule that derives the managed agent's DID. `ManagedIdentityConfig`
([`models.rs`](../src/source_auth/models.rs)) has five modes. It is set per identity
slot on the surface, and a Transit Point may override it for its own outbound leg.

| Mode | Derives the DID from | Counts in policy as |
| --- | --- | --- |
| `payload_extraction` | A field in the request payload metadata. Also accepted on the wire as `from_payload`. | `unverified` |
| `from_api_key` | A stored API key named by `api_key_id` | `unverified` |
| `from_mtls` | A stored certificate named by `certificate_id` | `unverified` |
| `static` | A fixed `did`, for test fixtures and stub agents | `unverified` |
| `from_jwt_claim` | A claim on a JWT already verified by source auth | `source_auth` |

Only `from_jwt_claim` is request-bound. The other four read a stored credential or the
request body and are independent of the credential authenticated on this request, which
is why they do not count as verified. An identity presentation reports `vp` or
`vp_unanchored` regardless of the configured mode; see
[`POLICY.md`](POLICY.md#caller-identity-verification-in-policy-input).

### `from_jwt_claim`

Requires `jwt_bearer` source auth on the same surface, so the token is cryptographically
verified before the DID is derived.

| Field | Default | Effect |
| --- | --- | --- |
| `claim` | `oid` | The claim whose value identifies the agent. The default is the stable Microsoft Entra Agent ID object identifier. |
| `namespace_claims` | empty | Additional claims folded into the identity hash to namespace the agent across tenants or issuers, for example `["iss", "tid"]`. Every listed claim must be present on the token, or resolution fails. |

One stable `did:webvh` is minted per distinct claim value. Token rotation keeps the DID
stable, and a shared identity-hash pepper keeps it identical across every gateway in the
fabric.

### Identity hash pepper

The two derivation paths hash differently.

| Mode | Hash |
| --- | --- |
| `payload_extraction` | Plain SHA-256 over the selected fields, sorted by path and joined as `field=value\|field=value` ([`identity_hash.rs`](../src/identity/identity_hash.rs)). No pepper. |
| `from_mtls`, `from_api_key`, `from_jwt_claim` | `HMAC-SHA256(pepper, canonical(fields))` ([`credential_identity.rs`](../src/identity/credential_identity.rs)) |
| `static` | None. The configured DID is used as given. |

![Payload identity derivation: request payload, extract the x-identity fields, sort and canonicalise, SHA-256 hash, look up in the identity store, then return the existing DID or mint a new one](assets/diagrams/payload-identity-derivation.png)

The pepper keeps a credential-derived hash non-invertible, so emitting it through policy
input or the audit log does not expose the certificate, key, or claim it came from. It is
read from `AG_IDENTITY_HASH_PEPPER`, as hex or as a loader reference such as `env://`,
`file://`, `aws_secrets://`, or `aws_parameter_store://`, and must decode to at least 32
bytes. A2A proxy identities other than Entra agents are hashed with it too.

Without it, or with a value that is too short or cannot be resolved, the gateway falls back
to an ephemeral pepper, and every **credential-derived** DID changes on restart. Payload-derived DIDs are unaffected. Two gateways that should mint
the same credential-derived DID for the same agent must share the pepper. See
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md#environment-variables).

Credential-derived modes skip body parsing entirely.

## Trust Recorder

The only writer of agent-in-trust-registry records
([`trust_recorder.rs`](../src/trust_registry_verification/trust_recorder.rs)). It fires
on the response leg and on discovery, and is idempotent.

After writing its records, the Trust Recorder publishes a name for each authority it
wrote. The name comes from the Authority register entry with that DID, or, failing that,
from the Issuer with that DID, which covers the `{{ surface.issuer_did }}` template. An
Issuer DID used as a record's entity is named after the Issuer too. A DID with no
matching Authority or Issuer stays unnamed.

When the managed agent has a display name (see [Display names](#display-names)), the
Trust Recorder also publishes the agent DID's entity reference field and attaches
`{"displayName": "<name>", "origin": "managed"}` as `context` on the records it creates
for the agent DID. Context is a snapshot taken at creation and is never rewritten; the
reference field carries the current name. A naming failure never skips record creation.

`authority_did` accepts the template `{{ surface.issuer_did }}`, resolved at write time
to the surface's configured Issuer DID. When the surface has no issuer configured, or its
issuer was deleted (deleting an Issuer does not check whether a surface still uses it), the
template does not resolve and the entry is skipped with a warning rather than written
with a placeholder.

An entry's `issuer_did` is not a signer and does not set the authority. It is written as
the `entity_id` of custom records whose `entity_target` is `issuer`, and nothing else. The
dashboard warns on the Trust Recorder panel and on the entry while the surface has no Issuer
selected, or its Issuer no longer exists, and an entry's authority is the template, because
that entry writes nothing. The
warning does not block saving, and it does not appear for entries with an explicit authority.

### Recorder status

The gateway keeps the Trust Recorder's last known outcome for each managed agent DID on each
surface ([`recorder_status.rs`](../src/trust_registry_verification/recorder_status.rs)). It is the
recorder's last outcome, not a live check of the trust registry.

Each entry has one state:

| State | Meaning |
| --- | --- |
| Recorded (`recorded`) | At least one record was written or already existed, and none failed. |
| Partly recorded (`partial`) | Some records were written or already existed and some failed. |
| Failed (`failed`) | No record was written. The reason is `no_response` (no reply within 10 seconds), `rejected` (the registry sent a problem report) or `error`. |
| Skipped (`skipped`) | The entry was not written. The reason is `registry_not_found`, `registry_not_connected`, `no_surface_issuer` (the `{{ surface.issuer_did }}` template did not resolve) or `error` (the trust registry lookup failed). |
| Not attempted yet (`not_attempted`) | The surface has a Trust Recorder and no outcome is stored yet, for example right after it was added. |

An entry that declares no records is not reported. The identity's overall state combines its
entries: when all entries share a state it is that state, when a written entry is mixed with an
unwritten one it is Partly recorded, and otherwise Failed ranks above Skipped. Only these
codes, counts and timestamps are kept; registry error text never reaches the status.

Statuses are stored in `_storage/trust_recorder_status/`, beside the identities directory and
without a `[storage_paths]` key, so a backup of `_storage` includes them. The recorder runs on
every response, so a status is written only when the outcome changes. The attempt time is
held in memory and, after a restart, shows the time of the last change until the next
attempt. Deleting a surface, or adding, removing or changing the entries of its Trust Recorder,
clears its statuses, so they show Not attempted yet until the next response. The outcome of a
run that began before the clear is dropped, so a run still waiting on a trust registry cannot
bring a cleared status back. A storage failure is logged as a warning and the status reads as
missing.

Managed identities whose surface has a Trust Recorder carry `trust_recorder` in the identity
list (`/v1/dashboard/stats` and its live updates), which also pushes an identity whose outcome
changed. Adding or removing a Trust Recorder, or a change another node wrote to shared storage,
shows on the next update or reload. `GET /v1/surfaces/{id}/trust-recorder-status` returns
`{"status": ...}` for a surface: the most recently attempted of its managed agents, or `null`
before the first attempt and while the surface has no Trust Recorder. It needs the same surface
access as `GET /v1/surfaces/{id}`.

## Display names

A display name is an unverified, human-readable label for a DID
([`display_name.rs`](../src/identity/display_name.rs)). Valid names are trimmed, keep
their case, contain no control characters or invisible Unicode format (`Cf`) characters
such as zero-width spaces and bidirectional overrides, and fit in 128 characters and
256 UTF-8 bytes. Descriptions are dropped when they contain either kind of character. An invalid or empty name is skipped with a warning, and the DID is shown
instead. Falling back to the DID is display-only: no reference field, context or VC
name is ever published with the DID as the name.

### Managed agents

The managed agent's display name is its surface name. On A2A and AP2 surfaces with an
`http` or `https` target, the dashboard shows the `name` in the target's Agent Card
instead (see [Agent Card names](#agent-card-names)). Each identity record carries an
origin (`managed` or `external_caller`), stamped when the gateway issues the DID. The
origin follows the identity slot the DID came from, not the request leg: on a surface
with no inbound slot, an inbound request that derives the DID from the protected slot
(or legacy `target.identity_injection`) issues it as `managed`, the same as the
outbound leg and the response path. A
record written before origins existed has none until the gateway next issues its
credential. Until then it is never published, and the dashboard shows it unnamed, in its
own row, with the LOCAL or REMOTE badge instead of an origin badge. A record is not
classified from the surface it links to: before origins existed, caller DIDs were also
stored as local records linked to the surface, so a link does not prove a managed agent.
Credential principals (the name of the backing certificate or secret) appear only in
the dashboard and are never published.

If one DID is managed on more than one surface, no name is published and the dashboard
shows a name conflict.

#### Agent Card names

The Agent Card name ([`target_card_names.rs`](../src/identity/target_card_names.rs))
is dashboard-only. It applies to every managed-identity mode, and the Identities page
shows it in place of the surface name. The card is read from
`<target endpoint>/.well-known/agent-card.json`, then `/.well-known/agent.json`, or from
the target origin plus the access point's `agent_card_path` when that is set. Surfaces of
other protocols, such as MCP, and targets with another scheme, such as `fabric://`, are
never looked up.

Lookups are cached per surface for 300 seconds and are re-read when the target endpoint
or card path changes, with a 5-second timeout for each card URL tried. The dashboard
never waits: until its first lookup finishes, and whenever the card has no valid `name`,
a row shows the surface name. When the card cannot be read (unreachable, blocked by
egress policy, a non-success status, an oversized body, or a non-JSON body), the row keeps
the last name read from the same target and card path, and the next lookup is retried
after the cache period; with no earlier name, it shows the surface name.

The card name is self-asserted by the target and never verified. The target is trusted
to serve traffic, not to choose what the gateway's Issuer signs, so the card name never
reaches the VC, Trust Recorder context, or trust-registry reference fields, and card
lookups never sit on the request path. A name conflict shows no name, whatever the card
says.

The agent identity VC carries the surface name as `credentialSubject.name` on both the
legacy and SSI paths. VCs are signed on each issuance, so the next VC after a surface
rename carries the new name under the same DID.

### Trust registry reference fields

The gateway publishes names as trust-registry reference fields
([`reference_fields.rs`](../src/trust_registries/reference_fields.rs)), never by
rewriting trust records:

| Trigger | Fields published |
| --- | --- |
| Issuer create, retry, or edit | Entity field for the Issuer DID, authority field for its Authority |
| Authority edit | Authority field, to every registry an Issuer of that Authority uses |
| Surface rename | Entity field for each managed DID of the surface, to each Trust Recorder registry |
| Trust Recorder | Entity field for the agent DID; authority field for each record's authority (an Authority, else an Issuer with that DID); entity field for an Issuer DID used as a record's entity |

An Authority or Issuer is either global or owned by one tenant, and an owned one is named
only within its tenant.
An Issuer publishes its Authority's name only when that Authority is global or in the
Issuer's tenant. The Trust Recorder names an Authority or Issuer only when it is global
or in the surface's tenant; a surface without a tenant names only global ones. A DID
that fails this check gets no reference field, but its records are still written, so
external DIDs keep working.

Each publish sends `create-reference-field`. On the problem-report code
`e.p.msg.conflict` it sends `update-reference-field`, and on a second conflict it
resends the update once. Any other error is logged and retried on the next trigger.
A reference field is shared by every writer for its type and id, so gateways that
publish different names for the same Authority overwrite each other, and the last write
wins. Fields are not create-only, so renaming an Authority or Issuer updates the name
in every registry that already holds it.
Successful publishes are cached per registry, field type, and id, so an unchanged name
is not re-sent. Publishing runs in the background and never delays or fails an HTTP
response, record creation, forwarding, or a TRQP query.

### External callers

Caller names appear only in the dashboard
([`caller_names.rs`](../src/observability/caller_names.rs)) and never override a
managed agent's name. They are resolved in the background, cached for 300 seconds, in
this order:

1. A verified agent name: a `host/@local` entry in the caller's `alsoKnownAs` that the
   DID resolver verifies back to the same DID. At most four entries are tried. Their
   egress controls are in [`POLICY.md`](POLICY.md#agent-name-resolution).
2. The `name` of the caller's Agent Card, which is not verified. The card is found through a
   DID-document service of type `AgentCard` or `A2AAgentCard`, or whose id ends in
   `#agent-card`. It is fetched under the strict egress policy with a 5-second timeout
   and a 64 KiB limit.
3. The DID.

Until the first lookup for a DID finishes, the dashboard row carries
`display_name_pending` and shows "resolving…". A finished lookup that found no name, or
that failed, shows the DID alone and is retried after the cache period.

## Related

- [`POLICY.md`](POLICY.md): how a derived DID is graded and exposed to OPA.
- [`FABRIC.md`](FABRIC.md): attribution rules on the fabric receive path.
- [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md): management-plane tokens, which are a separate concern.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md): where these stages sit in the request path.
