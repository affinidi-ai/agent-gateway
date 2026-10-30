# Credential Delegation

How the gateway lets a managed agent call a third-party API with credentials the agent
never holds. For a user-facing flow, the credentials belong to the human the agent acts
for, and are obtained with that person's consent.

Use the hosted [per-caller credential delegation guide](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/how-to-guides/setup/configure-per-caller-credential-delegation/)
for the operator procedure. This page documents the implementation in
[`src/credential_providers/`](../src/credential_providers/),
[`src/delegation_vault/`](../src/delegation_vault/), and
[`src/proxy/credential_delegation.rs`](../src/proxy/credential_delegation.rs).

## Moving parts

| Part | What it is |
| --- | --- |
| Credential provider | A configured OAuth 2.0 or API-key provider, such as Google or GitHub. Defined once and referenced by any number of surfaces. |
| Outbound credential binding | An entry in a surface's `outbound_credentials` naming a provider, the scopes, when it applies, and how the token is injected. |
| Delegation vault | Where obtained tokens are kept, one per agent, user, and provider. |
| Delegation audit log | A record of every lookup, consent prompt, refresh, and injection. |

## Credential providers

`CredentialProvider` ([`src/credential_providers/mod.rs`](../src/credential_providers/mod.rs))
has four types, set by `provider_type`.

| Type | Flow | Consent |
| --- | --- | --- |
| `oauth2_authorization_code` | Three-legged OAuth. The user signs in to the provider and approves the scopes. | Required, per user |
| `oauth2_client_credentials` | Two-legged, machine to machine. The gateway authenticates as the client. | None |
| `oauth2_jwt_bearer` | RFC 7523 JWT bearer grant. The gateway signs an assertion with its own key and exchanges it for a token, as Google service accounts require. | None |
| `api_key` | A static key resolved from the secrets store. No OAuth. | None |

A provider carries its authorization and token endpoints and its default scopes. Its
client ID and client secret are **references** into the secrets store, such as
`GOOGLE_CLIENT_SECRET`, and are never stored in the provider record itself.

The shared decisions (whether a type may serve a use, whether it sends the gateway's own
credential, and how Target Authentication and modern delegation obtain the credential) match on
`CredentialProviderType::grant()`: `UserConsent` (authorization code), `GatewayToken` (client
credentials and JWT bearer) or `StaticKey` (API key).

### JWT bearer providers

An `oauth2_jwt_bearer` provider holds its assertion settings under `jwt_bearer`.

```json
{
  "provider_type": "oauth2_jwt_bearer",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "default_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
  "jwt_bearer": {
    "assertion_issuer": "agent@project.iam.gserviceaccount.com",
    "assertion_subject": "agent@project.iam.gserviceaccount.com",
    "signing_key_secret_ref": "VERTEX_SA_KEY",
    "signing_algorithm": "RS256",
    "key_id": "1a2b3c"
  }
}
```

| Field | Meaning |
| --- | --- |
| `assertion_issuer` | The assertion `iss`. Required. |
| `assertion_subject` | The assertion `sub`. Optional: when absent the assertion carries no `sub` claim. A blank value is refused at save, so omit the field to send no `sub`. Set it for an authorization server that requires `sub` (RFC 7523 section 3), such as Ory Hydra. Google service account grants need none. |
| `audience` | The assertion `aud`. Optional, defaults to the provider's `token_endpoint`. Surrounding whitespace is trimmed and a blank value means unset. When set it must be 1 to 512 bytes with no whitespace or control characters; any URI or identifier is accepted, not only `https`. |
| `signing_key_secret_ref` | The `secret_id` of a secrets-store entry holding the private key. Required. |
| `signing_algorithm` | `RS256` (default) or `ES256`. |
| `key_id` | The `kid` header. Defaults to the `private_key_id` of a Google service account key; omitted when neither is set. |

The signing key secret holds either a PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----`;
RSA of 2048 to 8192 bits for `RS256`, P-256 for `ES256`) or a Google service account JSON
key, whose `private_key` is used. The secret is at most 16 KiB. The key is parsed when the
provider is saved, so a malformed key or one that does not match `signing_algorithm` is
refused with 400. It is never stored in the provider record, returned by the API or
logged; the gateway reads it from the secrets store for each grant, holds the key text in
zeroizing memory, signs one assertion with `ring`, and drops it. The secrets store is encrypted at
rest only when at-rest encryption is enabled, so enable it on any appliance that holds a
signing key. The AWS Secrets Manager backend is not implemented and cannot hold the key.

Each grant signs a fresh assertion with these claims:

| Claim | Value |
| --- | --- |
| `iss` | `assertion_issuer` |
| `sub` | `assertion_subject`, present only when it is set |
| `aud` | `audience` when set, else the provider's `token_endpoint` with surrounding whitespace removed |
| `iat` | 30 seconds in the past, to allow for clock skew at the authorization server |
| `exp` | 300 seconds after signing, so at most 330 seconds after `iat` |
| `jti` | A random UUID |
| `scope` | The requested scopes, space-separated, when there are any |

A change of `audience` changes the provider digest, so a gateway token cached for the old
audience is never reused. A provider stored without an audience keeps signing with `aud` equal
to the token endpoint. Provider listings include `audience` in the JWT bearer summary when it
is set.

In the dashboard, a new JWT Bearer provider with an empty Token Endpoint is prefilled with
Google's `https://oauth2.googleapis.com/token`, with a hint that other servers use their own.
The field stays editable, and neither the prefill nor the hint applies to an existing
provider. The optional Audience field defaults to the token endpoint.

The request posts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the
`assertion`, repeats the scopes as the `scope` form parameter, and sends the provider's
`resource`, when set, as the `resource` form parameter. `client_id_secret_ref`
and `client_secret_secret_ref` are optional: when both are set the client authenticates
with HTTP Basic (Ory Hydra requires it), when only the client ID is set it is sent as
`client_id`, and when neither is set no client authentication is sent (Google). A client
secret without a client ID is refused at save.

The `token_endpoint` of every OAuth provider (authorization code, Client Credentials and JWT
bearer) must be an `https` URL. The check runs when a provider is created and on any update that sends `token_endpoint`,
changes the type, clears a reference or sends `jwt_bearer` (every dashboard save does), so a
stored authorization code provider with an http token endpoint is refused on any dashboard
save until its endpoint is https. It also runs before every gateway grant, and before the authorization
code exchange, the legacy and modern refresh, and the modern consent exchange, each before any secret
is read. Under `AG_TEST_MODE=true` an
`http` endpoint listed exactly in `AG_BDD_OAUTH_ENDPOINT_ALLOWLIST` is also accepted, for
a local authorization server.

Every secret a provider of any type references (its client ID, client secret, API key,
and a JWT bearer provider's signing key) must belong to the provider's own tenant: an
appliance-wide provider uses appliance-wide secrets, and a tenant provider uses that
tenant's secrets. A reference to another tenant's secret, or from a tenant provider to an
appliance-wide secret, is refused at save and when the provider or the secret is moved to
another tenant. The same check runs each time a provider reads a secret, for every grant and
for API keys, so a provider stored before the rule, or edited on disk, fails at use instead
of sending another tenant's or an appliance-wide secret.

### Gateway grants

Client Credentials and JWT bearer tokens are gateway tokens: the gateway obtains them for
its own identity, with no user. Both grants are sent by `request_gateway_grant`
([`src/delegation_vault/gateway_token.rs`](../src/delegation_vault/gateway_token.rs))
through the shared `GATEWAY_GRANT_BACKOFF`, for legacy and modern delegation alike.

- The connection is pinned to the addresses the token endpoint resolved to when it was
  checked, redirects are off, and the whole grant, secret reads and assertion signing
  included, times out after 10 seconds. A token
  endpoint that resolves to loopback, an unspecified address or cloud metadata is never
  contacted.
- The response is read to at most 64 KiB in zeroizing memory; a larger declared length is
  refused unread.
- The response must have `token_type` `Bearer` and an `access_token` of at most 8 KiB of
  printable characters. A refresh token is dropped. A missing `expires_in` counts as 300
  seconds, and a longer one than 86,400 seconds is capped.
- The client secret and every secret the grant uses must belong to the provider's tenant.
  Creating or updating such a provider with another tenant's or an appliance-wide secret
  is refused with `Secret reference is not accessible`, and a stored provider that still
  references one fails as `forbidden` before anything is sent.
- A failure is reported as a fixed category: `unsupported`, `secret_unavailable`,
  `forbidden`, `unavailable`, `invalid_response` or `assertion_failed` (the JWT bearer signing
  key could not be parsed or the assertion could not be signed). The token endpoint's response body is
  never logged, returned or recorded; the log line carries the HTTP status and, when the
  body names one, the standard OAuth error code such as `invalid_grant`.
- A gateway grant is refused as `scope_mismatch`, a further fixed category, when the token
  endpoint's response carries a `scope` that lacks a requested scope. Both sides are split on
  whitespace and compared as sets of exact strings, so a configured entry such as
  `openid profile` counts as two scopes (modern MCP delegation does not accept a binding scope
  that contains whitespace), and a response without `scope` is taken to grant the requested
  scopes (RFC 6749 section 5.1). A refused grant is never cached and starts the retry
  backoff, in `GATEWAY_GRANT_BACKOFF` and in the gateway token cache, like a token endpoint
  failure. Like any failed grant, a refused refresh keeps a cached token that is still valid;
  with none, Target Authentication fails with `502 Target authentication failed`, a legacy
  delegation binding is unavailable, and modern MCP delegation answers 503
  `MCP credential service unavailable`. Modern MCP delegation also refuses a response whose
  `scope` adds a scope the binding did not request, with 403
  `MCP credential authorization denied`, and stores nothing; legacy delegation and Target
  Authentication accept such a response.
- After a token endpoint failure (unreachable, refused, timed out or an invalid response),
  `GATEWAY_GRANT_BACKOFF` holds back further grants for that provider record and scope set for 1
  second, doubling to at most 60 seconds, counted from when the failed grant completes. A grant
  inside that wait fails as `unavailable` without a request, on the legacy and the modern path.
  Requests on these paths are not serialised, so concurrent requests each send a grant, but
  grants that fail in the same window count as one failure. A success clears the backoff, and a
  slower failure from a grant sent before it is ignored. A local failure (a missing or
  cross-tenant secret, a blocked endpoint, or a signing key that cannot sign) starts no backoff
  and is reported as itself on every request.
- Legacy delegation renews a cached gateway token before it expires (see
  [Delegation vault](#delegation-vault)). Modern MCP delegation reuses its cached gateway token until it
  expires and then sends a new grant.

The authorization code exchange and the refresh of a user's token in the consent flow, and
the refresh of a modern delegated credential, use the same pinned, redirect-off client and
the same 64 KiB limit. A failure there names only
the HTTP status; the provider's response body is not logged or shown to the user.

## Target Authentication through a provider

A surface's Target Authentication can use a provider instead of a static secret, so the
gateway sends its own credential to the managed agent, on calls and on the agent card fetch:

```json
"auth": {
  "method": { "credential_provider": {
    "credential_provider_id": "<credential provider id>",
    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
    "inject_as": { "type": "bearer_header" } } },
  "fallback": "reject"
}
```

`credential_provider_id` is the provider record's `id`. `scopes` defaults to the provider's
`default_scopes`. `inject_as` is `bearer_header` (the default) or `custom_header`; `meta` is
refused, and a custom header may not be `Host`, `Content-Length`, `Transfer-Encoding` or
`Connection`.

| Provider type | Credential sent |
| --- | --- |
| `oauth2_client_credentials`, `oauth2_jwt_bearer` | A gateway token from the gateway token cache |
| `api_key` | The key, read from the secrets store per request |
| `oauth2_authorization_code` | Refused: it needs a user's consent |

Saving the surface is refused with 400 unless all of these hold, on the surface and on every
variant:

- The Target endpoint is `https`. `http`, `fabric://`, `proxy://` and `a2a-proxy://` Targets
  are refused; on a Fabric route only the receiving gateway, whose Target is `https`, holds the
  provider. Under `AG_TEST_MODE=true` an `http` Target whose origin is an origin-only entry of
  `AG_BDD_EGRESS_ALLOWLIST` is also accepted.
- The Access Point authenticates its callers (caller authentication with at least one method,
  or MCP resource authorization), so the gateway token is never sent on behalf of an anonymous
  caller.
- The provider belongs to the surface's tenant (an appliance-wide surface uses an
  appliance-wide provider) and its type is allowed above.
- No Transit Point uses `credential_provider`; Transit Points keep `transit_credentials`.

The same rules are checked again on every request, so a record edited on disk fails closed.
`TargetCredentialResolver` ([`src/proxy/target_credentials.rs`](../src/proxy/target_credentials.rs))
resolves Target Authentication for every method at every call site, in this order:

1. `credential_lookup` injects nothing.
2. The leg and the injection shape must allow the method: `credential_provider` works only on
   the call to an `https` Target and on its card fetch, never on a Fabric forward, an MCP
   proxy target or a Transit Point.
3. A caller the gateway did not authenticate gets no credential, and the request is forwarded
   without it. For `credential_provider` this includes any caller on a surface that does not
   authenticate its callers. The gateway's own agent card fetch is not affected, but only a
   `GET` to exactly one of the surface's agent card URLs, query included, counts as that
   fetch. Any other public discovery read, such as a path ending in `/discovery` or
   `/.well-known/ucp`, skips caller authentication and so never carries the credential,
   locally or over Fabric.
4. On the call to an `http(s)` Target, the credential, whatever the method, is attached only
   when the upstream URL stays on the Target endpoint's origin and under its base path (as
   the URL parser resolves it and as lenient routers resolve `%2e`, `%2f`, `\` and `;`), or
   is one of the surface's agent card URLs. A request whose path climbs out is answered 502.
5. For `credential_provider`: the `https` Target rule, then the header rule under
   [Precedence](#precedence-with-delegated-credentials), then the provider and its tenant and
   type, then the token. For `static_secret`: the header rule (an occupied header withholds the
   credential and forwards the request), then the secret and its tenant. A `static_secret`
   secret must belong to the surface's tenant (an appliance-wide surface uses an
   appliance-wide secret), because the gateway sends its value to an endpoint the surface's
   owner chose. Saving a surface that names any other secret is refused with 400, and such a
   secret found at use is answered 502 whatever the fallback, unless the header is already set.

| Failure | `fallback: reject` | `fallback: passthrough` |
| --- | --- | --- |
| Secret or provider missing, token unavailable (grant failed, timed out, or backing off) | 502 | Forwarded without the credential |
| Provider or secret outside the surface's tenant, non-`https` Target, path outside the Target base, header conflict, unsupported type, leg or header | 502 | 502 |

Every 502 carries the fixed body `Target authentication failed`. The Target Authentication log
line carries only the category and the surface ID; a failed grant's log line adds the provider
ID, the HTTP status and the standard OAuth error code. Each failed Target Authentication grant
also logs one `Gateway grant failed` warning (target `credential_delegation`) with
`provider_id`, `grant`, `category` and `stale_token_kept` (whether a still-valid cached token is
used instead). A request held back by the retry backoff sends nothing and logs `Gateway grant
held back by the retry backoff` at debug level with `provider_id` and `grant`.

### Precedence with delegated credentials

Target Authentication is the gateway's own identity and applies to every request it sends to the
Target; an `outbound_credentials` binding carries one caller's authority on that caller's
forwarded calls. A request carries at most one credential under a header name, compared without
regard to case (`bearer_header` writes `Authorization`):

| Situation | Save | Request |
| --- | --- | --- |
| `credential_provider` and a binding write the same header | 400, whatever the binding's `required_for` | A record loaded from disk fails the call with `HeaderConflict` (502 whatever the fallback, audit detail `target_auth_header_conflict`); neither credential replaces the other |
| `static_secret` and a binding write the same header | Saved; the collision is logged | The delegated credential is sent and the Target secret is not |
| Card fetch | n/a | Only Target Authentication applies; delegation never runs on it |

The Target credential replaces a caller header of the same name rather than being sent next to it.
A Transit Point forward, over HTTP or Fabric, sends a delegated credential, legacy or modern, in
place of a `static_secret` under the same name, and never forwards a managed agent's header of
that name; see [Credential headers on a Transit Point](#credential-headers-on-a-transit-point).
On a sending gateway's direct Fabric leg a modern delegated credential takes the place of a
same-name `static_secret`, whose secret is then not read.
On the receiving gateway of a Fabric route a header that arrived in the `ForwardRequest` counts as
a delegated credential; see [Target authentication over Fabric](FABRIC.md#target-authentication-over-fabric).
An operator who needs both credentials on one surface uses a `custom_header` for one of them.

A delegated credential that cannot be written as a valid header, or into the MCP `_meta` field,
is never skipped: the request is answered 500 with a fixed detail such as
`Invalid delegated credential header`, on Access Points, a sending gateway's Fabric leg and the
receiving gateway alike. A Transit Point refuses it, including duplicate modern delegated headers,
with `503` as described in [When a credential cannot be resolved](#when-a-credential-cannot-be-resolved).

The gateway's own agent card reads that attach Target Authentication are the card route behind
`/.well-known/agent-card.json` and the receiving gateway's policy context, both through
[`src/proxy/target_card.rs`](../src/proxy/target_card.rs). The Transit Point's card read for its
target-leg Trust Check, the managed agent name the dashboard shows, and the caller name read from a
caller's DID document send no Target credential, so a protected card yields no card or name there.

The [Agent card preview](SOURCE_AUTH.md#agent-card-preview) reads the card through the card
route's own path, so it presents the same Target credential as the gateway, with the same
fallback, and writes the same Target Authentication audit events, except that a refused
credential records no rejected request, because no caller is answered. It reports the credential
provider's name and, for a gateway token, the token's expiry, never the token, the provider id or
a secret id. It takes the token from the shared gateway token cache exactly as a caller's card
request would: a refresh never forces a new token.

### Gateway token cache

Target Authentication tokens are held per replica in memory
(`GatewayTokenCache`, [`src/delegation_vault/gateway_token.rs`](../src/delegation_vault/gateway_token.rs)),
never in the delegation vault. They are not listed by the vault API, not written to disk, and
not counted towards the `credentials` licence umbrella (`credentials.tokens` counts vault
records only).

- **Key.** Purpose, provider ID, a digest of the whole provider record, the sorted scopes,
  and the provider's `resource`. No caller or agent DID is part of it, so the card fetch and
  every caller share one token, and any provider edit starts a new key.
- **Lifetime.** `expires_in`, capped at 86,400 seconds, or 300 seconds when absent. Refresh
  starts 300 seconds before expiry, or halfway through a shorter life.
- **Single-flight.** At most one grant per key is in flight on a replica. Requests that find
  no valid token wait for it; while a valid token is being refreshed, other requests keep
  using it. The first request for a key, and each refresh, waits for the grant (at most 10
  seconds).
- **Failure.** A failed refresh keeps the still-valid token. Retries after a token endpoint
  failure (unreachable, refused, timed out or an invalid response) back off from 1 second to at
  most 60 seconds per key, counted from when the failed grant completes, including any wait for
  the key's grant; with no valid token inside that window the request fails as token unavailable
  without a grant. A local failure (a missing or cross-tenant secret, or a signing key that cannot
  sign) starts no backoff and is reported as itself on every request.
- **Bounds.** At most 4,096 keys; a key unused for 24 hours is dropped.
- **Invalidation.** Updating, deleting or moving a secret to another tenant drops the entries
  minted from it; updating, deleting or moving a provider drops its entries; an
  appliance-wide `POST /v1/config/reload` (by a caller with no tenant context) and Standby to
  Active activation drop every entry. A grant already in flight finishes for the requests
  waiting on it but is never cached. Each event reaches only the replica that handled it;
  another replica keeps its token until its own reload, restart or the token's expiry. After
  a compromise, rotate the secret, revoke the token at the authorization server, and reload
  every replica.

A provider that a surface's Target Authentication uses cannot be deleted, and cannot be
changed to a type that use does not allow; both answer 409.

`PUT /api/v1/credential-providers/{id}` keeps the stored value of every field the request
leaves out. Sending `null` clears an optional reference: `client_id_secret_ref`,
`client_secret_secret_ref`, `api_key_secret_ref`, `callback_url`, `resource` or
`consent_identity_strategy_id`. Sending `null` for `authorization_endpoint` or `description`
clears them the same way, and an absent field keeps the stored value. `additional_params`
is replaced as a whole, so `{}` clears it. A cleared reference is checked against the provider type, so
clearing one the type requires answers 400. The dashboard sends `null` for the client fields
of a JWT bearer provider when they are emptied, and the next grant then sends no client
authentication. Every update drops the provider's cached gateway token.

A secret that a provider references can be deleted: `DELETE /api/v1/secrets/{id}` answers 204
and the provider keeps its reference, so its next grant fails as `secret_unavailable` until the
secret is created again under the same Secret ID or the provider points at another one. The
dashboard asks first, in the Secrets list and in the secret editor. It reads each provider (the
provider list leaves secret references out) and, when any reference the secret
(`client_id_secret_ref`, `client_secret_secret_ref`, `api_key_secret_ref` or the JWT Bearer
`signing_key_secret_ref`), names them in a warning with **Delete secret anyway**. A secret no
provider references is deleted without a warning. When the providers cannot be read, the warning
says it could not check which providers reference the secret, and still offers the delete. A role
without `credential_providers.view` cannot read the providers and is not warned. Surfaces, A2A proxies and STS clients that reference
a secret are not checked.

Each resolution through a provider that injects a credential or fails emits a delegation audit
event: `token_injected` with
detail `target_auth_fresh`, `target_auth_cached`, `target_auth_stale` (refresh failed and the
kept token was still valid when the failed grant ended) or `target_auth_api_key`, or `token_not_found` with detail
`target_auth_<category>`, such as `target_auth_outside_target_base`. It carries the provider,
surface, scopes, injection shape, `via_fabric` and trace ID, and never a user hash, agent DID,
token ID or token. A resolution that withholds the credential from a caller emits none.

## Binding a provider to a surface

Each entry in `AgentSurface.outbound_credentials`
([`OutboundCredentialBinding`](../src/config/types.rs)) decides four things.

| Field | Options | Default |
| --- | --- | --- |
| `required_for` | `all` outbound requests, or `tools`: a list of MCP tool names, matched against `params.name` of a `tools/call` on Access Points and Fabric receive, never on Transit Points | `all` |
| `consent_mode` | `on_demand`, `pre_authorize`, or `elicit` | `on_demand` |
| `inject_as` | `bearer_header`, `custom_header { name, format }`, or `meta { field }` | `bearer_header` |
| `scopes` | Scopes to request | The provider's defaults |

`custom_header` takes a format string, so a provider that expects `token {value}` rather
than `Bearer {value}` still works. `meta` writes the token into a JSON-RPC `_meta` field
instead of a header.

A binding carries no destination, so where it applies depends on the hop.

- **Access Points and Fabric receive** forward only to their own Target, so a `tools`
  binding applies to a `tools/call` whose `params.name` it lists.
- **Transit Points** never apply a `tools` binding. A partner upstream names its own tools,
  so matching its tool names would hand it a credential meant for the Target's tools. A
  `tools` binding that lists a JSON-RPC method, such as `tools/call` or `message/send`,
  does not apply there either.

A binding to an `api_key`, `oauth2_client_credentials` or `oauth2_jwt_bearer` provider sends
the gateway's own credential: the operator's key, or a token granted with the provider's client
secret or signing key. Such a provider must belong to the surface's tenant (an appliance-wide
surface uses an appliance-wide provider), so a tenant cannot carry an appliance-wide credential
to a Target or partner it chose. An `oauth2_authorization_code` provider injects the consenting
user's token and may be appliance-wide for a tenant surface. The rule is checked by
`CredentialProvider::usable_by` ([`src/credential_providers/mod.rs`](../src/credential_providers/mod.rs)):

- Saving a surface that breaks it is refused with 400.
- Moving the surface or the provider to another tenant, or changing a provider bound by a
  surface of another tenant to a type that sends the gateway's credential, is refused with 409.
- Each request checks it again, on Access Points, Transit Points and Fabric receive, so a
  record stored before the rule or edited on disk sends nothing and requests no token. Legacy
  resolution refuses the request with 503, outcome `provider_unavailable` and detail
  `provider_forbidden`, as it does for a binding whose provider no longer exists; modern
  preparation refuses the request as a binding mismatch.

An `all` binding in `outbound_credentials` applies on every Transit Point of the surface, so
every partner upstream behind them receives the delegated credential; use it only when every
Transit Point's upstream should hold the credential. A surface with no `outbound_credentials`
applies each Transit Point's own `transit_credentials` on that Transit Point only. A surface
with `outbound_credentials` ignores `transit_credentials`.

A binding to an `oauth2_jwt_bearer` provider also needs what `credential_provider` Target
Authentication needs: the surface must authenticate its callers, and every leg the binding
reaches must be https (the Target and every Transit Point for `outbound_credentials`, and a
point's own Transit Point for its `transit_credentials`). Saving a surface that breaks this is
refused with 400, checked on the base surface and every variant, and changing a bound provider
to `oauth2_jwt_bearer` where it would break is refused with 409. Each request checks the rule
again for the leg it is on, so a record edited on disk never sends the gateway's token on such a
leg: on the HTTP Target leg the upstream URL must also stay under the Target base, and a
sending gateway's `fabric://` leg always fails it. Legacy resolution, on Access Points, Transit
Points and Fabric receive, refuses the request with 503, outcome `provider_unavailable` and
detail `jwt_bearer_leg_forbidden`, and never forwards it without that credential. Modern MCP
delegation refuses the request with 403 `MCP credential authorization denied`. API key
bindings are not subject to this rule.

A binding to an `oauth2_client_credentials` provider is refused on a plain http leg too:
saving a surface whose Target, or a Transit Point the binding reaches, is plain http is refused
with 400, and each request checks the leg again (`permits_client_credentials_leg`). Only plain
http is refused: https, `fabric://` (encrypted by DIDComm) and proxy routes whose upstream is
configured elsewhere are unaffected. Under `AG_TEST_MODE` an http origin named in the test
egress allowlist counts as https. Legacy resolution refuses the request with 503, outcome
`provider_unavailable` and detail `client_credentials_leg_forbidden`; modern MCP delegation
refuses it with 403. Retyping a bound provider to Client Credentials is refused with 409 when it would
break a leg. The caller-authentication and Target-base conditions apply to `oauth2_jwt_bearer` bindings only.

### Credential headers on a Transit Point

A Transit Point sends its target at most one value of each credential header, by the same
rule over HTTP and Fabric. It starts from the managed agent's headers, without the agent's
`Authorization` and `Cookie` and without a header named like the Transit Point's
`target_auth` header, whether or not the gateway adds that header to this request. It then
adds the `target_auth` header, and then the `bearer_header` and `custom_header` credentials of
its bindings, each replacing any earlier header of the same name. On a `2026-07-28` MCP
request, the credentials prepared for `outbound_credentials` are applied last in the same
way. So the managed agent can neither supply nor replace a credential, and a delegated
credential under the same name as `target_auth` replaces it; give them different names to
send both.

## When a token is missing

Delegation needs a user to key the token by, so a surface with delegation but no
authenticated source identity rejects the request with HTTP 403 `identity-required`. For an
authenticated caller, the consent mode decides what happens the first time.

| Mode | Behaviour |
| --- | --- |
| `on_demand` | The request fails with HTTP 401 and an `application/problem+json` `consent_required` body carrying the authorization URL. The caller has to interpret this payload itself; it is not the MCP elicitation mechanism. |
| `pre_authorize` | The session is refused at bind or `initialize` time until every binding's token already exists. After that, runtime traffic never sees a consent prompt. |
| `elicit` | Spec-compliant MCP elicitation. The gateway sends `elicitation/create` back over the open Streamable HTTP or SSE stream, with the authorization URL in the message, and waits up to `elicit_timeout_secs` (300 by default) for the user to finish or decline. Accepted risk: the stream and the pending prompt are keyed by surface and `Mcp-Session-Id`, not bound to the caller, so within one surface a caller holding another user's session id can receive that user's authorization URL, or answer or cancel their prompt. Isolation relies on the upstream issuing unguessable session ids; see "MCP session ownership" under Recorded Decisions in `docs/MCP_METADATA.md`. |

`elicit` needs an MCP client that advertised the `elicitation` capability during
`initialize`, and a capability record for its session. `elicit_fallback` decides
what happens when either is missing: `on_demand`, the default, degrades to the 401
response, and `fail` records `elicitation_unsupported` and forwards the tool call without
the credential. Elicit falls back when:

- the client did not advertise `elicitation`;
- the upstream returned a session id already in use on the surface (see "MCP session
  ownership" in `docs/MCP_METADATA.md`);
- the gateway has no capability record for the session, because the upstream answered
  `initialize` with SSE, sent an unusable `Mcp-Session-Id`, or the gateway restarted
  after the session opened.

A user who declines or cancels the elicitation, or does not answer before
`elicit_timeout_secs`, also has the call forwarded without it.

### When a credential cannot be resolved

A binding that applies but whose credential cannot be resolved refuses the request rather
than forwarding it without the credential. That covers a deleted or unreadable provider, an
API key whose secret cannot be read, a failed client-credentials or JWT bearer grant that
leaves no valid token to send (legacy delegation sends a still-valid cached token instead; see
[Delegation vault](#delegation-vault)), a vault read error, and consent that is needed but cannot be asked for because no authorization URL can be
built, for example when the provider has no `authorization_endpoint`. An Access Point and
Fabric receive answer `503`: on an MCP surface a JSON-RPC error (`-32603`, `Delegated
credentials unavailable`) carrying the request's id, otherwise an `application/problem+json`
body. The delegation audit records the binding's outcome, and `provider_unavailable` names a
provider that cannot be used.

A Transit Point refuses such a request with `503`, and also refuses with `403` one whose
transit token carries no caller identity, including every request to a Transit Point that sets
`require_transit_token: false` (a valid transit token sent there names the caller to policy
only, not to delegation), or for which neither its managed identity nor the transit
token's caller DID gives the agent half of the vault key. It also refuses when its delegation
stores are not available. An MCP Transit Point answers with a JSON-RPC error (`-32603` for
`503`, `-32001` for `403`) carrying the request's id, and any other Transit Point with an
`application/problem+json` body. A missing token still gets the consent answer above. A
Transit Point forwards a `GET` of a public discovery path, such as an agent card, without
checking a transit token, so it carries no caller, and it is forwarded without a delegated
credential, as it is without the `target_auth` one.

Outside these checks a request is still forwarded without the credential: on an Access Point
or Fabric receive whose delegation stores are not available, on Fabric receive for a request
with no user identity, and on the `elicit` outcomes above. A binding whose provider is outside
the surface's tenant (`provider_forbidden`), or that would send an `oauth2_jwt_bearer` token on
a leg that may not carry it (`jwt_bearer_leg_forbidden` or `client_credentials_leg_forbidden`), is refused like a deleted provider
(see [Binding a provider to a surface](#binding-a-provider-to-a-surface)).

A grant is looked up by the managed agent's DID, the caller's identity hash and the provider,
not by surface or Transit Point. Surfaces that share an agent DID, such as surfaces whose
managed identity is derived from the same JWT claim, therefore release to each other the
grants a user consented to on either. A Transit Point never looks a grant up under a
placeholder agent.

## Across Fabric

When a surface's Target or Transit Point is `fabric://`, its delegated credential reaches the peer
only if that Target or Transit Point opts in with `fabric_delegated_credentials: true`. The setting
is off by default, including on existing surfaces. With it off, the caller's own token is still
stripped and the peer receives no delegated credential.

With it on, the access token, never the refresh token, crosses to the peer, which can use it until
it expires. On the Target only a modern (`2026-07-28`) request carries it, inside the encrypted
framed stream; a legacy MCP or A2A request never does. On a Transit Point, every protocol carries
it, including A2A through header injection. A Transit Point on a surface without `outbound_credentials` uses only its own
`transit_credentials`, never another Transit Point's, whatever its destination. The surface's
Target uses only `outbound_credentials`, never a Transit Point's `transit_credentials`. Consent, refresh
and revocation stay on the sending gateway. See
[Delegated credentials over Fabric](FABRIC.md#delegated-credentials-over-fabric).

## Consent flow

For an authorization-code provider in `on_demand` mode:

```mermaid
sequenceDiagram
    participant A as Agent
    participant G as Agent Gateway
    participant U as User's browser
    participant P as OAuth provider
    participant API as Third-party API
    A->>G: Outbound request
    Note over G: Vault lookup for this agent,<br/>user, and provider: none found
    G-->>A: 401 consent_required, with the authorization URL
    U->>P: Sign in and approve the scopes
    P->>G: Redirect to the OAuth callback with a code
    Note over G: Check the state, exchange the code<br/>with the PKCE verifier, store the token
    A->>G: Retry
    Note over G: Vault lookup: found
    G->>API: Request with the injected token
    API-->>G: Response
    G-->>A: Response
```

The authorization URL uses PKCE with the `S256` challenge method. The `state` parameter is
an `OAuthState` carrying the agent DID, the user identity hash, the surface, the provider,
a random nonce, an expiry, and the PKCE code verifier. The callback therefore needs no
server-side session to know which request it completes.

`state` is always sealed with AES-256-GCM before it is base64url-encoded, so neither the
provider nor anyone else who sees the authorization URL can read it (the PKCE code verifier
included) or forge one naming a different agent or user. When encryption at rest is
enabled, its key seals the state; otherwise a key derived from `AG_IDENTITY_HASH_PEPPER`
does, so gateways that share the pepper can open each other's states. The callback refuses
a `state` this gateway did not seal, an expired one, and one whose nonce was already used
([`encode_oauth_state`, `decode_oauth_state`, `claim_oauth_state`](../src/delegation_vault/oauth.rs)).
Used nonces are remembered in the gateway process for 15 minutes, longer than a state
lives, so a restart or a different gateway instance does not know about them. A state is
used up only when its credential is stored, so a callback that fails before then, for
example at the token exchange, can be retried with the same state.

The callback lands on `/v1/identity/oauth/callback` unless `gateway.json` sets
`oauth_callback_route`. On success the gateway stores the
token and issues a `DelegationCredential`, a verifiable credential recording the
delegation chain, kept with the token as `delegation_vc`.

## Delegation vault

A `DelegationToken` ([`src/delegation_vault/mod.rs`](../src/delegation_vault/mod.rs)) is
keyed by three values.

| Key | Source |
| --- | --- |
| `agent_did` | The managed agent the delegation is for |
| `user_identity_hash` | The caller's [identity hash](#the-callers-identity-hash), from the identity source authentication established |
| `credential_provider_id` | The provider |

With API-key or mTLS source authentication, every caller presenting the same key or
certificate identity therefore shares one set of delegated tokens.

### The caller's identity hash

`user_identity_hash` is the lowercase hex SHA-256 of the JSON array
`[method, issuer, tenant, subject]`, written as RFC 8785 canonical JSON (no spaces):

| Source authentication | `method` | `issuer` | `subject` |
| --- | --- | --- | --- |
| `jwt_bearer`, and a resource access token | `jwt_bearer` | The token's `iss` | The token's `sub` |
| `api_key` | `api_key` | `""` | The `secret_id` |
| `api_key_provider` | `api_key_provider` | The API Key Provider agent id | The key's id |
| `did_auth` | `did_auth` | `""` | The DID |
| `mtls` | `mtls` | The lowercase hex SHA-256 of the certificate the client certificate was verified against: the configured CA certificate its chain ends at, or with pinned trust the pinned certificate | The principal the `identity_binding` derives |

`tenant` is the surface's `tenant_id`, or `null` on a surface with none. The same subject named
by another method, issuer, API Key Provider agent or tenant is therefore another caller, with
grants of its own. An mTLS caller is keyed by the certificate the gateway trusted, not by the
issuer name its certificate states, so replacing a trusted CA certificate, or a pinned
certificate, gives its callers new identity hashes. A JWT without a non-empty `sub`, or without an `iss`, names no caller: it has
no identity hash, so it is given no delegated credential: an Access Point answers `403`
`identity-required`, and a Transit Point `403`.

The transit token carries the same value, a policy reads it as
`input.transit.caller.user_identity_hash`, and a Workload Binding with `caller_source: did`
puts it in `user_hash`. To compute it for a JWT subject `alice` from
`https://login.example.com` on a surface with no tenant:

```sh
printf '%s' '["jwt_bearer","https://login.example.com",null,"alice"]' | shasum -a 256
```

Gateway tokens (client credentials and JWT bearer) have no user. Legacy delegation caches them
under the user hash `__client_credentials__:<hex SHA-256 of the provider digest and the sorted,
deduplicated scope set joined by spaces>`, so bindings with different scopes on one provider, or a
token granted before the provider was edited, never share a token.
After an upgrade each binding sends one new grant. Records under the old bare
`__client_credentials__` key are no longer read. Nothing removes expired vault records, so
they stay on disk and in the Credential Tokens list until an operator deletes them with
`DELETE /api/v1/delegation-vault/by-user/__client_credentials__`, which touches only the
records stored under that exact key. Modern MCP delegation caches them under
`__mcp_client_credentials__:<hex provider digest>`.

A lookup has four outcomes.

| Result | What the gateway does |
| --- | --- |
| Found and valid | Injects the token |
| Expired, with a refresh token | Refreshes it through the provider's token endpoint |
| Expired, no refresh token | Treats it as missing and applies the consent mode |
| Not found | Applies the consent mode |

For legacy gateway tokens a new grant starts `min(300 s, lifetime / 2)` before expiry, where the
lifetime runs from the time the current token was granted, so a short-lived token is
renewed halfway through its life rather than on every request. If that grant fails while
the cached token is still valid, the cached token is injected and the audit detail ends in
`_stale`. A cached token with no recorded expiry is renewed on its next use and is never
injected when that grant fails. A failed grant that leaves no valid token refuses the request;
see [When a credential cannot be resolved](#when-a-credential-cannot-be-resolved). A cached token granted before the provider was last
edited is never used, not even as a `_stale` fallback, so a changed subject, issuer, key,
token endpoint or scope set takes effect on the next request. Grants are not coalesced:
requests that reach the refresh point together can each send a grant, and the last token
stored is the one reused. The audit detail names the grant and the outcome, for example
`jwt_bearer_cached`, `client_credentials_fresh` or `jwt_bearer_unavailable`. Modern MCP
delegation reuses its cached gateway token only until it expires, then sends a new grant, with
no `_stale` fallback.

A cached gateway token records each secret its grant read (the client id and secret, or the JWT
bearer signing key and any client id and secret it sends) with that secret's last-change time
as read. The token is served, on the legacy and the modern path, only while each of those
secrets still exists in the provider's tenant with exactly that last-change time. Updating,
deleting or moving such a secret to another tenant therefore stops every cached token whose
grant read it, for every scope set, including the `_stale` fallback after a failed refresh;
moving the secret back is a further change and does not revive them. A grant that read a secret
just before it changed recorded the earlier time, so its token is not served afterwards, and
neither is a token when an older copy of the secret is restored. Changes to other secrets,
including a secret the provider references but its grant does not read, keep the cached tokens.
Each cache hit reads those secrets from the secrets store to compare their last-change times.
A gateway token stored before secret versions were recorded is never served: the next use sends a new grant.

### Storage

The vault uses **uncached** storage: tokens are read from disk on each lookup and are not
held in the in-memory cache, so they do not linger in process memory.

The vault is encrypted at rest **only when at-rest encryption is enabled** in the
bootstrap configuration (`[encryption] enabled = true`), because it uses the global
storage configuration like every other store. The default is off. With the default,
access and refresh tokens are written to `_storage/` as plaintext JSON. Enable encryption
at rest on any appliance that holds real user tokens. See
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md#configtoml).

## Downgrading

Earlier releases cannot read `credential_provider` Target Authentication or a credential
provider of type `oauth2_jwt_bearer`:

- On filesystem storage, a surface whose Target Authentication, or a variant's, is
  `credential_provider` is skipped at load, so its route stops answering. On DynamoDB
  storage its Target Authentication is read as none, and requests are forwarded to the
  Target without the credential.
- An `oauth2_jwt_bearer` provider is skipped at load, so every binding to it refuses its
  requests with `503` as for a deleted provider.

Before downgrading, switch those surfaces to `static_secret` or remove their Target
Authentication, then remove the bindings to `oauth2_jwt_bearer` providers and delete or
replace the providers; or restore a backup taken before the upgrade. Find them through the
management API, which reads either store: in `GET /api/v1/surfaces`, a `credential_provider`
key under `target.auth.method` on a surface or a variant, and in
`GET /api/v1/credential-providers`, a `provider_type` of `oauth2_jwt_bearer`. The gateway
token cache is not persisted, so it leaves nothing behind. The caller side has its own
rollback steps under [Required scopes](SOURCE_AUTH.md#required-scopes).

## Management API

| Route | Purpose |
| --- | --- |
| `GET /api/v1/delegation-vault` | List vault entries, as metadata only, without tokens |
| `GET`, `DELETE /api/v1/delegation-vault/{id}` | Read or revoke one entry |
| `DELETE /api/v1/delegation-vault/by-user/{user_hash}` | Revoke every delegation one user has granted |
| `GET /api/v1/delegation-audit` | The delegation audit log |

### Removing grants keyed by the old identity hash

Before the [identity hash](#the-callers-identity-hash) took the method, issuer and tenant, it
was the lowercase hex SHA-256 of the subject alone. A grant stored under that hash is never
found again: the user connects the account again, and the old entry stays in the vault, with
its refresh token, until it is revoked. Both hashes are 64 hex characters, so the vault list
does not show which entries are old. Entries under `__client_credentials__` are not affected.

For each user who connected an account before the upgrade, compute the old hash from the
subject (the JWT `sub`, the API key `secret_id` or key id, the DID, or the mTLS principal) and
revoke it:

```sh
OLD_HASH=$(printf '%s' 'alice' | shasum -a 256 | cut -d' ' -f1)
curl -X DELETE "$GATEWAY/api/v1/delegation-vault/by-user/$OLD_HASH" -H "Authorization: Bearer $TOKEN"
```

When the subjects are not known, list the vault and revoke by `id` every entry, other than
`__client_credentials__`, whose `created_at` is before the upgrade. Do this after every
instance runs the new release, as an instance still on the old one writes the old hash.

Credential providers have their own management routes in
[`src/credential_providers/router.rs`](../src/credential_providers/router.rs), gated on
the `credential_providers.*` permissions.

In the dashboard these live on the Credentials page, under the **Credential Providers**,
**Credential Tokens**, and **Credential Delegation Audit** tabs.

## Related

- [`SOURCE_AUTH.md`](SOURCE_AUTH.md): the source authentication that supplies the user identity.
- [`STS.md`](STS.md): token exchange, a different way of acting on a caller's behalf.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md): where outbound credentials sit in the request path.
