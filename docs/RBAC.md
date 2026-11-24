# Management API RBAC

Use the hosted [Agent Gateway reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/reference/)
for operator-facing authentication and authorization guidance. This page documents the management
authorization contract implemented by the checked-out source revision.

## Authorization model

Management API authorization uses named `Feature` values and role-to-feature assignments from
`RbacConfig`.

Protected routes apply `require_feature(...)`. The middleware resolves the authenticated user's role
and rejects a missing feature with `403 Forbidden`. Dashboard visibility checks are convenience and
defence in depth; they do not replace route enforcement.

Management PAT authorization further intersects the bound user's role with the PAT's feature scopes.
A PAT with explicit feature scopes is also refused with `403` by the authentication middleware on
any route none of its scopes covers, including routes a session reaches with no permission; deny is
the default, and [`route_scopes.rs`](../src/auth_manager/route_scopes.rs) lists the permissions that
cover each route. See [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md#feature-scopes). A new management route
needs an entry there as well as its `require_feature(...)`. Resource and tenant constraints are
separate authorization dimensions; they do not change the shape of the RBAC permissions response.

## Permissions endpoint

`GET /v1/permissions` returns a flat JSON object whose keys are dashboard feature names and whose
values are booleans:

```json
{
  "users.view": true,
  "gateways.edit": true,
  "surfaces.capture": true,
  "secrets.view": false,
  "sts_clients.edit": false
}
```

There is no `role` field, wrapper object, or granted-key array. The dashboard consumes this map
directly. The optional/public permission path returns the same shape with unavailable permissions
set to `false` when no authenticated user can be resolved.

For a session login the map reflects the user's role. When the caller authenticated with a personal
access token (`agpat_`), a key is `true` only when the owner's role grants the feature and the
token's feature scopes include it. This matches the feature-gated routes, which check the same
intersection. A token created without feature scopes reports the owner's full role. Routes whose
handler authorizes on the owner's role only (user management (`/v1/users`), settings writes,
`sign-jwt`, backup and restore, and storage export) also need the feature among the token's scopes,
which the authentication middleware checks, so the map matches them too. A token with explicit
scopes reaches this endpoint whatever its scopes. Resource patterns limit which resource ids a
token can reach, not which features it holds, so they do not change the map: a resource-scoped token is still refused on unscoped writes
even when the map says `true`. The response carries `Cache-Control: no-store` and
`Vary: Authorization, Cookie` because its body depends on the caller's credential, which arrives in
the `Authorization` header or the `__Host-session_token` cookie.

[`get_permissions`](../src/auth_manager/permissions.rs) defines the frontend-exposed key set. It is
not an enumeration of every backend `Feature`: route-only capabilities can be enforced without
appearing in this response. It carries no `departments.*` aliases: the RBAC loader normalises those
keys to `issuers.*`, so they are not valid access-token scopes.

## Token info endpoint

`GET /v1/token-info` (served as `GET /api/v1/token-info`) reports the credential making the call, so a
client can validate a bearer token and show who it is acting as. It takes no parameters and only reads
the identity the session-auth middleware already resolved, so a caller can only inspect its own
credential. It accepts a session token or an `agpat_` personal access token, sent as
`Authorization: Bearer` or in the `__Host-session_token` cookie (the header wins when both are present). A
PAT's resource-scope headers (such as `x-external-account`) are not required or evaluated on this
route. It returns `401` when the credential is missing, invalid or revoked, or its user is not
approved, and `403` when:

- the user, or the PAT's owner, has not accepted the current Terms and Conditions
  (`TERMS_ACCEPTANCE_REQUIRED`)
- the PAT has a broad tenant selector and no trusted edge is configured

The response is sent with `Cache-Control: no-store` and `Vary: Authorization, Cookie`.

```json
{ "user_id": "user-1", "token_id": "agat_...", "scopes": ["gateways.view", "secrets.view"] }
```

For a session login, `token_id` and `scopes` are `null` and the caller holds its full role. For a
personal access token, `token_id` is the token record ID and `scopes` is the list of feature scopes it
was issued, or `null` when it is not scope-restricted. It never returns the token secret or hash.

## Agent card preview

`GET /v1/surfaces/{id}/agent-card` needs `surfaces.view` and `POST
/v1/surfaces/{id}/agent-card/refresh` needs `surfaces.edit`, as the refresh changes nothing but
always fetches. Both make the gateway fetch the agent's card with the surface's Target
Authentication, so a `surfaces.view` holder can cause a credentialed fetch; each fetch is audited
(`agent_card.preview_fetch`) and limited per user and per surface to a burst of 10, then one every 6 seconds. A tenant token
gets `operator_only` instead of a fetch on an appliance-wide surface. See
[`PROTOCOLS.md`](PROTOCOLS.md#agent-card-preview).

## Agents API

`GET /v1/agents`, `GET /v1/agents/{id}` and `GET /v1/agents/{id}/agent-card` are read-only and
need `surfaces.view`. They group only the surfaces in the caller's tenant and PAT resource scope,
return `404` for an agent id outside it, and are not served when no auth backend is configured.
`GET /v1/agents` and `GET /v1/agents/{id}` return `target_name` on each agent, the name of the A2A proxy or remote gateway the
agent's endpoint names, and `null` for a URL endpoint, a missing record or another tenant's record.
`GET /v1/agents/{id}` returns each surface's `public_url`, the first external URL of the listener
its Access Point runs on plus its route, or `null` when no listener with an external URL matches.
`GET /v1/agents/{id}/agent-card` returns the card the gateway serves for the agent, read through
the agent card preview of its first running A2A or AP2 surface, or of the one `?surface_id=` names
(`404` with `"code": "surface_unavailable"` when it is not one of `card_surface_ids` or isn't
running on this gateway; an agent outside the caller's scope is a plain `404`), with `source` naming how the
gateway obtains it: `fetched` (a URL Target's card, rewritten), `generated` (by an A2A proxy) or
`remote_gateway` (served over Fabric). It also returns `surface_id` (the surface read through),
`card_surface_ids` (the surfaces the caller may read the card through, also on `not_running`) and
`upstream_card`, the card before this gateway rewrote it, reduced to the same Agent Card fields
(absent for a generated card, or when that card is not an Agent Card). The read is audited and rate limited as a preview read, and
answers `429` past the limits without an earlier preview. Only the card's A2A Agent Card fields are
returned, and no card or a body that is not an Agent Card is a `502`. A read whose fetch failed or
whose card the gateway refuses to serve is also a `502`, never the preview's last good card; a
card served without an identity credential is returned. When no `?surface_id=` is given and none
of the agent's surfaces runs on this gateway, the answer is `available: false` with
`not_running`. A tenant's
token sees the agents of appliance-wide surfaces, but the card is read only through a surface of
its own tenant: when only an appliance-wide surface could reach it, the answer is
`available: false` with `operator_only` and nothing is fetched, as in the preview. See
[`POLICY.md`](POLICY.md) for the egress rules it follows.

## Payments admin API

The x402 (`/api/admin/x402/...`) and MPP (`/api/admin/mpp/...`) admin routers require
`payments.view` on every route. The x402 delete routes (`transactions/{id}`, `verifications/{id}`,
`settlements/{id}`) additionally require `payments.delete`. When no auth backend is configured,
both routers deny every request instead of serving unauthenticated. The built-in defaults grant
`payments.view` and `payments.retry` to `poweruser` and `payments.edit` / `payments.delete` to
`administrator`; the base `user` role holds no payments permission.

The delegated payment ledger routes `GET /api/admin/payments`, `GET /api/admin/payments/{id}`,
`GET /api/admin/payments/summary`, `GET /api/admin/payments/breakers/{payment_gateway_id}` and
`GET /api/admin/payments/audit` (the `payment` records of the VP Audit Log, without their signed
credential) also require `payments.view`, and deny every request when no auth backend is configured. A
tenant-scoped caller sees only the rows of its own tenant's surfaces: a row recorded for an
operator's surface or another tenant's is left out of the list, its `{id}` returns `404`, and
no case status is asked for it, because a row names the resource, the transaction and the case
of someone else's payer. An operator caller, with no tenant, sees every row. A resource-scoped
token sees only the rows of the surfaces its scope allows. The summary counts only those rows; a
tenant caller or scoped token reads a breaker only for a payment gateway one of them names, and
an audit record only for a surface one of them belongs to (records of other surfaces are for
operator callers). Each row records one payment gate call and is kept for
`payment_ledger.retention_days` (seven by default) in `payments_ledger/`, beside the MPP transaction store (`_storage/payments_ledger/` by
default), as append-only hourly segment files; the list serves the newest 50,000 rows. The detail
of a held payment adds the live `case_status` agent-pay reports for its case, for a caller who
may read the row. See [Taking the payment](CONFIGURATION_REFERENCE.md#taking-the-payment).

## Gateways and payment gateways

A remote gateway is either a peer (`role: "peer"`) or a payment gateway (`role: "payment"`,
agent-pay). The two are managed by separate permissions and separate routes, so `gateways.*`
never reaches a payment gateway and `payment_gateways.*` never reaches a peer:

| Routes | Permissions |
| --- | --- |
| `/v1/gateways`, `/v1/gateways/{id}/…`, `/v1/gateways/{gateway_id}/connection-points`, `/v1/connection-points/…` | `gateways.view` / `gateways.edit` / `gateways.delete` |
| `/v1/payment-gateways`, `/v1/payment-gateways/connect-via-oob`, `/v1/payment-gateways/{id}` (get, put, delete), `/v1/payment-gateways/{id}/ping`, `…/surfaces`, `…/surfaces/{surface_id}/payment-manifest`, `…/info` | `payment_gateways.view` / `payment_gateways.edit` / `payment_gateways.delete` |
| `GET /v1/gateways/payment-providers` (the Surface Builder's payment gateway list) and `GET /v1/gateways/payment-logos/{sha256}` (payment method logos) | `payment_gateways.view` |
| `POST /v1/gateways/{id}/payment-role` (turn a peer into a payment gateway) | `gateways.edit` and `payment_gateways.edit` |

A route answers `404` for a gateway of the other role
([`role_scope.rs`](../src/gateways/role_scope.rs)), and `/v1/connection-points/…` answers `404`
for, and never lists, a payment gateway's connection points, so they can't be deleted, disabled or
reconnected there; both checks run after the permission check, so a caller
without the permission learns nothing about which ids exist. The built-in defaults grant
`payment_gateways.view` to `user` and `payment_gateways.edit` / `payment_gateways.delete` to
`administrator`. A token's resource scope treats both as `gateways` resources.

## Maintenance and welcome routes

`POST /v1/logs/truncate` removes the rotated `agent-gateway*.log*` files and keeps the current
`agent-gateway.log`; `POST /v1/metrics/truncate` drops stored metrics older than the retention
period. Both need `settings.edit`. Without an auth backend neither route is registered.

`GET /v1/logs/download` returns the server log files as one ZIP archive and needs `audit.view`.
The logs hold every tenant's detail, so it also refuses, with `403`, any PAT scoped by a tenant, a
resource pattern or required headers alone (see
[`ACCESS_TOKENS.md`](ACCESS_TOKENS.md#what-tenancy-does-not-partition)). A failed download
answers a fixed error body and logs the detail.

`GET` and `PUT /v1/notifications/user-welcome-template` read and change the notification a user
receives when their account is approved, and `POST /v1/notifications/send-welcome` sends a
notification with the given title and text to the user named in the request. All three need
`users.approve` and, without an auth backend, refuse every request with `403`.

The built-in defaults grant `settings.edit` and `users.approve` to `administrator` only. A personal
access token with feature scopes needs the permission among its scopes; one created without scopes
follows its owner's role. The other `/v1/notifications` routes act on the caller's own
notifications and need only a session (see
[`INTEGRATIONS.md`](INTEGRATIONS.md#in-dashboard-notifications)); a token with feature scopes is
refused on them with `403` whatever its scopes.

## Dashboard log lines

Log lines from the gateway log file need `logs.view`, checked against the caller's role and, for a
personal access token, its feature scopes ([`dashboard.rs`](../src/observability/dashboard.rs)).
The log holds every tenant's lines, the per-call credential delegation events among them, so the
two routes below also give them only to an appliance-wide caller: a session, or a PAT with
neither a resource pattern nor required headers. A tenant's PAT, and one scoped by a resource
pattern or by required headers alone, is answered as a caller without `logs.view` is, `logs.view`
or not, so it reads none of the per-call credential delegation events, which are written to this
log only (see [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md#what-tenancy-does-not-partition)):

- `GET /v1/dashboard/delta` leaves out `changes.logs`, and `GET /v1/dashboard/stats` returns an
  empty `proxy_info.log_entries`, without reading the log file.
- A dashboard WebSocket connection drops the `logs` section of each `DashboardDelta` and every
  `LogEntry` update. It checks its session, without extending it, and its user's role and status
  when it connects and again on each keep-alive ping (every 30 seconds), so an open connection
  keeps receiving log lines for up to 30 seconds after its session ends (logout, expiry or
  revocation) or its user loses `logs.view` or is no longer Approved.

A caller that cannot be checked gets no log lines: a request or connection without an RBAC guard
(no auth backend), an unknown user, a user who is not Approved, a failed user lookup, or an
unauthenticated WebSocket (`websocket_require_auth` off). The built-in defaults grant `logs.view`
to `user`.

## Integrations

Every route under `/v1/integrations` needs one of `integrations.view` (lists, reads and the
catalog), `integrations.edit` (creates, changes and test sends) or `integrations.delete`, and
refuses every request without an RBAC guard ([`api/mod.rs`](../src/integrations/api/mod.rs)). No
other permission is checked. The built-in defaults grant `integrations.view` to `user` and
`integrations.edit` / `integrations.delete` to `administrator`.

### Governance Audit integrations

All events are handled the same. An event set holding audit events, an integration delivering
them and its endpoint are listed, read, created, changed, deleted and test-sent under the same
`integrations.*` permissions as any other definition; no integration route checks `audit.view`.
`audit.view` guards the audit records themselves (the Audit page, the delegation-audit API and
the log download), not where they are forwarded.

This relaxes the previous release, in which a caller without `audit.view` did not see audit
integrations (lists left them out and reads answered `404`) and could not change them. As a
result:

- Every holder of `integrations.view` sees every endpoint's destination, the Governance Audit
  one included: webhook URLs, Kafka brokers and topics, SMTP hosts and recipients. Secret
  fields, such as a Slack webhook URL, are never returned. With the default roles that is every
  `user`.
- Holding `integrations.edit` means deciding where audit records go: it can put audit events in
  an event set and deliver them to any endpoint. Grant it with that in mind.

`gateways.edit` alone cannot reach one: integrations are not linked from gateways or connection
points, and audit events reach them only through the audit journal.
See [`OBSERVABILITY.md`](OBSERVABILITY.md#governance-audit-forwarding).

### Secrets in endpoints

`integrations.edit` can use, and therefore read, every appliance-wide secret. An endpoint's
secret field can hold a `$SECRET:<secret_id>` reference, which the gateway resolves itself when it
sends, so no `secrets.*` permission is checked. Creating an endpoint that holds a reference, or
changing the destination of one that already does, then sending a test delivers the secret's
value to a host the caller chooses. Grant `integrations.edit` only to roles that may read
secrets. The built-in defaults keep `integrations.edit` and `secrets.*` administrator-only.
Tenant-owned secrets never resolve for endpoints. A per-secret permission to use a secret without
reading it is not available yet. See
[`INTEGRATIONS.md`](INTEGRATIONS.md#endpoints-event-sets-and-integrations).

## Frontend use

The dashboard stores the map in its permissions context and checks the exact feature key before
rendering an operation. Adding a management feature therefore requires both backend route
enforcement and, when the dashboard uses it, inclusion in the permissions response. The backend
check remains authoritative even if a client ignores the UI gate.

OPA policy evaluation is a data-plane concern rather than management RBAC.
