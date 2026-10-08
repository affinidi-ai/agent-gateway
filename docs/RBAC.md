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
Resource and tenant constraints are separate authorization dimensions; they do not change the
shape of the RBAC permissions response.

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
intersection. A token created without feature scopes reports the owner's full role. Some routes
authorize on the owner's role only and never read the token's feature scopes, so a token is limited
there only by its owner's role: user management (`/v1/users`), settings writes, `sign-jwt`, backup
and restore, and storage export. For those routes the map can show `false` for a feature the route
still accepts. Resource patterns limit which resource ids a token can reach, not which features it
holds, so they do not change the map: a resource-scoped token is still refused on unscoped writes
even when the map says `true`. The response carries `Cache-Control: no-store` and
`Vary: Authorization, Cookie` because its body depends on the caller's credential, which arrives in
the `Authorization` header or the `session_token` cookie.

[`get_permissions`](../src/auth_manager/permissions.rs) defines the frontend-exposed key set. It is
not an enumeration of every backend `Feature`: route-only capabilities can be enforced without
appearing in this response. The response currently also includes `departments.*` aliases for legacy
dashboard compatibility; new UI uses `issuers.*`.

## Token info endpoint

`GET /v1/token-info` (served as `GET /api/v1/token-info`) reports the credential making the call, so a
client can validate a bearer token and show who it is acting as. It takes no parameters and only reads
the identity the session-auth middleware already resolved, so a caller can only inspect its own
credential. It accepts a session token or an `agpat_` personal access token, sent as
`Authorization: Bearer` or in the `session_token` cookie (the header wins when both are present). A
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

## Payments admin API

The x402 (`/api/admin/x402/...`) and MPP (`/api/admin/mpp/...`) admin routers require
`payments.view` on every route. The x402 delete routes (`transactions/{id}`, `verifications/{id}`,
`settlements/{id}`) additionally require `payments.delete`. When no auth backend is configured,
both routers deny every request instead of serving unauthenticated. The built-in defaults grant
`payments.view` and `payments.retry` to `poweruser` and `payments.edit` / `payments.delete` to
`administrator`; the base `user` role holds no payments permission.

## Governance Audit integrations

The integration routes require `integrations.view` / `integrations.edit` / `integrations.delete`
at the route. An integration in the `audit` category also requires `audit.view`, checked in the
handler against the same role and PAT scopes (`RbacGuard::allows`): without it the integration is
omitted from lists, reads return 404, and create, edit, delete and manual trigger return 403.
Without an authenticated caller or RBAC guard, audit integrations are always refused.
`gateways.edit` alone cannot reach one either: connection points and gateways cannot link an
audit integration, and event triggers refuse to publish to one.
See [`OBSERVABILITY.md`](OBSERVABILITY.md#governance-audit-forwarding).

## Frontend use

The dashboard stores the map in its permissions context and checks the exact feature key before
rendering an operation. Adding a management feature therefore requires both backend route
enforcement and, when the dashboard uses it, inclusion in the permissions response. The backend
check remains authoritative even if a client ignores the UI gate.

OPA policy evaluation is a data-plane concern rather than management RBAC.
