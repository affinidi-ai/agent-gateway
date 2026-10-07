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

[`get_permissions`](../src/auth_manager/permissions.rs) defines the frontend-exposed key set. It is
not an enumeration of every backend `Feature`: route-only capabilities can be enforced without
appearing in this response. The response currently also includes `departments.*` aliases for legacy
dashboard compatibility; new UI uses `issuers.*`.

## Token info endpoint

`GET /v1/token-info` (served as `GET /api/v1/token-info`) reports the credential making the call, so a
client can validate a bearer token and show who it is acting as. It takes no parameters and only reads
the identity the session-auth middleware already resolved, so a caller can only inspect its own
credential. It accepts either a session token or an `agpat_` personal access token as
`Authorization: Bearer`, and returns `401` without one or when the token is revoked. A PAT's
resource-scope headers (such as `x-external-account`) are not required or evaluated on this route,
but a PAT with a broad tenant selector still gets `403` when no trusted edge is configured. The
response is sent with `Cache-Control: no-store` and `Vary: Authorization`. The `scopes` list is
enforced only on feature-gated routes: a few routes authorize on the owner's role alone and ignore it.

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
