# Agent Onboarding Capture

Use the hosted [surface Quickstart](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/get-started/create-first-surface/)
for the supported product workflow. This page documents the temporary capture endpoint's unusual
security and lifecycle boundaries in the checked-out source revision.

## Security boundary

An onboarding capture request explicitly bypasses:

- source authentication;
- rate limiting;
- Trust Check;
- gateway and surface OPA;
- payment handling; and
- Target or Fabric forwarding.

The endpoint must therefore be treated as an unauthenticated, temporary observation endpoint. Its
response is generated locally and does not prove that a permanent surface configuration will admit
or successfully forward the same request.

## Implementation contract

`POST /v1/onboard/create-temp-surface` creates a session for `a2a`, `ap2`, or `mcp` and requires the
surface-edit capability. The response contains the session `config_id`, a legacy `channel_name`
field, the endpoint URL, and `ttl_seconds`.

`DELETE /v1/onboard/delete-temp-channel/{config_id}` deletes the in-memory session and requires the
surface-delete capability. The route name retains `channel` as a legacy API identifier.

## Lifetime

The session TTL is read from the settings store as `onboarding_channel_ttl_seconds`; the setting
name is legacy. The current stored value is used directly. The onboarding handler does not apply a
minimum or maximum clamp.

Each session has a Tokio expiry task. If the task removes an existing session, it broadcasts
`WsUpdate::ChannelExpired`. Manual deletion removes the session but does not emit that expiry event.
Sessions are memory-only and disappear when the process stops.

## Capture event

After a valid session request is parsed and handled, the onboarding code emits only
`WsUpdate::PayloadCaptured`. It stores:

- the received payload;
- the locally generated response payload;
- validation status and any validation error;
- a derived schema when identity metadata is recognized; and
- `None` for outbound request and inbound response because no forwarding occurs.

`WsUpdate::OnboardingAttempt` exists in the enum but is not emitted. Consumers must use
`PayloadCaptured` for onboarding observations.

For MCP capture, identity metadata is read canonically from `params._meta`, with explicit legacy
top-level `_meta` compatibility in the onboarding responder. For normal MCP surface semantics, see
[Protocol Support](PROTOCOLS.md).

## Implementation

- [`src/identity/handlers/onboarding.rs`](../src/identity/handlers/onboarding.rs) owns session
  creation, expiry, deletion, protocol responders, and capture emission.
- [`src/identity/router.rs`](../src/identity/router.rs) registers session and management routes.
- [`src/server/websocket.rs`](../src/server/websocket.rs) defines the emitted event shapes.
