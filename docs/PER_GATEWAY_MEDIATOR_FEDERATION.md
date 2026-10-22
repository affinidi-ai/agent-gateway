# Per-gateway mediators

By default two connected gateways share one mediator: the acceptor homes its
connection point on the inviter's mediator. A gateway can instead home its side
of a connection on its **own** mediator (GW1 on M1, GW2 on M2). Traffic then
flows `GW1 → M1 → M2 → GW2`, relayed between the mediators by **mediator
federation**, the mediator-to-mediator relay layer of
`affinidi-messaging-mediator` (§3, §6).

> **Status: experimental.** Choosing an acceptor mediator is behind the
> `mediator_federation` feature flag, off by default (§7). A connection made
> with one becomes Active, but requests between gateways on different mediators
> are not relayed: the relay scenarios in
> `tests/features/g2g/mediator_federation.feature` are tagged `@known-bug`.

---

## 1. How a connection point is bound to a mediator

Two records drive gateway-to-gateway connections:

- **`Mediator`** ([src/mediators/types.rs](../src/mediators/types.rs)): a
  registered mediator. It holds the mediator's `did` and the gateway's own
  identity on that mediator, `our_did` and `our_secrets`.
  A record created from a [mediator directory](INTEGRATIONS.md#mediator-directory)
  entry has `provided: true` and does not count toward the mediator limit. A mediator the operator stored for the same DID is a separate row.
- **`GatewayConnectionPoint`** ([src/gateways/connection_points/types.rs](../src/gateways/connection_points/types.rs)):
  holds a `mediator_id` and its own `connection_point_did`. The DID's
  `DIDCommMessaging` service endpoint is the mediator's URL, so anyone who
  resolves the connection point DID learns which mediator fronts it. A
  connection point created through `POST /v1/connection-points` also stores the
  mediator's DID as `mediator_did` (persisted and returned by the API), so the
  [event hook](INTEGRATIONS.md#event-hook) can still name the mediator on
  `connection_point.deleted` after the mediator record is removed. Records
  created earlier, or by other paths, may not have it.

The OOB handshake:

1. The **inviter** creates a connection point on its own mediator and publishes
   an OOB invitation URL that embeds that mediator's endpoint.
2. The **acceptor** reads the inviter's mediator from the URL and runs the
   handshake there, with temporary DIDs on that mediator.
3. Each side sends the other its permanent connection point DID (`channel_did`)
   and starts a listener on the mediator that DID names.

Neither handshake message carries a mediator field. Each side learns the
other's mediator by resolving the `channel_did` it received, so the wire format
is the same whichever mediators are involved.

Connection point DIDs take the mediator's endpoint from its stored DID document
when the gateway has one (`resolve_mediator_endpoint` in
[src/gateways/connection_points/handlers.rs](../src/gateways/connection_points/handlers.rs)),
and otherwise derive it from the mediator's `did:web`.

---

## 2. Shared mediator (the default)

Without an acceptor mediator (§5), the acceptor homes both its temporary and
permanent DIDs on the inviter's mediator (`connect_via_oob` in
[src/gateways/handlers.rs](../src/gateways/handlers.rs)). The inviter always
homes its permanent connection point on its own mediator
([src/gateways/approve.rs](../src/gateways/approve.rs)). Both connection point
DIDs therefore name one mediator, which delivers locally.

---

## 3. What the mediator layer provides

Mediator federation is described in
[`affinidi-messaging-mediator/docs/multi-mediator.md`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).
Gateways use its **single forward** shape (§1b):

```text
GW1 ──▶ M1 ─── POST /inbound ───▶ M2 ──▶ GW2
   forward to=M1, next=GW2-CP    authcrypt(GW1→GW2), verbatim
```

GW1 sends one `routing/2.0/forward` to M1 with `next` set to GW2's connection
point DID. M1 resolves that DID, sees that M2 fronts it, and relays the inner
envelope to M2's `/inbound`. M2 delivers it to GW2.

[`cross_mediator_forwarding.rs`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs)
is a runnable two-mediator demo. Pass it mediator **DIDs**, not URLs.

---

## 4. How a send is routed

Affinidi's mediator routes on the cleartext addressee of what reaches
`/inbound`
([mediation-and-routing.md](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/mediation-and-routing.md)).
A message addressed straight to a recipient is a direct delivery, refused with
`direct_delivery.recipient.unknown` (error 72) unless the recipient has an
account on that mediator. Only a `routing/2.0/forward` addressed to the
mediator itself is relayed.

`pack_and_send_message` ([src/comm/didcomm/client.rs](../src/comm/didcomm/client.rs))
therefore chooses the route for each send (`forward_target`):

- It resolves the recipient's DID and reads its `DIDCommMessaging` service
  endpoint.
- If that endpoint names a different mediator from the sender's own, the
  packed message is wrapped in a forward addressed to the sender's own mediator,
  with `next` set to the recipient.
- If it names the sender's mediator, or the route cannot be told (no service,
  no mediator on the profile, an unresolvable DID), the message is sent
  directly.

A service endpoint that is a DID is compared with the sender's mediator DID,
ignoring a trailing `:.well-known`. A URL is compared by host and port with
every endpoint the sender's mediator is known by: its REST endpoint, the service
endpoints in its DID document, and the origin derived from its `did:web`. Two
mediators on the same host and port are treated as one. A forward is logged at
`info`.

The route follows the connection, not the feature flag. Shared-mediator
connections are always sent directly, and a connection homed on another
mediator is always forwarded, including after the flag is turned off and on an
inviter that never turned it on.

Every `pack_and_send_message` caller is routed this way, including the
`fabric://` send leg (`forward_via_fabric` in
[src/proxy/fabric_forward.rs](../src/proxy/fabric_forward.rs)) and the primary
and retry forwards in [src/proxy/handler.rs](../src/proxy/handler.rs). Fabric
stream frames
([src/proxy/fabric_stream/transport.rs](../src/proxy/fabric_stream/transport.rs))
and the x402 facilitator
([src/x402/gateway_facilitator_service.rs](../src/x402/gateway_facilitator_service.rs))
always send directly, so they do not reach a gateway on another mediator.

---

## 5. Choosing the acceptor's mediator

The handshake stays on the inviter's mediator. Only each side's **permanent**
connection point moves.

1. `connect-via-oob` takes an optional `acceptor_mediator_id`
   ([src/gateways/handlers.rs](../src/gateways/handlers.rs)). It must name a
   `Mediator` within the caller's tenant and token scope that the new gateway's
   tenant may reference (its own tenant's or a global mediator; a global
   gateway may use only global mediators), that is `Active` and registered
   (`our_did` and `our_secrets` set), or the request gets `400` before any
   outbound call. An unknown mediator and one outside the caller's
   scope get the same response; a disabled and an unregistered one get one
   generic response.
2. The acceptor's permanent DID is minted on the selected mediator. Its
   temporary handshake DID stays on the inviter's mediator.
3. The inviter's permanent connection point is unchanged: it is always on the
   inviter's own mediator.
4. The acceptor's finalize step (`finalize_oob_connection_as_acceptor` in
   [src/gateways/connection_points/ws_listener.rs](../src/gateways/connection_points/ws_listener.rs))
   takes the mediator from the pending connection, so the stored `mediator_id`
   and the listener it starts agree. The temporary connection point records the
   same mediator and its record id, so recovery after the pending connection is
   lost rebuilds the acceptor's choice. The permanent connection point stores
   that record id as its `mediator_id`, so finalize, recovery and its listener
   read only that record, never a mediator found by DID. Finalize, like
   recovery, refuses to finish if that record is gone, carries another DID or is
   no longer `Active`. Recovery onto a mediator other
   than the temporary connection point's own requires that record to be
   `Active` with the same DID, and fails without it or without a store. A
   shared-mediator connection reads no mediator record.

Disabling a mediator stops it from being selected for a new connection and from
being used by recovery. Connection points already homed on it keep running.

With `did:peer` connection point DIDs, the relaying mediator resolves the peer's
DID without an HTTP call. With `did:web` or `did:webvh`, each gateway's DID
documents must be served at its public domain so the peer's mediator can read
them.

---

## 6. Mediator configuration

Each mediator is an independent mediator with its own DID, backend and config,
not a cluster member. The full reference is
[`multi-mediator.md` §5–§6](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).
For gateways, each mediator needs at least:

- `[processors.forwarding]` with forwarding and `external_forwarding` enabled,
  the same `relay_mode` on both mediators, and `relay_trusted_mediators` listing
  the peer mediator DIDs.
- `[security] enable_inter_mediator_relay = "true"` and
  `local_direct_delivery_allowed = "true"`.
- A `global_acl_default` that adds `SEND_FORWARDED` and `RECEIVE_FORWARDED` to
  the shipped default and keeps the message bits its own gateways need, for
  example `DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,RECEIVE_FORWARDED`.
- `[server] local_endpoints` listing every public URL in the mediator's own DID
  document. Without it, a mediator behind a proxy treats its own URL as
  external and relays messages to itself.

Validate the two mediators on their own with `cross_mediator_forwarding`
(§3) before connecting gateways.

---

## 7. Gateway setup

- Register M1 on GW1 and M2 on GW2 as `Mediator` records, each pointing at that
  mediator's public URL.
- Turn on `mediator_federation` under **Settings › System › Feature Flags** on
  the acceptor. While it is off, `connect-via-oob` refuses
  `acceptor_mediator_id` with `400`. While it is on, the **Connect via OOB**
  wizard shows a mediator picker listing the gateway's active, registered
  mediators. The inviter does not need the flag.
- Connect: GW1 issues the invitation, and GW2 accepts it with M2 selected.
  Leaving the picker on its default keeps the shared mediator (§2).

---

## 8. Troubleshooting mediator relay

| Symptom | Cause | Fix |
|---|---|---|
| Sender gets `200`, peer never receives, no relay in logs | The next hop was classified as local | Look for the mediator's "Storing locally" warning; check that the connection point DID names the peer's mediator |
| Message loops back | Public hostname differs from the bind address | Set `server.local_endpoints` to every public URL |
| `401` on `/inbound` at the receiver | The receiver does not accept relays | `enable_inter_mediator_relay = "true"` |
| error 60 `authorization.send_forwarded` at the receiver | Its default ACL lacks `SEND_FORWARDED` | Add it to `global_acl_default` |
| error 58 `authorization.receive_forwarded` at the sender | Its default ACL lacks `RECEIVE_FORWARDED` | Add it to `global_acl_default` |
| error 71 `direct_delivery.denied` | A single-forward relay landed as direct delivery | `local_direct_delivery_allowed = "true"` on the receiver |
| error 60 `authorization.relay.untrusted_peer` | A `rewrap` peer is not allow-listed | Add the peer mediator's DID to `relay_trusted_mediators` |

The full table is in
[`multi-mediator.md` §10](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).
