# Per-gateway mediator federation

Two federated gateways normally share one mediator: the acceptor homes its
connection point on the inviter's mediator. With per-gateway mediator
federation each gateway keeps its **own** mediator (GW1 on M1, GW2 on M2), and
traffic flows `GW1 → M1 → M2 → GW2`.

- **Mediator layer** (`affinidi-messaging-mediator`): relays between mediators
  (§3, §6).
- **Agent Gateway**: with the `mediator_federation` feature flag on,
  `connect-via-oob` takes an optional `acceptor_mediator_id`. When it is set,
  the acceptor homes its permanent connection point on that mediator instead of
  the inviter's (§5). When it is omitted, the acceptor uses the inviter's
  mediator (§2). With the flag off (the default), gateways behave as with a
  single shared mediator.

> **Status.** Selecting and validating `acceptor_mediator_id` has unit and BDD
> coverage, and a two-mediator connection reaches Active in the BDD harness.
> Request traffic between gateways on different mediators is not yet relayed:
> the two relay scenarios in `tests/features/g2g/mediator_federation.feature`
> stay `@known-bug`. Until they pass, treat `GW1 → M1 → M2 → GW2` as
> unverified end to end. This is why the whole feature is behind the
> `mediator_federation` feature flag, off by default (§7).

This document covers how the mediator/connection-point binding works, the
shared-mediator default, per-gateway mediator selection, and the Docker, proxy
and mediator-relay setup on both sides.

---

## 1. How Agent Gateway binds a mediator and a connection point

Two records drive G2G:

- **`Mediator`** ([src/mediators/types.rs](../src/mediators/types.rs)) — a
  registered mediator: its `did`, plus **`our_did` / `our_secrets`** (the
  gateway's own identity *on that mediator*).
- **`GatewayConnectionPoint`** ([src/gateways/connection_points/types.rs](../src/gateways/connection_points/types.rs))
  — carries a **`mediator_id`** and its own **`connection_point_did`** (distinct
  from the gateway DID). The DID's DIDComm **service endpoint is the mediator's
  URL**, so anyone resolving the CP DID learns which mediator fronts it.

The G2G handshake (OOB / out-of-band invitation):

1. **Inviter (GW1)** creates a connection point on **its** mediator (M1) and
   publishes an OOB invitation URL. The URL embeds M1's endpoint.
2. **Acceptor (GW2)** accepts the invitation. It extracts the **inviter's**
   mediator endpoint from the OOB URL and builds its own connection-point DIDs
   **on that same mediator (M1)**.
3. Both sides exchange permanent connection-point DIDs and start a WebSocket
   listener against **the shared mediator**.

Runtime send leg ([src/proxy/fabric_forward.rs](../src/proxy/fabric_forward.rs),
`forward_via_fabric`): to reach `fabric://{gateway_id}/{channel_id}`, GW1 takes
its listener's ATM client (connected to its own mediator) and
`pack_and_send_message(...)` to the remote gateway's CP DID.
When the `mediator_federation` flag is on, `pack_and_send_message`
([src/comm/didcomm/client.rs](../src/comm/didcomm/client.rs)) wraps the packed
message in a `routing/2.0/forward` addressed to the sender's **own** mediator
(naming the real recipient as `next`) whenever the sending profile has a
mediator, so the same call works whether the recipient is local to that
mediator or lives on a different one. With the flag off it sends the packed
message directly. See §5.3 for the sends that never go through it.

---

## 2. The shared-mediator default

When no acceptor mediator is selected (§5), the acceptor homes both its
temporary and permanent DIDs on the inviter's mediator:

**Acceptor side — [src/gateways/handlers.rs](../src/gateways/handlers.rs)** (the
`connect_via_oob` handler). It extracts the inviter's mediator from the OOB URL:

```rust
// Step 4: Extract inviter's mediator from OOB URL
let their_mediator_endpoint = req.oob_url.split("/oob").next()… ;
let their_mediator_did = fetch_mediator_did_from_url(&their_mediator_endpoint).await?;
```

…and, absent an `acceptor_mediator_id` (§5), builds **both** the temporary
handshake DID (Step 5) **and the permanent "secure" DID (Step 6)** on that
inviter mediator:

```rust
// Step 6: Create secure DID #2 (permanent connection)
let (secure_did, …) = generate_connection_point_identity(
    &secure_cp_id,
    &network_config.did.domain,
    …,
    &acceptor_mediator_endpoint,   // ← acceptor's own mediator (M2) when selected,
    did_method,                    //   else falls back to the inviter's (M1)
    …
)…;

// Step 7 stores the pending connection with the mediator the secure DID is
// homed on (acceptor's own when selected, else the inviter's):
mediator_did: acceptor_mediator_did.clone(),
```

**Inviter side — [src/gateways/approve.rs](../src/gateways/approve.rs)** (Step
4.5), when it mints the permanent gateway connection points, always uses its own
mediator:

```rust
// IMPORTANT: Use the SAME mediator as the OOB connection point
// Both sides of the connection MUST use the same mediator for the handshake to work!
let gw_mediator_did = mediator_did.clone();
```

The inviter always homes its permanent CP on its own mediator. The comment
refers to the temporary handshake, which must run on one mediator; it does not
constrain the acceptor's permanent CP.

---

## 3. What the mediator layer provides

Mediator federation is described in the authoritative
[`affinidi-messaging-mediator/docs/multi-mediator.md`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).
The flow you want is its **single forward** shape (§1b):

```text
GW1 ──▶ M1 ─── POST /inbound ───▶ M2 ──▶ GW2
   forward to=M1, next=GW2-CP    authcrypt(GW1→GW2), verbatim
```

GW1 sends one `forward` to M1 with `next = GW2's CP DID`. M1 resolves that DID,
sees it is mediated by M2, and relays the inner envelope to M2's `/inbound`. M2
delivers it to GW2. This is `GW1 → M1 → M2 → GW2`, and it is the envelope
`pack_and_send_message` produces (§5.3). With the shared-mediator default both
CP DIDs point at the same mediator (§2), so M1 delivers locally.

There is a runnable two-mediator demo at
[`affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs)
(pass mediator **DIDs**, not URLs) — use it to prove your two mediators relay
before wiring the gateways.

---

## 4. Summary

- **No mediator selected (§2):** both sides home on the inviter's mediator.
- **`acceptor_mediator_id` set on the connect request (§5):** the mediator
  layer (§3) relays between mediators, and each
  `GatewayConnectionPoint` already carries its own `mediator_id`, with its
  listener homed on that CP's mediator
  (`resolve_mediator_for_cp` in
  [src/gateways/connection_points/ws_listener.rs](../src/gateways/connection_points/ws_listener.rs)).

---

## 5. Per-gateway mediator selection

Goal: keep the **one-time handshake** on the inviter's mediator (it is a single
brief exchange between temporary DIDs), but home each side's **permanent**
connection point on **its own** mediator, so live `ForwardRequest` traffic goes
cross-mediator.

### 5.1 The mediator is discovered from the DID, not sent as a field

A common misconception is that the acceptor "sends its mediator (M2) back to the
inviter" as a field in the handshake. It does not — and it does not need to. The
OOB handshake exchanges exactly **one** value in each direction: a `channel_did`
(the sender's permanent connection-point DID).

- **`connection-setup` (GW2 → GW1)** — body is only
  `{ "channel_did": <GW2 secure DID>, "secret": … }`
  ([src/gateways/handlers.rs](../src/gateways/handlers.rs), Step 8); GW1 reads it
  as `acceptor_secure_did` (`process_connection_setup` in
  [src/gateways/connection_points/message_processor.rs](../src/gateways/connection_points/message_processor.rs)).
- **`connection-accepted` (GW1 → GW2)** — body is only
  `{ "channel_did": <GW1 gateway CP DID> }`
  ([src/gateways/approve.rs](../src/gateways/approve.rs), Step 5); GW2 reads it as
  `inviter_secure_did` (`process_connection_accepted`, same file as above).

Neither message carries a mediator field. The mediator is embedded **inside** the
exchanged DID as its DIDComm `service` endpoint when the DID is minted
(`generate_connection_point_identity_*` in
[src/gateways/connection_points/handlers.rs](../src/gateways/connection_points/handlers.rs)
— `did:peer` sets `PeerService { type_: "dm", endpoint: Uri(mediator_url) }`;
`did:web` writes the same endpoint into the DID document). So each side learns
the other's mediator **by resolving the `channel_did` it received** and reading
its service endpoint — automatically and symmetrically:

```text
GW2's channel_did ──resolve──▶ service endpoint = M2   (when acceptor_mediator_id is set)
GW1's channel_did ──resolve──▶ service endpoint = M1
```

**Consequence:** cross-mediator discovery uses **no** extra message field and
the handshake wire format is the same in both modes. The only difference is
*which mediator each side bakes into its permanent DID's service endpoint*
(§5.2).

### 5.2 Selection behaviour

1. **The acceptor may select its own mediator.** `ConnectViaOOBRequest` (POST to
   the OOB-connect endpoint) takes an optional `acceptor_mediator_id`
   ([src/gateways/handlers.rs](../src/gateways/handlers.rs), Step 4.5). When
   set, it must name an existing, **`Active`** `Mediator` record within the
   caller's tenant and token scope, with `our_did` / `our_secrets` already
   populated (register M2 on GW2 exactly like M1 is registered on GW1) —
   otherwise the request is rejected with `400`. An unknown mediator and one
   outside the caller's scope get the same response.
   Omitted, the acceptor falls back to the inviter's mediator (§2).
2. **The acceptor's *secure* DID is homed on the selected mediator.** Step 6
   generates `secure_did` with `acceptor_mediator_endpoint` (M2 when selected,
   else the inviter's M1). Step 5 (the temporary handshake DID) is unaffected —
   it always stays on the inviter's mediator so the connection-setup /
   connection-accepted exchange still completes on one mediator.
3. **The inviter's permanent CP is unaffected** —
   [src/gateways/approve.rs](../src/gateways/approve.rs) Step 4.5 already homes
   it on the inviter's own mediator; nothing there assumes the acceptor matches.
4. **The acceptor's finalize step follows the same mediator, including on
   recovery.** `finalize_oob_connection_as_acceptor`
   ([src/gateways/connection_points/ws_listener.rs](../src/gateways/connection_points/ws_listener.rs))
   resolves the permanent connection point's mediator from the pending
   connection's stored `mediator_did` (set in step 1 above) — not from the
   temporary handshake listener's mediator — so the persisted `mediator_id` and
   the listener it starts always agree, and connect to M2 when selected. The
   temporary connection point's metadata also carries this same
   `secure_mediator_did`, so the rare cache-miss recovery path (the pending
   connection lost between processes/restarts) reconstructs the **acceptor's**
   mediator instead of the inviter's. When the recovered mediator differs from
   the temporary connection point's own (the inviter's), recovery refuses to
   finish unless it names a known, Active mediator in the acceptor's store. In
   shared-mediator mode no lookup is needed, so the acceptor does not have to
   register the inviter's mediator.

After connecting with `acceptor_mediator_id` set, the runtime path is symmetric:

- `GW1 → GW2`: GW1's client (on M1) packs to GW2's CP DID (endpoint M2) → **M1
  relays to M2** → GW2.
- `GW2 → GW1`: GW2's client (on M2) packs to GW1's CP DID (endpoint M1) → **M2
  relays to M1** → GW1.

> **DID method note.** With **`did:peer`** the CP DID is self-resolving and
> embeds the mediator endpoint, so M1 can resolve GW2's CP with no HTTP call —
> the simplest choice for federation. With **`did:web` / `did:webvh`** the
> relaying mediator must HTTP-resolve the peer gateway's public domain to read
> the CP document, so each gateway's DID documents must be served at its public
> (proxied) domain.

### 5.3 Sends must be wrapped in a routing envelope to relay at all

Selecting a mediator (§5.2) only decides *which* mediator a DID's service
endpoint advertises. It does not, by itself, make a cross-mediator send work —
that depends on **how** the message is delivered to the sender's own mediator.

Affinidi's mediator ([mediation-and-routing.md](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/mediation-and-routing.md))
routes purely on the cleartext addressee of what arrives at `/inbound`: a
packed message addressed directly to the final recipient (`to = recipient_did`,
no routing envelope) is a **direct delivery** attempt, refused with
`direct_delivery.recipient.unknown` (error 72) unless the recipient already has
an account on **that same mediator**. Only a message addressed to the mediator
**itself**, wrapped in `routing/2.0/forward` with `body.next = recipient_did`,
is read as a relay instruction — the mediator resolves `next`'s own service
endpoint and forwards externally when it differs (auto-creating the account),
per the `[processors.forwarding]` config in §6.2.

With the `mediator_federation` flag on, `pack_and_send_message`
([src/comm/didcomm/client.rs](../src/comm/didcomm/client.rs)) therefore calls the SDK's
`ATM::forward_and_send_message(profile, false, packed, Some(msg_id),
my_own_mediator_did, recipient_did, None, None, false)`
([affinidi-messaging-sdk/src/transports/mod.rs](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-sdk/src/transports/mod.rs))
before sending. It addresses the outer envelope to **the sender's own connected
mediator**, never the recipient's; the sender's mediator resolves the recipient
and decides whether to relay. For a same-mediator recipient the mediator
delivers locally, provided its own public URL is listed in
`server.local_endpoints` (§6.2). Callers of `pack_and_send_message` get the
wrap: the `forward_via_fabric` send leg above and the primary and retry forward
calls in [src/proxy/handler.rs](../src/proxy/handler.rs). With the flag off,
sends go directly to the recipient.

Not every gateway send goes through it. Fabric stream frames
([src/proxy/fabric_stream/transport.rs](../src/proxy/fabric_stream/transport.rs))
and the x402 facilitator
([src/x402/gateway_facilitator_service.rs](../src/x402/gateway_facilitator_service.rs))
send directly, and a profile without a mediator sends unwrapped. Those paths are
not forward-wrapped, so they do not reach a gateway on another mediator.

---

## 6. Deployment setup — two mediators behind a proxy

This section is mediator configuration only. Validate the relay with it before
connecting the gateways. Roles: **A = the
relaying/sending mediator, B = the receiving mediator**; in a bidirectional
federation **both mediators play both roles**, so apply both columns to each.
Source of truth: [`multi-mediator.md` §5](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).

### 6.1 Build each mediator + config

Use the `mediator-setup` wizard (see the mediator `README.md`). Each mediator
gets its **own** DID, its **own** backend (Redis or Fjall), and its **own**
config. Two independent mediators, **not** a cluster.

### 6.2 Relay-critical config on **each** mediator

```toml
[processors.forwarding]
enabled              = "true"
external_forwarding  = "true"     # false collapses every forward to local — never for federation
relay_mode           = "blind"    # or "rewrap"; BOTH mediators must match
relay_trusted_mediators = "did:web:mediator-2.example.com"  # the peer mediator DIDs, comma-separated
max_hops             = "10"

[security]
enable_inter_mediator_relay = "true"   # admits the anonymous peer /inbound hop on B
local_direct_delivery_allowed = "true" # single-forward relays land as DIRECT delivery (§1b)
# The shipped default ACL grants neither forwarded bit. Add both to it; this
# mediator also hosts its own gateways' accounts, so keep their message bits.
global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,RECEIVE_FORWARDED"
# A mediator that only relays (hosts no gateways) can use the "Relay only"
# recipe: "DENY_ALL,SEND_FORWARDED,RECEIVE_FORWARDED". Use "ALLOW_ALL" only in
# a local lab: it grants every account every permission.

[server]
# CRITICAL behind a proxy / public hostname. Declare every public URL that
# appears in this mediator's DID document, or the mediator relays to ITSELF
# (a message addressed to one of its own users loops back). The default
# 0.0.0.0 bind never literally matches a public hostname.
local_endpoints = ["https://mediator-1.example.com"]   # M2 lists https://mediator-2.example.com
```

Keep `relay_trusted_mediators` set to the peer mediators you federate with.
Left empty, the mediator accepts relayed traffic from any mediator. The list
applies to `rewrap` and TSP hops, not to `blind` relay.

Why the ACL bits (see [`multi-mediator.md` §6](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md)):

- On **A**, the peer mediator's auto-created account needs **`RECEIVE_FORWARDED`**
  (else error 58 `authorization.receive_forwarded`). Nothing but
  `global_acl_default` creates that account.
- On **B**, the account-less relayed sender is auto-registered and needs
  **`SEND_FORWARDED`** (else error 60 `authorization.send_forwarded`).

### 6.3 Proxy / URL requirements

- Each mediator's **public proxy URL must be listed in its own
  `server.local_endpoints`** (§6.2) — this is the single most common failure
  behind a load balancer / tunnel.
- The public URL you put behind the proxy is the mediator's `/inbound` +
  WebSocket surface. Relay uses `POST {endpoint}/inbound` with
  `Content-Type: application/didcomm-encrypted+json`, and prefers a pooled
  WebSocket once traffic is steady (it negotiates a `relay-ack` subprotocol —
  make sure the proxy allows WebSocket upgrades, otherwise it silently falls
  back to REST).
- If gateway CP DIDs are `did:web`/`did:webvh`, each gateway's DID documents
  must be resolvable at its public (proxied) domain so the **peer mediator** can
  read the CP's service endpoint.

### 6.4 Validate the mediators alone (before touching the gateways)

```sh
# From a checkout of https://github.com/affinidi/affinidi-tdk-rs, in crates/messaging/affinidi-messaging-helpers
cargo run --example cross_mediator_forwarding -- \
  --mediator1 <M1_DID> --mediator2 <M2_DID>
# expect an Alice(on M1) → M1 → M2 → Bob(on M2) timeline; add --ping-pong for latency
```

If this fails, fix the mediators first: gateways on different mediators cannot
exchange messages until it passes. Use [`multi-mediator.md` §10](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md)
troubleshooting (it maps every relay error code to a fix).

---

## 7. Gateway setup behind a proxy

- Register **M1** on **GW1** and **M2** on **GW2** as `Mediator` records (DID +
  `our_did`/`our_secrets`), each pointing at that mediator's public proxy URL.
- Both gateway instances sit behind their proxy with a stable public domain
  (needed for `did:web` CP resolution; harmless for `did:peer`).
- Create the G2G connection: GW1 issues the OOB invitation (on M1); GW2 accepts
  it via `connect_via_oob`, passing **`acceptor_mediator_id`** set to M2's
  registered `Mediator.id` on GW2 (§5.2). Omitting the field keeps the
  shared-mediator fallback (§2).
- Enable the `mediator_federation` feature flag under **Settings › System ›
  Feature Flags** on both gateways (default off). While it is off,
  `connect_via_oob` refuses `acceptor_mediator_id` with `400` and sends are not
  forward-wrapped. While it is on, the **Connect via OOB** wizard shows a
  mediator picker that sets `acceptor_mediator_id`.

---

## 8. End-to-end verification

1. Mediators relay in isolation (§6.4). ✅ gate — do not proceed until green.
2. Connect GW1↔GW2 with `acceptor_mediator_id` set (§7); confirm GW1's
   permanent CP records `mediator_id = M1` and GW2's records `mediator_id = M2`.
3. Send a `fabric://` request GW1→GW2. In **M1's** logs expect a relay to M2's
   `/inbound` (a `FORWARD_ENQUEUED` with `endpoint=<M2>`), and delivery at GW2's
   M2 listener. Repeat GW2→GW1 through M2→M1.
4. Watch for the mediator "Storing locally — it will not be delivered" warnings
   (§2 of the mediator doc): they mean a hop was misclassified as local — almost
   always a missing `server.local_endpoints` or a CP DID still advertising the
   wrong mediator.

---

## 9. Common failure modes (mediator relay)

| Symptom | Cause | Fix |
|---|---|---|
| Sender gets `200`, peer never receives, no relay in logs | next hop classified local | check for "Storing locally" warning; ensure the CP DID advertises the peer's mediator |
| Message loops back | public hostname ≠ bind address | set `server.local_endpoints` to every public URL |
| `401` on `/inbound` at receiver | receiver not a relay | `enable_inter_mediator_relay = "true"` |
| error 60 `authorization.send_forwarded` at receiver | receiver default lacks `SEND_FORWARDED` | widen `global_acl_default` |
| error 58 `authorization.receive_forwarded` at sender | peer account on sender lacks the bit | sender `global_acl_default` must grant `RECEIVE_FORWARDED` |
| error 71 `direct_delivery.denied` | single-forward landed as direct delivery | `local_direct_delivery_allowed = "true"` on receiver |
| error 60 `authorization.relay.untrusted_peer` | rewrap peer not allow-listed | add the peer mediator's DID to `relay_trusted_mediators`; both sides on `rewrap` |
| `400 e.p.authorization.did.session_mismatch` on the receiving mediator's anonymous `ANON-INBOUND` relay session | Mediator image older than v0.20.4: in blind relay mode the inner envelope is addressed to the final recipient, not the receiving mediator, and hits the direct-delivery session-DID check meant for authenticated senders | Run a newer mediator on both sides |

Full table: [`multi-mediator.md` §10](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md).

---

## References

- [src/gateways/handlers.rs](../src/gateways/handlers.rs) — acceptor OOB connect (§2 constraint, §5 change point)
- [src/gateways/approve.rs](../src/gateways/approve.rs) — inviter approval / permanent CP creation
- [src/gateways/connection_points/types.rs](../src/gateways/connection_points/types.rs) — `GatewayConnectionPoint.mediator_id`
- [src/mediators/types.rs](../src/mediators/types.rs) — `Mediator` (`did`, `our_did`, `our_secrets`)
- [src/proxy/fabric_forward.rs](../src/proxy/fabric_forward.rs) — the `fabric://` send leg
- [src/gateways/connection_points/ws_listener.rs](../src/gateways/connection_points/ws_listener.rs) — `resolve_mediator_for_cp`, per-CP listener
- [`affinidi-messaging-mediator/docs/multi-mediator.md`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-mediator/docs/multi-mediator.md) — the authoritative mediator federation reference
- [`affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/messaging/affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs) — runnable two-mediator demo
