# VTA integration PoC — reviewer runbook

This runbook demonstrates the gateway delegating **JWT signing to a Verifiable
Trust Agent (VTA)** end to end, and verifying the result. It is the acceptance
vehicle for the VTA integration PoC (VTA-01…07).

## What the PoC proves

- The gateway signs tokens through a **pluggable signing connector**
  (`CredentialAuthority`). With `[vta]` enabled, `sign_token` dispatches the
  VTA's `keys/sign-jws/0.1` Trust Task; the VTA holds the key and returns a
  compact JWS. The gateway **never sees the private key**.
- The connector seam is the **single point every protocol path funnels
  through**: an MCP or A2A agent that needs a downstream token reaches it via
  STS token issuance (`/oauth2/token` → `VcIssuerSigner` →
  `CredentialAuthority::sign_token`); payment receipts and AP2 gateway-VPs use
  the same seam. Proving the seam proves the flow.
- It **fails closed**: an unreachable VTA yields an error, never a fabricated
  token. Inputs are **verified before** any signing call (no signing oracle).

## Architecture (one picture)

```
agent (MCP/A2A)                      gateway                           VTA
     │  request a downstream token      │                               │
     ├─────────────────────────────────►│  STS verifies the subject     │
     │                                  │  assertion FIRST              │
     │                                  │                               │
     │                                  │  CredentialAuthority          │
     │                                  │    ::sign_token(claims)       │
     │                                  ├── keys/sign-jws/0.1 ─────────►│  VTA-held key
     │                                  │   { keyId, header{typ,kid},   │  signs
     │                                  │     payload }                 │  b64url(h).b64url(p)
     │                                  │◄──── { jws, alg, keyId } ─────┤
     │◄──── VTA-signed JWT ─────────────┤  (private key never leaves    │
     │                                  │   the VTA)                    │
```

The gateway **never sends `alg`** — the VTA sets it from the key record and
echoes it, along with the `keyId` it signed with. Both are checked against what
was requested before the signature is attributed to the gateway's issuer DID: a
mismatch is refused rather than published. The request itself is DI-signed by
the control key, because `keys/sign-jws/0.1` declares its request proof
mandatory. The payload is JCS-canonicalized by the VTA, so the JSON inside the
returned `jws` is **not byte-identical** to what was sent — use the returned
`jws` as it is rather than re-deriving its segments.

## Configure the connector

`[vta]` is off by default (local in-process signing). To delegate to a VTA:

```toml
[vta]
enabled = true
base_url = "http://127.0.0.1:3000"
vta_did  = "did:webvh:<scid>:localhost%3A3000"
context_id = "ctx-gateway"          # the VTA context the gateway's grant lives in
signing_key_id = "gateway-jwt"       # the pinned VTA-held JWT key (required)
signing_key_public = "z6Mk…"         # its multibase public key (see §Key custody)
auth_key_source = "file:///var/lib/agw/vta_control_key"   # optional; ephemeral if absent

# Signing quota — bounds how many signatures can be minted per window.
# Enabled by default; 0 disables it.
sign_quota_max = 600
sign_quota_window_secs = 60

# Keys that no longer sign but must still be published so tokens they signed
# keep verifying (rotation, or a surface-by-surface migration).
[[vta.retiring_keys]]
key_id = "gateway-jwt-previous"
public_key = "z6Mk…"                 # required if that key was internal
```

Validation is **fail-closed**: an enabled block missing `base_url`, `vta_did`,
`context_id`, or `signing_key_id` is a startup error, never a silent fallback to
local signing. A `retiring_keys` entry naming the active key, or a quota with a
zero window, is also rejected at startup.

## Key custody and recovery (VTA-17)

**Provision the gateway's signing key as an internal key.** An internal key is
generated from the VTA's system CSPRNG, is never derived from the master seed,
and is **never exported by any surface — to anybody, at any role, including
super-admin**. That is the property SEC0-6115 condition 2 asks for.

```jsonc
// keys/create payload (DI-signed; an internal key has no derivation path, so it
// must be named explicitly)
{ "keyType": "ed25519", "keyId": "gateway-jwt", "label": "gateway-jwt", "internal": true }
```

**Capture `publicKey` from the response into `signing_key_public`.** This is not
optional bookkeeping: the VTA refuses to return an internal key's record to any
caller, so `keys/show` **cannot** resolve it later. With it recorded, the gateway
also publishes its JWKS with **no VTA call at all**.

**Recovery.** An internal key **cannot be recovered** if the VTA is lost — that is
the cost of non-exportability. Therefore:

| Item | Requirement |
|---|---|
| **Seed backup owner** | A **named** operator owns the VTA's encrypted backup (`pnm backup export`) and its restore test. Record the name in the deployment runbook — "the team" is not an owner. |
| **Loss of the VTA** | The internal signing key is gone. Recovery is **re-provision + rotate**: mint a new internal key, publish it, and move the old `kid` to `retiring_keys` — **keeping its `public_key`**, so tokens it signed keep verifying until they expire. |
| **Accepted risk** | Non-exportability means no key escrow. A VTA operator with host access could still *use* the key (not extract it); that insider risk is accepted explicitly in ADR-0109. |

Because recovery is "rotate, never restore", **`retiring_keys` is the recovery
mechanism** — keep the retired entry until every token it signed has expired.

## Field contract for VTA-signed STS tokens (VTA-09)

When `[vta] enabled = true`, STS access tokens and ID-JAGs are signed by the VTA.
What a relying party sees changes in exactly two ways:

| Claim / header | Local backend | VTA backend |
|---|---|---|
| `iss` | the gateway issuer DID | **the `did:key` of the VTA signing key** (`issuer_did()` of the active backend) |
| `kid` | `key-1` | the **pinned VTA key id** |
| `alg` | `EdDSA` | `EdDSA` (the **VTA** sets it from the key record) |
| everything else | unchanged | unchanged |

**Why `iss` is a `did:key`, not the gateway DID or the trust agent's DID.** A
`did:key` is the public key written as a DID, so its document is that key and
nothing else: it resolves with no hosting, nobody can repoint it, and a
compromised gateway — which holds no signing key — cannot make tokens verify
under a key of its own choosing. The gateway DID's document and the JWKS are
both served by the gateway, so anything anchored there can be rewritten by
whoever controls the host. The trust agent's own DID does not list the key at
all, and two gateways sharing one agent would claim the same issuer. A
different key is a different issuer, so **rotating the signing key changes
`iss`**; the loopback ID-JAG check accepts any `did:key` issuer whose key the
gateway still publishes, so tokens signed before a rotation or by a
per-surface key keep verifying. A verifier that wants this protection resolves
`iss` rather than trusting the gateway's JWKS, and `kid` remains the key
record id, not a verification-method id.

Both the **`iss` value** and the **verification keys** come from the *same*
`CredentialAuthority`, so they can never disagree:

- `/oauth2/jwks.json` publishes that backend's key set (active + retiring +
  carried-over local), so a resource server verifies by selecting on `kid`.
- `/.well-known/oauth-authorization-server` advertises the same `issuer`.
- **Loopback ID-JAG redemption** resolves self-trust from the same authority, so
  the gateway recognises its own tokens whichever backend minted them.

**Consumers that must accept the new shape**: anything verifying STS tokens by
`iss` + `jwks_uri` keeps working unchanged (both move together). Anything that
**hard-codes** the gateway's issuer DID must be updated — and note that the
fabric issuer-attestation path (`PeerIssuers.attested`) anchors on the gateway
DID, so moving the *issuer* DID needs re-attestation (tracked in VTA-14).

**Dev fallback.** Set `[vta] enabled = false` (the default) to sign locally
again. Nothing is migrated or deleted by switching, so the flip is reversible in
both directions — the local key is still published while a VTA key is active.

## One control key per connection, and why

A VTA **supersedes** a control DID's session when that DID authenticates again:
the older access token immediately starts returning
`401 unauthorized: token superseded`. Observed live — running the three
`live_*` tests in parallel, all authenticating as the same seeded control key,
makes two of them fail; `--test-threads=1` passes.

That is correct VTA behaviour, and it is exactly why a connection mints its
**own** control key (VTA-24) rather than sharing one:

- two gateway processes (HA pair, blue/green rollout) sharing a control key
  would continuously evict each other's sessions;
- two *connections* on one gateway sharing a key would do the same;
- and revoking the grant for one connection would strand all of them.

Run live tests with `--test-threads=1`, or give each its own control key.

## Bundled sidecar runbook (VTA-21)
Example deployment: [`config/examples/vta-bundled/`](../config/examples/vta-bundled/)
(compose file, Kubernetes pod, the `[vta]` block, the sidecar's setup file and
entrypoint).

**This is not a key-custody tier.** The sidecar shares a host, a disk and an
operator with the gateway, so "the keys are held by a separate agent" is not a
property this shape has. `GET /v1/vta/status` reports `tier: "bundled"` and
`custody_claim: false`; nothing in the product may claim otherwise. The
separately-operated (`appliance`) tier is the one that supports the claim.

**Why packaging and not a library.** Linking `vta-sdk` forces
`affinidi-did-resolver-cache-sdk` 0.8.22 → 0.8.41 through cargo's whole-graph
version unification, which needs a newer `affinidi-did-web` than the gateway
stack carries and breaks the default build (confirmed and reverted during
VTA-02). An in-process build would need *more* of the VTA workspace, so the
coupling is strictly worse. The gateway therefore speaks the same Trust Task
REST surface to a sidecar as to a remote VTA — one code path, zero dependency
coupling.

### First start: no operator action

With `[vta] mode = "embedded"` and `auto_bootstrap = true`:

1. The gateway generates its control key (kept encrypted in its own storage; it
   never leaves the gateway) and writes its `did:key` to
   `gateway-enrolment.env` in the shared `bootstrap_dir`. Public data only.
2. The sidecar's entrypoint sets the VTA up **once, with no admin**, then
   enrols that DID **offline, before the daemon listens**, as role `initiator`
   in context `gateway` with exactly `context-create, key-mint, sign-jws,
   sign-document`. The role, context and capabilities are fixed in the script,
   never taken from the gateway's file. It then writes the VTA's own `did:key`
   to `vta-identity.env`.
3. The gateway **pins** that DID (the first one it sees; a different one later
   is refused), authenticates, asks the VTA what it holds (`auth/whoami`) and
   requires **exactly** the grant above — more is a failure, not a bonus —
   and creates a non-exportable signing key `gateway-jwt-1`, capturing its
   public half (the VTA will not return an internal key's record again).
4. The record is persisted encrypted (`vta_bundled_state.json`), the `[vta]`
   block is completed from it, and signing goes through the VTA.

Both DIDs are `did:key`. The gateway's, because the sidecar listens on loopback
only and cannot resolve a published `did:webvh` of the gateway's; the VTA's,
because it is an internal service nobody resolves, its keys are non-exportable
whatever its DID method, and a `did:webvh` would need a recovery-key custodian
outside the deployment (spec KEY-116/119) that a fresh install has not got.
`control_did_method = "did_webvh"` is refused with `auto_bootstrap`.

**The gateway is not super-admin of its sidecar.** It holds one context-scoped
entry. The super-admin slot stays empty (`owner: unclaimed`) until a person
claims the trust agent; until then admin work is the VTA's offline CLI on the
host. A compromised gateway can sign within its grant, bounded by the quota and
audited, but cannot export the seed or an internal key, grant itself more, or
create a context outside `gateway/*`.

### States, and what to do

`GET /v1/vta/status` reports `bootstrap.state`. Nothing below is ever fixed
automatically.

| State | Meaning | Signing | Operator action |
|---|---|---|---|
| `connected` | Authenticated, exact grant, key present | the VTA | none |
| `waiting_for_vta` | The sidecar published no identity or did not answer in `bootstrap_wait_secs` | local if it never connected, otherwise **refused** | start the sidecar, restart the gateway |
| `enrolment_refused` | The sidecar refused the gateway or granted something other than the bundled grant | local if it never connected | read the sidecar's entrypoint log |
| `revoked` | Was connected; the sidecar now refuses it | **refused** | re-grant offline (`vta acl create`), restart |
| `vta_replaced` | A different trust agent answers at the pinned address | **refused** | investigate, then `--vta-rebootstrap` |
| `vta_lost` | The pinned agent no longer holds the signing key | **refused** | `--vta-rebootstrap` |
| `misconfigured` | The control key, the shared folder or the identity file is wrong | local if it never connected | fix the named problem |

"Refused" rather than "local" once the sidecar has signed anything: tokens
already issued carry its key, and switching to the gateway's own key would
change the issuer under callers.

`agent-gateway --vta-rebootstrap` (without `--yes` it only shows what it would
do) forgets the pinned trust agent and **retires** the current signing key,
which stays published as a retiring key so tokens it signed still verify. The
next start bootstraps again under a new key id (`gateway-jwt-2`, …); a retired
key id is never reused. It is never run automatically: a new trust agent means
new keys and DIDs.

### Rotating the control key

`agent-gateway --vta-rotate-control-key --yes`, **with the gateway stopped**
(a trust agent supersedes a DID's session when it authenticates again, and the
running connector holds the old key in memory). It moves the gateway's access
entry to a new `did:key` with `acl/swap-key`: the new key signs a short proof
that it agrees to take the entry over, and the agent copies the entry exactly,
so the grant cannot widen. The new key is stored as pending before the swap is
sent, so a crash part-way is finished or abandoned at the next start by asking
the agent which key is live.

This is hygiene, not recovery from a leak: whoever holds the current key can
rotate it to one of their own, exactly as with a `did:webvh` control key.
Recovery is an operator re-granting the gateway, and the agent audits every
swap. **After a swap the old key's already-issued access token can keep
signing until it expires (up to 15 minutes)**: the agent's signing gates fall
back to the role in the token when the access entry is missing. Rotate during a
quiet period, and treat a suspected leak as "revoke and wait out the token".

### Isolation and encryption

The sidecar shares the gateway's network namespace (a Kubernetes Pod, or
Compose `network_mode: "service:gateway"`) and listens on `127.0.0.1:8100`
only; it has no TLS and no unix socket, so loopback in a private namespace is
what keeps it off every network. The gateway additionally **reserves** every
VTA address it knows (`src/vta/isolation.rs`) and refuses it on both pinned
egress paths, so a surface, MCP proxy or A2A proxy pointed at the sidecar is
blocked even where the network allowed it. `GET /v1/vta/status` lists the
reserved origins.

**Encryption at rest is mandatory here** and enforced at startup: the sidecar's
key material is on this host's disk, so it is the only thing between a disk
image and the signing keys. A bundled deployment without it fails closed. The
sidecar's own seed is `encrypted_file` with `[hardened] enabled = true`, its
passphrase supplied as a mounted secret and never read from config or the
environment.

### Restarting under Compose

The sidecar joins the gateway's network namespace (`network_mode: "service:gateway"`),
so restart the **gateway first and the sidecar second**:
`docker compose restart gateway && docker compose restart vta`, or recreate both with
`docker compose up -d --force-recreate`. A plain `docker compose restart` fails the
sidecar with "cannot join network of a non running container", and Docker's restart
policy does not bring it back. A one-shot `bootstrap-init` service makes the shared
`/bootstrap` volume sticky and world-writable, because the gateway image's user and the
VTA image's uid 1000 differ and a fresh named volume is root-owned. In the Kubernetes pod
the containers share the pod's namespace, so either can restart on its own.

### Image, upgrade, backup and loss

**Build the VTA image from `verifiable-trust-infrastructure` branch
`gateway-integration`** until `Capability::ContextCreate` is released; a stock
image refuses the sidecar's grant with "unknown capability". Pin both images by
digest; an unpinned sidecar is a supply-chain hole in the component holding the
keys.

**Upgrade.** Upgrade the VTA first, confirm `bootstrap.state` is still
`connected`, then the gateway. The signing keys live in the `vta-data` volume
and survive the container.

**Backup and loss.** Back up `vta-data` and the seed passphrase **separately**
(spec VTA-050), alongside the gateway's `_storage`; they are one unit. Internal
keys are never in any backup, and `pnm backup` needs DIDComm or TSP, which this
sidecar does not run. Losing `vta-data` loses every key the VTA held. The
recovery is **rotate, not restore**: see `vta_lost` / `vta_replaced` above. The
retired key's public half is recorded, so tokens it signed still verify.

**Switching bundled → remote** is a configuration change: drop `auto_bootstrap`
and set `mode`, `base_url` and `vta_did` (and, for a remote agent, grant the
gateway on it yourself). No code path differs.

### What was verified, and how

Three layers, from the outside in:

- **Real containers.** `scripts/vta-bundled-compose-e2e.sh` runs the shipped Compose example
  with real images (`GATEWAY_IMAGE=… VTA_IMAGE=… ./scripts/vta-bundled-compose-e2e.sh`; not
  part of CI). It checks first start with no manual grant, the shared loopback and the
  shared-volume permissions, that nothing else on the network reaches the trust agent, a
  restart that keeps the same identity, a revoked gateway that is reported and never
  re-enrolled, an offline re-grant, and a control-key rotation run in a one-off gateway
  container beside the sidecar (20 checks). Each check reads only the logs written since its
  own restart. It found three faults the other layers could not: the
  gateway never received its mandatory backup key or certificates, the shared `/bootstrap`
  volume was unwritable by both users, and a plain `docker compose restart` fails the sidecar.
- **Real binaries.** `scripts/vta-bundled-e2e.sh` runs the real `vta` and `agent-gateway`
  binaries from zero in temporary directories (`VTA_BIN=… ./scripts/vta-bundled-e2e.sh`; needs a
  built VTA and `make config-debug` once; not part of CI). It covers: first start with no
  manual step; restart keeping the same identity and creating no second key; a revoked gateway
  reported and **not** re-enrolled by the entrypoint; re-grant and restart; and a real
  `acl/swap-key` rotation. Also checked by hand: a wiped sidecar reported as `vta_replaced`
  and recovered with `--vta-rebootstrap --yes`, and a rotation interrupted after the swap
  finished at the next start.
- **Behaviour scenarios and unit tests.** `tests/features/surface/trust_agent_bootstrap.feature`
  (a connected, a waiting, a refused and an over-granted trust agent, through the real gateway
  binary and a mock trust agent) and `trust_agent_signing.feature` (the tenant check), plus
  unit tests against a mock trust agent for every state and recovery.

The Kubernetes pod was validated for syntax only; no cluster was available.

## Bring up a local VTA (for the live e2e)

```bash
cd ../verifiable-trust-infrastructure

# Build the VTA (it serves keys/sign-jws and keys/sign-document, both specified
# upstream). Build this target specifically: a workspace-wide `cargo build` can
# unify the `test-support` feature in, which compiles the agent's
# response-conformance gate into the binary.
cargo build -p vta-service --features webvh --bin vta

# One-time setup (prints the VTA did:webvh and base URL http://localhost:3000).
VTA_ALLOW_PRIVATE_ENDPOINTS=1 ./target/debug/vta setup \
  --from local-dev/vta-root-webvh-setup.toml

# Seed the gateway's control did:key (the fixed test seed [42u8;32]).
./target/debug/vta import-did --config /tmp/vta-dev-root/config.toml \
  --did did:key:z6MkgAnvkP45uNxwCKeNdt6wrYkEjpYX4f7Nrd8MQqFL8Fbn \
  --role admin --label gateway

# Run it (detached; survives terminal cleanup).
VTA_ALLOW_PRIVATE_ENDPOINTS=1 nohup ./target/debug/vta \
  --config /tmp/vta-dev-root/config.toml >/tmp/vta_run.log 2>&1 & disown
```

Use `http://127.0.0.1:3000` (not `localhost`) so the gateway dials IPv4.

## Run the end-to-end demonstration

Live test — provisions a VTA-held signing key, signs a JWT through the connector
seam, and verifies the compact JWS against the key's published public key:

```bash
cd trust-gateway
VTA_LIVE_URL=http://127.0.0.1:3000 \
VTA_LIVE_DID="did:webvh:<scid>:localhost%3A3000" \
  cargo test --bin agent-gateway \
    vta::authority::poc_tests::live_sign_token_against_real_vta_verifies \
    -- --ignored --nocapture
```

Expected tail:

```
LIVE key_id=m/26'/7'/…'/0' public_key=z6Mk…
LIVE_OK: a real VTA-signed JWT verifies (key z6Mk…)
```

## Always-run coverage (no VTA required)

These run in CI and assert the PoC's guarantees against a mock VTA that really
Ed25519-signs, using the same logic as the real handler:

| Test (`src/vta/authority.rs::poc_tests`) | Asserts |
|---|---|
| `sign_token_produces_a_vta_signed_jwt_that_verifies` | a VTA-signed JWT verifies; the pinned `keyId` is used; the VTA sets `alg` |
| `a_mismatched_response_key_id_is_refused` | a response echoing a different `keyId` yields no token (fail-closed attribution) |
| `sign_token_typ_carries_the_requested_jose_typ` | the JOSE `typ` (e.g. `oauth-id-jag+jwt`) is honored |
| `fails_closed_when_the_vta_is_unreachable` | a down VTA errors — no fabricated token |
| `inputs_are_verified_before_any_vta_signing_call` | an unverified input is refused before any VTA call (no oracle) |
| `no_private_key_material_crosses_the_seam` | only `jws` crosses back — never key material |
| `the_jwks_publishes_retiring_and_carried_over_keys_by_kid` | rotation/migration keeps old keys verifying |
| `a_token_verifies_against_its_key_selected_by_kid` | a verifier picks the right key by `kid` |
| `the_signing_quota_fails_closed_once_exhausted` | an over-quota call never reaches the VTA |

The VTA-side task and its wall-off (`keys/sign-jws/0.1`, the forbidden header
members, a JWT-only output distinct from credential signing) are covered in the
`verifiable-trust-infrastructure` repo. The `0.1` spec refuses `alg`, `crit`,
`b64`, `jwk`, `jku` and `x5u` in `header`; the gateway sends only `typ` and
`kid`, so none of them can arise from this side.

Credentials go through the other specified task, `keys/sign-document/0.1`
(`src/vta/context_identity.rs`). The gateway builds the credential itself, with
the same builder the local issuer uses, and names the context's own `did:key` as
its `issuer`. The agent builds the `eddsa-jcs-2022` proof and signs only as the
DID the document names, only with a key that DID's own document lists for the
requested relationship — so the credential can only come from the context's key,
never from the agent's own. The gateway checks the answer against what it asked
for (key, signer, verification method, purpose, challenge and domain, and that
the document is exactly what it sent) before attributing anything to the
context. `src/vta/context_identity.rs`'s tests cover each of those refusals.

## Scope notes

- DI-credential issuance via the VTA (`keys/sign-document`) and JWKS discovery
  for local verification are wired in VTA-08; this PoC covers the JWT path.
- Every Trust Task the gateway sends on the signing path carries a control-key
  DI proof: `keys/sign-jws/0.1` declares its request proof **mandatory**, so a
  bearer-only call is refused `proofRequired`. The bearer says a session
  exists; the proof says *this* request came from the key behind it.
- The live tests need a grant that is **`--role admin` *and* scoped to one
  context**, which is the combination they jointly describe:
  `vta acl create --did <control did> --role initiator --contexts gwtest --capabilities context-create,key-mint,sign-jws,sign-document`
  followed by `vta acl update <control did> --role admin`. The role is what
  `live_grant_scope_is_parsed_from_the_real_token` checks is detected as
  over-privileged; the context scoping is what makes
  `live_the_gateway_cannot_create_a_top_level_context` get its refusal. An
  `import-did --role admin` grant leaves contexts **unrestricted** and fails the
  second test. The published auth DID the `auth_did` chain test mints needs its
  own entry with the same capabilities — the test prints the exact command.
- Stop the agent before any `acl` or `context` write: it holds a file lock on
  its store and the command otherwise fails `FjallError: Locked`.

## Operator runbook: connecting a trust agent

### What connecting does, and does not, change

Connecting a trust agent is **opt-in and forward-only**. It changes what the
gateway does from that point on; it moves nothing that already exists.

| | Effect |
|---|---|
| **Newly onboarded agents** | Key is minted inside the trust agent; the gateway never holds a private half |
| **Agents that already exist** | **Unchanged — they keep their gateway-held keys, permanently** |
| **Gateway credential/token signing** | Moves to the trust agent |
| **The peer-gateway issuer attestation** | Signs as, and claims, the gateway's trust-agent context |
| **TLS, SAML, x402, DIDComm keys** | Unchanged — see `vta::key_surfaces` for why each stays |

**There is no migration for existing agents, by design.** Re-keying them would
change their DIDs, invalidating credentials already issued to them and any
trust-registry record that names them. A long-lived deployment will therefore
keep most of its agents on gateway-held keys indefinitely. If you need them
moved, that is a re-onboarding exercise with a DID change, not a setting.

**Disconnecting strands the agents onboarded while connected.** Their keys live
in the trust agent, so revoking, deleting or disabling the connection stops them
signing, and the only recovery is re-onboarding with a new DID. The gateway
therefore refuses those three actions with `409` while any agent keeps its key
in the connection, naming how many. Repeat the request with
`?acknowledge_stranded_agents=true` to proceed; the dashboard asks for a second
click on Revoke with that message.

`GET /v1/key-management/inventory` answers "which agents still have a key on
this disk" directly, per record.

### Connecting

There are two routes. **The dashboard is the normal one** — `[vta]` is not
required for anything described in this document, and a gateway configured
entirely from the screens reaches the agent for tokens, credentials, the
credential embedded in an injected presentation, and newly onboarded agents'
keys. See *Manual walkthrough* below for that path end to end.

The steps here are the **config-file** route, for fleet or IaC installs that
cannot use a dashboard.

1. **Start the gateway with `[vta]` enabled.** For a separately-operated
   trust agent (`mode = "appliance"`) it publishes a `did:webvh` to
   authenticate with on first boot and logs it, along with the URL that
   document is served at. For a bundled sidecar (`mode = "embedded"`) it
   authenticates as the plain `did:key` and publishes nothing, because the
   sidecar is reached over loopback and cannot resolve the gateway's public
   address.

   `control_did_method = "did_key" | "did_webvh"` chooses explicitly. Absent,
   the gateway decides in this order: a configured `auth_did` (a DID you host
   yourself) wins; then `control_did_method`; then `did_key` for a bundled
   sidecar; then the older `publish_auth_did` (`false` means `did_key`);
   otherwise `did_webvh`. `control_did_method` and `publish_auth_did` must
   agree when both are set.

2. **Make that URL reachable from the trust agent.** It is served
   unauthenticated at `/vta-auth/did.jsonl` (and under `/.well-known/`). The
   agent resolves it on *every* authentication, so a gateway behind NAT or on a
   private subnet needs that one path exposed to wherever the agent runs.

   **It must be publicly resolvable.** A trust agent's DID resolver blocks
   loopback and private hosts by default as an SSRF guard
   (`HostPolicy::PublicOnly`), and refuses before any signature is checked —
   the failure looks like a proof error, not a networking one. A deployment
   that cannot expose the path should set `control_did_method = "did_key"`, so
   the gateway authenticates as the plain `did:key`, and accept that rotating the
   key needs a fresh grant. Development setups can opt in with
   `VTA_ALLOW_PRIVATE_ENDPOINTS` on the agent. The DID's address is
   `http://` for `localhost` and `https://` for every other host, on the port
   the gateway's own DID names, so a development gateway serving HTTPS on a
   local port cannot be resolved by the agent either.

   A warning at startup that the auth DID could not be resolved is **expected**
   — the listener is not up yet when the check runs. What matters is whether
   the agent can reach it, which that check cannot answer.

**Connections created in the dashboard** authenticate the same way. A new
connection mints its own control key and publishes its own `did:webvh` at
`/vta-auth/{connection_id}/did.jsonl` (and under `/.well-known/`), under the
domain the gateway's own DID names. That DID is the one the pairing step shows
and the grant command names, and it stays the same when the control key is
replaced. The same reachability rule applies: the agent resolves it on every
authentication. A gateway whose own DID names no domain, or a connection created
through the API with `"control_identity": "did_key"`, authenticates as the
`did:key` of its control key instead. A connection created before this existed
keeps the `did:key` it was granted. Replacing a published connection's key
means updating its log off this host; the gateway holds only the current signing
key, so a compromise is recovered by revoking the grant, not by rotating.

3. **Run the grant command the gateway prints**, on the agent, as an
   administrator. This is the one consent step; the gateway never holds admin
   on the agent. With provisioning enabled it confers exactly five
   capabilities — `context-create`, `key-mint`, `sign`, `sign-jws`,
   `sign-document` — scoped to one context, and uses `vta acl create` because
   `vta import-did` carries no `--capabilities` flag.

   `sign-jws` and `sign-document` are **not** implied by `sign`: a grant
   carrying only `sign` passes pairing and then refuses every
   `keys/sign-jws` (tokens, issuer attestation) or `keys/sign-document`
   (agent-identity credential) call at runtime. An agent granted before either
   capability existed must be re-granted.

4. **Verify.** `GET /v1/vta/status` reports the tier and resolution;
   `GET /v1/key-management/inventory` lists connections, per-surface mappings,
   and the key surfaces still held locally.

### Manual walkthrough (dashboard only, no `[vta]`)

A full local run from an empty machine, using nothing but the screens. Useful
for reviewing the operator experience, and for reproducing a report.

**Ports.** `3000` agent · `3002` dashboard dev server · `8080` gateway HTTP ·
`8443` gateway HTTPS · `9000` gateway outbound · `9100` sample A2A agent.

#### 1. Create and run the agent

```bash
cd <verifiable-trust-infrastructure>
export VTA_ALLOW_PRIVATE_ENDPOINTS=1
export VTACFG=~/vta-dev-root/config.toml

./target/debug/vta setup --from local-dev/vta-local-persistent.toml   # copy the VTA DID it prints
./target/debug/vta --config $VTACFG context create --id gwtest
./target/debug/vta --config $VTACFG                                   # leave running
```

`VTA_ALLOW_PRIVATE_ENDPOINTS=1` is needed on **every** `vta` command; without
it the agent refuses to resolve a private address and the failure surfaces as
`proofInvalid` rather than as a networking error.

`gwtest` is the **parent** context: the gateway's own keys live there and
per-surface sub-contexts hang beneath it. It has no DID of its own at this
point, and needs none — the gateway gives it one on first issuance.

> The agent holds a **file lock** on its store while running. Every later
> `acl` / `context` write needs it stopped first, or it fails `FjallError:
> Locked`. Step 3 is where this bites.

Health check: `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/health` → `200`.

#### 2. Start the gateway

```bash
cd <trust-gateway>
cargo build                 # l-run-debug.sh runs the binary, it does not build it
cd www/default && npm run build && cd -   # the dashboard is served from this bundle
./scripts/l-run-debug.sh
```

**Both builds matter, and neither warns you when the other is stale.** The
gateway serves the dashboard from `www/default/build`, so a `cargo build`
alone leaves whatever bundle was last compiled in place — which can be hours
old. A UI change that is not rebuilt fails *silently*: the screen accepts the
edit, the save returns `200`, and the field never reaches the API. Hard-reload
the browser afterwards (`Cmd+Shift+R`); a normal reload may serve the old
bundle from cache.

Open **`http://localhost:8080`** — not `:8443`. WebAuthn's `external_origin` is
pinned to the former, so a passkey returns `401` on any other origin.

#### 3. Connect the agent

**Trust Agent → Connect an agent**, with endpoint `http://127.0.0.1:3000`, the
DID from step 1, and context `gwtest`. Backend *my own agent*, transport
*HTTPS*, then **Pair**.

Copy the printed `vta acl create` command, **stop the agent**, run it (adding
`--config ~/vta-dev-root/config.toml`), start the agent again, then **Verify**.

Env-var prefixes are `VAR=1 cmd`, not `export VAR=1 cmd` — `export` takes only
assignments and will reject a command argument.

The final step mints the signing key itself and offers *Use this agent for all
signing*, pre-checked when no agent is the default yet. **Done** applies it.

#### 4. Confirm the gateway signs through the agent

**Settings → System → Key management** should name the connection. Then, in the
browser console on `:8080`:

```js
(async () => {
  const r = await fetch('/api/v1/identity/issue', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    // Unique per run: a repeated identity returns the CACHED credential,
    // whose kid would be whatever signed it originally.
    body: JSON.stringify({ agent_identity: { sub: `check-${Date.now()}` } }),
  });
  if (!r.ok) return console.error('HTTP', r.status, await r.text());
  const b = await r.json();
  const d = s => JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')));
  const [h, p] = b.credential.split('.').slice(0,2).map(d);
  console.table({
    is_new: b.is_new, alg: h.alg, kid: h.kid,
    issuer: typeof p.issuer === 'object' ? p.issuer?.id : p.issuer,
    subject: p.credentialSubject?.id,
  });
})();
```

`issuer` is the **W3C VC field**, not `iss` — reading `iss` returns
`undefined` and looks like a failure when nothing is wrong.

**What a pass looks like:** `kid` is the `gateway-jwt-…` the wizard minted, and
`issuer` is the agent's DID — on **port 3000**. Those two agreeing is the
property being checked: `create_credential` fails closed rather than
attributing a credential to an issuer that did not sign it.

`subject` tells you where the **new agent's own** key was minted, which is a
separate question. `did:key:…` means it was minted inside the trust agent and
the gateway never held a private half — the result you want. A
`did:webvh:…:8443` means the gateway minted it locally, so check that an agent
is the appliance default in Settings → System → Key management.

This endpoint is **appliance-scoped**: it passes no surface, so a surface's own
`Signing key` does not apply here and changing it will not move these values.
Use step 5 to exercise that setting.

#### 5. Optional — a surface, end to end

The step above exercises credential issuance. The **injected presentation** on a
live request is the other half, and the only place a surface's own
`Signing key` applies.

Point an `a2a` surface (not `mcp` — MCP validates every POST and a plain body
is rejected `-32600`) at any A2A listener. It needs **both** of:

- an **Identity** element set to **From Payload**, meta field `agentIdentity`,
  field `sub` — this is what *produces* the identity, and
- **Inject VP** on the target — this only injects a presentation once one
  exists.

With the toggle alone the gateway logs *"inject_vp is enabled but no identity
binding VP was produced"* and signs nothing, so the agent stays idle and looks
broken when it is behaving correctly.

Set **Signing key** to the connection, send a valid `message/send` through the
surface's route, and inspect
`message.metadata["https://fabric.affinidi.io/extensions/agent-identity-credential/v1"]`
on what arrives: the embedded credential's issuer should be the agent.

#### Troubleshooting

| Symptom | Cause |
|---|---|
| **The agent log stays silent on a surface request** | Check the *gateway* log first. `inject_vp is enabled but no identity binding VP was produced` means no identity was resolved, so there is no presentation to sign and the agent is idle **correctly**. The toggle only injects a VP once one exists — producing it needs the **Identity** element set to **From Payload** (meta field `agentIdentity`). |
| **A dashboard setting appears to do nothing** | The bundle is stale — `cargo build` does not rebuild the UI. Read the record back through the API (`GET /v1/surfaces`) before suspecting the backend: a field that saved as `null` means the browser is running old code, not that resolution is broken. Then `cd www/default && npm run build` and hard-reload. |
| `401` on login | dashboard opened on `:8443`; use `http://localhost:8080` |
| `FjallError: Locked` | the agent was running during a CLI write |
| `proofInvalid` | `VTA_ALLOW_PRIVATE_ENDPOINTS=1` missing on the agent |
| `429 rate_limited` | the agent's auth bucket (dev default: burst 10, refill 1/5 s). The gateway honours `retryAfterSecs` and retries once, capped at 2 s |
| `export: not valid in this context` | `export VAR=1 cmd` — use `VAR=1 cmd` |
| `context … has no DID, so it cannot sign as itself` | a hand-made context with no identity; the gateway grants one on first use, so this means that call was refused — check the grant carries `context-create` |
| **Pairing verifies, then every signature fails** | the grant predates the `sign-jws` or `sign-document` capability. `sign` is accepted as a substitute for neither, and the shortfall is invisible until the first signing call — re-run the `vta acl create` command with both included |
| `422 proofRequired` on a signing call | the request reached the agent without its control-key proof. `keys/sign-jws/0.1` requires one; a bearer token alone is not enough (the gateway signs every request to the signing tasks) |

### How an agent's presentation is signed

A newly onboarded agent's key lives in its own trust agent context, so the
presentation it makes is signed there, with `keys/sign-document/0.1`, and the
gateway never has the private half.

That task reads the signer from a document's `issuer` or `controller`, and a
presentation names its holder with `holder`. So the presentation sent for
signing carries **both**, set to the same agent DID:

- the trust agent finds its signer in `controller`, signs only as that DID, and
  only with a key that DID's document lists under `authentication`;
- `holder` stays, so the presentation still names who is presenting, and the
  gateway's own verifier — which reads `holder` — is unchanged.

The one visible difference from a presentation the gateway signs itself is that
extra `controller` member. A verifier elsewhere that rejects unknown members
would reject it; one that ignores them will not notice. A challenge and a domain
are bound into the proof when the caller supplies them, and the gateway's
verifier (`src/identity/ssi/di_jcs.rs`) checks `eddsa-jcs-2022` itself so that
binding is part of what it verifies — changing the challenge or domain afterwards
breaks the proof. The gateway refuses to sign if the context's DID is not the
holder the presentation names.

A revision of the task that recognises `holder` directly would make the extra
member unnecessary; it is a one-line removal in `src/vta/vp_issuer.rs` when that
exists.

### Rolling back

Disabling `[vta]` returns the gateway to local signing — **but it is not a
clean undo once agents have been onboarded against the trust agent.**

- **Agents onboarded while connected have no local key.** Their key exists only
  in the agent's context. Disconnecting leaves them unable to present, and the
  gateway cannot sign for them, because it never had the material. They have to
  be re-onboarded, which gives them new DIDs.
- **Agents that predate the connection are unaffected** and resume exactly as
  before — they never stopped using their own keys.
- **The gateway's own signing** returns to the local issuer key, which was never
  deleted.
- **Peer gateways keep the issuer DID they pinned.** If the attestation claimed
  a trust-agent context DID and now claims the gateway DID again, each pairing
  must be re-attested: `DELETE` then `POST /v1/gateways/{id}/issuer`, or add the
  new issuer with `POST /v1/gateways/{id}/trusted-issuers`. Until then
  presentations from those peers fail attribution — fail-closed, and the error
  names the fix.

The safe sequence for a rollback is therefore: stop onboarding new agents →
re-attest peer connections → disable `[vta]` → re-onboard any agents that were
created while connected.

### Known residues

These are deliberate and recorded in `vta::key_surfaces`, which computes them
rather than asserting them:

- **The VTA control key stays on the gateway.** It is what authenticates *to*
  the agent, so it cannot live there. This is the irreducible residue: a
  compromised gateway can still ask the agent to sign within its grant. The
  difference from custody is that the grant is bounded, revocable, and every
  use is attributable.
- **The auth DID's update key is the control key**, on this host. Tolerable
  because the agent is the sole relying party and revoking the access entry ends
  access whatever the document says. Consequence: key rotation is not a
  compromise-recovery mechanism for that DID — revoke-and-re-grant is.
- **The gateway's `proxy_did` update key is its local issuer key.** Nothing in
  production resolves that DID for a trust decision any more, so the exposure is
  currently inert — but contingently, not structurally. Anything that starts
  resolving it re-arms the risk in full.
