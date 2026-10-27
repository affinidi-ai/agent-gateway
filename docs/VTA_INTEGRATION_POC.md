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
     │                                  │   { keyId, header{typ},       │  signs
     │                                  │     payload, algorithm }      │  b64url(h).b64url(p)
     │                                  │◄──────── { jws } ─────────────┤
     │◄──── VTA-signed JWT ─────────────┤  (private key never leaves    │
     │                                  │   the VTA)                    │
```

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
| `iss` | the gateway issuer DID | **the VTA-backed issuer DID** (`issuer_did()` of the active backend) |
| `kid` | `key-1` | the **pinned VTA key id** |
| `alg` | `EdDSA` | `EdDSA` (the **VTA** sets it from the key record) |
| everything else | unchanged | unchanged |

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
(compose file + `[vta]` block).

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

**Bring-up.**

```bash
cd config/examples/vta-bundled
export TG_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export TG_VTA_CONTROL_KEY="$(openssl rand -hex 32)"
docker compose up -d
# Read the sidecar's DID and pin it in config.bundled.toml, then restart the
# gateway. An unpinned VTA means signing with whatever answers that address.
docker compose exec vta vta did show
```

**Isolation.** The sidecar is on an `internal: true` network with no published
ports, so nothing outside the deployment unit has a route to it. The gateway
additionally **reserves** every VTA address it knows
(`src/vta/isolation.rs`) and refuses it on both pinned egress paths, so a
surface, MCP proxy or A2A proxy pointed at the sidecar is blocked even when the
network would have allowed it. `GET /v1/vta/status` lists the reserved origins.
The second layer exists because the forward leg deliberately permits loopback
and RFC 1918 — exactly where a bundled VTA lives.

**Encryption at rest is mandatory here** and enforced at startup: the sidecar's
key material is on this host's disk, so it is the only thing between a disk
image and the signing keys. A bundled deployment without it fails closed rather
than starting with a security story that does not hold.

**Upgrade.** Pin both images by digest; an unpinned sidecar is a supply-chain
hole in the component holding the keys. Upgrade the VTA first, confirm
`GET /v1/vta/connections/{id}/status` still reports `connected`, then the
gateway. The signing keys live in the `vta-data` volume and survive the
container, so a rolled-back image finds the same keys.

**Backup and loss.** Back up `vta-data` alongside the gateway's `_storage`;
they are one unit. Losing `vta-data` loses every key the VTA held. The recovery
path is **rotate, not restore**, exactly as in *Key custody and recovery*
above: provision a fresh key, publish it, and keep the lost `kid` in
`retiring_keys` only if its public half was recorded — otherwise tokens it
signed can no longer be verified, which is why `signing_key_public` is worth
setting at provisioning time.

**Switching bundled → remote** is a configuration change only: `mode`,
`base_url`, `vta_did`. No code path differs, and the surface/variant mappings,
connection records and pairing state are unaffected.

## Bring up a local VTA (for the live e2e)

```bash
cd ../verifiable-trust-infrastructure

# Build the VTA (includes the VTA-06 keys/sign-jws task).
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
  cargo test --bin agent-trust-gateway \
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
| `sign_token_typ_carries_the_requested_jose_typ` | the JOSE `typ` (e.g. `oauth-id-jag+jwt`) is honored |
| `fails_closed_when_the_vta_is_unreachable` | a down VTA errors — no fabricated token |
| `inputs_are_verified_before_any_vta_signing_call` | an unverified input is refused before any VTA call (no oracle) |
| `no_private_key_material_crosses_the_seam` | only `jws` crosses back — never key material |
| `the_jwks_publishes_retiring_and_carried_over_keys_by_kid` | rotation/migration keeps old keys verifying |
| `a_token_verifies_against_its_key_selected_by_kid` | a verifier picks the right key by `kid` |
| `the_signing_quota_fails_closed_once_exhausted` | an over-quota call never reaches the VTA |

The VTA-side task and its wall-off (`keys/sign-jws/0.1`, a `typ` allow-list, a
JWT-only output distinct from credential signing) are covered in the
`verifiable-trust-infrastructure` repo.

## Scope notes

- DI-credential issuance via the VTA (`credentials/issue`) and JWKS discovery
  for local verification are wired in VTA-08; this PoC covers the JWT path.
- The connector's signing call is bearer-authenticated; write provisioning
  (`keys/create`) additionally carries a control-key DI proof — done
  out-of-band at onboarding, not on the hot signing path.

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

1. **Start the gateway with `[vta]` enabled.** On first boot it publishes a
   `did:webvh` to authenticate with and logs it, along with the URL that
   document is served at.

2. **Make that URL reachable from the trust agent.** It is served
   unauthenticated at `/vta-auth/did.jsonl` (and under `/.well-known/`). The
   agent resolves it on *every* authentication, so a gateway behind NAT or on a
   private subnet needs that one path exposed to wherever the agent runs.

   **It must be publicly resolvable.** A trust agent's DID resolver blocks
   loopback and private hosts by default as an SSRF guard
   (`HostPolicy::PublicOnly`), and refuses before any signature is checked —
   the failure looks like a proof error, not a networking one. A deployment
   that cannot expose the path should keep the plain `did:key` and accept that
   rotating the key needs a fresh grant. Development setups can opt in with
   `VTA_ALLOW_PRIVATE_ENDPOINTS` on the agent.

   A warning at startup that the auth DID could not be resolved is **expected**
   — the listener is not up yet when the check runs. What matters is whether
   the agent can reach it, which that check cannot answer.

3. **Run the grant command the gateway prints**, on the agent, as an
   administrator. This is the one consent step; the gateway never holds admin
   on the agent. With provisioning enabled it confers exactly three
   capabilities — `context-create`, `key-mint`, `sign` — scoped to one context,
   and uses `vta acl create` because `vta import-did` carries no
   `--capabilities` flag.

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
