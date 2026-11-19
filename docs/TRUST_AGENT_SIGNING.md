# Trust agent signing

The gateway signs tokens, credentials and presentations either with its own keys (local
signing) or through a Verifiable Trust Agent (VTA) that holds the keys and signs on request,
within the grant its operator gave the gateway. This document describes both, how a trust agent
is connected and chosen, and the limits. The terms are defined in
[`CONTEXT.md`](../CONTEXT.md#trust-agent); the control key is explained in plain words in
[how the control key rotates](vta-auth-key-rotation/how-it-works.md).

Signing through a trust agent is a key-management improvement: many keys on the gateway's disk
become one authority that its operator can withdraw. It is not, by itself, a custody claim: the
gateway still holds the control key it authenticates with and can ask the trust agent to sign
anything within its grant until that grant is revoked.

## Local signing

With no trust agent chosen, the gateway signs with its own keys: the same keys, the same DIDs,
the same JWKS and the same `kid`s as always. Every signature is made by the VTA signing library,
`vta-signing`, running inside the gateway process, so local and remote signing share one code
path.

- The key files stay the source of truth (`issuer_config.json`, agent identity records,
  `did:webvh` key pairs). Nothing new is persisted: the gateway holds each private key in
  memory only while it signs. There is no key store, database or working directory, and no
  setting for one.
- The gateway links the library alone, not the VTA service, so none of the VTA's storage, access
  control or audit code runs in the gateway process.
- Tokens are signed over the exact payload bytes the gateway builds, so claims are not
  reserialised. The only difference a verifier can see is the order of the header members,
  which the library sorts.
- Credential and presentation proofs are `eddsa-rdfc-2022`: the gateway builds the canonical
  hash data and the library signs those bytes, so gateways that predate `eddsa-jcs-2022`
  verification still accept them. `did:webvh` log entries are signed the same way.
- Not covered: DIDComm (the messaging library needs the key material for key agreement), the
  HMAC transit token, third-party client assertion keys, x402 chain keys, and the control key
  the gateway authenticates to a trust agent with.

## Which signer is used

A signing key resolves in this order, first match wins:

1. a surface variant's `signing` block;
2. the surface's `signing` block;
3. the owning issuer's `signing` block (`PUT /v1/issuers/{id}`, `signing`; an empty block clears
   it);
4. the gateway-wide default, **Gateway signing** (`default_signing` in the settings, Settings →
   Security → Gateway signing);
5. the `[vta]` block, when it is enabled;
6. the gateway's own key.

A `signing` block names `backend` (`local` or `vta`) and, for a trust agent, `connection_id`,
`context_id` and `key_id`; a surface or issuer block without `key_id` is refused on save. In the
dashboard this is the **Signing key source** field: **Gateway secret** or **Verifiable Trust
Agent**, which picks one of the connected agents.

The gateway-wide signer (`ApplianceAuthority`) is resolved on every call, so changing Gateway
signing moves STS access tokens, ID-JAGs, MCP access tokens, payment receipts, the agent identity
credential and the Fabric issuer attestation to the new signer with no restart. Changing it needs
both `settings.edit` and `key_management.edit` (see [`RBAC.md`](RBAC.md#trust-agents-and-key-management)),
and the dashboard asks for confirmation first, because it changes the issuer of everything issued
from then on.

Signing fails closed. A choice that cannot be resolved refuses to sign rather than signing
locally; a surface whose mapping cannot be read (a surface or issuer store error) or names a block
that cannot sign refuses the request; an unreachable trust agent yields an error, never a
fabricated token. Inputs are verified before any signing call, so the gateway is never a signing
oracle. A scope nobody chose a trust agent for issues under the gateway-wide signer.

### What moves to a trust agent, and what stays

| | Effect of choosing a trust agent |
| --- | --- |
| Tokens and credentials the gateway signs | Signed by the trust agent |
| The Fabric issuer attestation | Signs as, and claims, the trust agent context |
| Agents onboarded from then on | Their key is created inside the trust agent; the gateway never holds the private half |
| Agents that already exist | Unchanged: they keep their gateway-held keys, since moving them would change their DIDs |
| TLS, SAML, x402 and DIDComm keys | Unchanged; `vta::key_surfaces` computes which keys stay local and why |

`GET /v1/key-management/inventory` lists, per record, which keys still live on the gateway's disk.
The dashboard shows it on Secrets → Key Management.

## Issuer DIDs

What a trust agent signs is attributed to the trust agent's key or context, never to the gateway
DID.

| Artifact | Issuer when a trust agent signs |
| --- | --- |
| STS access token, ID-JAG, MCP access token, payment receipt (`keys/sign-jws/0.1`) | `iss` is the `did:key` of the trust agent key that signed; `kid` is that key's record id; `alg` is set by the trust agent from the key record |
| Agent identity credential, presentation, issuer attestation (`keys/sign-document/0.1`) | The DID of the context it was signed in: a `did:key` or a `did:webvh` (see [Context DIDs](#context-dids)) |

A `did:key` is the public key written as a DID: it resolves with no hosting, nobody can repoint
it, and two gateways sharing one trust agent never claim the same issuer. The gateway DID's
document and the JWKS are served by the gateway, so anything anchored there can be rewritten by
whoever controls the host; the trust agent's own DID does not list the signing key at all. A
verifier that wants this protection resolves `iss` rather than trusting the gateway's JWKS.

The `iss` value and the verification keys come from the same authority, so they never disagree:

- `/oauth2/jwks.json` publishes the gateway-wide signer's key set (the active key, the retiring
  keys and the carried-over local key), so a resource server verifies by selecting on `kid`.
- `/.well-known/oauth-authorization-server` advertises the same `issuer`.
- The gateway's MCP Resource Server and loopback ID-JAG redemption resolve self-trust from the
  same authority. A token issued under the gateway DID or the `did:key` of any key it publishes
  (retired keys included) is the gateway's own, both when it is verified and when token exchange
  refuses self-issued subject and actor tokens; an ID-JAG signed by a retired key is redeemed
  through jwt-bearer, never exchanged.

A different key is a different issuer, so rotating the signing key or changing the signer
changes `iss`. Anything that verifies by `iss` and `jwks_uri` keeps working; anything that
hard-codes the gateway's issuer DID must be updated. A Fabric peer pins the issuer it was
attested, so after the gateway-wide signer changes each peer pairing must be re-attested:
`DELETE` then `POST /v1/gateways/{id}/issuer`, or add the new issuer with
`POST /v1/gateways/{id}/trusted-issuers`. Until then presentations from those peers fail
attribution, and the error names the fix.

## How the gateway signs through a trust agent

Every Trust Task the gateway sends on the signing path is DI-signed by its control key, because
`keys/sign-jws/0.1` declares its request proof mandatory; the bearer token says a session exists,
the proof says this request came from the key behind it.

**Tokens** (`keys/sign-jws/0.1`). The gateway sends `keyId`, a header of `typ` and `kid` only,
and the payload; it never sends `alg`, and the task refuses `alg`, `crit`, `b64`, `jwk`, `jku`
and `x5u` in the header. The trust agent echoes the `alg` and `keyId` it signed with, and both
are checked against what was requested before the signature is attributed: a mismatch is
refused. The payload is JCS-canonicalised by the trust agent, so the returned `jws` is used as
it is.

**Credentials** (`keys/sign-document/0.1`, [`src/vta/context_identity.rs`](../src/vta/context_identity.rs)).
The gateway builds the credential with the same builder the local issuer uses and names the
context's DID as its `issuer`. The trust agent builds the `eddsa-jcs-2022` proof and signs only
as the DID the document names, with a key that DID's document lists for the requested
relationship. The gateway checks the answer against what it asked for (key, signer, verification
method, purpose, challenge and domain, and that the document is exactly what it sent) before
attributing anything to the context.

**Presentations** of an agent whose key lives in the trust agent are signed in the agent's own
context with `keys/sign-document/0.1`. That task reads the signer from `issuer` or `controller`,
so the presentation carries both `holder` and `controller`, set to the same agent DID: the
trust agent signs only as that DID, with a key its document lists under `authentication`, and the
gateway's verifier, which reads `holder`, is unchanged. The extra `controller` member is the
only visible difference from a presentation the gateway signs itself. A challenge and a domain
are bound into the proof when the caller supplies them, and the gateway's verifier
([`src/identity/ssi/di_jcs.rs`](../src/identity/ssi/di_jcs.rs)) checks `eddsa-jcs-2022` itself.
The gateway refuses to sign if the context's DID is not the holder the presentation names. The
same agent's JWTs (`sign-jwt` in the agents API, the AP2 presentation) are signed in its context
too.

Each trust agent client bounds its calls: a per-call timeout (`[vta] timeout_ms`), at most
`max_concurrent` calls in flight (excess fails fast), one retry of a transient failure (after
the trust agent's `retryAfterSecs` on a `429`), and a circuit breaker that opens for 30 seconds
after five consecutive failures. A signing quota (`sign_quota_max` per `sign_quota_window_secs`,
600 per minute by default) bounds what a looping or compromised caller can mint, and fails
closed. The calls are counted in the [trust agent metrics](OBSERVABILITY.md#trust-agent-metrics).

## Context DIDs

A context the gateway creates (its issuer context, a surface's, an agent's) signs as one DID, set
for the whole deployment by `[vta] context_did_method`:

- `did_key` (default): the `did:key` of a key the context holds. Nothing to host; rotating the key
  changes the DID, so peers that pinned it pair again.
- `did_webvh`: a `did:webvh` the trust agent creates in the context (`webvh/dids/create`, which the
  grant's `key-mint` allows) and records as the context's DID. The trust agent holds its signing
  key and its update key; the gateway never does. Its operator can rotate the key
  (`webvh/dids/rotate-keys`, an administrator's task) without changing the DID, so peers keep
  working.

With `did_webvh` the log must be reachable by every verifier: `context_did_hosting = "gateway"`
serves it at `/vta-issuer/{token}/did.jsonl` (the token is a digest of the trust agent and the
context), and `"vta_server"` publishes it through a webvh server registered on the trust agent
(`context_did_server_id`). The gateway signs as a context's `did:webvh` with the
`assertionMethod` of its verified log whose key the context holds; before each signature it
checks whether the log grew, and re-reads it and republishes the hosted copy when it did. A
context whose record names no DID signs as its `did:webvh` only when that is the only one it
holds.

The setting applies to contexts created after it is set: existing contexts and agents keep their
DID, because changing an agent's DID would invalidate credentials already issued to it. The
Verifiable Trust Agent tab, `GET /v1/vta/status` and the key inventory say which method is in use.

A VTA-built `did:webvh` uses one key as its signing key and its log's update key, so a trust
agent whose `keys/sign-document` signed a caller's document as that key's `did:key` would let
anyone holding the gateway's grant forge a log entry that rewrites the DID. The VTA refuses this
(`failedPrecondition` for a key any held `did:webvh` log names as an update or pre-rotation key);
use `did_webvh` only with a trust agent that does.

The gateway asks for the newest version of a task first and falls back to the older one only
when the trust agent answers `unsupportedVersion` or `unsupportedType`: `contexts/update-did` 1.2
then 1.1, and `vta/dids/list` 0.1 then `webvh/dids/list` 1.0. Any other refusal is final.

## Connections

A trust agent is reached through a **connection**. Connections are added on **Connections →
Verifiable Trust Agent** (`/v1/vta/connections`), or by the `[vta]` block, which the gateway
mirrors as the read-only connection `vta-bootstrap`. Connecting is optional and forward-only: it
changes what the gateway does from then on and moves nothing that already exists.

### The grant

The trust agent's operator runs the grant command the gateway prints, as an administrator; it is
the one consent step, and the gateway never holds admin on the trust agent. It confers the
`initiator` role, scoped to one context, with four capabilities: `context-create`, `key-mint`,
`sign-jws` and `sign-document` (`vta acl create`, since `vta import-did` carries no
`--capabilities` flag). `context-create` lets the gateway create sub-contexts under its own
context, through `vta/contexts/create`, and never a top-level one; `[vta] max_contexts` bounds how
many it creates. `sign-jws` and `sign-document` are not implied by `sign`: a grant with only
`sign` passes pairing and then refuses every token or credential signature.

### Control identities

Each connection mints its own control key. A trust agent supersedes a control DID's session when
that DID authenticates again (the older token gets `401 unauthorized: token superseded`), so two
gateways, or two connections, sharing a control key would keep evicting each other, and revoking
one grant would strand them all.

A connection added from the dashboard authenticates as a `did:webvh` the gateway publishes at
`/vta-auth/{connection_id}/did.jsonl` (and under `/.well-known/`), under the domain the gateway's
own DID names. That DID is the one the pairing step shows and the grant command names, and it
stays the same when the control key is replaced. A gateway whose own DID names no domain, or a
connection created through the API with `"control_identity": "did_key"`, authenticates as the
`did:key` of its control key instead; a connection created before published identities existed
keeps the `did:key` it was granted.

The `[vta]` block chooses with `control_did_method = "did_key" | "did_webvh"`. Absent, a
configured `auth_did` (a DID you host yourself) wins, then the older `publish_auth_did` (`false`
means `did_key`), otherwise `did_webvh`, published at `/vta-auth/did.jsonl`.

The trust agent resolves a published `did:webvh` on every authentication, so that path must be
reachable from it and publicly resolvable: a trust agent's DID resolver blocks loopback and
private hosts by default, and refuses before any signature is checked, so the failure looks like
a proof error. The DID's address is `http://` for `localhost` and `https://` for every other
host, on the port the gateway's own DID names. A deployment that cannot expose the path uses
`did_key` and accepts that replacing the key needs a new grant. A startup warning that the auth
DID could not be resolved is expected: the listener is not up when the check runs.

### Disconnecting

Agents onboarded while a connection was in use keep their key in it, so revoking, deleting or
disabling the connection stops them signing, and the only recovery is re-onboarding with a new
DID. The gateway refuses those three actions with `409`, naming how many agents keep their key
there, unless the request repeats with `?acknowledge_stranded_agents=true`; the dashboard asks for
a second click on Revoke with that message.

### A trust agent for one surface or issuer

A surface's `signing.connection_id` (with its `context_id` and `key_id`) has its identity
credential issued and signed by that trust agent, under the DID of the context it names; every
other surface keeps the default. An issuer's `signing` block applies the same to every surface
it owns that sets none of its own.

### Tenancy

Connections are tenant-owned records (resource kind `vta-connections`): a tenant PAT reads its own
tenant's connections and appliance-wide ones, and a surface's or issuer's `signing.connection_id`
must name a connection of its own tenant or an appliance-wide one. A connection's
`control_key_ref` must name a secret its tenant may reference. Gateway signing, the `[vta]` block
and its control key are appliance-wide. See
[`ACCESS_TOKENS.md`](ACCESS_TOKENS.md#trust-agent-connections) and
[`RBAC.md`](RBAC.md#trust-agents-and-key-management).

### Isolation

The gateway reserves every trust agent address it knows and refuses it on both pinned egress
paths, so no surface, MCP proxy or A2A proxy can be pointed at a trust agent. See
[`POLICY.md`](POLICY.md#trust-agent-addresses).

## Control key rotation

Rotating a control key is hygiene, not recovery from a leak: whoever holds the current key can
rotate it to one of their own. Recovery is the trust agent's operator revoking the grant and
granting the gateway again.

### A connection you added

A connection that authenticates as a published `did:webvh` can replace its control key without a
new grant: the DID, and so the access entry on the trust agent, do not change. Use **Rotate
control key** on the connection's row on Connections → Verifiable Trust Agent, or
`POST /v1/vta/connections/{id}/control-key/rotate` (`key_management.edit`).

Three steps, each saved on the connection record before the action that follows it, so a restart
resumes the rotation instead of repeating it:

1. **Introduce**: a log entry, signed by the current key, adds the new key to the DID document
   beside the old one. A trust agent re-reads a cached document that does not define the key a
   proof names, so it accepts the new key at once.
2. **Switch**: the connection's one cached client moves to the new key and signs in with it. A
   call that took the old token a moment earlier is retried once.
3. **Retire**: a log entry, signed by the new key, removes the old key, and the old seed is
   deleted.

If the trust agent refuses the new key, the gateway retries (10 s, doubling to 60 s) until
`[vta] connection_key_switch_timeout_secs` (default 330) has passed, then rolls back: the old key
is the only one published again and the new seed is deleted, so signing never stopped. A trust
agent that cannot be reached leaves the rotation under way, with the last error on the
connection; **Cancel** (`POST …/control-key/rotate/cancel`) puts the old key back until the switch
has happened. The request answers `200` when the rotation finished within 15 seconds, `202` while
it carries on, `502` when it was rolled back. It is refused with `409` for a connection that
authenticates as a `did:key`, one that is disabled or not connected, one already rotating, and
`vta-bootstrap`.

### The `[vta]` block's control key

When the `[vta]` block authenticates as a `did:key` held in a file
(`control_did_method = "did_key"`, `auth_key_source = "file://<path>"`, no `auth_did`), the
gateway moves that key while it runs, with `acl/swap-key`:

- **On demand**: the **Rotate control key** button on the tab's Control key card, or
  `POST /v1/vta/control-key/rotate` (`key_management.edit`). It answers `404` when the gateway
  holds no such key, `409` while a rotation is running, `429` with a `Retry-After` within ten
  minutes of the last rotation, `503` on a standby gateway and `502` when the trust agent refuses
  the swap.
- **On a schedule**, only when `[vta] control_key_rotation_days` is above `0` (default `0`; at
  most `3650`). It runs on the active gateway only, with a random delay of up to six hours. A
  failure keeps the current key, retries after an hour, doubling up to a day, and logs an error
  after three failures in a row.

The new key signs a short proof that it takes the access entry over, and the trust agent copies
the entry exactly, so the grant cannot widen; signing keys, the issuer and agents' keys are
untouched. The swap goes through the session the gateway already has, so nothing in flight is
superseded. The new key is stored as pending before the swap is sent, so an interrupted rotation
is settled at the next start, or on the next refused sign-in, by asking the trust agent which key
is live.

`vta_control_key_rotation.json`, beside the key file, records when the gateway began holding the
key and when it last rotated. `GET /v1/vta/status` reports it as
`control_key: {control_did, rotated_at?, next_rotation_at?, rotation_days}`, or `null` when the
gateway holds no such key. Each rotation logs `vta_control_key_rotated` (old and new DID, what
triggered it) on the `vta_audit` target. After restoring a backup taken before the last rotation,
print the stored key's DID with `agent-gateway --vta-print-control-did`, grant that DID on the
trust agent again, and start the gateway.

## Signing keys and recovery

Provision the gateway's signing key as an **internal** key: generated from the trust agent's
system CSPRNG, never derived from its master seed, and never exported to anybody at any role.
Key Management's **Provision a signing key** does this for a connection
(`POST /v1/vta/connections/{id}/keys`). For the `[vta]` block, create it on the trust agent:

```jsonc
// keys/create payload: an internal key has no derivation path, so it is named explicitly
{ "keyType": "ed25519", "keyId": "gateway-jwt", "label": "gateway-jwt", "internal": true }
```

and record the `publicKey` the response returns in `signing_key_public`: the trust agent refuses
to return an internal key's record later, and with it the gateway publishes its JWKS with no
trust agent call.

An internal key cannot be recovered if the trust agent is lost. Recovery is re-provision and
rotate: mint a new key, sign with it, and keep the old one published as a retiring key
(`[[vta.retiring_keys]]` with its `public_key`, or the connection's retired keys after
`POST /v1/vta/connections/{id}/rotate`) until every token it signed has expired. Name an owner
for the trust agent's encrypted backup (`pnm backup export`) and its restore test. A trust agent
operator with host access can still use the key, though not extract it.

## Set up

### From the dashboard

1. **Connections → Verifiable Trust Agent → Add VTA** opens the connect wizard
   (`/connections/trust-agents/connect`). Enter a name, the trust agent's address and DID, and the
   context it granted, then **Create and pair**.
2. Run the printed `vta acl create` command on the trust agent, as its administrator.
3. **Verify** checks the grant; a refusal shows its reason.
4. **Complete** provisions the connection's signing key and offers **Use this agent for all
   signing**, pre-checked only while no default is stored. **Done** applies it.

Settings → Security → Gateway signing then shows **Verifiable Trust Agent** with the connection.
To check it, issue a credential (`POST /v1/identity/issue` with a new `agent_identity.sub`): its
`kid` is the key the wizard provisioned and its `issuer` (the credential field, not `iss`) is the
context's DID. That endpoint is appliance-scoped, so a surface's own Signing key source does not
apply there; a surface's choice shows in the presentation it injects on a request, which needs an
Identity element that produces an identity and **Inject VP** on the Target.

### From the configuration file

For fleet or infrastructure-as-code installs, set the `[vta]` block (see
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md)):

```toml
[vta]
enabled = true
base_url = "https://vta.internal:8443"
vta_did  = "did:webvh:<scid>:vta.internal"
context_id = "ctx-gateway"
signing_key_id = "gateway-jwt"
signing_key_public = "z6Mk…"
auth_key_source = "file:///var/lib/agw/vta_control_key"

[[vta.retiring_keys]]
key_id = "gateway-jwt-previous"
public_key = "z6Mk…"
```

An enabled block missing `base_url`, `vta_did`, `context_id` or `signing_key_id`, a retiring key
naming the active key, or a quota with a zero window is a startup error, never a fallback to local
signing. On first boot the gateway logs the control DID to grant and, for a published one, the URL
it is served at. Make that URL reachable from the trust agent, run the grant, then check
`GET /v1/vta/status` (the resolution in use) and `GET /v1/key-management/inventory`. Setting
`enabled = false` returns to local signing; nothing is migrated or deleted, and the local key is
still published while a trust agent key is active.

### Rolling back

Returning to the gateway's own key is not a clean undo once agents were onboarded through a
trust agent: their keys exist only there, so they must be re-onboarded with new DIDs. Agents that
predate the connection are unaffected, and the gateway's own key was never deleted. The safe
order is: stop onboarding new agents, re-attest peer pairings, change the signer, then re-onboard
the agents created while connected.

### Troubleshooting

| Symptom | Cause |
| --- | --- |
| `proofInvalid` on pairing | The trust agent cannot resolve the control `did:webvh` (a private address, or the path not exposed). Development trust agents need `VTA_ALLOW_PRIVATE_ENDPOINTS=1` |
| Pairing verifies, then every signature fails | The grant lacks `sign-jws` or `sign-document`; `sign` substitutes for neither. Grant again with both |
| `context … has no DID, so it cannot sign as itself` | The gateway could not give the context a DID; check the grant carries `context-create` |
| `422 proofRequired` on a signing call | The request reached the trust agent without its control-key proof |
| `429 rate_limited` | The trust agent's authentication rate limit. The gateway honours `retryAfterSecs` and retries once |
| `401 unauthorized: token superseded` | Another process authenticated as the same control DID; give each its own control key |
| A surface's presentation is not signed | No identity was resolved (`inject_vp is enabled but no identity binding VP was produced` in the gateway log); **Inject VP** only injects a presentation once an Identity element produces one |
| `FjallError: Locked` on a trust agent CLI write | The trust agent holds a lock on its store while running; stop it first |

### Testing against a real trust agent

The ignored `live_*` tests under `src/vta/` run against a real trust agent, with
`VTA_LIVE_URL`, `VTA_LIVE_DID` and, for some, `VTA_LIVE_PARENT_CONTEXT` or
`VTA_LIVE_OPERATOR` set. Run them with `-- --ignored --test-threads=1`: they authenticate as the
same seeded control key, and a parallel run supersedes their sessions. A local trust agent for
them is built from `verifiable-trust-infrastructure` with
`cargo build -p vta-service --features webvh --bin vta` (building that target alone keeps test
features out of the binary), set up with `vta setup`, given a context, and granted the control
`did:key` of the fixed test seed with the command above. Use `http://127.0.0.1:3000`, not
`localhost`, so the gateway dials IPv4. A few tests also need the grant raised to `admin` while
staying scoped to one context, which each such test names.

## Limits

### On the trust agent

- **A missing access entry does not stop signing at once.** The trust agent's signing gates read
  the entry live but, when it is missing, fall back to the role in the caller's access token, so a
  revoked or swapped-away DID can keep signing until its token expires (up to 15 minutes). Treat a
  suspected leak as "revoke, then wait out the token".
- **A rotated control key's old session lives on for up to 15 minutes**, for the same reason.
  Rotation protects against old copies of the key (backups, snapshots), not against a session
  already open. After a rotation the trust agent also keeps accepting the old key for its DID cache
  time (`[did_cache] ttl_secs`, 60 seconds by default, 300 at most).
- **The control key stays on the gateway.** It is what authenticates to the trust agent, so a
  compromised gateway can still ask the trust agent to sign within its grant. The grant is
  bounded, revocable and every use is attributable.
- **A published control `did:webvh`'s update key is the control key**, on this host. Revoking the
  access entry ends access whatever the document says, so revoke and grant again rather than
  rotating after a compromise.
- **The gateway's own `proxy_did` update key is its local issuer key.** Nothing resolves that DID
  for a trust decision today; anything that starts to would re-arm the exposure.

### Connections and surfaces

- **An agent's own key stays where it was created.** A surface that signs through its own
  connection has its identity credential issued by that trust agent, but each agent's own key,
  and so the presentation it makes, stays with the signer it was onboarded under, so one request
  can touch two signers.
- **A custom connection's control key is rotated by hand only**, with no schedule, and one that
  authenticates as a `did:key` cannot be rotated without a new grant.
- **A local development gateway's published control DID names its TLS port**, which a trust agent
  resolving a `localhost` DID over plain `http` cannot reach; development connections use
  `"control_identity": "did_key"`.
- **No per-tenant default.** A signing key is chosen per surface, per issuer or gateway-wide.

### Publication

- **The token endpoint publishes one key set.** `/oauth2/jwks.json` serves the gateway-wide
  signer's keys only, so a token a surface signs with another trust agent key may not verify
  through it; such a token verifies by resolving its `iss`.
- **Context `did:webvh` logs hosted by the gateway are republished on the next signature.** After
  the trust agent's operator rotates a context's key, a verifier resolving the DID sees the
  previous key, which signed everything so far, until the gateway next signs as it. Hosting on the
  trust agent's webvh server has no such window.
- **The trust agent hosts only its own DID.** Context `did:webvh` logs are served by the gateway
  or by a webvh server registered on the trust agent.
- **Issuer records keep their private keys on the gateway's disk** and are not in the key
  inventory.

### Local signing

- **The gateway's own keys live in its files.** Local signing is one code path, not a custody
  improvement; a KMS or HSM would plug in behind the library's `Signer` trait.
- **Credential proofs are `eddsa-rdfc-2022`** until every peer verifies `eddsa-jcs-2022`.
- **AP2 gateway presentations always sign locally**, even when a trust agent is chosen.

### Transports

- `transport = "unix"` is accepted in configuration and rejected by validation.
- DIDComm needs an adapter over the mediator client; a `didcomm` connection with no channel
  fails closed.
