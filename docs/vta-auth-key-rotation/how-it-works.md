# Bundled trust agent: how the control key rotates, in plain terms

## What the control key is

The Gateway and its bundled trust agent (the VTA sidecar) know each other through a
**control key**:

- The Gateway holds a private key, kept encrypted in its own storage. It never leaves the
  Gateway.
- Its public ID is a `did:key` (for a `did:key` the ID *is* the public key).
- The trust agent has an **access entry** for that ID. The entry says what the Gateway may do:
  sign tokens, sign documents, create keys and sub-areas, only inside the `gateway` area, with
  no admin rights.

Every time the Gateway talks to the trust agent, it proves it holds that private key.

The control key is **not** a signing key. Credentials, tokens and presentations are signed
by keys that live **inside the trust agent** (`gateway-jwt-N`, `gateway-issuer`, and one key
per agent). The control key only lets the Gateway *ask* the trust agent to sign.

## What rotation does

Rotation gives the Gateway a new control key and moves its access entry to it:

1. The Gateway creates a new key and saves it, encrypted, as "pending".
2. Using the **current** key, it asks the trust agent to move its access entry to the new ID.
   The request carries a short proof, signed by the **new** key, that the new key agrees.
3. The trust agent moves the entry in one step. It copies it exactly: same rights, same
   area, nothing more.
4. The Gateway checks the new key works, then makes it the current key and drops the old one.

### What does not change

- The trust agent's own ID and the `gateway` area.
- The signing keys and their public keys, so everything already signed still verifies.
- The issuer ID on credentials. Receivers see no difference.
- The agents' own keys and IDs.

## When it happens

- **Automatically, every 90 days** by default. The Gateway checks once an hour whether a
  rotation is due and adds a random delay of up to six hours, so many gateways don't rotate
  at the same moment.
- **On demand**, from the dashboard: **Trust Agent** page → **Bundled trust agent control key**
  card → **Rotate control key** (it asks you to confirm first). The same is available as
  `POST /v1/vta/control-key/rotate`.
- **Offline**, with the Gateway stopped: `agent-gateway --vta-rotate-control-key --yes`.

The Trust Agent page shows the current control ID, when it was last rotated and when the next
rotation is due. `GET /v1/vta/status` reports the same as `control_key_rotated_at`,
`control_key_next_rotation_at` and `control_key_rotation_days`.

The Gateway keeps running during a rotation. Requests that are in flight finish normally, and
the next request uses the new key.

If a scheduled rotation fails, the current key keeps working. The Gateway tries again after an
hour, then after two, four and so on up to a day, and logs an error once three attempts in a row
have failed.

## Setup

One setting in the `[vta]` block of the Gateway's configuration:

```toml
[vta]
# Days between automatic control-key rotations. 0 turns automatic rotation off.
control_key_rotation_days = 90
```

It applies only to the bundled trust agent. It is read at startup.

Nothing has to be done on the trust agent: it already supports moving an access entry.

## Security measures

- **Rights can't grow.** The trust agent copies the access entry exactly; the Gateway can't
  ask for more in a rotation.
- **Strong new keys.** Each new key comes from the operating system's secure random number
  generator.
- **Encrypted at rest.** The current and pending keys are stored encrypted, like the rest of
  the Gateway's key material.
- **Nothing secret leaves the Gateway.** Logs, the API, audit records and the dashboard show
  only public IDs, never keys or tokens.
- **Safe if interrupted.** The new key is saved *before* the trust agent is asked. If the
  Gateway stops halfway, the next start asks the trust agent which key is live and finishes
  or cancels the rotation. A rotation can't lock the Gateway out.
- **Catches up if another process rotated.** If the trust agent refuses the key the Gateway
  holds, the Gateway looks at the key stored for it, finishing an interrupted rotation first,
  and tries once more only if that is a different key. It never retries the same key.
- **Safe if refused.** If the trust agent refuses, the old key keeps working and nothing
  changes. A failed rotation never makes the Gateway sign locally instead.
- **One at a time.** Only one rotation runs at once, only the Active instance rotates on
  schedule, and a manual rotation is refused within ten minutes of the previous one.
- **Only authorised people.** The button and the API need key-management edit rights.
- **Audited on both sides.** The Gateway logs `vta_control_key_rotated` with the old and new
  IDs and what triggered it. The trust agent records every move of an access entry.

## What rotation does not protect against

- **The 15-minute window.** After a rotation, a session the old key already opened can keep
  working until it expires, up to 15 minutes. This is how the trust agent works today. It
  also means in-flight requests don't fail during a rotation.
- **Someone who holds the current key right now.** They could rotate it to a key of their
  own first. The Gateway would then be refused, which is visible, and the trust agent's audit
  shows the move. Recovery is an operator re-granting the Gateway on the trust agent.

Rotation protects against **old copies** of the key: backups, disk snapshots, or a copied
storage folder stop working once the key has been rotated.

## Restoring a backup

A backup taken before the last rotation contains a control key the trust agent no longer
accepts. To recover **without losing any signing keys**:

1. Print the ID of the restored key: `agent-gateway --vta-print-control-did`.
2. On the trust agent, grant that ID the same rights again:
   ```bash
   vta acl create --did <that ID> --role initiator --contexts gateway \
     --capabilities context-create,key-mint,sign-jws,sign-document --label agent-gateway-bundled
   ```
3. Start the Gateway.

Don't use `--vta-rebootstrap` for this: it creates new signing keys, which changes the
issuer.

## Not covered

Trust agents you connect yourself from the dashboard use a `did:webvh` control ID. Their key
rotates by updating the published DID document, which is a different mechanism and is not
part of this.
