# Trust agent control keys: how they rotate, in plain terms

## What the control key is

The Gateway and a trust agent (a VTA) know each other through a **control key**:

- The Gateway holds a private key, kept encrypted in its own storage. It never leaves the
  Gateway.
- Its public ID is either a `did:key` (the ID *is* the public key) or a `did:webvh` the Gateway
  publishes.
- The trust agent has an **access entry** for that ID. The entry says what the Gateway may do:
  sign tokens, sign documents, create keys and sub-areas, only inside its own area, with no admin
  rights.

Every time the Gateway talks to the trust agent, it proves it holds that private key.

The control key is **not** a signing key. Tokens, credentials and presentations are signed by
keys that live **inside the trust agent** when a trust agent is connected. The control key only
lets the Gateway *ask* the trust agent to sign.

There are two ways to replace a control key, one for each kind of ID. Neither is needed for the
Gateway to sign with its own keys.

## Rotating a `did:key` control key (`acl/swap-key`)

This applies to the trust agent connection set in the `[vta]` block of the Gateway's
configuration, when its control key is a `did:key` the Gateway keeps in a file
(`control_did_method = "did_key"` and `auth_key_source = "file://<path>"`).

Rotation gives the Gateway a new control key and moves its access entry to it:

1. The Gateway creates a new key and saves it, encrypted, as "pending".
2. Using the **current** key, it asks the trust agent to move its access entry to the new ID.
   The request carries a short proof, signed by the **new** key, that the new key agrees.
3. The trust agent moves the entry in one step. It copies it exactly: same rights, same area,
   nothing more.
4. The Gateway checks the new key works, then makes it the current key and drops the old one.

### What does not change

- The trust agent's own ID and the area the Gateway works in.
- The signing keys and their public keys, so everything already signed still verifies.
- The issuer ID on credentials. Receivers see no difference.

### When it happens

- **On demand**, from the dashboard: **Trust Agent** page → **Control key** card →
  **Rotate control key** (it asks you to confirm first). The same is available as
  `POST /v1/vta/control-key/rotate`.
- **On a schedule**, only if you set `control_key_rotation_days` in the `[vta]` block. The
  Gateway checks once an hour whether a rotation is due and adds a random delay of up to six
  hours, so many gateways don't rotate at the same moment.

The Trust Agent page shows the current control ID, when it was last rotated and when the next
rotation is due. `GET /v1/vta/status` reports the same under `control_key`
(`control_did`, `rotated_at`, `next_rotation_at`, `rotation_days`); it is absent when the
Gateway holds no `did:key` control key it can rotate.

The Gateway keeps running during a rotation. Requests that are in flight finish normally, and
the next request uses the new key.

If a scheduled rotation fails, the current key keeps working. The Gateway tries again after an
hour, then after two, four and so on up to a day, and logs an error once three attempts in a row
have failed.

### Setup

```toml
[vta]
# Days between automatic control-key rotations. 0 (the default) turns automatic rotation off.
control_key_rotation_days = 90
```

It is read at startup. Nothing has to be done on the trust agent: it already supports moving an
access entry.

### Security measures

- **Rights can't grow.** The trust agent copies the access entry exactly; the Gateway can't ask
  for more in a rotation.
- **Strong new keys.** Each new key comes from the operating system's secure random number
  generator.
- **Encrypted at rest.** The current and pending keys are stored encrypted, like the rest of the
  Gateway's key material.
- **Nothing secret leaves the Gateway.** Logs, the API, audit records and the dashboard show only
  public IDs, never keys or tokens.
- **Safe if interrupted.** The new key is saved *before* the trust agent is asked. If the Gateway
  stops halfway, the next start asks the trust agent which key is live and finishes or cancels the
  rotation. A rotation can't lock the Gateway out.
- **Catches up if another process rotated.** If the trust agent refuses the key the Gateway holds,
  the Gateway looks at the key stored for it, finishing an interrupted rotation first, and tries
  once more only if that is a different key. It never retries the same key.
- **Safe if refused.** If the trust agent refuses, the old key keeps working and nothing changes.
  A failed rotation never makes the Gateway sign locally instead.
- **One at a time.** Only one rotation runs at once, only the Active instance rotates on schedule,
  and a manual rotation is refused within ten minutes of the previous one.
- **Only authorised people.** The button and the API need key-management edit rights.
- **Audited on both sides.** The Gateway logs `vta_control_key_rotated` with the old and new IDs
  and what triggered it. The trust agent records every move of an access entry.

### What rotation does not protect against

- **The 15-minute window.** After a rotation, a session the old key already opened can keep
  working until it expires, up to 15 minutes. This is how the trust agent works today. It also
  means in-flight requests don't fail during a rotation.
- **Someone who holds the current key right now.** They could rotate it to a key of their own
  first. The Gateway would then be refused, which is visible, and the trust agent's audit shows
  the move. Recovery is an operator re-granting the Gateway on the trust agent.

Rotation protects against **old copies** of the key: backups, disk snapshots, or a copied storage
folder stop working once the key has been rotated.

### Restoring a backup

A backup taken before the last rotation contains a control key the trust agent no longer accepts.
To recover **without losing any signing keys**:

1. Print the ID of the restored key: `agent-gateway --vta-print-control-did`.
2. On the trust agent, grant that ID the same rights again:
   ```bash
   vta acl create --did <that ID> --role initiator --contexts <context> \
     --capabilities context-create,key-mint,sign-jws,sign-document --label agent-gateway
   ```
3. Start the Gateway.

## Rotating a `did:webvh` control key (connections you add yourself)

A connection you add from the dashboard authenticates as a `did:webvh` the Gateway publishes, so
its key can be replaced **without a new grant**: the ID stays the same and the trust agent's access
entry is untouched. This is done by hand, from the **Rotate control key** action on the
connection's row on the Trust Agent page (or `POST /v1/vta/connections/{id}/control-key/rotate`).
There is no schedule for it.

1. The Gateway adds a new key to the published document, beside the old one.
2. It signs in to the trust agent with the new key, through the connection it already has.
3. It removes the old key and deletes its secret.

Normally this takes a few seconds and signing carries on throughout. If the trust agent refuses the
new key, the Gateway keeps trying for a while (`[vta] connection_key_switch_timeout_secs`, 330
seconds by default), then goes back to the old key and says so; the old key was never removed until
the new one had worked. A rotation that a restart interrupted is resumed, and one that has not
switched yet can be cancelled.

The same limits apply as above: after the old key is removed the trust agent may keep accepting it
for its own DID cache time (60 seconds by default, 300 at most), and a session it already opened
can last up to 15 minutes.

## Not covered

Scheduled rotation of a connection you added, and rotation of a `did:key` connection you added
without a new grant, are not done.
