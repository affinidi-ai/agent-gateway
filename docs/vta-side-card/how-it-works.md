# Bundled VTA sidecar: how it works, in plain terms

The detailed, step-by-step engineering plan is
[`implementation-plan.md`](implementation-plan.md).

## What we're building

Today, to let the Gateway sign through a VTA (Verifiable Trust Agent), someone has to:
1. run a VTA somewhere,
2. copy its address and DID into the Gateway,
3. run a "grant" command on the VTA by hand,
4. restart things.

**After this change, a new installation does all of that by itself.** The VTA ships as a second
container next to the Gateway (a "sidecar"). On first start the two set themselves up and connect.
Nobody is asked anything.

The manual "connect my own VTA" option stays exactly as it is, for people who host their own VTA.

## How it works, step by step

Three things are involved:
- the **Gateway** container
- the **VTA** container
- a small **shared folder** that both can see

### The first start

1. **The Gateway creates its identity.**
   - It generates a private key and keeps it encrypted in its own storage. The key never leaves
     the Gateway.
   - From that key it gets its public ID, a `did:key`.
2. **The Gateway leaves a note in the shared folder:** "my ID is `did:key:…`". The note holds
   only public information.
3. **The VTA sets itself up, once.**
   - It creates its master seed (stored encrypted) and its own ID (also a `did:key`).
   - It creates a `gateway` area (a "context").
   - It registers the Gateway's ID with **limited rights**: sign tokens, sign documents, create
     keys, and create sub-areas. Only inside `gateway`, and **no admin rights**.
   - What the Gateway may do is fixed by our VTA startup script, not by the note. The note only
     says *who* the Gateway is.
4. **The VTA writes its own ID back to the shared folder**, then starts listening on `127.0.0.1`
   (its own loopback). Only the Gateway can reach it.
5. **The Gateway connects.**
   1. It reads the VTA's ID and **remembers it** (pins it). From then on it only talks to that VTA.
   2. It logs in with its key.
   3. It checks it got **exactly** the rights it expected. More counts as an error, not a bonus.
6. **The Gateway asks the VTA to create a signing key that can never be exported**, and saves that
   key's public half.
7. **Done.** Tokens and credentials are now signed inside the VTA.

### Every start after that

- Both sides see "already set up" and skip the steps above.
- The Gateway logs in again with the same key, to the same remembered VTA.

### When something goes wrong

| Situation | What happens |
|---|---|
| The VTA is slow or down on the very first start | The install still finishes, using the Gateway's own key, and the dashboard says why. |
| A *different* VTA shows up at the address | The Gateway refuses it and reports it. |
| The VTA's data was lost | The Gateway does **not** silently create a new one, because that would break everything signed before. It reports the problem, and an operator runs one explicit recovery command. |
| Someone revoked the Gateway's access | The Gateway stops signing and does **not** re-register itself. |

### Later (not in this iteration)

A person will be able to "claim" the sidecar VTA with a one-time code and become its owner. They
will then see and control the Gateway's access like any other client. Until then the VTA has no
human owner. Admin work means running the VTA's command-line tool on the host.

## What changes where

### In the VTA

Very little, and nothing in its network API:
- **Our own startup script** for the VTA container runs the VTA's existing commands in order:
  `vta setup` (no admin), `vta context create`, `vta acl create` (registers the Gateway's ID).
  Then it starts the VTA.
- **A base setup file** that we ship:
  - `did:key` for the VTA
  - listens on loopback only
  - encrypted seed storage, with the passphrase supplied as a secret
  - no messaging services
- **Small upstream changes:**
  - **Done:** the offline "register a client" and "create context" commands now write an audit
    record (on our `gateway-integration` branch).
  - **Needed:** the "may create sub-contexts" capability (`context-create`) must be merged and
    released. Until then, the sidecar image is built from our `gateway-integration` branch.
  - **Strongly recommended:** once a client's access entry is removed, it should be refused at
    once. Today it can keep signing for up to 15 minutes, until its login token expires.
  - **Nice to have:** let the setup file grant capabilities directly, and a cleaner way to read the
    VTA's ID after setup.

### In the Gateway

1. **First fix:** the automatic connection must use `did:key`.
   - A recent change made the Gateway publish and use a `did:webvh` by default.
   - That is fine for a manually connected VTA. For the sidecar it breaks login, because the
     sidecar can't reach the Gateway's public address to look the DID up.
   - We add one deployment setting that chooses the method (`control_did_method = "did_key"` or
     `"did_webvh"`). The default for the sidecar is `did_key`.
2. **The automatic set-up step:**
   - write the note
   - wait for the VTA
   - remember (pin) its ID
   - log in
   - check the rights
   - create the signing key
   - save everything encrypted
3. **Clear status in the API and dashboard:** connected, waiting for the VTA, refused, VTA
   replaced, VTA lost, or revoked. Plus who owns the VTA (for now, "unclaimed").
4. **Control-key rotation** using the VTA's existing `acl/swap-key` operation (explained below), as the
   command `agent-gateway --vta-rotate-control-key --yes`, run with the gateway stopped.
5. **A corrected Docker Compose example and a new Kubernetes example**, with both images pinned.
6. **Docs, tests and a changelog entry.**

## Why `did:key` for the Gateway's control key

The control key is what the Gateway uses to log in to the VTA.

**Rotation works the same way as with `did:webvh`.** The VTA already supports swapping a client's
key: `acl/swap-key`.
1. The Gateway, logged in with its current key, creates a new key.
2. The new key signs a short "I agree to take over" note.
3. The VTA moves the Gateway's access entry to the new key. It keeps exactly the same rights,
   and nobody else has to approve it.

One caveat applies today: after a swap, the old key's current login token keeps working until it
expires (up to 15 minutes). The fix is a small VTA change listed above.

That is the same idea as rotating a `did:webvh`. **The risk is the same too.** Anyone who steals
the current key can rotate it to their own key and lock the Gateway out. With either method,
recovery is an admin granting access again, and both leave an audit record.

**What `did:key` saves us is infrastructure:**
- With a `did:webvh` the Gateway must **host** its DID document on a public HTTPS address.
- The VTA must **look it up on every login**.
- The Gateway's public domain must be known **at first boot**.

The sidecar listens only on loopback and has no route to the Gateway's public address, so it
would need extra networking and a DID resolver just to log in. A `did:key` carries its public key
inside the ID itself. Nothing to host, nothing to look up, nothing that can be unreachable.

**The option stays.** A deployment setting can still choose `did_webvh`, and manually connected
VTAs keep `did:webvh` as their default.

## Why `did:key` for the VTA itself (this iteration)

- **The VTA isn't a public service.** It is an internal helper that only the Gateway talks to,
  and the Gateway already knows and pins its ID. Nobody outside needs to look the VTA's DID up.
- **A `did:webvh` would have to be hosted by the Gateway.** The VTA must never be exposed, so
  the Gateway would have to publish the VTA's DID document for it, adding moving parts for no
  benefit here.
- **The keys never leave the VTA anyway.** Signing keys are non-exportable whatever DID method
  the VTA uses, so `did:webvh` adds no protection for them.
- **It wouldn't help against a full compromise.** If the whole deployment (Gateway, VTA and
  host) is compromised, the attacker controls everything a `did:webvh` update could do as well.
- **The spec asks for something a fresh install doesn't have.** A `did:webvh` with update keys
  must commit to a recovery key held by someone *outside* this deployment. That can't exist on a
  fresh install with no human involved.

That makes a natural next step: when a person claims the VTA, they can become that outside
custodian, and switching the VTA to `did:webvh` then makes sense.

## What this does *not* claim

The sidecar shares a host, a disk and an operator with the Gateway. So this tier improves **key
management** (keys are non-exportable, separated, audited and rate-limited), but it is **not** a
"your keys are held by an independent party" setup. The dashboard and API keep saying so
(`custody_claim: false`). That claim belongs to a VTA that someone else operates.
