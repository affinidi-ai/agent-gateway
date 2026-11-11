# Trust agent open items

What the trust agent (VTA) integration does not do yet, and the limits worth knowing
about. The behaviour that exists is in [`VTA_INTEGRATION_POC.md`](VTA_INTEGRATION_POC.md).

## On the trust agent

- **A missing access entry does not stop signing at once.** The signing gates read the entry
  live but, when it is missing, fall back to the role in the caller's access token. A revoked or
  swapped-away DID can keep signing until its access token expires (up to 15 minutes). Until a
  missing entry denies, treat a suspected leak as "revoke, then wait out the token".
- **`Capability::ContextCreate` is not in a released trust agent.** A grant that names it needs
  a trust agent built from the `verifiable-trust-infrastructure` branch `gateway-integration`,
  until it is released with its specification change.
- **A rotated control key's old session lives on for up to 15 minutes.** After a swap the
  trust agent's signing gates fall back to the role in an already-issued access token, so a
  copy of the old key that holds a token keeps signing until it expires. Rotation protects
  against old copies of the key (backups, snapshots), not against a session already open.
  The trust agent ending the old DID's sessions on a swap would close this.

## Custom trust agents for one surface

- **An agent's own key stays in the default signing.** A surface that signs through a custom
  connection has its identity credential issued by that trust agent, but each agent's own key,
  and so the presentation it holds, is created in and signed by the appliance default, because
  an onboarded agent keeps its key where it was created. Only the issuer's signature moves to
  the custom trust agent.
- **A custom connection's `did:webvh` control identity needs the trust agent to reach the
  gateway over the address it was published at.** A local development gateway names its TLS
  port, which a trust agent resolving a `localhost` DID over plain `http` cannot reach, so the
  live check connects its custom trust agent with `control_identity: "did_key"`.
- **Surface signing cannot name the `vta-bootstrap` connection.** A surface's
  `signing.connection_id` of `vta-bootstrap` is refused as unusable (the record has no control
  key of its own); the `[vta]` block is reached through the appliance default only.
- **A custom connection's control key can only be rotated by hand, and only as a `did:webvh`.**
  There is no schedule for it, and a connection that authenticates as a `did:key` cannot be
  rotated without a new grant. After a rotation the trust agent keeps accepting the old key for
  its DID cache time (60 seconds by default, 300 at most).

## Local signing

- **The gateway's own keys still live in its files.** The VTA library signs with them from an
  in-process working store, but the private keys are generated and kept by the gateway, so local
  signing is a single code path, not a custody improvement. Generating keys inside the library
  needs a storage design for a store shared by an Active and a Standby node.
- **Credential proofs are `eddsa-rdfc-2022`.** The library signs `eddsa-jcs-2022` documents
  itself; the gateway keeps building the RDFC hash data and has the library sign it, because
  gateways that predate `eddsa-jcs-2022` verification would refuse JCS proofs. Moving to JCS
  waits until every peer runs a release that verifies it.
- **AP2 gateway presentations always sign locally.** They build their own local authority
  instead of using the one selected for the surface, so a connected trust agent never signs them.
- **The library's signing path decrypts the imported key and writes an audit row per
  signature.** If that shows up in signing latency, a per-key cache belongs inside the library.
- **`vta-service` needs `rest` and `didcomm` enabled to build.** Its default-features-off build
  does not compile, and its HTTP dependency selects the aws-lc backend of the JWT library.

- **The two-gateway suite (`make gw-e2e`) fails intermittently under parallelism.** Linking the
  VTA crates moves the DID resolver libraries to newer versions, and with them the suite fails
  in roughly half of its full runs, in scenarios that depend on DID resolution between the
  gateways (the restart backfill of a peer's issuer DID, 50 concurrent MCP calls over the
  fabric). Each of those scenarios passes when run alone, and the commit before the VTA crates
  were linked passed every full run. The failures also appear on the commit that only adds the
  dependencies, so they do not come from the signing change. Until it is traced, run the suite more than once and read a single failing scenario as
  suspect, not as proof. Pinning the resolver to 0.8.43 with `vta-service` 0.78 lowered the
  failure rate (one failing full run in four) without removing it, so the resolver version alone
  does not explain it.

## Tenancy and publication

- **No per-tenant default.** `KeyDirectory::with_tenant_mapping` exists but nothing calls it, and
  signing scopes carry no `tenant_id`, so a tenant maps each surface by hand.
- **The token endpoint publishes one key set.** `/oauth2/jwks.json` serves the appliance's
  signer; `KeyDirectory::jwks()`, which would publish every connection's keys, is not served,
  so a token a surface signs with a tenant's own trust agent key may not verify through it.
- **Issuer records keep their private keys on the gateway's disk** and are not part of the
  key inventory.

## Transports

- `transport = "unix"` is accepted in configuration and rejected by validation.
- DIDComm needs an adapter over the mediator client; a `didcomm` connection with no channel
  fails closed.
