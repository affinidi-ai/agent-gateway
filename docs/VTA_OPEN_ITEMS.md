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

- **The gateway's own keys still live in its files.** `vta-signing` signs with them in memory,
  but the private keys are generated and kept by the gateway, so local signing is a single code
  path, not a custody improvement. Key storage, or a KMS or HSM, would plug in behind the
  library's `Signer` trait.
- **Credential proofs are `eddsa-rdfc-2022`.** The library signs `eddsa-jcs-2022` documents
  itself; the gateway keeps building the RDFC hash data and has the library sign it, because
  gateways that predate `eddsa-jcs-2022` verification would refuse JCS proofs. Moving to JCS
  waits until every peer runs a release that verifies it.
- **AP2 gateway presentations always sign locally.** They build their own local authority
  instead of using the one selected for the surface, so a connected trust agent never signs them.
- **The two-gateway suite (`make gw-e2e`) fails intermittently under parallelism.** On a
  development laptop a full run fails in roughly a third to a half of its runs (4 of 8 with the
  signing library, 2 of 6 on the release before it), in scenarios that depend on DID resolution
  or timing between the gateways (the restart backfill of a peer's issuer DID, concurrent MCP
  calls over the fabric). Each scenario passes when run alone, and the signing change does not
  cause it. Until it is traced, run the suite more than once and read a single failing scenario
  as suspect, not as proof.

## Tenancy and publication

- **No per-tenant default.** A signing key is chosen per surface, per issuer or gateway-wide;
  there is no tenant-level choice, so a tenant sets each of its surfaces or issuers.
- **Changing the gateway-wide trust agent changes the attested issuer.** A peer pins the issuer
  it was attested when the pair was made and refuses identity presentations from any other, so
  after the choice moves to another agent (or back to the gateway's own key) existing peers must
  be paired again.
- **The token endpoint publishes one key set.** `/oauth2/jwks.json` serves the key set of the
  gateway-wide signer only, so a token a surface signs with a different trust agent key may not
  verify through it.
- **Issuer records keep their private keys on the gateway's disk** and are not part of the
  key inventory.

## Transports

- `transport = "unix"` is accepted in configuration and rejected by validation.
- DIDComm needs an adapter over the mediator client; a `didcomm` connection with no channel
  fails closed.
