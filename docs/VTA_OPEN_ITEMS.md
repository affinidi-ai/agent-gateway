# Trust agent open items

What the trust agent (VTA) integration does not do yet, and the limits worth knowing
about. The behaviour that exists is in [`VTA_INTEGRATION_POC.md`](VTA_INTEGRATION_POC.md).

## On the trust agent

- **A missing access entry does not stop signing at once.** The signing gates read the entry
  live but, when it is missing, fall back to the role in the caller's access token. A revoked or
  swapped-away DID can keep signing until its access token expires (up to 15 minutes). Until a
  missing entry denies, treat a suspected leak as "revoke, then wait out the token".
- **`Capability::ContextCreate` is not in a released trust agent.** The bundled sidecar's grant
  names it, so the sidecar image must be built from the `gateway-integration` branch until it
  is released with its specification change.
- **The offline CLI's audit rows** are written by the `gateway-integration` branch; a trust
  agent built without that change enrols the gateway with no audit record.

## Custom trust agents beside the bundled default

- **An agent's own key stays in the appliance default.** A surface that signs through a custom
  connection has its identity credential issued by that trust agent, but each agent's own key,
  and so the presentation it holds, is created in and signed by the appliance default (the
  bundled sidecar), because an onboarded agent keeps its key where it was created. Only the
  issuer's signature moves to the custom trust agent.
- **A custom connection's `did:webvh` control identity needs the trust agent to reach the
  gateway over the address it was published at.** A local development gateway names its TLS
  port, which a trust agent resolving a `localhost` DID over plain `http` cannot reach, so the
  live check connects its custom trust agent with `control_identity: "did_key"`.
- **Surface signing cannot name the bundled connection.** A surface's `signing.connection_id`
  of `vta-bootstrap` is refused as unusable (the record has no control key of its own); the
  bundled sidecar is reached through the appliance default only.

## On the bundled sidecar

- **No person owns it.** The super-admin slot stays empty (`owner: unclaimed`). A claim flow
  (a one-time code with a claim check shown on both sides) would let a person become the owner
  and see or revoke the gateway's access.
- **Its own DID is a `did:key`.** A `did:webvh` needs a recovery-key custodian outside the
  deployment, which a claim would provide.
- **A sidecar that starts after the gateway is only picked up at the next start.** There is no
  hot adoption.
- **Control-key rotation needs the gateway stopped.** The running connector holds the key in
  memory and the trust agent supersedes a DID's session when it authenticates again.
- **The Kubernetes pod was validated for syntax only.** The Compose example is run with real
  containers by `scripts/vta-bundled-compose-e2e.sh`; no cluster was available for the pod.
- **Compose restarts must be ordered.** The sidecar joins the gateway's network namespace, so
  restart the gateway first and the sidecar second. A plain `docker compose restart` fails
  the sidecar and Docker's restart policy does not bring it back.
- **The images need more than 8 GB to build.** `vti-specs-core` and the `agent-gateway` crate
  are killed by the out-of-memory killer in an 8 GB Docker VM; 16 GB builds both.

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
