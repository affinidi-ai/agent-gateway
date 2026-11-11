// Kept free of imports: `TrustCheckQueryForm` reads these at module load, and it is loaded
// from `definition.ts` through `TrustCheckPanel`, so taking them from `definition.ts` would
// read them before they are initialized.

export const AGENT_IDENTITY_ISSUER_DID_TEMPLATE = '{{ input.agent.identity_issuer_did }}';
/**
 * The `{{ input.gateway.source_id }}` template resolves at runtime to
 * the DID of the **sending gateway** on the fabric-inbound receive path
 * (populated by `process_forward_request` on GW2). On direct inbound
 * (non-fabric) the value is `null` and the template resolves empty — the
 * Trust Check probe then denies fail-safe. Only meaningful on the caller
 * leg (`ap-ma`) of surfaces that are reachable via `fabric://`.
 */
export const INPUT_GATEWAY_SOURCE_ID_TEMPLATE = '{{ input.gateway.source_id }}';
