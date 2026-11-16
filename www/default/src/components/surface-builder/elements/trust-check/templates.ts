// Imports nothing: TrustCheckQueryForm reads these when it loads, which can happen while
// definition.ts is still loading, since definition.ts imports the panels that render the form.

/**
 * The `{{ input.agent.provider_did }}` template — the caller's **provider**
 * DID (e.g. the department / issuing org) resolved at runtime from the
 * caller's `https://fabric.affinidi.io/extensions/trust-registry`
 * extension.
 *
 * This is **no longer** the caller-leg Authority default: both legs now
 * require the operator to pick an explicit Issuer / Authority literal DID
 * from the gateway's own registers (see `classifyTargetAuthoritySelection`),
 * because deriving the authority from a payload / agent-card trust-registry
 * extension trips the runtime `TRUST_REGISTRY_METADATA_UNAVAILABLE` gate
 * whenever that extension is absent. The constant survives only as the
 * template for the Entity ID picker's `provider` subject (a JSON-API /
 * power-user option), mapped via `templateForSubject` / `subjectForTemplate`.
 */
export const AUTHORITY_ID_TEMPLATE = '{{ input.agent.provider_did }}';

/**
 * Other OPA `PolicyInput` template tokens used across the Trust Check UI.
 * Kept as named constants so the panel copy, the Advanced Entity ID help,
 * and the fullscreen editor banners all reference one canonical string —
 * avoiding subtle whitespace typos (`{{input.agent.did}}` vs
 * `{{ input.agent.did }}`) that would silently fail at runtime as
 * `TEMPLATE_RESOLUTION_FAILED`.
 */
export const AGENT_DID_TEMPLATE = '{{ input.agent.did }}';
export const AGENT_AUTHORITY_DID_TEMPLATE = '{{ input.agent.authority_did }}';
export const EXTENSION_IDENTITY_DID_TEMPLATE = '{{ input.extension_identity.did }}';
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
