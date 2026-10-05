/**
 * Capability constants for the element registry.
 *
 * Capabilities are strings that describe what an element provides or needs.
 * Compatibility checks compare a candidate's `requires` against the union
 * of capabilities provided by source/target nodes.
 */

// ─── Pipeline capabilities ──────────────────────────────────────────────────
export const PIPELINE_SOURCE = 'pipeline-source'; // access-point provides
export const PIPELINE_SINK = 'pipeline-sink'; // target provides
export const PIPELINE_EDGE = 'pipeline-edge'; // middleware lives between source/sink
export const EGRESS_CAPABLE = 'egress-capable'; // transit-point provides

// ─── Structural capabilities ────────────────────────────────────────────────
export const SURFACE_PERIMETER = 'surface-perimeter'; // AP, TP snap to surface edge
export const SURFACE_INTERIOR = 'surface-interior'; // Target lives inside surface
export const MIDDLEWARE_SLOT = 'middleware-slot'; // Can host middleware on its edges

// ─── Feature capabilities (what middleware can attach to) ───────────────────
export const IDENTITY_TARGET = 'identity-target';
export const POLICY_TARGET = 'policy-target';
export const PAYMENT_TARGET = 'payment-target';
export const NETWORKING_TARGET = 'networking-target';
export const RATE_LIMIT_TARGET = 'rate-limit-target';
export const TRUST_REGISTRY_TARGET = 'trust-registry-target';
export const EXTENSION_TARGET = 'extension-target';
export const METADATA_TARGET = 'metadata-target';
export const MCP_TOOL_TARGET = 'mcp-tool-target';
export const CREDENTIAL_TARGET = 'credential-target';
export const WORKLOAD_BINDING_TARGET = 'workload-binding-target'; // transit-point provides

// ─── Actor capabilities ─────────────────────────────────────────────────────
export const NPC_CONNECTABLE = 'npc-connectable'; // Can have NPC nodes attached
export const CONFIGURABLE = 'configurable'; // Has a config panel

// ─── Edge-attach hints (which side of the pipeline middleware runs on) ──────
export const ATTACHES_TO_INGRESS = 'attaches-to-ingress'; // AP-side
export const ATTACHES_TO_TARGET = 'attaches-to-target'; // Target-side
export const ATTACHES_TO_EGRESS = 'attaches-to-egress'; // Transit-side
