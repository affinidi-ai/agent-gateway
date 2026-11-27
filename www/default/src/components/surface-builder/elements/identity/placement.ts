import type { DependencyNode } from '../types';

export const INBOUND_IDENTITY_NODE_ID = 'identity-inbound';
export const INBOUND_IDENTITY_SLOT_ID = 'request:identity-inbound';

/** True when the Identity node sits in the inbound caller slot (`identity_slots.inbound`). */
export const isInboundIdentity = (node?: Pick<DependencyNode, 'id' | 'slotId'>): boolean =>
  node?.id === INBOUND_IDENTITY_NODE_ID || node?.slotId === INBOUND_IDENTITY_SLOT_ID;

const TRANSIT_POINT_IDENTITY_SLOT_IDS = new Set([
  'request:identity-managed_identity',
  'response:identity-managed_identity',
]);

/** True when the Identity node is a Transit Point's `managed_identity`. */
export const isTransitPointIdentity = (node?: Pick<DependencyNode, 'slotId'>): boolean =>
  !!node?.slotId && TRANSIT_POINT_IDENTITY_SLOT_IDS.has(node.slotId);

/**
 * The Transit Point caller authentication (`source_auth.type`) each identity type that takes
 * its DID from the caller's credential needs.
 */
const TRANSIT_POINT_CALLER_METHODS: Record<string, ReadonlySet<string>> = {
  from_api_key: new Set(['api_key', 'api_key_provider']),
  from_jwt_claim: new Set(['jwt_bearer']),
  from_mtls: new Set(['mtls']),
};

/** Whether a Transit Point's `source_auth` lets this caller-bound identity type derive a DID. */
export const transitPointCallerAllows = (type: string, sourceAuth: unknown): boolean => {
  const methods = TRANSIT_POINT_CALLER_METHODS[type];
  const method =
    sourceAuth && typeof sourceAuth === 'object' ? (sourceAuth as { type?: unknown }).type : null;
  return !!methods && typeof method === 'string' && methods.has(method);
};
