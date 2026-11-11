import type { DependencyNode } from '../types';

export const INBOUND_IDENTITY_NODE_ID = 'identity-inbound';
export const INBOUND_IDENTITY_SLOT_ID = 'request:identity-inbound';

/** True when the Identity node sits in the inbound caller slot (`identity_slots.inbound`). */
export const isInboundIdentity = (node?: Pick<DependencyNode, 'id' | 'slotId'>): boolean =>
  node?.id === INBOUND_IDENTITY_NODE_ID || node?.slotId === INBOUND_IDENTITY_SLOT_ID;

/** Identity types that read the credential the caller presented, so they can name the method. */
export const SOURCE_METHOD_TYPES: ReadonlySet<unknown> = new Set([
  'from_jwt_claim',
  'from_api_key',
]);

/** The id of the Caller Context method the inbound Identity reads, when it names one. */
export const referencedMethodId = (nodes: DependencyNode[]): string | undefined => {
  const inbound = nodes.find(n => n.type === 'identity' && isInboundIdentity(n));
  const config = inbound?.config as Record<string, any> | undefined;
  return config && SOURCE_METHOD_TYPES.has(config.type) && typeof config.source_method === 'string'
    ? config.source_method || undefined
    : undefined;
};
