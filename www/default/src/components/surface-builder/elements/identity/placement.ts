import type { DependencyNode } from '../types';

export const INBOUND_IDENTITY_NODE_ID = 'identity-inbound';
export const INBOUND_IDENTITY_SLOT_ID = 'request:identity-inbound';

/** True when the Identity node sits in the inbound caller slot (`identity_slots.inbound`). */
export const isInboundIdentity = (node?: Pick<DependencyNode, 'id' | 'slotId'>): boolean =>
  node?.id === INBOUND_IDENTITY_NODE_ID || node?.slotId === INBOUND_IDENTITY_SLOT_ID;
