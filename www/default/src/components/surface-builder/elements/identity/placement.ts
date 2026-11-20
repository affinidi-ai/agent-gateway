import type { DependencyNode } from '../types';
import { readMethods } from '../caller-auth/methods';

export const INBOUND_IDENTITY_NODE_ID = 'identity-inbound';
export const INBOUND_IDENTITY_SLOT_ID = 'request:identity-inbound';

/** True when the Identity node sits in the inbound caller slot (`identity_slots.inbound`). */
export const isInboundIdentity = (node?: Pick<DependencyNode, 'id' | 'slotId'>): boolean =>
  node?.id === INBOUND_IDENTITY_NODE_ID || node?.slotId === INBOUND_IDENTITY_SLOT_ID;

/** The Caller Context element, when the surface has one. */
export const callerAuthNode = (nodes: DependencyNode[]) =>
  nodes.find(n => n.type === 'caller-auth');

/** The Caller Context methods of the surface, in list order. */
export const callerAuthMethods = (nodes: DependencyNode[]) => {
  const callerAuth = callerAuthNode(nodes);
  return callerAuth ? readMethods(callerAuth.config) : [];
};
