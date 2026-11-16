import type { DependencyNode } from '../types';
import { readMethods } from '../caller-auth/methods';
import { effectiveSourceMethod } from './sourceMethods';

export const INBOUND_IDENTITY_NODE_ID = 'identity-inbound';
export const INBOUND_IDENTITY_SLOT_ID = 'request:identity-inbound';

/** True when the Identity node sits in the inbound caller slot (`identity_slots.inbound`). */
export const isInboundIdentity = (node?: Pick<DependencyNode, 'id' | 'slotId'>): boolean =>
  node?.id === INBOUND_IDENTITY_NODE_ID || node?.slotId === INBOUND_IDENTITY_SLOT_ID;

/** The Caller Context methods of the surface, in list order. */
export const callerAuthMethods = (nodes: DependencyNode[]) => {
  const callerAuth = nodes.find(n => n.type === 'caller-auth');
  return callerAuth ? readMethods(callerAuth.config) : [];
};

/** The id of the Caller Context method the inbound Identity reads, when it reads one. */
export const referencedMethodId = (nodes: DependencyNode[]): string | undefined => {
  const inbound = nodes.find(n => n.type === 'identity' && isInboundIdentity(n));
  return effectiveSourceMethod(inbound?.config, callerAuthMethods(nodes));
};
