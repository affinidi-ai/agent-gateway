import type { Protocol } from './elements/types';

/**
 * Protocols selectable when creating an Agent Surface.
 */
export const SURFACE_PROTOCOL_OPTIONS: Protocol[] = ['a2a', 'mcp'];

/**
 * Full set of `Protocol` values the type system recognises. Used for
 * validating untrusted inputs (e.g. `?protocol=` query strings) before
 * narrowing to a `Protocol`.
 */
export const ALL_PROTOCOLS: Protocol[] = ['a2a', 'ap2', 'mcp', 'didcomm'];

export interface ProtocolMeta {
  label: string;
  icon: string;
  description: string;
}

/**
 * Display metadata for protocols rendered as cards in the create flows
 * (Add Channel, Onboard, Create Surface). Single source of truth — do
 * not duplicate icon/description strings in individual call sites.
 */
export const PROTOCOL_META: Record<'a2a' | 'ap2' | 'mcp', ProtocolMeta> = {
  a2a: {
    label: 'A2A / UCP',
    icon: 'fas fa-exchange-alt',
    description:
      'Agent-to-Agent protocol for direct communication between intelligent agents, including support for UCP extensions',
  },
  ap2: {
    label: 'AP2',
    icon: 'fas fa-layer-group',
    description:
      'The Agent Payments Protocol (AP2) extends A2A with secure, auditable, payment-agnostic financial transactions initiated by AI agents.',
  },
  mcp: {
    label: 'MCP',
    icon: 'fas fa-plug',
    description: 'Model Context Protocol for connecting AI models with external data sources',
  },
};

/** Friendly label for a protocol, falling back to upper-cased id for unknown values. */
export function getProtocolLabel(p: Protocol | string): string {
  return (PROTOCOL_META as Record<string, ProtocolMeta>)[p]?.label ?? p.toUpperCase();
}
