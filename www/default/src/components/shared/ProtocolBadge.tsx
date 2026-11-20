import React from 'react';

export interface ProtocolMeta {
  key: string;
  label: string;
  badgeClass: string;
}

/** The surface protocols and their badge colours, the same on every page that shows one. */
export const SURFACE_PROTOCOLS: ProtocolMeta[] = [
  { key: 'a2a', label: 'A2A', badgeClass: 'text-bg-primary' },
  { key: 'ap2', label: 'AP2', badgeClass: 'text-bg-warning' },
  { key: 'mcp', label: 'MCP', badgeClass: 'text-bg-info' },
];

export function protocolMetaFor(protocol: string): ProtocolMeta {
  return (
    SURFACE_PROTOCOLS.find(p => p.key === protocol) ?? {
      key: protocol,
      label: protocol.toUpperCase(),
      badgeClass: 'text-bg-secondary',
    }
  );
}

export const ProtocolBadge: React.FC<{ protocol: string; 'data-testid'?: string }> = ({
  protocol,
  'data-testid': testId,
}) => {
  const meta = protocolMetaFor(protocol);
  return (
    <span className={`badge ${meta.badgeClass}`} data-testid={testId}>
      {meta.label}
    </span>
  );
};
