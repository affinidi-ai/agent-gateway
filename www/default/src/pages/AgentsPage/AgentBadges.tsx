import React from 'react';
import type { AgentTrustRegistry } from '../../api';
import { Badge } from '../../components/shared/Badge';
import { CopyButton } from '../../components/shared/CopyButton';
import {
  NO_DID,
  NO_TRUST_REGISTRY,
  TRUST_NOT_CHECKED,
  protocolBadgeLabel,
  protocolTone,
  shortenDid,
  statusLabel,
  trustRegistryLabels,
} from './agentLabels';

export const AgentProtocolBadge: React.FC<{ protocol: string; runtime: string }> = ({
  protocol,
  runtime,
}) => (
  <Badge
    value={protocolBadgeLabel(protocol, runtime)}
    tone={protocolTone(protocol)}
    size="sm"
    data-testid="agents-protocol-badge"
  />
);

export const AgentStatusBadge: React.FC<{ status: string }> = ({ status }) => (
  <Badge
    value={statusLabel(status)}
    tone={status === 'active' ? 'success' : 'secondary'}
    size="sm"
    data-testid="agents-status-badge"
  />
);

/** Configuration only: the title says it wasn't checked against a registry. */
export const AgentTrustRegistryBadges: React.FC<{ trust: AgentTrustRegistry }> = ({ trust }) => {
  const labels = trustRegistryLabels(trust);
  if (labels.length === 0) {
    return (
      <span className="badge badge-none" data-testid="agents-trust-none">
        {NO_TRUST_REGISTRY}
      </span>
    );
  }
  return (
    <span className="d-inline-flex flex-wrap" style={{ gap: '0.25rem' }} title={TRUST_NOT_CHECKED}>
      {labels.map(label => (
        <Badge
          key={label}
          value={label}
          tone="info"
          size="sm"
          prefix={<i className="fas fa-check-circle me-1" aria-hidden="true" />}
          data-testid={`agents-trust-${label.toLowerCase()}`}
        />
      ))}
    </span>
  );
};

interface AgentDidProps {
  did: string | null;
  /** Shown as the tooltip, after the full DID. */
  note?: string | null;
  /** Show the full DID instead of the shortened one. */
  full?: boolean;
}

/** The agent's DID in monospace with a copy button, or `No DID` without one. */
export const AgentDid: React.FC<AgentDidProps> = ({ did, note, full = false }) => {
  if (!did) {
    return (
      <span className="text-muted small" data-testid="agents-no-did">
        {NO_DID}
      </span>
    );
  }
  return (
    <span className="d-inline-flex align-items-center" style={{ minWidth: 0 }}>
      <code
        className="small text-break"
        title={note ? `${did}\n${note}` : did}
        data-testid="agents-did"
      >
        {full ? did : shortenDid(did)}
      </code>
      <CopyButton text={did} title="Copy DID" data-testid="agents-copy-did-button" />
    </span>
  );
};
