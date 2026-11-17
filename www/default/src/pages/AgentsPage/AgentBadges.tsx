import React from 'react';
import type { AgentIdentity, AgentTrustRegistry } from '../../api';
import { Badge } from '../../components/shared/Badge';
import { CopyButton } from '../../components/shared/CopyButton';
import { NO_DID, protocolLabel, protocolTone, shortenDid, trustRegistryLabel } from './agentLabels';

/** The protocol only; how the agent is reached is the Route. */
export const AgentProtocolBadge: React.FC<{ protocol: string }> = ({ protocol }) => (
  <Badge
    value={protocolLabel(protocol)}
    tone={protocolTone(protocol)}
    size="sm"
    data-testid="agents-protocol-badge"
  />
);

/** `Recorded` when any of the agent's identities was recorded to a trust registry. */
export const AgentTrustRegistryBadge: React.FC<{ trust: AgentTrustRegistry }> = ({ trust }) => {
  if (!trust.recorded) {
    return (
      <span className="badge badge-none" data-testid="agents-trust-not-recorded">
        {trustRegistryLabel(trust)}
      </span>
    );
  }
  return (
    <Badge
      value={trustRegistryLabel(trust)}
      tone="success"
      size="sm"
      prefix={<i className="fas fa-check-circle me-1" aria-hidden="true" />}
      data-testid="agents-trust-recorded"
    />
  );
};

interface AgentDidProps {
  did: string;
  /** Show the full DID instead of the shortened one. */
  full?: boolean;
}

/** A DID in monospace with a copy button; the shortened form keeps the full value as tooltip. */
export const AgentDid: React.FC<AgentDidProps> = ({ did, full = false }) => (
  <span className="d-inline-flex align-items-center" style={{ minWidth: 0 }}>
    <code className="small text-break" title={did} data-testid="agents-did">
      {full ? did : shortenDid(did)}
    </code>
    <CopyButton text={did} title="Copy DID" data-testid="agents-copy-did-button" />
  </span>
);

/** Every identity of the agent, one per line, or `No DID` without any. */
export const AgentIdentities: React.FC<{ identities: AgentIdentity[] }> = ({ identities }) => {
  if (identities.length === 0) {
    return (
      <span className="text-muted small" data-testid="agents-no-did">
        {NO_DID}
      </span>
    );
  }
  return (
    <ul className="list-unstyled mb-0" data-testid="agents-identities">
      {identities.map(identity => (
        <li key={identity.did}>
          <AgentDid did={identity.did} />
        </li>
      ))}
    </ul>
  );
};
