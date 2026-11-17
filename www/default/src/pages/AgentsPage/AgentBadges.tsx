import React from 'react';
import type { AgentIdentity, AgentTrustRegistry } from '../../api';
import { Badge } from '../../components/shared/Badge';
import { TrustRecorderStateBadge } from '../../components/trust-recorder/TrustRecorderStateBadge';
import { CopyButton } from '../../components/shared/CopyButton';
import {
  NO_DID,
  identitiesLabel,
  protocolBadgeClass,
  protocolLabel,
  routeDescription,
  runtimeIcon,
  runtimeLabel,
  shortenDid,
  trustRegistryLabel,
} from './agentLabels';

/**
 * How the gateway reaches the agent (Direct, Proxied, Fabric): the one style for the route on
 * every page, with what it means as the tooltip and for screen readers.
 */
export const AgentRouteBadge: React.FC<{ runtime: string; 'data-testid'?: string }> = ({
  runtime,
  'data-testid': testId,
}) => (
  <span
    className="badge text-bg-light border agent-route-badge"
    title={routeDescription(runtime)}
    data-testid={testId}
  >
    <i className={`fas ${runtimeIcon(runtime)} me-1`} aria-hidden="true" />
    <span>{runtimeLabel(runtime)}</span>
    <span className="visually-hidden">. {routeDescription(runtime)}</span>
  </span>
);

/** The protocol only, styled like the Surfaces page's; how the agent is reached is the Runtime. */
export const AgentProtocolBadge: React.FC<{ protocol: string }> = ({ protocol }) => (
  <span className={`badge ${protocolBadgeClass(protocol)}`} data-testid="agents-protocol-badge">
    {protocolLabel(protocol)}
  </span>
);

/**
 * `Recorded` when any of the agent's identities was written to a trust registry, in the Agent
 * Identities page's Trust Recorder badge; the tooltip says recording is not a trust decision.
 */
export const AgentTrustRegistryBadge: React.FC<{ trust: AgentTrustRegistry }> = ({ trust }) => {
  if (!trust.recorded) {
    return (
      <span className="badge badge-none" data-testid="agents-trust-not-recorded">
        {trustRegistryLabel(trust)}
      </span>
    );
  }
  return (
    <span title="An identity of this agent was written to a trust registry. This does not mean the agent is trusted.">
      <TrustRecorderStateBadge state="recorded" testId="agents-trust-recorded" />
    </span>
  );
};

interface AgentDidProps {
  did: string;
  /** Show the full DID instead of the shortened one. */
  full?: boolean;
  /** Render the DID in muted text instead of the code colour. */
  muted?: boolean;
}

/** A DID in monospace with a copy button; the shortened form keeps the full value as tooltip. */
export const AgentDid: React.FC<AgentDidProps> = ({ did, full = false, muted = false }) => (
  <span className="d-inline-flex align-items-center" style={{ minWidth: 0 }}>
    <code
      className={`small text-break${muted ? ' text-muted' : ''}`}
      title={did}
      data-testid="agents-did"
    >
      {full ? did : shortenDid(did)}
    </code>
    <CopyButton text={did} title="Copy DID" data-testid="agents-copy-did-button" />
  </span>
);

interface AgentIdentitiesProps {
  identities: AgentIdentity[];
  /** How many surfaces use the agent; with none of them holding a DID, `No DID` is flagged. */
  surfaceCount: number;
}

/**
 * A count badge, styled like the surfaces count, then the first DID; every DID is in the
 * tooltip. Without any, `No DID`, flagged as a warning while surfaces use the agent.
 */
export const AgentIdentities: React.FC<AgentIdentitiesProps> = ({ identities, surfaceCount }) => {
  if (identities.length === 0) {
    if (surfaceCount === 0) {
      return (
        <span className="text-muted small" data-testid="agents-no-did">
          {NO_DID}
        </span>
      );
    }
    return (
      <Badge
        value={NO_DID}
        tone="warning"
        size="sm"
        prefix={<i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />}
        title={
          surfaceCount === 1
            ? 'The surface using this agent has no DID'
            : `None of the ${surfaceCount} surfaces using this agent has a DID`
        }
        data-testid="agents-no-did"
      />
    );
  }
  const [first] = identities;
  const more = identities.length - 1;
  return (
    <div
      className="d-flex align-items-center gap-2 small"
      style={{ maxWidth: '16rem' }}
      title={identities.map(identity => identity.did).join('\n')}
      data-testid="agents-identities"
    >
      <span
        className="badge text-bg-primary"
        aria-label={identitiesLabel(identities.length)}
        data-testid="agents-identities-count"
      >
        {identities.length}
      </span>
      <AgentDid did={first.did} muted />
      {more > 0 && (
        <span className="text-muted text-nowrap" data-testid="agents-identities-more">
          +{more}
        </span>
      )}
    </div>
  );
};
