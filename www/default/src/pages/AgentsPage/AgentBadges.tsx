import React from 'react';
import type { AgentIdentity, AgentTrustRegistry } from '../../api';
import { TrustRecorderStateBadge } from '../../components/trust-recorder/TrustRecorderStateBadge';
import { Badge } from '../../components/shared/Badge';
import { CopyButton } from '../../components/shared/CopyButton';
import { ProtocolBadge } from '../../components/shared/ProtocolBadge';
import {
  NO_IDENTITY,
  identityNoun,
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
export const AgentRoute: React.FC<{ runtime: string; 'data-testid'?: string }> = ({
  runtime,
  'data-testid': testId,
}) => (
  <span className="text-nowrap" title={routeDescription(runtime)} data-testid={testId}>
    <i className={`fas ${runtimeIcon(runtime)} me-1`} aria-hidden="true" />
    <span>{runtimeLabel(runtime)}</span>
    <span className="visually-hidden">. {routeDescription(runtime)}</span>
  </span>
);

/** The protocol only, in the Surfaces page's badge; how the agent is reached is the Route. */
export const AgentProtocolBadge: React.FC<{ protocol: string }> = ({ protocol }) => (
  <ProtocolBadge protocol={protocol} data-testid="agents-protocol-badge" />
);

/**
 * `Recorded` when any of the agent's identities was written to a trust registry, in the Agent
 * Identities page's Trust Recorder badge; the tooltip says recording is not a trust decision.
 */
export const AgentTrustRegistryBadge: React.FC<{ trust: AgentTrustRegistry }> = ({ trust }) => {
  if (!trust.recorded) {
    return (
      <Badge
        tone="secondary"
        size="sm"
        value={trustRegistryLabel(trust)}
        data-testid="agents-trust-not-recorded"
      />
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
  /** How many surfaces use the agent; while any do, the tooltip says none of them has a DID. */
  surfaceCount: number;
}

/**
 * A count badge, like Used by surfaces, then "identity" or "identities", with every DID in the
 * tooltip. Without any, `No identity` in muted text, like an empty Used by surfaces cell.
 */
export const AgentIdentities: React.FC<AgentIdentitiesProps> = ({ identities, surfaceCount }) => {
  if (identities.length === 0) {
    let title: string | undefined;
    if (surfaceCount === 1) title = 'The surface using this agent has no DID';
    else if (surfaceCount > 1)
      title = `None of the ${surfaceCount} surfaces using this agent has a DID`;
    return (
      <span className="text-muted" title={title} data-testid="agents-no-identity">
        {NO_IDENTITY}
      </span>
    );
  }
  return (
    <div
      className="d-flex align-items-center gap-2 text-nowrap"
      title={identities.map(identity => identity.did).join('\n')}
      data-testid="agents-identities"
    >
      <span className="badge text-bg-primary" data-testid="agents-identities-count">
        {identities.length}
      </span>{' '}
      <span>{identityNoun(identities.length)}</span>
    </div>
  );
};
