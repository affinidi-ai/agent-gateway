import React from 'react';
import type { AgentRecord } from '../../api';
import { AgentProtocolBadge, AgentRouteBadge } from '../AgentsPage/AgentBadges';
import { UNNAMED_AGENT, endpointHost } from '../AgentsPage/agentLabels';

/**
 * Name with its protocol and route beside it; an unnamed agent also shows its endpoint host,
 * so it can be told apart. Read-only: no actions.
 */
const AgentDetailHeader: React.FC<{ agent: AgentRecord }> = ({ agent }) => {
  const host = agent.name ? null : endpointHost(agent);
  return (
    <div className="card-header py-3" data-testid="agent-details-header">
      <h6 className="m-0 font-weight-bold text-primary d-flex flex-wrap align-items-center gap-2">
        <i className="fas fa-robot" aria-hidden="true" />
        <span data-testid="agent-details-name">
          {agent.name ?? <span className="text-muted fst-italic">{UNNAMED_AGENT}</span>}
        </span>
        {host && (
          <span className="small text-muted fw-normal" data-testid="agent-details-endpoint-host">
            {host}
          </span>
        )}
        <AgentProtocolBadge protocol={agent.protocol} />
        <AgentRouteBadge runtime={agent.runtime} data-testid="agent-details-runtime" />
      </h6>
    </div>
  );
};

export default AgentDetailHeader;
