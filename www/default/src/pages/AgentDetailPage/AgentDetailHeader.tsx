import React from 'react';
import type { AgentRecord } from '../../api';
import { AgentProtocolBadge, AgentStatusBadge } from '../AgentsPage/AgentBadges';
import { UNNAMED_AGENT, runtimeIcon, runtimeLabel } from '../AgentsPage/agentLabels';

/** Name, status and protocol, with the runtime on the right. Read-only: no actions. */
const AgentDetailHeader: React.FC<{ agent: AgentRecord }> = ({ agent }) => (
  <div
    className="card-header py-3 d-flex flex-wrap gap-2 justify-content-between align-items-center"
    data-testid="agent-details-header"
  >
    <h6 className="m-0 font-weight-bold text-primary d-flex flex-wrap align-items-center gap-2">
      <i className="fas fa-robot" aria-hidden="true" />
      <span data-testid="agent-details-name">
        {agent.name ?? <span className="text-muted fst-italic">{UNNAMED_AGENT}</span>}
      </span>
      <AgentStatusBadge status={agent.status} testId="agent-details-status" />
      <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />
    </h6>
    <span className="small text-muted" data-testid="agent-details-runtime">
      <i className={`fas ${runtimeIcon(agent.runtime)} me-1`} aria-hidden="true" />
      {runtimeLabel(agent.runtime)}
    </span>
  </div>
);

export default AgentDetailHeader;
