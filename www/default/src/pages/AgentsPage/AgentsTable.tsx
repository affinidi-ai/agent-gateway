import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentRecord } from '../../api';
import { AgentIdentities, AgentProtocolBadge, AgentTrustRegistryBadge } from './AgentBadges';
import { UNNAMED_AGENT, lastActivityLabel, runtimeIcon, runtimeLabel } from './agentLabels';

interface AgentsTableProps {
  agents: AgentRecord[];
  retentionMinutes?: number;
  onOpen: (agent: AgentRecord) => void;
}

/** One row per managed agent. A row opens the details. */
const AgentsTable: React.FC<AgentsTableProps> = ({ agents, retentionMinutes, onOpen }) => (
  <div className="table-responsive">
    <table className="table table-hover table-sm">
      <thead>
        <tr>
          <th style={{ width: '20%' }}>Agent</th>
          <th style={{ width: '15%' }}>Runtime &amp; protocol</th>
          <th style={{ width: '20%' }}>Identities</th>
          <th style={{ width: '17%' }}>Used by surfaces</th>
          <th style={{ width: '13%' }}>Trust registry</th>
          <th style={{ width: '15%' }}>Last activity</th>
        </tr>
      </thead>
      <tbody>
        {agents.map(agent => (
          <tr
            key={agent.id}
            className="agents-row"
            tabIndex={0}
            onClick={() => onOpen(agent)}
            onKeyDown={e => {
              if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                e.preventDefault();
                onOpen(agent);
              }
            }}
            data-testid={`agents-row-${agent.id}`}
          >
            <td>
              {agent.name ? (
                <strong data-testid="agents-name">{agent.name}</strong>
              ) : (
                <span className="text-muted fst-italic" data-testid="agents-unnamed">
                  {UNNAMED_AGENT}
                </span>
              )}
            </td>
            <td>
              <div className="small mb-1" data-testid="agents-runtime">
                <i className={`fas ${runtimeIcon(agent.runtime)} me-1`} aria-hidden="true" />
                {runtimeLabel(agent.runtime)}
              </div>
              <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />
            </td>
            <td>
              <AgentIdentities identities={agent.identities} />
            </td>
            <td>
              <ul className="list-unstyled mb-0" data-testid="agents-surfaces">
                {agent.surfaces.map(surface => (
                  <li key={surface.surface_id}>
                    <Link
                      to={`/surfaces/${encodeURIComponent(surface.surface_id)}`}
                      onClick={e => e.stopPropagation()}
                      data-testid="agents-surface-link"
                    >
                      {surface.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </td>
            <td>
              <AgentTrustRegistryBadge trust={agent.trust_registry} />
            </td>
            <td>
              <span
                className={agent.last_activity_at ? 'small' : 'small text-muted'}
                title={agent.last_activity_at ?? undefined}
                data-testid="agents-last-activity"
              >
                {lastActivityLabel(agent.last_activity_at, retentionMinutes)}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default AgentsTable;
