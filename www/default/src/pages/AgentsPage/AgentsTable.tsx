import React from 'react';
import type { AgentRecord } from '../../api';
import { AgentIdentities, AgentProtocolBadge, AgentTrustRegistryBadge } from './AgentBadges';
import {
  UNNAMED_AGENT,
  lastActivityLabel,
  runtimeIcon,
  runtimeLabel,
  surfacesUsedLabel,
} from './agentLabels';

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
          <th style={{ width: '18%' }}>Agent</th>
          <th style={{ width: '10%' }}>Runtime</th>
          <th style={{ width: '10%' }}>Protocol</th>
          <th style={{ width: '19%' }}>Identities</th>
          <th style={{ width: '16%' }}>Used by surfaces</th>
          <th style={{ width: '13%' }}>Trust registry</th>
          <th style={{ width: '14%' }}>Last activity</th>
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
              <div className="small" data-testid="agents-runtime">
                <i className={`fas ${runtimeIcon(agent.runtime)} me-1`} aria-hidden="true" />
                {runtimeLabel(agent.runtime)}
              </div>
            </td>
            <td>
              <AgentProtocolBadge protocol={agent.protocol} />
            </td>
            <td>
              <AgentIdentities identities={agent.identities} />
            </td>
            <td>
              {agent.surfaces.length === 0 ? (
                <span className="small text-muted" data-testid="agents-surfaces-count">
                  {surfacesUsedLabel(0)}
                </span>
              ) : (
                <div
                  className="d-flex align-items-center gap-2 small"
                  style={{ maxWidth: '16rem' }}
                  title={agent.surfaces.map(surface => surface.name).join(', ')}
                  data-testid="agents-surfaces"
                >
                  <span
                    className="badge rounded-pill text-bg-primary"
                    aria-label={surfacesUsedLabel(agent.surfaces.length)}
                    data-testid="agents-surfaces-count"
                  >
                    {agent.surfaces.length}
                  </span>
                  <span className="text-truncate" data-testid="agents-surface-names">
                    {agent.surfaces.map(surface => surface.name).join(', ')}
                  </span>
                </div>
              )}
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
