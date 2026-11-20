import React from 'react';
import type { AgentRecord } from '../../api';
import {
  AgentIdentities,
  AgentProtocolBadge,
  AgentRoute,
  AgentTrustRegistryBadge,
} from './AgentBadges';
import { UNNAMED_AGENT, endpointHost, lastActivityLabel, surfacesUsedLabel } from './agentLabels';

interface AgentsTableProps {
  agents: AgentRecord[];
  retentionMinutes?: number;
  onOpen: (agent: AgentRecord) => void;
}

/** Lets a cell's `text-truncate` content cut at the column's width rather than widen the table. */
const FIT_COLUMN: React.CSSProperties = { maxWidth: '0px' };

/** One row per managed agent. A row opens the details. */
const AgentsTable: React.FC<AgentsTableProps> = ({ agents, retentionMinutes, onOpen }) => (
  <div className="table-responsive">
    <table className="table table-hover table-sm agents-table">
      <thead>
        <tr>
          <th style={{ width: '24%' }}>Agent</th>
          <th style={{ width: '10%' }}>Route</th>
          <th style={{ width: '8%' }}>Protocol</th>
          <th style={{ width: '8%' }}>Identities</th>
          <th style={{ width: '16%' }}>Used by surfaces</th>
          <th style={{ width: '12%' }} className="text-nowrap">
            Trust registry
          </th>
          <th style={{ width: '12%' }}>Last activity</th>
          <th aria-hidden="true" />
        </tr>
      </thead>
      <tbody>
        {agents.map(agent => {
          const host = endpointHost(agent);
          return (
            <tr
              key={agent.id}
              className="agents-row"
              role="link"
              aria-label={`${agent.name ?? UNNAMED_AGENT}${host ? `, ${host}` : ''}`}
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
              <td style={FIT_COLUMN}>
                <strong
                  className="text-break"
                  data-testid={agent.name ? 'agents-name' : 'agents-unnamed'}
                >
                  {agent.name ?? UNNAMED_AGENT}
                </strong>
                {host && (
                  <div className="text-truncate" title={host} data-testid="agents-endpoint-host">
                    <small className="text-muted">{host}</small>
                  </div>
                )}
              </td>
              <td>
                <AgentRoute runtime={agent.runtime} data-testid="agents-runtime" />
              </td>
              <td>
                <AgentProtocolBadge protocol={agent.protocol} />
              </td>
              <td>
                <AgentIdentities
                  identities={agent.identities}
                  surfaceCount={agent.surfaces.length}
                />
              </td>
              <td style={FIT_COLUMN}>
                {agent.surfaces.length === 0 ? (
                  <span className="text-muted" data-testid="agents-surfaces-count">
                    {surfacesUsedLabel(0)}
                  </span>
                ) : (
                  <div
                    className="d-flex align-items-center gap-2"
                    title={agent.surfaces.map(surface => surface.name).join(', ')}
                    data-testid="agents-surfaces"
                  >
                    <span
                      className="badge text-bg-primary flex-shrink-0"
                      aria-label={surfacesUsedLabel(agent.surfaces.length)}
                      data-testid="agents-surfaces-count"
                    >
                      {agent.surfaces.length}
                    </span>
                    <span
                      className="text-truncate"
                      style={{ minWidth: 0 }}
                      data-testid="agents-surface-names"
                    >
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
                  className={agent.last_activity_at ? undefined : 'text-muted'}
                  title={agent.last_activity_at ?? undefined}
                  data-testid="agents-last-activity"
                >
                  {lastActivityLabel(agent.last_activity_at, retentionMinutes)}
                </span>
              </td>
              <td
                className="text-end align-middle agents-row-chevron"
                data-testid="agents-row-chevron"
              >
                <i className="fas fa-chevron-right" aria-hidden="true" />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

export default AgentsTable;
