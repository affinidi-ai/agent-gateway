import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentSurfaceSummary } from '../../api';
import { Badge } from '../../components/shared/Badge';
import { AgentStatusBadge } from '../AgentsPage/AgentBadges';
import { protocolLabel, protocolTone } from '../AgentsPage/agentLabels';

/** The surfaces that expose this agent. One in iteration 1. */
const SurfacesTab: React.FC<{ surfaces: AgentSurfaceSummary[] }> = ({ surfaces }) => (
  <div className="table-responsive" data-testid="agent-surfaces-tab">
    <table className="table table-sm">
      <thead>
        <tr>
          <th style={{ width: '12%' }}>Protocol</th>
          <th>Surface</th>
          <th>Access point route</th>
          <th style={{ width: '12%' }}>Status</th>
        </tr>
      </thead>
      <tbody>
        {surfaces.map(surface => (
          <tr key={surface.surface_id} data-testid={`agent-surfaces-row-${surface.surface_id}`}>
            <td>
              <Badge
                value={protocolLabel(surface.protocol)}
                tone={protocolTone(surface.protocol)}
                size="sm"
              />
            </td>
            <td>
              <Link
                to={`/surfaces/${encodeURIComponent(surface.surface_id)}`}
                data-testid="agent-surfaces-link"
              >
                {surface.name}
              </Link>
            </td>
            <td>
              <code className="small">{surface.route}</code>
            </td>
            <td>
              <AgentStatusBadge status={surface.status} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default SurfacesTab;
