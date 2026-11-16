import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentSurfaceSummary, AgentTraffic } from '../../api';
import StatCard from '../../components/StatCard';
import { formatWindow } from '../AgentsPage/agentLabels';

interface TrafficTabProps {
  traffic: AgentTraffic;
  surfaces: AgentSurfaceSummary[];
}

/**
 * Totals cover only the metrics retention window, so every card names that
 * window. The gateway keeps no 7-day history. The API returns agent totals
 * only, so the per-surface breakdown shows only for a single-surface agent.
 */
const TrafficTab: React.FC<TrafficTabProps> = ({ traffic, surfaces }) => {
  const windowLabel = formatWindow(traffic.window_minutes);
  const failed = traffic.failed + traffic.gateway_faults;
  const perSurface =
    surfaces.length === 1 ? [{ ...surfaces[0], count: traffic.total_requests }] : [];

  return (
    <div data-testid="agent-traffic-tab">
      <div className="row">
        <StatCard
          title={`Requests (last ${windowLabel})`}
          value={traffic.total_requests}
          icon="fa-exchange-alt"
          color="primary"
          testId="agent-traffic-requests"
        />
        <StatCard
          title="Requests (7 days)"
          value="—"
          subtitle="Needs longer metrics history"
          icon="fa-calendar-week"
          color="info"
          testId="agent-traffic-requests-7d"
        />
        <StatCard
          title={`Failed requests (last ${windowLabel})`}
          value={failed}
          icon="fa-exclamation-triangle"
          color={failed > 0 ? 'danger' : 'success'}
          testId="agent-traffic-failed"
        />
        <StatCard
          title={`P95 latency (last ${windowLabel})`}
          value={traffic.p95_latency_ms === null ? '—' : `${traffic.p95_latency_ms} ms`}
          icon="fa-stopwatch"
          color="info"
          testId="agent-traffic-p95"
        />
      </div>

      {perSurface.length > 0 && (
        <div data-testid="agent-traffic-by-surface">
          <h6 className="font-weight-bold">Requests by surface (last {windowLabel})</h6>
          {perSurface.map(surface => {
            const percent = traffic.total_requests > 0 ? 100 : 0;
            return (
              <div key={surface.surface_id} className="mb-2">
                <div className="d-flex justify-content-between small">
                  <Link
                    to={`/surfaces/${encodeURIComponent(surface.surface_id)}`}
                    data-testid="agent-traffic-surface-link"
                  >
                    {surface.name}
                  </Link>
                  <span>{surface.count}</span>
                </div>
                <div className="progress" style={{ height: '0.5rem' }}>
                  <div
                    className="progress-bar"
                    role="progressbar"
                    style={{ width: `${percent}%` }}
                    aria-valuenow={percent}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-label={`${surface.name} requests`}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default TrafficTab;
