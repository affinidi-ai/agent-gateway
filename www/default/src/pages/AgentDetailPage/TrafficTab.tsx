import React from 'react';
import type { AgentTraffic } from '../../api';
import StatCard from '../../components/StatCard';
import { EmptyState } from '../../components/shared/EmptyState';
import { formatWindow } from '../AgentsPage/agentLabels';

interface TrafficTabProps {
  traffic: AgentTraffic;
}

/**
 * Totals cover only the metrics retention window, so every card names that
 * window. The API returns agent totals only, so there is no per-surface breakdown.
 */
const TrafficTab: React.FC<TrafficTabProps> = ({ traffic }) => {
  const windowLabel = formatWindow(traffic.window_minutes);
  const failed = traffic.failed + traffic.gateway_faults;

  if (traffic.total_requests === 0) {
    return (
      <div data-testid="agent-traffic-empty">
        <EmptyState
          icon="fa-chart-bar"
          title={`No requests in the last ${windowLabel}`}
          body="Requests to this agent's surfaces show here."
        />
      </div>
    );
  }

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
    </div>
  );
};

export default TrafficTab;
