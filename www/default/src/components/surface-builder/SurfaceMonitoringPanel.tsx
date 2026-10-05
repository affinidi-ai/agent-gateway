import React, { useEffect, useMemo, useRef, useState } from 'react';
import { apiClient, type AgentSurface } from '../../api';
import { useApp } from '../../context/AppContext';
import { WS_DASHBOARD_WITH_LOGS, WS_NONE } from '../../utils/wsSubscriptions';
import MonitoringTab from './monitoring/MonitoringTab';
import SurfaceCapturePanel from './monitoring/capture/SurfaceCapturePanel';

interface SurfaceMonitoringPanelProps {
  surfaceId: string;
  surfaceName: string;
}

type TpSlice =
  | { kind: 'aggregate' }
  | { kind: 'ap'; label: string }
  | { kind: 'tp'; alias: string; label: string };

const SLICE_AGGREGATE: TpSlice = { kind: 'aggregate' };

function sliceToWire(slice: TpSlice): string | undefined {
  if (slice.kind === 'aggregate') return undefined;
  if (slice.kind === 'ap') return '__ap__';
  return slice.alias;
}

function sliceKey(slice: TpSlice): string {
  if (slice.kind === 'aggregate') return '__agg__';
  if (slice.kind === 'ap') return '__ap__';
  return `tp:${slice.alias}`;
}

function sliceLabel(slice: TpSlice): string {
  if (slice.kind === 'aggregate') return 'Aggregated';
  return slice.label;
}

/**
 * Surface monitoring view. Wraps the channel-level `MonitoringTab` with
 * a surface-scoped dashboard filter and a transit-point slice picker.
 *
 * The underlying channel `config_id` always equals `surface_id`, so the
 * channel filter alone scopes everything to this surface. The transit
 * point picker layers on top using the wire format documented in
 * `parse_tp_filter` on the backend:
 *   * Aggregated   → no `transit_point` query param
 *   * Access Point → `transit_point=__ap__`
 *   * a TP alias   → `transit_point=<alias>`
 */
const SurfaceMonitoringPanel: React.FC<SurfaceMonitoringPanelProps> = ({
  surfaceId,
  surfaceName,
}) => {
  const { state, actions } = useApp();
  const [surface, setSurface] = useState<AgentSurface | null>(null);
  const [slice, setSlice] = useState<TpSlice>(SLICE_AGGREGATE);
  const [captureMode, setCaptureMode] = useState(false);

  // Fetch the surface so we can list its Transit Points for the filter.
  useEffect(() => {
    let cancelled = false;
    apiClient
      .getSurface(surfaceId)
      .then(s => {
        if (!cancelled) setSurface(s);
      })
      .catch(() => {
        // Non-fatal: panel still works without the TP list (filter
        // collapses to "Aggregated" + "Access Point" only).
      });
    return () => {
      cancelled = true;
    };
  }, [surfaceId]);

  const transitPoints = useMemo(() => {
    const points = (surface?.transit?.points || []) as Array<{
      alias?: string;
      name?: string;
    }>;
    return points
      .map((p, idx) => {
        const alias = p.alias || p.name || '';
        if (!alias) return null;
        const userName = typeof p.name === 'string' ? p.name.trim() : '';
        return { alias, label: userName || `Transit Point ${idx + 1}` };
      })
      .filter((p): p is { alias: string; label: string } => p !== null);
  }, [surface]);

  const apLabel = useMemo(() => {
    const apName = surface?.access_point?.name;
    return (typeof apName === 'string' && apName.trim()) || 'Access Point';
  }, [surface]);

  // Push the active slice into the global dashboard filter. Always pin
  // `channelId = surfaceId` so per-surface scope sticks regardless of
  // the slice; only `transitPoint` changes between selections.
  useEffect(() => {
    if (!surfaceId) return;
    const transitPoint = sliceToWire(slice);
    const current = state.dashboardFilters || {};
    if (current.channelId === surfaceId && current.transitPoint === transitPoint) {
      return;
    }
    actions.setDashboardFilters({ channelId: surfaceId, transitPoint });
    actions.setActiveView('filtered');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [surfaceId, slice]);

  // Subscribe to dashboard + logs WS sections while mounted.
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD_WITH_LOGS);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Force an initial load when the filter has propagated and the
  // filtered store is empty (mirrors EditChannelPage).
  useEffect(() => {
    const activeStore = state.activeView === 'global' ? state.globalState : state.filteredState;
    const expectedTp = sliceToWire(slice);
    const filtersAlignWithSlice =
      state.dashboardFilters?.channelId === surfaceId &&
      state.dashboardFilters?.transitPoint === expectedTp;
    if (filtersAlignWithSlice && activeStore.lastSyncTimestamp === null) {
      actions.loadDashboardStats(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    state.dashboardFilters,
    state.activeView,
    state.filteredState.lastSyncTimestamp,
    state.globalState.lastSyncTimestamp,
    surfaceId,
    slice,
  ]);

  const stats = useMemo(() => {
    return state.activeView === 'global' ? state.globalState.stats : state.filteredState.stats;
  }, [state.activeView, state.globalState.stats, state.filteredState.stats]);

  // Project filtered dashboard stats into the `ChannelMetrics` shape
  // `MonitoringTab` expects. Same translation as EditChannelPage. Charts
  // and logs intentionally clear on view change because the previous
  // slice's history may not belong to the new slice.
  const channelMetrics = useMemo(() => {
    if (!stats?.metrics?.time_series || !stats?.metrics?.latency_time_series) {
      return null;
    }
    return {
      channel_config_id: surfaceId,
      time_series: stats.metrics.time_series.map(point => ({
        timestamp: point.timestamp,
        count: point.count || 0,
        rule_accepts: point.rule_accepts || 0,
        rule_denies: point.rule_denies || 0,
        gateway_faults: point.gateway_faults || 0,
      })),
      latency_time_series: stats.metrics.latency_time_series.map(point => ({
        timestamp: point.timestamp,
        avg_latency_ms: point.avg_latency_ms || 0,
        p50_latency_ms: point.p50_latency_ms || 0,
        p95_latency_ms: point.p95_latency_ms || 0,
        p99_latency_ms: point.p99_latency_ms || 0,
        min_latency_ms: point.min_latency_ms || 0,
        max_latency_ms: point.max_latency_ms || 0,
        sample_count: point.sample_count || 0,
      })),
    };
  }, [stats, surfaceId]);

  const slices: TpSlice[] = useMemo(() => {
    return [
      SLICE_AGGREGATE,
      { kind: 'ap', label: apLabel },
      ...transitPoints.map(tp => ({ kind: 'tp' as const, alias: tp.alias, label: tp.label })),
    ];
  }, [apLabel, transitPoints]);

  const activeKey = sliceKey(slice);
  const reloading = state.activeView === 'filtered' && stats === null;

  // Hold the "Updating…" indicator visible for at least one second so it
  // doesn't strobe on a fast network. If the user changes the view again
  // while the badge is still showing, restart the one-second window.
  const [showReloading, setShowReloading] = useState(false);
  const minVisibleUntilRef = useRef<number>(0);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (reloading) {
      minVisibleUntilRef.current = Date.now() + 1000;
      setShowReloading(true);
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
      return;
    }
    const remaining = minVisibleUntilRef.current - Date.now();
    if (remaining <= 0) {
      setShowReloading(false);
      return;
    }
    if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
    hideTimerRef.current = setTimeout(() => {
      setShowReloading(false);
      hideTimerRef.current = null;
    }, remaining);
    return () => {
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
    };
  }, [reloading]);

  if (captureMode) {
    return (
      <div style={{ height: '100%', overflowY: 'auto', padding: '1rem' }}>
        <SurfaceCapturePanel
          surfaceId={surfaceId}
          surface={surface}
          onClose={() => setCaptureMode(false)}
        />
      </div>
    );
  }

  return (
    <div style={{ height: '100%', overflowY: 'auto', padding: '1rem' }}>
      <div className="d-flex align-items-center flex-wrap gap-2 mb-3">
        <label htmlFor="surface-monitoring-slice" className="text-muted small mb-0 me-1">
          View:
        </label>
        <select
          id="surface-monitoring-slice"
          className="form-select form-select-sm"
          style={{ width: 'auto', minWidth: 220 }}
          value={activeKey}
          onChange={e => {
            const next = slices.find(s => sliceKey(s) === e.target.value);
            if (next) setSlice(next);
          }}
        >
          {slices.map(s => {
            const key = sliceKey(s);
            return (
              <option key={key} value={key}>
                {sliceLabel(s)}
                {s.kind === 'ap' ? ' (inbound)' : ''}
                {s.kind === 'tp' ? ' (outbound)' : ''}
              </option>
            );
          })}
        </select>
        {showReloading && (
          <span className="text-muted small ms-2" aria-live="polite">
            <i className="fas fa-circle-notch fa-spin me-1" />
            Updating…
          </span>
        )}
        <button
          type="button"
          className="btn btn-sm btn-primary ms-auto"
          onClick={() => setCaptureMode(true)}
          title="Live payload capture for this surface"
        >
          <i className="fas fa-eye me-1"></i> Capture
        </button>
      </div>
      <MonitoringTab
        channelMetrics={channelMetrics}
        formData={{ config_id: surfaceId, name: surfaceName }}
        dashboardStats={stats}
        state={state}
        actions={actions}
        protocol={(surface?.access_point as any)?.protocol}
      />
    </div>
  );
};

export default SurfaceMonitoringPanel;
