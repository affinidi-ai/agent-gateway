import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title as ChartTitle,
  Tooltip,
  Legend,
  Filler,
  ChartOptions,
  Plugin,
} from 'chart.js';
import { apiClient } from '../api';
import { useApp } from '../context/AppContext';
import { WS_DASHBOARD, WS_NONE } from '../utils/wsSubscriptions';
import { AppButton } from '../components/shared/AppButton';
import FieldHelp from '../components/shared/FieldHelp';
import { UI_COLORS, chartAreaFill } from '../utils/uiPalette';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ChartTitle,
  Tooltip,
  Legend,
  Filler
);

// Custom plugin: draws a vertical dashed line at the active data index
// and synchronises hover across all charts that share the same chartRefsArray.
const crosshairPlugin: Plugin<'line'> = {
  id: 'crosshair',
  afterDraw(chart) {
    const active = chart.tooltip?.getActiveElements();
    if (active && active.length > 0) {
      const ctx = chart.ctx;
      const x = active[0].element.x;
      const topY = chart.scales.y.top;
      const bottomY = chart.scales.y.bottom;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x, topY);
      ctx.lineTo(x, bottomY);
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(100, 100, 100, 0.4)';
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.restore();
    }
  },
  afterEvent(chart, args) {
    const refs: (ChartJS<'line'> | null)[] = (chart as any).__syncRefs;
    if (!refs) return;
    const event = args.event;
    if (event.type === 'mouseout') {
      refs.forEach(sibling => {
        if (!sibling || sibling === chart) return;
        sibling.setActiveElements([]);
        sibling.tooltip?.setActiveElements([], { x: 0, y: 0 });
        sibling.update('none');
      });
      return;
    }
    if (event.type !== 'mousemove') return;
    const elements = chart.getActiveElements();
    if (!elements.length) return;
    const dataIndex = elements[0].index;
    refs.forEach(sibling => {
      if (!sibling || sibling === chart) return;
      const siblingElements = sibling.data.datasets.map((_, dsIdx) => ({
        datasetIndex: dsIdx,
        index: dataIndex,
      }));
      sibling.setActiveElements(siblingElements);
      sibling.tooltip?.setActiveElements(siblingElements, { x: 0, y: 0 });
      sibling.update('none');
    });
  },
};

interface SystemMetricsSample {
  timestamp: string;
  process_cpu_percent: number;
  process_memory_bytes: number;
  system_cpu_percent: number;
  system_total_memory_bytes: number;
  system_used_memory_bytes: number;
}

interface SystemInfo {
  name: string | null;
  kernel_version: string | null;
  os_version: string | null;
  host_name: string | null;
  uptime_seconds: number;
}

interface SystemMetricsResponse {
  system_info: SystemInfo;
  samples: SystemMetricsSample[];
  current: SystemMetricsSample | null;
}

const formatUptime = (totalSeconds: number): string => {
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0 || parts.length === 0) parts.push(`${minutes}m`);
  return parts.join(' ');
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return bytes.toFixed(0) + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
};

const formatTime = (ts: string): string => {
  const d = new Date(ts);
  return d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
};

const formatTooltipTime = (ts: string): string => {
  const d = new Date(ts);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
};

const TIME_RANGES = ['10m', '1h', '6h', '12h', '24h'] as const;
type TimeRange = (typeof TIME_RANGES)[number];

const LIVE_INTERVALS = [
  { label: '5 seconds', ms: 5_000 },
  { label: '10 seconds', ms: 10_000 },
  { label: '30 seconds', ms: 30_000 },
  { label: '1 minute', ms: 60_000 },
] as const;

const SystemMetricsPage: React.FC = () => {
  const { actions } = useApp();
  const [data, setData] = useState<SystemMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<TimeRange>('1h');
  const [isLive, setIsLive] = useState(true);
  const [liveInterval, setLiveInterval] = useState(30_000);
  const [lastRefreshTime, setLastRefreshTime] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastTimestampRef = useRef<string | null>(null);

  // Chart instance refs for synchronized hover
  const chartRef1 = useRef<ChartJS<'line'> | null>(null);
  const chartRef2 = useRef<ChartJS<'line'> | null>(null);
  const chartRef3 = useRef<ChartJS<'line'> | null>(null);
  const chartRef4 = useRef<ChartJS<'line'> | null>(null);
  const chartRefs = useRef<(ChartJS<'line'> | null)[]>([]);

  // Subscribe to everything except logs to reduce WS payload size
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the shared refs array in sync
  useEffect(() => {
    const arr = [chartRef1.current, chartRef2.current, chartRef3.current, chartRef4.current];
    chartRefs.current = arr;
    arr.forEach(c => {
      if (c) (c as any).__syncRefs = arr;
    });
  });

  // Full fetch – used on first load and when timeRange changes.
  const fetchFull = useCallback(async () => {
    try {
      const resp = await apiClient.getSystemMetrics(timeRange);
      setData(resp);
      setLastRefreshTime(new Date());
      // Track the latest sample timestamp for incremental polling
      if (resp?.samples?.length) {
        lastTimestampRef.current = resp.samples[resp.samples.length - 1].timestamp;
      }
    } catch (err) {
      console.error('Failed to fetch system metrics:', err);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  // Incremental fetch – only retrieves samples newer than `lastTimestampRef`.
  const fetchIncremental = useCallback(async () => {
    if (!lastTimestampRef.current) {
      // No baseline yet – fall back to full fetch
      return fetchFull();
    }
    try {
      const resp: SystemMetricsResponse = await apiClient.getSystemMetrics(
        undefined,
        lastTimestampRef.current
      );
      if (resp?.samples?.length) {
        lastTimestampRef.current = resp.samples[resp.samples.length - 1].timestamp;
        setLastRefreshTime(new Date());
        setData(prev => {
          if (!prev) return resp;
          // Compute the time-range cutoff so we don't accumulate unbounded samples
          const rangeMs =
            {
              '10m': 600_000,
              '1h': 3_600_000,
              '6h': 21_600_000,
              '12h': 43_200_000,
              '24h': 86_400_000,
            }[timeRange] ?? 3_600_000;
          const cutoff = new Date(Date.now() - rangeMs).toISOString();
          const merged = [...prev.samples, ...resp.samples].filter(s => s.timestamp > cutoff);
          return {
            ...prev,
            samples: merged,
            current: resp.current ?? prev.current,
            system_info: resp.system_info,
          };
        });
      } else {
        // No new samples, but update system_info (uptime etc.)
        setLastRefreshTime(new Date());
        setData(prev =>
          prev
            ? { ...prev, current: resp.current ?? prev.current, system_info: resp.system_info }
            : prev
        );
      }
    } catch (err) {
      console.error('Failed to fetch system metrics (incremental):', err);
    }
  }, [timeRange, fetchFull]);

  // Initial fetch + re-fetch when timeRange changes.
  useEffect(() => {
    lastTimestampRef.current = null; // Reset on range change to do a full fetch
    fetchFull();
  }, [fetchFull]);

  // Live-update timer – uses recursive setTimeout to avoid overlapping fetches.
  useEffect(() => {
    let cancelled = false;
    if (intervalRef.current) {
      clearTimeout(intervalRef.current);
      intervalRef.current = null;
    }
    if (isLive) {
      const tick = () => {
        fetchIncremental().then(
          () => {
            if (!cancelled) {
              intervalRef.current = setTimeout(tick, liveInterval);
            }
          },
          () => {
            if (!cancelled) {
              intervalRef.current = setTimeout(tick, liveInterval);
            }
          }
        );
      };
      intervalRef.current = setTimeout(tick, liveInterval);
    }
    return () => {
      cancelled = true;
      if (intervalRef.current) {
        clearTimeout(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isLive, liveInterval, fetchIncremental]);

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status" />
          <p className="mt-2">Loading system metrics…</p>
        </div>
      </div>
    );
  }

  const samples = data?.samples ?? [];
  const current = data?.current ?? null;
  const totalMemMB = (current?.system_total_memory_bytes ?? 0) / (1024 * 1024);

  // Down-sample labels so the x-axis stays readable
  const labels = samples.map(s => formatTime(s.timestamp));

  const cpuChartData = {
    labels,
    datasets: [
      {
        label: 'Process CPU %',
        data: samples.map(s => s.process_cpu_percent),
        borderColor: UI_COLORS.primary,
        backgroundColor: chartAreaFill(UI_COLORS.primary, 0.1),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      },
      {
        label: 'System CPU %',
        data: samples.map(s => s.system_cpu_percent),
        borderColor: UI_COLORS.success,
        backgroundColor: chartAreaFill(UI_COLORS.success, 0.1),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      },
    ],
  };

  const memoryChartData = {
    labels,
    datasets: [
      {
        label: 'Process Memory',
        data: samples.map(s => s.process_memory_bytes / (1024 * 1024)),
        borderColor: UI_COLORS.warning,
        backgroundColor: chartAreaFill(UI_COLORS.warning, 0.1),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
        yAxisID: 'y',
      },
      {
        label: 'System Used Memory',
        data: samples.map(s => s.system_used_memory_bytes / (1024 * 1024)),
        borderColor: UI_COLORS.danger,
        backgroundColor: chartAreaFill(UI_COLORS.danger, 0.1),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
        yAxisID: 'y',
      },
    ],
  };

  // Dedicated process-only charts
  const processCpuChartData = {
    labels,
    datasets: [
      {
        label: 'Process CPU %',
        data: samples.map(s => s.process_cpu_percent),
        borderColor: UI_COLORS.primary,
        backgroundColor: chartAreaFill(UI_COLORS.primary, 0.15),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      },
    ],
  };

  const processMemoryChartData = {
    labels,
    datasets: [
      {
        label: 'Process Memory (MB)',
        data: samples.map(s => s.process_memory_bytes / (1024 * 1024)),
        borderColor: UI_COLORS.warning,
        backgroundColor: chartAreaFill(UI_COLORS.warning, 0.15),
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      },
    ],
  };

  const cpuOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { position: 'top' },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: context => {
            const idx = context[0].dataIndex;
            const ts = samples[idx]?.timestamp;
            return ts ? formatTooltipTime(ts) : context[0].label;
          },
        },
      },
    },
    scales: {
      x: { ticks: { maxTicksLimit: 12 } },
      y: { beginAtZero: true, max: 100, title: { display: true, text: 'CPU %' } },
    },
  };

  const memoryOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { position: 'top' },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: context => {
            const idx = context[0].dataIndex;
            const ts = samples[idx]?.timestamp;
            return ts ? formatTooltipTime(ts) : context[0].label;
          },
        },
      },
    },
    scales: {
      x: { ticks: { maxTicksLimit: 12 } },
      y: {
        type: 'linear',
        beginAtZero: true,
        max: totalMemMB > 0 ? totalMemMB : undefined,
        title: { display: true, text: 'MB' },
      },
    },
  };

  const processCpuOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: context => {
            const idx = context[0].dataIndex;
            const ts = samples[idx]?.timestamp;
            return ts ? formatTooltipTime(ts) : context[0].label;
          },
        },
      },
    },
    scales: {
      x: { ticks: { maxTicksLimit: 10 } },
      y: {
        beginAtZero: true,
        max: 100,
        ticks: { precision: 0 },
        title: { display: true, text: 'CPU %' },
      },
    },
    animation: { duration: 300, easing: 'easeInOutQuart' },
  };

  const processMemoryOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: context => {
            const idx = context[0].dataIndex;
            const ts = samples[idx]?.timestamp;
            return ts ? formatTooltipTime(ts) : context[0].label;
          },
        },
      },
    },
    scales: {
      x: { ticks: { maxTicksLimit: 10 } },
      y: {
        beginAtZero: true,
        max: totalMemMB > 0 ? totalMemMB : undefined,
        title: { display: true, text: 'MB' },
      },
    },
    animation: { duration: 300, easing: 'easeInOutQuart' },
  };

  const totalMem = current?.system_total_memory_bytes ?? 0;
  const usedMem = current?.system_used_memory_bytes ?? 0;
  const memPct = totalMem > 0 ? ((usedMem / totalMem) * 100).toFixed(1) : '—';

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-start justify-content-end mb-4">
        <div className="d-flex align-items-center" style={{ gap: '0.5rem' }}>
          {/* Time Range selector */}
          <select
            className="form-control form-control-sm dropdown-styling"
            style={{ width: 'auto' }}
            value={timeRange}
            onChange={e => setTimeRange(e.target.value as TimeRange)}
          >
            <option value="10m">Last 10 minutes</option>
            <option value="1h">Last 1 hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="12h">Last 12 hours</option>
            <option value="24h">Last 24 hours</option>
          </select>
          {isLive && (
            <select
              className="form-control form-control-sm dropdown-styling"
              style={{ width: 'auto' }}
              value={liveInterval}
              onChange={e => setLiveInterval(Number(e.target.value))}
            >
              {LIVE_INTERVALS.map(opt => (
                <option key={opt.ms} value={opt.ms}>
                  {opt.label}
                </option>
              ))}
            </select>
          )}
          <AppButton
            variant={isLive ? 'secondary' : 'outline-secondary'}
            size="md"
            style={{ marginLeft: '16px' }}
            onClick={() => setIsLive(prev => !prev)}
            title={isLive ? 'Pause live updates' : 'Resume live updates'}
            iconStart={
              <i
                className={`fas ${isLive ? 'fa-pause' : 'fa-play'} fa-sm me-1`}
                aria-hidden="true"
              />
            }
          >
            {isLive ? 'Live' : 'Paused'}
          </AppButton>
          <AppButton
            variant="primary"
            size="md"
            className="shadow-sm"
            onClick={fetchFull}
            loading={loading}
            loadingLabel="Refreshing..."
            disabled={loading}
            iconStart={<i className="fas fa-sync-alt fa-sm me-1" aria-hidden="true" />}
          >
            Refresh
          </AppButton>
        </div>
      </div>

      {/* System info */}
      {data?.system_info && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="card shadow">
              <div
                className="card-body py-2 d-flex flex-wrap align-items-center"
                style={{ gap: '1.5rem' }}
              >
                {data.system_info.name && (
                  <span>
                    <strong>System:</strong> {data.system_info.name}
                  </span>
                )}
                {data.system_info.os_version && (
                  <span>
                    <strong>OS:</strong> {data.system_info.os_version}
                  </span>
                )}
                {data.system_info.kernel_version && (
                  <span>
                    <strong>Kernel:</strong> {data.system_info.kernel_version}
                  </span>
                )}
                {data.system_info.host_name && (
                  <span>
                    <strong>Host:</strong> {data.system_info.host_name}
                  </span>
                )}
                {data.system_info.uptime_seconds != null && (
                  <span>
                    <strong>Uptime:</strong> {formatUptime(data.system_info.uptime_seconds)}
                  </span>
                )}
                {lastRefreshTime && (
                  <span>
                    <strong>Last refresh:</strong>{' '}
                    {lastRefreshTime.toLocaleTimeString(undefined, {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                      hour12: false,
                    })}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Current values */}
      <div className="row mb-4">
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-primary shadow h-100 py-2">
            <div className="card-body">
              <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                Process CPU{' '}
                <FieldHelp testId="field-help-process-cpu" ariaLabel="About Process CPU">
                  CPU used by this gateway's own process only, not the rest of the host machine.
                </FieldHelp>
              </div>
              <div className="h5 mb-0 font-weight-bold text-gray-800">
                {current ? `${current.process_cpu_percent.toFixed(1)}%` : '—'}
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-success shadow h-100 py-2">
            <div className="card-body">
              <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                System CPU{' '}
                <FieldHelp testId="field-help-system-cpu" ariaLabel="About System CPU">
                  Total CPU used across the whole host machine, including this gateway and anything
                  else running on it.
                </FieldHelp>
              </div>
              <div className="h5 mb-0 font-weight-bold text-gray-800">
                {current ? `${current.system_cpu_percent.toFixed(1)}%` : '—'}
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-warning shadow h-100 py-2">
            <div className="card-body">
              <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                Process Memory{' '}
                <FieldHelp testId="field-help-process-memory" ariaLabel="About Process Memory">
                  Memory used by this gateway's own process only.
                </FieldHelp>
              </div>
              <div className="h5 mb-0 font-weight-bold text-gray-800">
                {current ? formatBytes(current.process_memory_bytes) : '—'}
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-danger shadow h-100 py-2">
            <div className="card-body">
              <div className="text-xs font-weight-bold text-danger text-uppercase mb-1">
                System Memory{' '}
                <FieldHelp testId="field-help-system-memory" ariaLabel="About System Memory">
                  Total memory in use across the whole host machine, including this gateway and
                  anything else running on it.
                </FieldHelp>
              </div>
              <div className="h5 mb-0 font-weight-bold text-gray-800">
                {current ? `${formatBytes(usedMem)} / ${formatBytes(totalMem)} (${memPct}%)` : '—'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Process Charts */}
      <div className="row">
        <div className="col-lg-6 mb-4">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-microchip me-1"></i> Process CPU
              </h6>
            </div>
            <div className="card-body" style={{ height: '300px' }}>
              {samples.length > 0 ? (
                <Line
                  ref={chartRef1}
                  data={processCpuChartData}
                  options={processCpuOptions}
                  plugins={[crosshairPlugin]}
                />
              ) : (
                <p className="text-muted text-center mt-5">
                  No data yet — metrics are collected every 30 seconds.
                </p>
              )}
            </div>
          </div>
        </div>
        <div className="col-lg-6 mb-4">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-warning">
                <i className="fas fa-memory me-1"></i> Process Memory
              </h6>
            </div>
            <div className="card-body" style={{ height: '300px' }}>
              {samples.length > 0 ? (
                <Line
                  ref={chartRef2}
                  data={processMemoryChartData}
                  options={processMemoryOptions}
                  plugins={[crosshairPlugin]}
                />
              ) : (
                <p className="text-muted text-center mt-5">
                  No data yet — metrics are collected every 30 seconds.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Combined System + Process Charts */}
      <div className="row">
        <div className="col-lg-12 mb-4">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">CPU Usage (System + Process)</h6>
            </div>
            <div className="card-body" style={{ height: '300px' }}>
              {samples.length > 0 ? (
                <Line
                  ref={chartRef3}
                  data={cpuChartData}
                  options={cpuOptions}
                  plugins={[crosshairPlugin]}
                />
              ) : (
                <p className="text-muted text-center mt-5">
                  No data yet — metrics are collected every 30 seconds.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="row">
        <div className="col-lg-12 mb-4">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">Memory Usage (System + Process)</h6>
            </div>
            <div className="card-body" style={{ height: '300px' }}>
              {samples.length > 0 ? (
                <Line
                  ref={chartRef4}
                  data={memoryChartData}
                  options={memoryOptions}
                  plugins={[crosshairPlugin]}
                />
              ) : (
                <p className="text-muted text-center mt-5">
                  No data yet — metrics are collected every 30 seconds.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SystemMetricsPage;
