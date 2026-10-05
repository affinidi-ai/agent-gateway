import React, { useMemo, useEffect, useRef } from 'react';
import { apiClient } from '../../../api';
import { Line, Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title as ChartTitle,
  Tooltip,
  Legend,
  ChartOptions,
  Filler,
  BarElement,
  ArcElement,
} from 'chart.js';
import { formatTime, formatDID } from '../../../utils/stringUtils';
import ChannelLogsViewer from './ChannelLogsViewer';
import { DashboardStats } from '../../../types';
import { UI_COLORS, chartAreaFill, withAlpha } from '../../../utils/uiPalette';

interface ChannelMetrics {
  channel_config_id: string;
  time_series: Array<{
    timestamp: string;
    count: number;
    rule_accepts: number;
    rule_denies: number;
    gateway_faults: number;
  }>;
  latency_time_series: Array<{
    timestamp: string;
    avg_latency_ms: number;
    p50_latency_ms: number;
    p95_latency_ms: number;
    p99_latency_ms: number;
    min_latency_ms: number;
    max_latency_ms: number;
    sample_count: number;
  }>;
}

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ChartTitle,
  Tooltip,
  Legend,
  Filler,
  BarElement,
  ArcElement
);

export interface MonitoringTabProps {
  channelMetrics: ChannelMetrics | null;
  formData: {
    config_id: string;
    name?: string;
  };
  dashboardStats: DashboardStats | null;
  state: any; // AppState from useApp
  actions: any; // AppContext actions
}

const MonitoringTab: React.FC<MonitoringTabProps> = ({
  channelMetrics,
  formData,
  dashboardStats,
  state,
  actions,
}) => {
  const [selectedBucket, setSelectedBucket] = React.useState<number | null>(null);
  const previousBucketRef = React.useRef<number | null>(null);
  const [chartsKey, setChartsKey] = React.useState(0);
  const chartContainerRef = useRef<HTMLDivElement>(null);

  // UCP Operation Stats
  const [ucpOperationStats, setUcpOperationStats] = React.useState<Array<{
    operation: string;
    count: number;
    successful: number;
    failed: number;
    percentage: number;
  }> | null>(null);

  // Extract channelTimeSeries from channelMetrics
  const channelTimeSeries = useMemo(() => {
    return channelMetrics?.time_series || [];
  }, [channelMetrics]);

  // Extract channelLatencyTimeSeries from channelMetrics
  const channelLatencyTimeSeries = useMemo(() => {
    return channelMetrics?.latency_time_series || [];
  }, [channelMetrics]);

  // Prepare connections chart data for this channel
  const channelConnectionsChartData = useMemo(() => {
    if (!channelTimeSeries || channelTimeSeries.length === 0) {
      return { labels: [], datasets: [] };
    }

    const labels = channelTimeSeries.map((point: any) => formatTime(point.timestamp));

    // Extract data arrays from time series
    const connectionsData = channelTimeSeries.map((point: any) => point.count || 0);
    const ruleAcceptsData = channelTimeSeries.map((point: any) => point.rule_accepts || 0);
    const ruleDeniesData = channelTimeSeries.map((point: any) => point.rule_denies || 0);
    const failedData = channelTimeSeries.map((point: any) => point.failed || 0);
    const gatewayFaultsData = channelTimeSeries.map((point: any) => point.gateway_faults || 0);

    const allDatasets = [
      {
        label: 'Connections',
        data: connectionsData,
        borderColor: UI_COLORS.primary,
        backgroundColor: chartAreaFill(UI_COLORS.primary),
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 4,
        fill: true,
        tension: 0.3,
      },
      {
        label: 'Rule Accepts',
        data: ruleAcceptsData,
        borderColor: UI_COLORS.success,
        backgroundColor: chartAreaFill(UI_COLORS.success),
        borderWidth: 1,
        pointRadius: 1,
        pointHoverRadius: 3,
        fill: true,
        tension: 0.3,
      },
      {
        label: 'Rule Denies',
        data: ruleDeniesData,
        borderColor: UI_COLORS.warning,
        backgroundColor: chartAreaFill(UI_COLORS.warning),
        borderWidth: 1,
        pointRadius: 1,
        pointHoverRadius: 3,
        fill: true,
        tension: 0.3,
      },
      {
        label: 'Failed',
        data: failedData,
        borderColor: UI_COLORS.orange,
        backgroundColor: chartAreaFill(UI_COLORS.orange),
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 4,
        fill: true,
        tension: 0.3,
      },
      {
        label: 'Gateway Faults',
        data: gatewayFaultsData,
        borderColor: UI_COLORS.danger,
        backgroundColor: chartAreaFill(UI_COLORS.danger),
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 4,
        fill: true,
        tension: 0.3,
      },
    ];

    // Hide datasets that have no data
    const datasets = allDatasets.map(dataset => ({
      ...dataset,
      hidden: !dataset.data.some((value: number) => value > 0),
    }));

    const visibleCount = datasets.filter(d => !d.hidden).length;

    return { labels, datasets };
  }, [channelTimeSeries]);

  // Force chart re-render when tab becomes visible/active
  // This fixes Chart.js initialization issues in hidden containers
  useEffect(() => {
    if (!channelConnectionsChartData.labels.length) return;

    // Use ResizeObserver to detect when chart container gets dimensions
    if (chartContainerRef.current) {
      let hasTriggered = false;

      const observer = new ResizeObserver(entries => {
        for (const entry of entries) {
          const { width, height } = entry.contentRect;

          // If container has proper dimensions, data is present, and we haven't triggered yet
          if (width > 0 && height > 0 && !hasTriggered) {
            hasTriggered = true;
            // Small delay to ensure all layout is complete
            setTimeout(() => {
              setChartsKey(prev => prev + 1);
            }, 50);
          }
        }
      });

      observer.observe(chartContainerRef.current);
      return () => observer.disconnect();
    }
  }, [channelConnectionsChartData.labels.length]); // Re-check when data changes

  // Sync selectedBucket with settings on mount and when settings change
  React.useEffect(() => {
    if (state.settings?.bucket_seconds && selectedBucket === null) {
      setSelectedBucket(state.settings.bucket_seconds);
    }
  }, [state.settings?.bucket_seconds, selectedBucket]);

  // Fetch UCP operation stats for this channel (only for A2A/UCP channels)
  React.useEffect(() => {
    if (!formData.config_id) {
      setUcpOperationStats(null);
      return;
    }

    const fetchUcpStats = async () => {
      try {
        const response = await apiClient.fetch(
          `/api/v1/dashboard/surface/${formData.config_id}/ucp-operations`
        );
        if (response.ok) {
          const stats = await response.json();
          setUcpOperationStats(stats);
        } else {
          setUcpOperationStats(null);
        }
      } catch (error) {
        console.error('Failed to fetch UCP operation stats:', error);
        setUcpOperationStats(null);
      }
    };

    // Get channel data from dashboardStats to check if it's a UCP channel.
    // If dashboardStats hasn't loaded yet (channel === undefined), fetch anyway —
    // the API returns an empty array for non-UCP channels so it's safe.
    // Only skip the fetch when dashboardStats IS loaded and the channel is
    // confirmed to have no UCP extensions.
    const channel: any = dashboardStats?.channels?.find(
      (ch: any) => ch.config_id === formData.config_id
    );

    if (channel === undefined) {
      // dashboardStats not loaded yet — fetch optimistically
      fetchUcpStats();
      return;
    }

    // dashboardStats is loaded; check both top-level (legacy) and virtual channel locations
    const hasTopLevelUcp =
      channel?.primary_extension?.includes('ucp.dev') ||
      channel?.supported_extensions?.some((ext: string) => ext.includes('ucp.dev'));
    const defaultVC =
      channel?.virtual_channels?.find((vc: any) => vc.id === channel.default_virtual_channel_id) ||
      channel?.virtual_channels?.[0];
    const hasVCUcp =
      defaultVC?.primary_extension?.includes('ucp.dev') ||
      defaultVC?.supported_extensions?.some((ext: string) => ext.includes('ucp.dev'));
    const isUcpChannel = channel?.protocol === 'a2a' && (hasTopLevelUcp || hasVCUcp);

    if (isUcpChannel) {
      fetchUcpStats();
    } else {
      setUcpOperationStats(null);
    }
  }, [formData.config_id, dashboardStats?.channels, channelMetrics]);

  // Handler for bucket selector change
  const handleBucketChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const newBucket = parseInt(event.target.value, 10);
    setSelectedBucket(newBucket);
    actions.setDashboardBucketOverride(newBucket);

    // Only trigger refresh if bucket actually changed
    if (previousBucketRef.current !== newBucket) {
      previousBucketRef.current = newBucket;
      // Use setTimeout to ensure state has updated
      setTimeout(() => {
        actions.loadDashboardStats(true);
      }, 0);
    }
  };

  // Prepare latency chart data for this channel
  const channelLatencyChartData = useMemo(() => {
    if (!channelLatencyTimeSeries || channelLatencyTimeSeries.length === 0) {
      return { labels: [], datasets: [] };
    }

    const data = channelLatencyTimeSeries;
    const labels = data.map((point: { timestamp: string }) => formatTime(point.timestamp));

    return {
      labels,
      datasets: [
        {
          label: 'p50 (Median)',
          data: data.map((point: any) => point.p50_latency_ms || 0),
          borderColor: UI_COLORS.success,
          backgroundColor: chartAreaFill(UI_COLORS.success),
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 4,
          fill: false,
          tension: 0.3,
        },
        {
          label: 'p95',
          data: data.map((point: any) => point.p95_latency_ms || 0),
          borderColor: UI_COLORS.warning,
          backgroundColor: chartAreaFill(UI_COLORS.warning),
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 4,
          fill: false,
          tension: 0.3,
        },
        {
          label: 'p99',
          data: data.map((point: any) => point.p99_latency_ms || 0),
          borderColor: UI_COLORS.danger,
          backgroundColor: chartAreaFill(UI_COLORS.danger),
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 4,
          fill: false,
          tension: 0.3,
        },
        {
          label: 'Average',
          data: data.map((point: any) => point.avg_latency_ms || 0),
          borderColor: UI_COLORS.primary,
          backgroundColor: chartAreaFill(UI_COLORS.primary),
          borderWidth: 1,
          pointRadius: 1,
          pointHoverRadius: 3,
          fill: false,
          tension: 0.3,
          borderDash: [5, 5],
        },
      ],
    };
  }, [channelLatencyTimeSeries]);

  // Chart options
  const connectionsChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          usePointStyle: true,
          pointStyle: 'circle',
          boxWidth: 8,
          boxHeight: 8,
          padding: 15,
        },
      },
      title: {
        display: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          precision: 0,
        },
      },
    },
    animation: {
      duration: 300,
      easing: 'easeInOutQuart',
    },
    transitions: {
      active: {
        animation: {
          duration: 0,
        },
      },
    },
  };

  const latencyChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },
    scales: {
      x: {
        display: true,
        title: {
          display: true,
          text: 'Time',
        },
      },
      y: {
        display: true,
        title: {
          display: true,
          text: 'Latency (ms)',
        },
        beginAtZero: true,
      },
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
  };

  // Prepare identity-channel chart data filtered for this channel
  const getChannelIdentityChartData = useMemo(() => {
    if (!dashboardStats?.identities || !formData.config_id) {
      return {
        labels: [],
        datasets: [],
      };
    }

    // Filter identities that have been used on this channel
    // Use the channel_usage array in each identity record
    const channelIdentities = dashboardStats.identities.filter((identity: any) => {
      return identity.channel_usage?.some((cu: any) => cu.channel_config_id === formData.config_id);
    });

    if (channelIdentities.length === 0) {
      return {
        labels: [],
        datasets: [],
      };
    }

    // Build chart data from identities with channel_usage
    // Note: We don't have per-channel success/deny/fault breakdown in channel_usage yet,
    // so we'll show total usage count only
    const identityData = channelIdentities.map((identity: any) => {
      const channelUsage = identity.channel_usage.find(
        (cu: any) => cu.channel_config_id === formData.config_id
      );

      return {
        did: identity.did,
        total: channelUsage?.usage_count || 0,
      };
    });

    // Sort identities by total count (descending)
    const sortedIdentities = identityData.sort((a, b) => b.total - a.total).slice(0, 10);

    // Build labels and data arrays
    const labels: string[] = [];
    const totalData: number[] = [];

    sortedIdentities.forEach(identity => {
      // Format DID for compact display
      labels.push(formatDID(identity.did));
      totalData.push(identity.total);
    });

    return {
      labels,
      datasets: [
        {
          label: 'Total Requests',
          data: totalData,
          backgroundColor: 'rgba(54, 162, 235, 0.8)',
          borderColor: 'rgba(54, 162, 235, 1)',
          borderWidth: 1,
        },
      ],
    };
  }, [dashboardStats?.identities, formData.config_id]);

  const identityChannelChartOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {
      legend: {
        position: 'top',
        display: false, // Hide legend since we only have one dataset
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: {
          precision: 0,
        },
      },
      y: {
        ticks: {
          font: {
            size: 10,
            family: 'monospace',
          },
          autoSkip: false,
        },
      },
    },
    animation: {
      duration: 500,
      easing: 'easeInOutQuart',
    },
  };

  // Prepare UCP operation chart data
  const ucpOperationChartData = useMemo(() => {
    if (!ucpOperationStats || ucpOperationStats.length === 0) {
      return { labels: [], datasets: [] };
    }

    // Sort by operation name to ensure consistent ordering
    const sortedStats = [...ucpOperationStats].sort((a, b) =>
      a.operation.localeCompare(b.operation)
    );

    const labels = sortedStats.map(stat => stat.operation);
    const data = sortedStats.map(stat => stat.count);

    // Color scheme for different UCP operations
    const colors = [
      withAlpha(UI_COLORS.primary, 0.8),
      withAlpha(UI_COLORS.success, 0.8),
      withAlpha(UI_COLORS.accentTeal, 0.8),
      withAlpha(UI_COLORS.warning, 0.8),
      withAlpha(UI_COLORS.danger, 0.8),
      withAlpha(UI_COLORS.neutralMuted, 0.8),
      withAlpha(UI_COLORS.accentPurple, 0.8),
    ];

    return {
      labels,
      datasets: [
        {
          data,
          backgroundColor: colors.slice(0, labels.length),
          borderColor: colors.slice(0, labels.length).map(c => c.replace('0.8', '1')),
          borderWidth: 1,
        },
      ],
    };
  }, [ucpOperationStats]);

  const ucpOperationChartOptions: ChartOptions<'pie'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        display: true,
      },
      tooltip: {
        callbacks: {
          label: function (context) {
            const label = context.label || '';
            const value = context.parsed || 0;
            const stat = ucpOperationStats?.find(s => s.operation === label);
            const percentage = stat?.percentage.toFixed(1) || '0';
            return `${label}: ${value} (${percentage}%)`;
          },
        },
      },
    },
  };

  return (
    <div>
      {!channelMetrics ||
      (channelTimeSeries.length === 0 && channelLatencyTimeSeries.length === 0) ? (
        <div className="alert alert-info">
          <i className="fas fa-info-circle"></i> No metrics data available for this channel yet.
          Metrics will appear once the channel starts handling requests.
        </div>
      ) : (
        <>
          {/* Connections Over Time Chart */}
          <div className="card shadow mb-4 monitoring-chart-card">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-chart-area"></i> Connections Over Time
              </h6>
              <select
                className="form-control form-control-sm dropdown-styling"
                style={{ width: 'auto' }}
                value={
                  selectedBucket ||
                  state.filteredState?.currentBucketSeconds ||
                  state.settings?.bucket_seconds ||
                  30
                }
                onChange={handleBucketChange}
              >
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={300}>5 minutes</option>
                <option value={900}>15 minutes</option>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={10800}>3 hours</option>
                <option value={21600}>6 hours</option>
              </select>
            </div>
            <div className="card-body">
              <div ref={chartContainerRef} style={{ height: '300px' }}>
                {(() => {
                  const willRender = channelConnectionsChartData.labels.length > 0;
                  return willRender ? (
                    <Line
                      key={`connections-${chartsKey}`}
                      data={channelConnectionsChartData}
                      options={connectionsChartOptions}
                      redraw={false}
                    />
                  ) : (
                    <div className="d-flex justify-content-center align-items-center h-100">
                      <p className="text-muted">No connection data available</p>
                    </div>
                  );
                })()}
              </div>
            </div>
          </div>

          {/* Latency Over Time Chart */}
          <div className="card shadow mb-4 monitoring-chart-card">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-tachometer-alt"></i> Connection Latency Over Time (p50, p95,
                p99)
              </h6>
              <select
                className="form-control form-control-sm dropdown-styling"
                style={{ width: 'auto' }}
                value={
                  selectedBucket ||
                  state.filteredState?.currentBucketSeconds ||
                  state.settings?.bucket_seconds ||
                  30
                }
                onChange={handleBucketChange}
              >
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={300}>5 minutes</option>
                <option value={900}>15 minutes</option>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={10800}>3 hours</option>
                <option value={21600}>6 hours</option>
              </select>
            </div>
            <div className="card-body">
              <div style={{ height: '300px' }}>
                {channelLatencyChartData.labels.length > 0 ? (
                  <Line
                    key={`latency-${chartsKey}`}
                    data={channelLatencyChartData}
                    options={latencyChartOptions}
                    redraw={false}
                  />
                ) : (
                  <div className="d-flex justify-content-center align-items-center h-100">
                    <p className="text-muted">No latency data available</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Identity Connections for This Channel */}
          <div className="card shadow mb-4 monitoring-chart-card">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-fingerprint"></i> Identity Connections for This Channel
              </h6>
            </div>
            <div className="card-body">
              <div style={{ height: '400px' }}>
                {getChannelIdentityChartData.labels.length > 0 ? (
                  <Bar
                    key={`identity-${chartsKey}`}
                    data={getChannelIdentityChartData}
                    options={identityChannelChartOptions}
                    redraw={false}
                  />
                ) : (
                  <div className="d-flex justify-content-center align-items-center h-100">
                    <p className="text-muted">
                      No identity connection data available for this channel
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* UCP Operation Distribution (only shown if UCP stats available) */}
          {ucpOperationStats && ucpOperationStats.length > 0 && (
            <div className="card shadow mb-4 monitoring-chart-card">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-chart-pie"></i> UCP Operation Distribution
                </h6>
              </div>
              <div className="card-body">
                <div style={{ height: '400px' }}>
                  <Pie
                    key={`ucp-${chartsKey}`}
                    data={ucpOperationChartData}
                    options={ucpOperationChartOptions}
                    redraw={false}
                  />
                </div>
                <div className="mt-3">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>Operation</th>
                        <th className="text-end">Count</th>
                        <th className="text-end">Success</th>
                        <th className="text-end">Failed</th>
                        <th className="text-end">%</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...ucpOperationStats]
                        .sort((a, b) => a.operation.localeCompare(b.operation))
                        .map(stat => (
                          <tr key={stat.operation}>
                            <td>
                              <code>{stat.operation}</code>
                            </td>
                            <td className="text-end">{stat.count}</td>
                            <td className="text-end text-success">{stat.successful}</td>
                            <td className="text-end text-danger">{stat.failed}</td>
                            <td className="text-end">{stat.percentage.toFixed(1)}%</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Info about data source */}
          <div className="text-end">
            <small className="text-muted">
              <i className="fas fa-info-circle"></i> Updates automatically with dashboard data
            </small>
          </div>
        </>
      )}

      {/* Channel Logs Section - Always shown */}
      <ChannelLogsViewer channelConfigId={formData.config_id} channelName={formData.name} />
    </div>
  );
};

export default MonitoringTab;
