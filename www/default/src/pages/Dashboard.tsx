import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { apiClient } from '../api';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
  Filler,
  ArcElement,
  BarElement,
} from 'chart.js';
import { useApp } from '../context/AppContext';
import StatCard from '../components/StatCard';
import ChartCard from '../components/ChartCard';
import IdentityDetailsModal from '../components/IdentityDetailsModal';
import { AppButton } from '../components/shared/AppButton';
import { DeleteButton } from '../components/shared/DeleteButton';
import { GraphEmptyState } from '../components/shared/GraphConnectionEmptyState';
import { Form } from 'react-bootstrap';
import {
  CHART_PALETTE,
  UI_COLORS,
  chartAreaFill,
  chartBarFill,
  withAlpha,
} from '../utils/uiPalette';

// Static sample fixture shown behind the empty-state overlay.
// Values are committed constants — never recomputed, never random.
const CONNECTIONS_SAMPLE_FIXTURE = {
  labels: [
    '00:00',
    '00:30',
    '01:00',
    '01:30',
    '02:00',
    '02:30',
    '03:00',
    '03:30',
    '04:00',
    '04:30',
    '05:00',
    '05:30',
  ],
  datasets: [
    {
      label: 'Connections',
      data: [12, 28, 45, 38, 62, 54, 71, 48, 83, 67, 55, 42],
      borderColor: UI_COLORS.primary,
      backgroundColor: chartAreaFill(UI_COLORS.primary),
      borderWidth: 1,
      fill: true,
      tension: 0.4,
      hidden: false,
    },
    {
      label: 'Rule Accepts',
      data: [10, 24, 40, 34, 55, 48, 63, 42, 74, 60, 49, 38],
      borderColor: UI_COLORS.success,
      backgroundColor: chartAreaFill(UI_COLORS.success),
      borderWidth: 1,
      fill: true,
      tension: 0.4,
      hidden: false,
    },
    {
      label: 'Rule Denies',
      data: [2, 4, 5, 4, 7, 6, 8, 6, 9, 7, 6, 4],
      borderColor: UI_COLORS.accentPurple,
      backgroundColor: chartAreaFill(UI_COLORS.accentPurple),
      borderWidth: 1,
      fill: true,
      tension: 0.4,
      hidden: false,
    },
  ],
};

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  ArcElement,
  BarElement
);

const Dashboard: React.FC = () => {
  const { state, actions, getCurrentStats } = useApp();
  const navigate = useNavigate();
  const [showDidModal, setShowDidModal] = useState(false);
  const [didDocument, setDidDocument] = useState<any>(null);
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [selectedIdentity, setSelectedIdentity] = useState<any>(null);
  const [configuredSurfaceCount, setConfiguredSurfaceCount] = useState<number | null>(null);

  // Bucket selector for aggregated connections graph
  const [selectedBucket, setSelectedBucket] = useState<number | null>(null);
  const previousBucketRef = useRef<number | null>(null);

  // Track if we've ever loaded data (to avoid showing spinner on refreshes)
  const hasLoadedOnce = useRef<boolean>(false);
  const isMountedRef = useRef<boolean>(false);

  // Get the currently active stats (global or filtered)
  const stats = getCurrentStats();

  // Mark as loaded once we have stats
  if (stats && !hasLoadedOnce.current) {
    hasLoadedOnce.current = true;
  }

  const loadConfiguredSurfaceCount = useCallback(async () => {
    try {
      const surfaces = await apiClient.listSurfaces();
      if (isMountedRef.current) {
        setConfiguredSurfaceCount(surfaces.length);
      }
    } catch {
      if (isMountedRef.current) {
        setConfiguredSurfaceCount(null);
      }
    }
  }, []);

  const loadDashboardData = useCallback(
    async (force?: boolean) => {
      const statsRefresh =
        force === undefined ? actions.loadDashboardStats() : actions.loadDashboardStats(force);
      await Promise.all([statsRefresh, loadConfiguredSurfaceCount()]);
    },
    [actions, loadConfiguredSurfaceCount]
  );

  // Clear any dashboard filters when viewing main dashboard (only once on mount)
  useEffect(() => {
    isMountedRef.current = true;
    actions.setDashboardFilters(null);
    loadDashboardData(true);

    // Subscribe to everything except logs to reduce WS payload size
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      isMountedRef.current = false;
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run only once on mount

  const agentSurfacesCount = configuredSurfaceCount ?? stats?.channels?.length ?? 0;

  // Sync selectedBucket with settings on mount and when settings change
  useEffect(() => {
    if (state.settings?.bucket_seconds && selectedBucket === null) {
      setSelectedBucket(state.settings.bucket_seconds);
    }
  }, [state.settings?.bucket_seconds, selectedBucket]);

  // Show DID document modal
  const showDidDocumentModal = (didDoc: any) => {
    setDidDocument(didDoc);
    setShowDidModal(true);
  };

  // Show identity details modal
  const showIdentityDetails = (identity: any) => {
    setSelectedIdentity(identity);
    setShowIdentityModal(true);
  };

  const [channelChartView, setChannelChartView] = useState<'pie' | 'bar' | 'connections'>('pie');
  const [isRefreshing, setIsRefreshing] = useState(false);

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
        loadDashboardData(true);
      }, 0);
    }
  };

  // Debug: Log when dashboard stats change
  useEffect(() => {
    // console.log('Dashboard stats updated:', {
    //   totalConnections: stats?.metrics?.total_connections,
    //   timeSeriesLength: stats?.metrics?.time_series?.length,
    //   latestPoint: stats?.metrics?.time_series?.[stats.metrics.time_series.length - 1]
    // });
  }, [stats?.metrics]);

  // Prepare connections chart data - memoized to avoid recalculating on every render
  const connectionsChartData = useMemo(() => {
    if (!stats?.metrics?.time_series) {
      return {
        labels: [],
        datasets: [],
      };
    }

    const data = stats.metrics.time_series;

    // Convert timestamps to local time
    const labels = data.map(point => {
      const date = new Date(point.timestamp);
      return date.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
    });

    // Define all possible datasets
    const allDatasets = [
      {
        label: 'Gateway Faults',
        data: data.map(point => point.gateway_faults || 0),
        borderColor: UI_COLORS.danger,
        backgroundColor: chartAreaFill(UI_COLORS.danger),
        borderWidth: 1,
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Connections',
        data: data.map(point => point.count || 0),
        borderColor: UI_COLORS.primary,
        backgroundColor: chartAreaFill(UI_COLORS.primary),
        borderWidth: 1,
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Rule Accepts',
        data: data.map(point => point.rule_accepts || 0),
        borderColor: UI_COLORS.success,
        backgroundColor: chartAreaFill(UI_COLORS.success),
        borderWidth: 1,
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Rule Denies',
        data: data.map(point => point.rule_denies || 0),
        borderColor: UI_COLORS.accentPurple,
        backgroundColor: chartAreaFill(UI_COLORS.accentPurple),
        borderWidth: 1,
        fill: true,
        tension: 0.4,
      },
    ];

    // Split datasets into those with data and those without, but hide empty ones from rendering
    const datasets = allDatasets.map(dataset => ({
      ...dataset,
      hidden: !dataset.data.some(value => value > 0),
    }));

    return {
      labels,
      datasets,
    };
  }, [stats?.metrics?.time_series]);

  // Prepare channel distribution chart data
  const getChannelDistributionData = () => {
    if (!stats?.channels || stats.channels.length === 0) {
      //console.log('Channel Distribution: No channels data', { hasStats: !!stats, channelsLength: stats?.channels?.length });
      return { labels: [], datasets: [] };
    }

    const channelData = stats.channels.map(channel => ({
      name: channel.name,
      connections: channel.accept_count || 0,
      rules: channel.rule_count || 0,
      total_connections: channel.accept_count || 0,
      successful: channel.accept_count || 0,
      failed: channel.deny_count || 0,
      gateway_faults: channel.gateway_faults || 0,
    }));

    const totalConnections = channelData.reduce((sum, ch) => sum + ch.total_connections, 0);
    const hasTraffic = totalConnections > 0;

    // Sort by activity (connections or rules) and take top 10
    const sortedChannels = channelData
      .map(ch => ({
        ...ch,
        activityValue: hasTraffic ? ch.total_connections : ch.rules,
      }))
      .filter(ch => ch.activityValue > 0) // Only show channels with data
      .sort((a, b) => b.activityValue - a.activityValue) // Most active first
      .slice(0, 10); // Maximum 10 channels

    // console.log('Channel Distribution Data:', {
    //   totalChannels: channelData.length,
    //   displayedChannels: sortedChannels.length,
    //   totalConnections,
    //   hasTraffic,
    //   channels: sortedChannels
    // });

    const colors = CHART_PALETTE;

    const dataToDisplay = sortedChannels.map(r => r.activityValue);

    if (channelChartView === 'pie') {
      return {
        labels: sortedChannels.map(r => r.name),
        datasets: [
          {
            data: dataToDisplay,
            backgroundColor: colors.slice(0, sortedChannels.length),
            borderWidth: 0,
          },
        ],
      };
    } else if (channelChartView === 'bar') {
      return {
        labels: sortedChannels.map(r => r.name),
        datasets: [
          {
            label: hasTraffic ? 'Connections' : 'Rules',
            data: dataToDisplay,
            backgroundColor: UI_COLORS.primary,
            borderColor: UI_COLORS.primary,
            borderWidth: 1,
          },
        ],
      };
    } else {
      // connections view
      return {
        labels: sortedChannels.map(r => r.name),
        datasets: [
          {
            label: 'Total Connections',
            data: sortedChannels.map(r => r.total_connections),
            backgroundColor: UI_COLORS.success,
            borderColor: UI_COLORS.success,
            borderWidth: 1,
          },
          {
            label: 'Rules Count',
            data: sortedChannels.map(r => r.rules),
            backgroundColor: UI_COLORS.accentTeal,
            borderColor: UI_COLORS.accentTeal,
            borderWidth: 1,
          },
        ],
      };
    }
  };

  // Prepare latency chart data - memoized to avoid recalculating on every render
  const latencyChartData = useMemo(() => {
    if (!stats?.metrics?.latency_time_series) {
      return {
        labels: [],
        datasets: [],
      };
    }

    const data = stats.metrics.latency_time_series;

    // Convert timestamps to local time
    const labels = data.map(point => {
      const date = new Date(point.timestamp);
      return date.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
    });

    return {
      labels,
      datasets: [
        {
          label: 'p50 (Median)',
          data: data.map(point => point.p50_latency_ms || 0),
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
          data: data.map(point => point.p95_latency_ms || 0),
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
          data: data.map(point => point.p99_latency_ms || 0),
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
          data: data.map(point => point.avg_latency_ms || 0),
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
  }, [stats?.metrics?.latency_time_series]);

  // Chart options for different chart types
  const doughnutChartOptions: ChartOptions<'doughnut'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
      },
    },
    animation: {
      duration: 500,
      easing: 'easeInOutQuart',
    },
  };

  const barChartOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: channelChartView === 'connections',
      },
    },
    scales: {
      y: {
        beginAtZero: true,
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
        callbacks: {
          title: context => {
            // Get the original timestamp from the data
            const dataIndex = context[0].dataIndex;
            const timestamp = stats?.metrics?.latency_time_series?.[dataIndex]?.timestamp;
            if (timestamp) {
              const date = new Date(timestamp);
              return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false,
                timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              });
            }
            return context[0].label;
          },
        },
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
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: context => {
            // Get the original timestamp from the data
            const dataIndex = context[0].dataIndex;
            const timestamp = stats?.metrics?.time_series?.[dataIndex]?.timestamp;
            if (timestamp) {
              const date = new Date(timestamp);
              return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false,
                timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              });
            }
            return context[0].label;
          },
        },
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

  // Prepare identity-channel chart data
  const getIdentityChannelChartData = () => {
    if (
      !stats?.metrics?.identity_channel_stats ||
      stats.metrics.identity_channel_stats.length === 0
    ) {
      return {
        labels: [],
        datasets: [],
      };
    }

    const identityChannelStats = stats.metrics.identity_channel_stats;

    // Create a map of config_id to channel name
    const configIdToName: Record<string, string> = {};
    stats.channels.forEach(channel => {
      if (channel.config_id) {
        configIdToName[channel.config_id] = channel.name;
      }
    });

    // Create a set of channel names that have duplicates
    const channelNameCounts: Record<string, number> = {};
    const duplicateChannelNames = new Set<string>();

    stats.channels.forEach(channel => {
      channelNameCounts[channel.name] = (channelNameCounts[channel.name] || 0) + 1;
    });

    Object.entries(channelNameCounts).forEach(([name, count]) => {
      if (count > 1) {
        duplicateChannelNames.add(name);
      }
    });

    // Aggregate data by identity hash
    const identityMap: Record<
      string,
      { channels: Record<string, { success: number; deny: number; fault: number }>; total: number }
    > = {};

    identityChannelStats.forEach(stat => {
      if (!identityMap[stat.identity_hash]) {
        identityMap[stat.identity_hash] = {
          channels: {},
          total: 0,
        };
      }

      // Map config_id to channel name for display
      const channelName = configIdToName[stat.channel_config_id] || stat.channel_config_id;
      identityMap[stat.identity_hash].channels[channelName] = {
        success: stat.success_count,
        deny: stat.deny_count,
        fault: stat.fault_count,
      };
      identityMap[stat.identity_hash].total += stat.total_count;
    });

    // Sort identities by total count (descending), then by identity hash alphabetically
    const sortedIdentities = Object.entries(identityMap)
      .sort((a, b) => {
        // Primary sort: by total connections (descending)
        const totalDiff = b[1].total - a[1].total;
        if (totalDiff !== 0) return totalDiff;

        // Secondary sort: by identity hash alphabetically (ascending)
        return a[0].localeCompare(b[0]);
      })
      .slice(0, 10);

    // Build labels (shortened identity hash + channel)
    const labels: string[] = [];
    const successData: number[] = [];
    const denyData: number[] = [];
    const faultData: number[] = [];

    sortedIdentities.forEach(([identity, data]) => {
      const shortIdentity = identity.substring(0, 8) + '...';
      // Sort channels alphabetically for each identity
      const sortedChannels = Object.entries(data.channels).sort((a, b) => a[0].localeCompare(b[0]));

      sortedChannels.forEach(([channel, counts]) => {
        // Show channel name with warning if there are multiple channels with the same name
        const displayName = duplicateChannelNames.has(channel) ? `${channel} ⚠️` : channel;
        labels.push(`${shortIdentity} → ${displayName}`);
        successData.push(counts.success);
        denyData.push(counts.deny);
        faultData.push(counts.fault);
      });
    });

    return {
      labels,
      datasets: [
        {
          label: 'Success',
          data: successData,
          backgroundColor: chartBarFill(UI_COLORS.success),
          borderColor: withAlpha(UI_COLORS.success, 1),
          borderWidth: 1,
        },
        {
          label: 'Denied',
          data: denyData,
          backgroundColor: chartBarFill(UI_COLORS.warning),
          borderColor: withAlpha(UI_COLORS.warning, 1),
          borderWidth: 1,
        },
        {
          label: 'Gateway Fault',
          data: faultData,
          backgroundColor: chartBarFill(UI_COLORS.danger),
          borderColor: withAlpha(UI_COLORS.danger, 1),
          borderWidth: 1,
        },
      ],
    };
  };

  const identityChannelChartOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {
      legend: {
        position: 'top',
        display: true,
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },
    scales: {
      x: {
        stacked: true,
        beginAtZero: true,
        ticks: {
          precision: 0,
        },
      },
      y: {
        stacked: true,
      },
    },
    animation: {
      duration: 500,
      easing: 'easeInOutQuart',
    },
  };

  const handleSettingsClick = () => {
    navigate('/settings');
  };

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    try {
      await loadDashboardData();
    } finally {
      setIsRefreshing(false);
    }
  };

  // Only show loading spinner on INITIAL load (when we've never loaded data before)
  // Don't show spinner for subsequent refreshes to avoid disturbing the user
  if (!hasLoadedOnce.current && state.isLoading.dashboard) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: 'calc(100vh - 150px)' }}
        >
          <div className="text-center">
            <div className="spinner-border text-primary" role="status"></div>
          </div>
        </div>
      </div>
    );
  }

  // Show error state if there's an error
  if (state.error) {
    return (
      <div className="container-fluid">
        <div className="row justify-content-center">
          <div className="col-lg-6">
            <div className="card border-left-danger shadow">
              <div className="card-body">
                <div className="text-center">
                  <div className="mb-3">
                    <i className="fas fa-exclamation-triangle hero-status-icon danger"></i>
                  </div>
                  <h4 className="text-gray-800">Dashboard Error</h4>
                  <p className="text-gray-600 mb-4">{state.error}</p>
                  <button
                    className="btn btn-primary"
                    onClick={handleManualRefresh}
                    disabled={isRefreshing}
                  >
                    <i className={`fas fa-sync-alt ${isRefreshing ? 'fa-spin' : ''} me-2`}></i>
                    Try Again
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Empty state: only shown when dashboard is truly empty (no identities, surfaces, or connections)
  const isConnectionsEmpty =
    (stats?.total_identities ?? 0) === 0 &&
    agentSurfacesCount === 0 &&
    (stats?.metrics?.total_connections ?? 0) === 0;

  return (
    <div className="container-fluid" data-testid="page-dashboard">
      {/* Statistics Cards Row */}
      <div id="statistics-section"></div>
      <div className="row">
        <StatCard
          title="Total Agent Identities"
          value={stats?.total_identities ?? 0}
          icon="fa-users"
          color="primary"
          onClick={() => navigate('/identities')}
          testId="dashboard-stat-identities"
        />

        <StatCard
          title="Agent Surfaces"
          value={agentSurfacesCount}
          icon="fa-route"
          color="success"
          onClick={() => navigate('/surfaces')}
          badge={(() => {
            const faultCount =
              stats?.channels?.filter(
                r => r.last_status === 'fault' || r.last_status === 'gateway_fault'
              ).length || 0;
            return faultCount > 0
              ? {
                  text: `${faultCount} FAULT${faultCount > 1 ? 'S' : ''}`,
                  color: 'danger' as const,
                }
              : undefined;
          })()}
          testId="dashboard-stat-channels"
        />

        <StatCard
          title="Total Connections"
          value={stats?.metrics?.total_connections ?? 0}
          icon="fa-exchange-alt"
          color="info"
          subtitle={`Last ${stats?.metrics?.connections_window_minutes ?? 60} minutes`}
          onClick={handleSettingsClick}
          testId="dashboard-stat-connections"
        />

        {/* Combined Latency Card */}
        <div className="col-xl-3 col-md-6 mb-4">
          <div
            className="card stat-card success shadow h-100 py-2 clickable"
            onClick={handleSettingsClick}
            style={{ cursor: 'pointer' }}
          >
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col me-2">
                  <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                    Avg Latency
                    <small
                      className="text-muted d-block"
                      style={{
                        fontSize: '0.65rem',
                        fontWeight: 'normal',
                        textTransform: 'none',
                        cursor: 'pointer',
                      }}
                      title="Click to change settings"
                    >
                      Last {stats?.metrics?.latency_window_minutes ?? 60} min
                    </small>
                  </div>
                  <div className="mb-2">
                    <div className="d-flex align-items-center mb-1">
                      <i
                        className="fas fa-arrow-right text-success me-2"
                        style={{ fontSize: '0.875rem' }}
                      ></i>
                      <span className="text-xs text-muted me-2">Request:</span>
                      <span className="h6 mb-0 font-weight-bold text-gray-800">
                        {stats?.metrics?.avg_request_latency
                          ? `${stats.metrics.avg_request_latency.toFixed(2)}ms`
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="d-flex align-items-center">
                      <i
                        className="fas fa-arrow-left text-warning me-2"
                        style={{ fontSize: '0.875rem' }}
                      ></i>
                      <span className="text-xs text-muted me-2">Response:</span>
                      <span className="h6 mb-0 font-weight-bold text-gray-800">
                        {stats?.metrics?.avg_response_latency
                          ? `${stats.metrics.avg_response_latency.toFixed(2)}ms`
                          : 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-clock fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div id="metrics-section"></div>
      <div id="connections-section"></div>
      <div className="row">
        <ChartCard
          title="Aggregated Connections Over Time"
          headerActions={
            <Form.Select
              aria-label="Select time interval for aggregated connections chart"
              className="form-control form-control-sm dropdown-styling"
              style={{ width: 'auto' }}
              value={
                selectedBucket ||
                state.globalState.currentBucketSeconds ||
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
            </Form.Select>
          }
        >
          <div className="connections-chart-wrapper">
            <div
              style={{
                height: '100%',
                filter: isConnectionsEmpty ? 'blur(3px)' : undefined,
                opacity: isConnectionsEmpty ? 0.4 : 1,
              }}
              aria-hidden={isConnectionsEmpty || undefined}
              {...(isConnectionsEmpty
                ? ({ inert: '' } as React.HTMLAttributes<HTMLDivElement>)
                : {})}
            >
              <Line
                aria-label="Aggregated connections over time chart"
                role="img"
                data={isConnectionsEmpty ? CONNECTIONS_SAMPLE_FIXTURE : connectionsChartData}
                options={connectionsChartOptions}
                redraw={false}
              />
            </div>
            {isConnectionsEmpty && <GraphEmptyState onCtaClick={() => navigate('/surfaces/new')} />}
          </div>
        </ChartCard>
      </div>

      {/* Surface Stats and Source-Destination Charts Row */}
      <div className="row">
        {/* Surface Distribution */}
        <div className="col-lg-6 mb-4">
          <div className="card shadow h-100">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-chart-pie"></i> Surface Distribution
              </h6>
              <div className="btn-group btn-group-sm" role="group">
                <button
                  type="button"
                  className={`btn btn-outline-primary ${channelChartView === 'pie' ? 'active' : ''}`}
                  onClick={() => setChannelChartView('pie')}
                >
                  Pie
                </button>
                <button
                  type="button"
                  className={`btn btn-outline-primary ${channelChartView === 'bar' ? 'active' : ''}`}
                  onClick={() => setChannelChartView('bar')}
                >
                  Bar
                </button>
                <button
                  type="button"
                  className={`btn btn-outline-primary ${channelChartView === 'connections' ? 'active' : ''}`}
                  onClick={() => setChannelChartView('connections')}
                >
                  Connections
                </button>
              </div>
            </div>
            <div className="card-body">
              <div style={{ height: '300px' }}>
                {channelChartView === 'pie' ? (
                  <Doughnut
                    aria-label="Surface distribution chart"
                    role="img"
                    data={getChannelDistributionData()}
                    options={doughnutChartOptions}
                  />
                ) : (
                  <Bar
                    aria-label={
                      channelChartView === 'connections'
                        ? 'Surface connections chart'
                        : 'Surface distribution bar chart'
                    }
                    role="img"
                    data={getChannelDistributionData()}
                    options={barChartOptions}
                  />
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Identity Connections */}
        <div className="col-lg-6 mb-4">
          <div className="card shadow h-100">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-fingerprint"></i> Identity Connections by Channel
              </h6>
            </div>
            <div className="card-body">
              <div style={{ height: '300px' }}>
                {getIdentityChannelChartData().labels.length > 0 ? (
                  <Bar
                    aria-label="Identity connections by channel chart"
                    role="img"
                    data={getIdentityChannelChartData()}
                    options={identityChannelChartOptions}
                  />
                ) : (
                  <div className="d-flex justify-content-center align-items-center h-100">
                    <p className="text-muted">No identity-channel data available</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Latency Stats Row */}
      <div id="latency-section"></div>
      <div className="row">
        <ChartCard
          title="Connection Latency Over Time (p50, p95, p99)"
          headerActions={
            <Form.Select
              aria-label="Select time interval for latency chart"
              className="form-control form-control-sm dropdown-styling"
              style={{ width: 'auto' }}
              value={
                selectedBucket ||
                state.globalState.currentBucketSeconds ||
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
            </Form.Select>
          }
        >
          <div style={{ height: '300px' }}>
            <Line
              aria-label="Connection latency over time chart"
              role="img"
              data={latencyChartData}
              options={latencyChartOptions}
              redraw={false}
            />
          </div>
        </ChartCard>
      </div>

      {/* Configuration Section */}
      <div id="configuration-section"></div>
      <div className="row">
        <div className="col-lg-12 mb-4">
          <div className="card shadow">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-cog"></i> Gateway Configuration
              </h6>
              <div className="d-flex align-items-center gap-2">
                <DeleteButton
                  onDelete={async () => {
                    await actions.truncateMetrics();
                  }}
                  title="Clear all stored metrics data"
                  variant="danger"
                >
                  Delete
                </DeleteButton>
                <button
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => navigate('/logs')}
                  title="View system logs"
                >
                  <i className="fas fa-file-alt"></i> Logs
                </button>
                <button
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => navigate('/settings')}
                  title="Configure dashboard settings"
                >
                  <i className="fas fa-cog"></i> Settings
                </button>
              </div>
            </div>
            <div className="card-body">
              <div className="row">
                <div className="col-md-6">
                  <h6>Identity & DID</h6>
                  <table className="table table-sm">
                    <tbody>
                      <tr>
                        <td>
                          <strong>Proxy DID:</strong>
                        </td>
                        <td>
                          <code className="text-sm">
                            {stats?.proxy_info?.did ? (
                              <span
                                title={`${stats.proxy_info.did} (click to view DID document)`}
                                onClick={() => showDidDocumentModal(stats.proxy_info.did_document)}
                                style={{
                                  cursor: 'pointer',
                                  textDecoration: 'underline',
                                  color: UI_COLORS.primary,
                                }}
                              >
                                {stats.proxy_info.did.substring(0, 40)}...
                              </span>
                            ) : (
                              'Not configured'
                            )}
                          </code>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <strong>Extensions:</strong>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              stats?.proxy_info?.extensions_enabled
                                ? 'text-bg-success'
                                : 'text-bg-secondary'
                            }`}
                          >
                            {stats?.proxy_info?.extensions_enabled ? 'ENABLED' : 'DISABLED'}
                          </span>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <strong>WebSocket Status:</strong>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              state.wsStatus === 'CONNECTED'
                                ? 'text-bg-success'
                                : state.wsStatus === 'CONNECTING'
                                  ? 'text-bg-secondary'
                                  : state.wsStatus === 'ERROR'
                                    ? 'text-bg-danger'
                                    : 'text-bg-warning'
                            }`}
                          >
                            {state.wsStatus}
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div className="col-md-6">
                  <h6>System Status</h6>
                  <table className="table table-sm">
                    <tbody>
                      <tr>
                        <td>
                          <strong>Active Channels:</strong>
                        </td>
                        <td>
                          <span className="text-muted">
                            {stats?.channels
                              ? `${stats.channels.filter(r => r.last_status === 'success').length}/${stats.channels.length} recently active`
                              : 'No channels'}
                          </span>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <strong>Total Identities:</strong>
                        </td>
                        <td>
                          <span className="text-muted">{stats?.total_identities || 0}</span>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <strong>Server Uptime:</strong>
                        </td>
                        <td>
                          <span className="text-muted">
                            {stats?.proxy_info?.uptime_formatted || 'Unknown'}
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* DID Document Modal */}
      {showDidModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex={-1}>
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  <i className="fas fa-id-card"></i> DID Document
                </h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setShowDidModal(false)}
                  aria-label="Close"
                />
              </div>
              <div className="modal-body">
                <pre>
                  <code>
                    {didDocument
                      ? JSON.stringify(didDocument, null, 2)
                      : 'No DID document available'}
                  </code>
                </pre>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowDidModal(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      {showDidModal && <div className="modal-backdrop fade show"></div>}

      {/* Identity Details Modal */}
      {showIdentityModal && selectedIdentity && (
        <IdentityDetailsModal
          identity={selectedIdentity}
          onClose={() => setShowIdentityModal(false)}
        />
      )}
    </div>
  );
};

export default Dashboard;
