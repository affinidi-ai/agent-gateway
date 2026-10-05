import React, { createContext, useContext, useReducer, useEffect, ReactNode } from 'react';
import {
  DashboardStats,
  Settings,
  Theme,
  WSStatus,
  TruncateMetricsResult,
  UserSettingsOverrides,
} from '../types';
import { apiClient, sessionManager } from '../api';
import { applyChartTheme } from '../utils/chartTheme';

// Dual state storage: one for global (unfiltered) view, one for filtered view
interface DashboardStateStore {
  stats: DashboardStats | null;
  lastSyncTimestamp: number | null;
  currentBucketSeconds: number | null;
}

interface AppState {
  // UI State
  theme: Theme;
  sidebarCollapsed: boolean;

  // Dual Data State - separate stores for filtered and unfiltered views
  globalState: DashboardStateStore; // For main dashboard (no filters)
  filteredState: DashboardStateStore; // For channel/gateway/identity filtered views

  // Active view selector
  activeView: 'global' | 'filtered';

  settings: Settings | null;
  userSettingsOverrides: UserSettingsOverrides | null;

  // Current filter configuration
  dashboardBucketOverride: number | null; // User override from dashboard dropdown
  dashboardFilters: {
    channelId?: string;
    gatewayId?: string;
    identityDid?: string;
    /**
     * Surface monitoring slice. Wire format mirrors the backend
     * `?transit_point=...` query parameter:
     *   * undefined / '' → aggregated (AP + every TP)
     *   * '__ap__'       → Access Point only
     *   * '<alias>'      → only the named Transit Point
     */
    transitPoint?: string;
  } | null; // Global filters applied to all dashboard queries

  // WebSocket State
  wsStatus: WSStatus;
  wsConnection: WebSocket | null;
  showReconnectingModal: boolean;

  // Loading States
  isLoading: {
    dashboard: boolean;
    settings: boolean;
  };

  // Error State
  error: string | null;
}

type AppAction =
  | { type: 'SET_THEME'; payload: Theme }
  | { type: 'TOGGLE_SIDEBAR' }
  | { type: 'SET_DASHBOARD_STATS'; payload: { stats: DashboardStats; view: 'global' | 'filtered' } }
  | { type: 'APPLY_DASHBOARD_DELTA'; payload: { delta: any; view: 'global' | 'filtered' } }
  | { type: 'SET_BUCKET_SECONDS'; payload: { bucket: number | null; view: 'global' | 'filtered' } }
  | { type: 'SET_DASHBOARD_BUCKET_OVERRIDE'; payload: number | null }
  | {
      type: 'SET_DASHBOARD_FILTERS';
      payload: {
        channelId?: string;
        gatewayId?: string;
        identityDid?: string;
        transitPoint?: string;
      } | null;
    }
  | { type: 'SET_ACTIVE_VIEW'; payload: 'global' | 'filtered' }
  | { type: 'SET_SETTINGS'; payload: Settings }
  | { type: 'SET_USER_SETTINGS_OVERRIDES'; payload: UserSettingsOverrides | null }
  | { type: 'SET_LOADING'; payload: { key: keyof AppState['isLoading']; value: boolean } }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_WS_STATUS'; payload: WSStatus }
  | { type: 'SET_WS_CONNECTION'; payload: WebSocket | null }
  | { type: 'SET_SHOW_RECONNECTING_MODAL'; payload: boolean }
  | { type: 'UPDATE_STATS_FROM_WS'; payload: { metrics?: Partial<DashboardStats['metrics']> } }
  | {
      type: 'SET_LAST_SYNC_TIMESTAMP';
      payload: { timestamp: number; view: 'global' | 'filtered' };
    };

const initialDashboardStore: DashboardStateStore = {
  stats: null,
  lastSyncTimestamp: null,
  currentBucketSeconds: null,
};

const initialState: AppState = {
  theme: 'light',
  sidebarCollapsed: localStorage.getItem('dashboard-sidebar-collapsed') === 'true',
  globalState: { ...initialDashboardStore },
  filteredState: { ...initialDashboardStore },
  activeView: 'global',
  settings: null,
  userSettingsOverrides: null,
  dashboardBucketOverride: null,
  dashboardFilters: null,

  wsStatus: 'CONNECTING',
  wsConnection: null,
  showReconnectingModal: false,
  isLoading: {
    dashboard: false,
    settings: false,
  },
  error: null,
};

function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case 'SET_THEME':
      return { ...state, theme: action.payload };
    case 'TOGGLE_SIDEBAR':
      return { ...state, sidebarCollapsed: !state.sidebarCollapsed };

    case 'SET_ACTIVE_VIEW':
      return { ...state, activeView: action.payload };

    case 'SET_DASHBOARD_STATS':
      const { stats, view } = action.payload;
      const targetStore = view === 'global' ? 'globalState' : 'filteredState';
      return {
        ...state,
        [targetStore]: {
          ...state[targetStore],
          stats,
          lastSyncTimestamp: Math.floor(Date.now() / 1000),
        },
      };

    case 'SET_BUCKET_SECONDS':
      const bucketTargetStore = action.payload.view === 'global' ? 'globalState' : 'filteredState';
      return {
        ...state,
        [bucketTargetStore]: {
          ...state[bucketTargetStore],
          currentBucketSeconds: action.payload.bucket,
        },
      };

    case 'SET_DASHBOARD_BUCKET_OVERRIDE':
      // Reset both stores' timestamps when bucket override changes to force full refresh
      return {
        ...state,
        dashboardBucketOverride: action.payload,
        globalState: {
          ...state.globalState,
          lastSyncTimestamp: null,
        },
        filteredState: {
          ...state.filteredState,
          lastSyncTimestamp: null,
        },
      };

    case 'APPLY_DASHBOARD_DELTA':
      const deltaView = action.payload.view;
      const deltaTargetStore = deltaView === 'global' ? 'globalState' : 'filteredState';
      const currentStore = state[deltaTargetStore];

      if (!currentStore.stats) {
        return state; // Can't apply delta without initial state
      }

      const delta = action.payload.delta;
      const updated = { ...currentStore.stats };

      // Apply metrics updates
      if (delta.changes?.metrics) {
        const metricsUpdate = delta.changes.metrics;

        // Check if bucket interval changed - if so, force full refresh
        if (
          currentStore.currentBucketSeconds !== null &&
          metricsUpdate.bucket_seconds !== currentStore.currentBucketSeconds
        ) {
          return {
            ...state,
            [deltaTargetStore]: {
              ...currentStore,
              lastSyncTimestamp: null,
              currentBucketSeconds: null,
            },
          };
        }

        // Merge new time series buckets (deduplicate by timestamp)
        let updatedTimeSeries = updated.metrics.time_series || [];
        if (metricsUpdate.new_time_series_points?.length > 0) {
          const existingMap = new Map(
            updatedTimeSeries.map((point: any) => [point.timestamp, point])
          );

          metricsUpdate.new_time_series_points.forEach((point: any) => {
            existingMap.set(point.timestamp, point);
          });

          updatedTimeSeries = Array.from(existingMap.values()).sort(
            (a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
        }

        // Trim points that have fallen outside the connections window.
        // Align the cutoff to epoch bucket boundaries to match the backend's
        // aligned_start calculation, preventing counts from diverging between
        // delta-updated state and a full reload.
        const windowMinutes = updated.metrics.connections_window_minutes || 60;
        const bucketSec = metricsUpdate.bucket_seconds || 30;
        const nowEpoch = Math.floor(Date.now() / 1000);
        const alignedEnd = Math.floor(nowEpoch / bucketSec) * bucketSec;
        const desiredBuckets = Math.floor((windowMinutes * 60) / bucketSec);
        const alignedStart = alignedEnd - desiredBuckets * bucketSec;
        const windowCutoff = alignedStart * 1000;
        updatedTimeSeries = updatedTimeSeries.filter(
          (point: any) => new Date(point.timestamp).getTime() >= windowCutoff
        );

        // Merge new latency series points (deduplicate by timestamp)
        let updatedLatencySeries = updated.metrics.latency_time_series || [];
        if (metricsUpdate.new_latency_points?.length > 0) {
          const existingLatencyMap = new Map(
            updatedLatencySeries.map((point: any) => [point.timestamp, point])
          );
          metricsUpdate.new_latency_points.forEach((point: any) => {
            existingLatencyMap.set(point.timestamp, point);
          });
          updatedLatencySeries = Array.from(existingLatencyMap.values()).sort(
            (a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
        }

        // Trim latency points outside the window too
        updatedLatencySeries = updatedLatencySeries.filter(
          (point: any) => new Date(point.timestamp).getTime() >= windowCutoff
        );

        // Update metrics - preserve existing stats when filters are active (backend returns empty arrays)
        updated.metrics = {
          ...updated.metrics,
          time_series: updatedTimeSeries,
          latency_time_series: updatedLatencySeries,
          total_connections:
            metricsUpdate.total_connections !== undefined
              ? metricsUpdate.total_connections
              : updated.metrics.total_connections,
          avg_latency:
            metricsUpdate.avg_latency !== undefined
              ? metricsUpdate.avg_latency
              : updated.metrics.avg_latency,
          avg_request_latency:
            metricsUpdate.avg_request_latency !== undefined
              ? metricsUpdate.avg_request_latency
              : updated.metrics.avg_request_latency,
          avg_response_latency:
            metricsUpdate.avg_response_latency !== undefined
              ? metricsUpdate.avg_response_latency
              : updated.metrics.avg_response_latency,
          channel_stats:
            metricsUpdate.channel_stats?.length > 0
              ? metricsUpdate.channel_stats
              : updated.metrics.channel_stats,
          identity_channel_stats:
            metricsUpdate.identity_channel_stats?.length > 0
              ? metricsUpdate.identity_channel_stats
              : updated.metrics.identity_channel_stats,
        };
      }

      // Apply log updates
      if (delta.changes?.logs?.new_entries?.length > 0) {
        // Merge and deduplicate log entries by file_position, then sort by file order
        const merged = [...updated.proxy_info.log_entries, ...delta.changes.logs.new_entries];
        const seen = new Map<number, any>();
        for (const entry of merged) {
          seen.set(entry.file_position, entry);
        }
        const deduped = Array.from(seen.values());
        deduped.sort((a: any, b: any) => a.file_position - b.file_position);
        updated.proxy_info = {
          ...updated.proxy_info,
          log_entries: deduped.slice(-300), // Keep last 300 entries
        };
      }

      // Apply channel updates
      if (delta.changes?.channels) {
        const channelMap = new Map(updated.channels.map((ch: any) => [ch.config_id, ch]));

        if (delta.changes.channels.added?.length > 0) {
          delta.changes.channels.added.forEach((channel: any) => {
            channelMap.set(channel.config_id, channel);
          });
        }

        if (delta.changes.channels.updated?.length > 0) {
          delta.changes.channels.updated.forEach((channelUpdate: any) => {
            // MERGE delta data with existing channel to preserve fields like virtual_channels
            // Delta only includes metrics data, not full channel configuration
            const existingChannel = channelMap.get(channelUpdate.config_id);
            if (existingChannel) {
              channelMap.set(channelUpdate.config_id, {
                ...existingChannel, // Preserve existing data (virtual_channels, etc.)
                ...channelUpdate, // Apply metrics updates
                // Ensure critical configuration fields are never overwritten with undefined
                virtual_channels:
                  existingChannel.virtual_channels || channelUpdate.virtual_channels,
                default_virtual_channel_id:
                  existingChannel.default_virtual_channel_id ||
                  channelUpdate.default_virtual_channel_id,
              });
            } else {
              // New channel not in local cache - just add it
              channelMap.set(channelUpdate.config_id, channelUpdate);
            }
          });
        }

        if (delta.changes.channels.removed?.length > 0) {
          delta.changes.channels.removed.forEach((id: string) => {
            channelMap.delete(id);
          });
        }

        updated.channels = Array.from(channelMap.values());
      }

      // Apply identity updates
      if (delta.changes?.identities) {
        const identityMap = new Map(updated.identities.map((id: any) => [id.did, id]));

        if (delta.changes.identities.added?.length > 0) {
          delta.changes.identities.added.forEach((identity: any) => {
            identityMap.set(identity.did, identity);
          });
        }

        if (delta.changes.identities.updated?.length > 0) {
          delta.changes.identities.updated.forEach((identity: any) => {
            identityMap.set(identity.did, identity);
          });
        }

        updated.identities = Array.from(identityMap.values());
        if (delta.changes.identities.total_identities !== undefined) {
          updated.total_identities = delta.changes.identities.total_identities;
        }
      }

      // Apply task updates. The backend always sends the full task list
      // (it doesn't compute incremental task additions/removals), so we
      // replace rather than merge — otherwise stale `task_id`s from
      // surfaces that have since been updated/deleted linger forever
      // until a full refresh.
      if (delta.changes?.tasks) {
        updated.tasks = {
          summary: delta.changes.tasks.tasks.summary,
          tasks: delta.changes.tasks.tasks.tasks || [],
          metrics: delta.changes.tasks.tasks.metrics,
        };
        updated.connection_point_tasks = delta.changes.tasks.connection_point_tasks;
        updated.mcp_proxy_tasks = delta.changes.tasks.mcp_proxy_tasks;
      }

      // Apply unread notification count
      if (delta.changes?.unread_count !== undefined) {
        updated.unread_count = delta.changes.unread_count;
      }

      return {
        ...state,
        [deltaTargetStore]: {
          ...currentStore,
          stats: updated,
          lastSyncTimestamp: delta.timestamp,
        },
      };

    case 'SET_SETTINGS':
      return { ...state, settings: action.payload };
    case 'SET_USER_SETTINGS_OVERRIDES':
      return { ...state, userSettingsOverrides: action.payload };
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: { ...state.isLoading, [action.payload.key]: action.payload.value },
      };
    case 'SET_ERROR':
      return { ...state, error: action.payload };
    case 'SET_WS_STATUS':
      return { ...state, wsStatus: action.payload };
    case 'SET_WS_CONNECTION':
      return { ...state, wsConnection: action.payload };
    case 'SET_SHOW_RECONNECTING_MODAL':
      return { ...state, showReconnectingModal: action.payload };

    case 'UPDATE_STATS_FROM_WS':
      // Update the active view's stats
      const wsTargetStore = state.activeView === 'global' ? 'globalState' : 'filteredState';
      const wsCurrentStore = state[wsTargetStore];

      return {
        ...state,
        [wsTargetStore]: {
          ...wsCurrentStore,
          stats: wsCurrentStore.stats
            ? {
                ...wsCurrentStore.stats,
                ...action.payload,
                metrics: action.payload.metrics
                  ? { ...wsCurrentStore.stats.metrics, ...action.payload.metrics }
                  : wsCurrentStore.stats.metrics,
              }
            : null,
        },
      };

    case 'SET_DASHBOARD_FILTERS':
      // Check if filters actually changed
      const filtersChanged =
        JSON.stringify(state.dashboardFilters) !== JSON.stringify(action.payload);

      // If filters changed and we're setting a new filter (not clearing), reset filtered state for fresh load
      const isSettingFilter =
        action.payload !== null &&
        (action.payload.channelId !== undefined ||
          action.payload.gatewayId !== undefined ||
          action.payload.identityDid !== undefined ||
          action.payload.transitPoint !== undefined);

      const isClearingFilter = action.payload === null;

      if (filtersChanged && isSettingFilter) {
        return {
          ...state,
          dashboardFilters: action.payload,
          activeView: 'filtered', // Switch to filtered view
          filteredState: {
            stats: null,
            lastSyncTimestamp: null,
            currentBucketSeconds: null,
          },
        };
      }

      // If clearing filters, switch back to global view
      if (filtersChanged && isClearingFilter && state.activeView === 'filtered') {
        return {
          ...state,
          dashboardFilters: action.payload,
          activeView: 'global',
        };
      }

      return {
        ...state,
        dashboardFilters: action.payload,
      };

    case 'SET_LAST_SYNC_TIMESTAMP': {
      const tsTargetStore = action.payload.view === 'global' ? 'globalState' : 'filteredState';
      return {
        ...state,
        [tsTargetStore]: {
          ...state[tsTargetStore],
          lastSyncTimestamp: action.payload.timestamp,
        },
      };
    }

    default:
      return state;
  }
}

interface AppContextType {
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
  // Helper to get the currently active dashboard stats based on view
  getCurrentStats: () => DashboardStats | null;
  actions: {
    toggleTheme: () => void;
    toggleSidebar: () => void;
    loadDashboardStats: (force?: boolean) => Promise<void>;
    setDashboardFilters: (
      filters: {
        channelId?: string;
        gatewayId?: string;
        identityDid?: string;
        transitPoint?: string;
      } | null
    ) => void;
    setActiveView: (view: 'global' | 'filtered') => void;
    loadSettings: () => Promise<void>;
    updateSettings: (settings: Partial<Settings>) => Promise<void>;
    resetSettings: () => Promise<void>;
    loadUserSettings: () => Promise<void>;
    updateUserSettings: (settings: Partial<UserSettingsOverrides>) => Promise<void>;
    resetUserSettings: () => Promise<void>;
    truncateMetrics: () => Promise<TruncateMetricsResult>;
    setDashboardBucketOverride: (bucket: number | null) => void;
    connectWebSocket: () => void;
    disconnectWebSocket: () => void;
    setWsKeepAlive: (keep: boolean) => void;
    setWsSubscription: (sections: string[]) => void;
  };
}

export const AppContext = createContext<AppContextType | undefined>(undefined);
AppContext.displayName = 'AppContext';

export const useApp = (): AppContextType => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};

interface AppProviderProps {
  children: ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(appReducer, initialState);

  // Initialize theme from localStorage
  useEffect(() => {
    const savedTheme = (localStorage.getItem('dashboard-theme') as Theme) || 'light';
    dispatch({ type: 'SET_THEME', payload: savedTheme });

    // Apply theme to body
    if (savedTheme === 'dark') {
      document.body.classList.add('dark-theme');
    }
    applyChartTheme(savedTheme === 'dark');
  }, []);

  // Actions - defined early so they can be used in WebSocket callbacks
  const lastRefreshTimeRef = React.useRef<number>(0);

  // Separate refs for global and filtered state syncing
  const globalLastSyncTimestampRef = React.useRef<number | null>(null);
  const filteredLastSyncTimestampRef = React.useRef<number | null>(null);
  const globalCurrentBucketSecondsRef = React.useRef<number | null>(null);
  const filteredCurrentBucketSecondsRef = React.useRef<number | null>(null);
  const globalLastLogPositionRef = React.useRef<number | null>(null);
  const filteredLastLogPositionRef = React.useRef<number | null>(null);

  const refreshIntervalRef = React.useRef<number>(5); // Default 5 seconds
  const dashboardBucketOverrideRef = React.useRef<number | null>(null);
  const settingsRef = React.useRef<Settings | null>(null);
  const dashboardFiltersRef = React.useRef<AppState['dashboardFilters']>(null);
  const activeViewRef = React.useRef<'global' | 'filtered'>('global');
  const scheduledRefreshTimeoutRef = React.useRef<NodeJS.Timeout | null>(null);
  const wsKeepAliveRef = React.useRef<boolean>(false);
  const wsSubscriptionRef = React.useRef<string[]>([]);

  // Keep refs in sync with state
  React.useLayoutEffect(() => {
    activeViewRef.current = state.activeView;
  }, [state.activeView]);

  // Use useLayoutEffect for timestamp refs to ensure they're synced before other effects run
  React.useLayoutEffect(() => {
    // Sync global state refs
    globalLastSyncTimestampRef.current = state.globalState.lastSyncTimestamp;
    globalCurrentBucketSecondsRef.current = state.globalState.currentBucketSeconds;
    // Track the highest log file_position so delta requests fetch only new entries
    const logEntries = state.globalState.stats?.proxy_info?.log_entries;
    if (logEntries && logEntries.length > 0) {
      globalLastLogPositionRef.current = Math.max(...logEntries.map(e => e.file_position));
    }
  }, [
    state.globalState.lastSyncTimestamp,
    state.globalState.currentBucketSeconds,
    state.globalState.stats?.proxy_info?.log_entries,
  ]);

  React.useLayoutEffect(() => {
    // Sync filtered state refs (including null values!)
    filteredLastSyncTimestampRef.current = state.filteredState.lastSyncTimestamp;
    filteredCurrentBucketSecondsRef.current = state.filteredState.currentBucketSeconds;
    const logEntries = state.filteredState.stats?.proxy_info?.log_entries;
    if (logEntries && logEntries.length > 0) {
      filteredLastLogPositionRef.current = Math.max(...logEntries.map(e => e.file_position));
    }
  }, [
    state.filteredState.lastSyncTimestamp,
    state.filteredState.currentBucketSeconds,
    state.filteredState.stats?.proxy_info?.log_entries,
  ]);

  React.useEffect(() => {
    dashboardBucketOverrideRef.current = state.dashboardBucketOverride;
  }, [state.dashboardBucketOverride]);

  React.useEffect(() => {
    settingsRef.current = state.settings;
  }, [state.settings]);

  // Keep refresh interval ref in sync with settings
  React.useEffect(() => {
    refreshIntervalRef.current = state.settings?.refresh_interval_seconds || 5;
  }, [state.settings?.refresh_interval_seconds]);

  const loadDashboardStats = React.useCallback(async (force: boolean = false): Promise<void> => {
    // Get refresh interval from ref (to avoid stale closure)
    const refreshInterval = refreshIntervalRef.current * 1000;
    const now = Date.now();

    // Throttle: Skip if called too recently (unless forced)
    if (!force && now - lastRefreshTimeRef.current < refreshInterval) {
      // If we're being throttled, schedule a refresh for when the throttle expires
      // (unless one is already scheduled)
      if (scheduledRefreshTimeoutRef.current === null) {
        const timeUntilNextRefresh = refreshInterval - (now - lastRefreshTimeRef.current);
        scheduledRefreshTimeoutRef.current = setTimeout(() => {
          scheduledRefreshTimeoutRef.current = null;
          loadDashboardStats(false);
        }, timeUntilNextRefresh);
      }
      return;
    }

    // Clear any scheduled refresh since we're doing one now
    if (scheduledRefreshTimeoutRef.current !== null) {
      clearTimeout(scheduledRefreshTimeoutRef.current);
      scheduledRefreshTimeoutRef.current = null;
    }

    lastRefreshTimeRef.current = now;

    dispatch({ type: 'SET_LOADING', payload: { key: 'dashboard', value: true } });
    dispatch({ type: 'SET_ERROR', payload: null });

    try {
      // Get current filters from refs
      const currentFilters = dashboardFiltersRef.current;

      // Determine which state store to use based on filters
      const isFilteredView =
        currentFilters !== null &&
        (currentFilters.channelId !== undefined ||
          currentFilters.gatewayId !== undefined ||
          currentFilters.identityDid !== undefined ||
          currentFilters.transitPoint !== undefined);
      const targetView: 'global' | 'filtered' = isFilteredView ? 'filtered' : 'global';

      // Get appropriate refs for this view
      const lastSyncTimestampRef =
        targetView === 'global' ? globalLastSyncTimestampRef : filteredLastSyncTimestampRef;
      const currentBucketSecondsRef =
        targetView === 'global' ? globalCurrentBucketSecondsRef : filteredCurrentBucketSecondsRef;

      // Use delta endpoint if we have previous sync timestamp (stored in ref to avoid stale closure)
      if (lastSyncTimestampRef.current) {
        // Use dashboard override if set, otherwise use settings, otherwise calculate from window
        let bucketSeconds: number;
        if (dashboardBucketOverrideRef.current !== null) {
          bucketSeconds = dashboardBucketOverrideRef.current;
        } else if (settingsRef.current?.bucket_seconds) {
          bucketSeconds = settingsRef.current.bucket_seconds;
        } else {
          // Fallback: calculate from connections_window
          const connectionsWindow = settingsRef.current?.connections_window || 5;
          if (connectionsWindow < 10) {
            bucketSeconds = 30;
          } else if (connectionsWindow < 60) {
            bucketSeconds = 60;
          } else {
            bucketSeconds = 300;
          }
        }

        // If bucket changed, force full refresh
        if (
          currentBucketSecondsRef.current !== null &&
          currentBucketSecondsRef.current !== bucketSeconds
        ) {
          if (targetView === 'global') {
            globalLastSyncTimestampRef.current = null;
          } else {
            filteredLastSyncTimestampRef.current = null;
          }
          dispatch({
            type: 'SET_BUCKET_SECONDS',
            payload: { bucket: bucketSeconds, view: targetView },
          });
          // Recursively call with force=true to do full refresh
          return loadDashboardStats(true);
        }

        dispatch({
          type: 'SET_BUCKET_SECONDS',
          payload: { bucket: bucketSeconds, view: targetView },
        });

        // Capture bucket size for this request to detect stale responses
        const requestBucketSeconds = bucketSeconds;

        // Incremental update
        const params = new URLSearchParams({
          since: lastSyncTimestampRef.current.toString(),
          bucket_seconds: bucketSeconds.toString(),
        });
        if (currentFilters?.channelId) params.append('surface_id', currentFilters.channelId);
        if (currentFilters?.gatewayId) params.append('gateway_id', currentFilters.gatewayId);
        if (currentFilters?.identityDid) params.append('identity_did', currentFilters.identityDid);
        if (currentFilters?.transitPoint) {
          params.append('transit_point', currentFilters.transitPoint);
        }
        // Send max log file_position so the server returns only entries after it
        const lastLogPosRef =
          targetView === 'global' ? globalLastLogPositionRef : filteredLastLogPositionRef;
        if (lastLogPosRef.current !== null) {
          params.append('since_log_position', lastLogPosRef.current.toString());
        }

        const url = `/api/v1/dashboard/delta?${params}`;

        const response = await apiClient.fetch(url);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const delta = await response.json();

        // Check if bucket size changed while request was in flight - ignore stale response
        if (currentBucketSecondsRef.current !== requestBucketSeconds) {
          // Bucket changed - this response is stale, ignore it and trigger fresh request
          return loadDashboardStats(true);
        }

        dispatch({ type: 'APPLY_DASHBOARD_DELTA', payload: { delta, view: targetView } });
      } else {
        // Full sync (first load or after error)

        // Use dashboard override if set, otherwise use settings, otherwise calculate from window
        let bucketSeconds: number;
        if (dashboardBucketOverrideRef.current !== null) {
          bucketSeconds = dashboardBucketOverrideRef.current;
        } else if (settingsRef.current?.bucket_seconds) {
          bucketSeconds = settingsRef.current.bucket_seconds;
        } else {
          // Fallback: calculate from connections_window
          const connectionsWindow = settingsRef.current?.connections_window || 5;
          if (connectionsWindow < 10) {
            bucketSeconds = 30;
          } else if (connectionsWindow < 60) {
            bucketSeconds = 60;
          } else {
            bucketSeconds = 300;
          }
        }

        dispatch({
          type: 'SET_BUCKET_SECONDS',
          payload: { bucket: bucketSeconds, view: targetView },
        });

        // Capture bucket size for this request to detect stale responses
        const requestBucketSeconds = bucketSeconds;

        const stats = await apiClient.getDashboardStats(
          bucketSeconds,
          currentFilters?.channelId,
          currentFilters?.gatewayId,
          currentFilters?.identityDid,
          currentFilters?.transitPoint
        );

        // Check if bucket size changed while request was in flight - ignore stale response
        if (currentBucketSecondsRef.current !== requestBucketSeconds) {
          // Bucket changed - this response is stale, ignore it and trigger fresh request
          return loadDashboardStats(true);
        }

        dispatch({ type: 'SET_DASHBOARD_STATS', payload: { stats, view: targetView } });
      }
    } catch (error) {
      console.error('Failed to load dashboard stats:', error);
      dispatch({
        type: 'SET_ERROR',
        payload: error instanceof Error ? error.message : 'Failed to load dashboard stats',
      });

      // On error, reset sync state for the active view to force full stats next time
      const currentFilters = dashboardFiltersRef.current;
      const isFilteredView =
        currentFilters !== null &&
        (currentFilters.channelId !== undefined ||
          currentFilters.gatewayId !== undefined ||
          currentFilters.identityDid !== undefined ||
          currentFilters.transitPoint !== undefined);
      if (isFilteredView) {
        filteredLastSyncTimestampRef.current = null;
      } else {
        globalLastSyncTimestampRef.current = null;
      }
    } finally {
      dispatch({ type: 'SET_LOADING', payload: { key: 'dashboard', value: false } });
    }
  }, []); // No dependencies - using refs to avoid stale closures

  // WebSocket connection management
  const wsRef = React.useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = React.useRef<NodeJS.Timeout | null>(null);
  const disconnectTimeoutRef = React.useRef<NodeJS.Timeout | null>(null);
  const fullDisconnectTimeoutRef = React.useRef<NodeJS.Timeout | null>(null);
  const intentionalDisconnectRef = React.useRef<boolean>(false); // Flag to prevent auto-reconnect on intentional disconnect

  const connectWebSocket = React.useCallback(() => {
    if (wsRef.current) {
      //console.debug('[WebSocket] Already connected, skipping connection attempt');
      return; // Already connected
    }

    // Don't connect websocket on the sign-in page.
    const isOnSignInPage = window.location.pathname === '/login';

    if (isOnSignInPage) {
      //console.debug('[WebSocket] Skipping connection on sign-in page');
      return;
    }

    // Clear intentional disconnect flag when connecting
    intentionalDisconnectRef.current = false;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBase = process.env.REACT_APP_WS_URL ?? `${protocol}//${window.location.host}/api/ws`;

    ////console.log('[WebSocket] Attempting to connect to:', wsBase);
    const ws = new WebSocket(wsBase);
    // Set ref immediately so the guard at the top prevents a second
    // connection when React StrictMode double-mounts.
    wsRef.current = ws;

    ws.onopen = () => {
      // If this socket was superseded (e.g. StrictMode remount), close it silently
      if (wsRef.current !== ws) {
        ws.close();
        return;
      }
      ////console.log('[WebSocket] ✓ Connected successfully');
      // Clear any pending disconnect/reconnect timeouts
      if (disconnectTimeoutRef.current) {
        clearTimeout(disconnectTimeoutRef.current);
        disconnectTimeoutRef.current = null;
      }
      if (fullDisconnectTimeoutRef.current) {
        clearTimeout(fullDisconnectTimeoutRef.current);
        fullDisconnectTimeoutRef.current = null;
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }

      // Hide reconnecting modal if it was showing
      dispatch({ type: 'SET_SHOW_RECONNECTING_MODAL', payload: false });
      dispatch({ type: 'SET_WS_STATUS', payload: 'CONNECTED' });
      dispatch({ type: 'SET_WS_CONNECTION', payload: ws });

      // Send current subscription (if any) so the server filters deltas
      if (wsSubscriptionRef.current.length > 0) {
        ws.send(JSON.stringify({ type: 'subscribe', sections: wsSubscriptionRef.current }));
      }
    };

    ws.onmessage = event => {
      // Ignore messages from a superseded socket
      if (wsRef.current !== ws) return;
      try {
        // Centralized JSON parsing - parse once and distribute to all listeners
        // This eliminates redundant parsing in individual components
        const message = JSON.parse(event.data);

        // Check for authentication errors
        if (
          message.type === 'error' &&
          (message.error === 'unauthorized' ||
            message.error === 'authentication_failed' ||
            message.message?.includes('authentication'))
        ) {
          console.error('WebSocket authentication failed - redirecting to sign in');
          disconnectWebSocket();
          sessionManager.expireSession();
          return;
        }

        // Dispatch custom event with pre-parsed message for components
        // This allows components to receive parsed objects instead of re-parsing
        const customEvent = new CustomEvent('ws-message', { detail: message });
        window.dispatchEvent(customEvent);

        switch (message.type) {
          case 'connected':
            break;
          case 'identity_created':
            loadDashboardStats(true); // Force refresh to show new identity immediately
            break;
          case 'identity_updated':
            loadDashboardStats(true); // Force refresh to show updated timestamp immediately
            break;
          case 'metrics_updated':
            // The server now pushes dashboard_delta periodically, so we no longer
            // need to HTTP-poll /delta on every metrics notification.
            break;
          case 'log_entry':
            // Server-pushed dashboard_delta now includes logs, so no HTTP fetch needed.
            break;
          case 'dashboard_delta':
            // Server-pushed pre-computed delta – apply directly without an HTTP round-trip.
            // Also derive a filtered delta for the filtered view when filters are active.
            if (message.delta) {
              const d = message.delta;
              const c = d.changes || {};
              const parts: string[] = [];
              if (c.metrics) {
                const m = c.metrics;
                const tsPts = m.new_time_series_points?.length || 0;
                const latPts = m.new_latency_points?.length || 0;
                parts.push(
                  `metrics(ts=${tsPts}, lat=${latPts}, conns=${m.total_connections ?? '-'}, avgLat=${m.avg_latency ?? '-'}ms, chans=${m.channel_stats?.length ?? 0})`
                );
              }
              if (c.logs?.new_entries?.length) parts.push(`logs(+${c.logs.new_entries.length})`);
              if (c.channels) {
                const ch = c.channels;
                parts.push(
                  `channels(+${ch.added?.length || 0} ~${ch.updated?.length || 0} -${ch.removed?.length || 0})`
                );
              }
              if (c.identities) {
                const id = c.identities;
                parts.push(`identities(+${id.added?.length || 0} ~${id.updated?.length || 0})`);
              }
              if (c.tasks) {
                const t = c.tasks;
                const taskCount = t.tasks?.tasks?.length || 0;
                const cpTasks = t.connection_point_tasks
                  ? Object.keys(t.connection_point_tasks).length
                  : 0;
                const mcpTasks = t.mcp_proxy_tasks ? Object.keys(t.mcp_proxy_tasks).length : 0;
                parts.push(`tasks(${taskCount}, cp=${cpTasks}, mcp=${mcpTasks})`);
              }
              if (c.unread_count !== undefined) parts.push(`unread=${c.unread_count}`);
              const sizeKb = (new Blob([event.data]).size / 1024).toFixed(2);
              const localTime = new Date(d.timestamp * 1000).toLocaleString();
              // Simple hash of the payload for dedup/debugging
              let hash = 0;
              for (let i = 0; i < event.data.length; i++) {
                hash = ((hash << 5) - hash + event.data.charCodeAt(i)) | 0;
              }
              const hashHex = (hash >>> 0).toString(16).padStart(8, '0');
              console.log(
                `[WS delta] ${localTime} | ${sizeKb} KB | #${hashHex} | ${parts.length ? parts.join(', ') : 'empty'}`
              );
              // console.log(`[WS delta] message: ${JSON.stringify(message, null, 2)}`);

              dispatch({
                type: 'APPLY_DASHBOARD_DELTA',
                payload: { delta: message.delta, view: 'global' },
              });

              // Update lastSyncTimestamp from the delta so the next full refresh
              // (e.g. when switching to filtered view) starts from the right point.
              if (message.delta.timestamp) {
                dispatch({
                  type: 'SET_LAST_SYNC_TIMESTAMP',
                  payload: { timestamp: message.delta.timestamp, view: 'global' },
                });
              }

              // The WS broadcast now includes all delta sections (metrics,
              // logs, channels, identities, tasks). No HTTP /delta polling needed
              // for the global view.

              // Also derive a filtered delta for the filtered view when filters are active,
              // so channel-specific monitoring/logging updates in real-time via WS too.
              const currentFilters = dashboardFiltersRef.current;
              const hasFilters =
                currentFilters &&
                (currentFilters.channelId ||
                  currentFilters.gatewayId ||
                  currentFilters.identityDid);
              if (hasFilters && message.delta.changes) {
                const src = message.delta.changes;
                const filtered: any = {};

                // Filter metrics: time_series and latency by channel, zero out aggregates
                if (src.metrics) {
                  const fm = { ...src.metrics };
                  if (
                    currentFilters.channelId ||
                    currentFilters.gatewayId ||
                    currentFilters.identityDid
                  ) {
                    // Server filters these to empty for these filters
                    fm.total_connections = 0;
                    fm.avg_latency = null;
                    fm.avg_request_latency = null;
                    fm.avg_response_latency = null;
                    fm.channel_stats = [];
                  }
                  if (currentFilters.channelId && fm.identity_channel_stats) {
                    fm.identity_channel_stats = fm.identity_channel_stats.filter(
                      (s: any) => s.channel_config_id === currentFilters.channelId
                    );
                  }
                  // Strip global time_series from the filtered view – these are
                  // pre-aggregated across all channels and can't be split client-side.
                  // The initial HTTP full-refresh already provides the correctly
                  // filtered series; we must not overwrite it with global data.
                  fm.new_time_series_points = [];
                  fm.new_latency_points = [];
                  filtered.metrics = fm;
                }

                // Filter logs by channel tag
                if (src.logs?.new_entries?.length) {
                  let entries = src.logs.new_entries;
                  if (currentFilters.channelId) {
                    const tag = `[CHANNEL:${currentFilters.channelId}]`;
                    entries = entries.filter((e: any) => e.message?.includes(tag));
                  }
                  if (entries.length > 0) {
                    filtered.logs = { new_entries: entries };
                  }
                }

                // Pass through channels, identities, tasks unchanged
                if (src.channels) filtered.channels = src.channels;
                if (src.identities) filtered.identities = src.identities;
                if (src.tasks) filtered.tasks = src.tasks;
                if (src.unread_count !== undefined) filtered.unread_count = src.unread_count;

                const filteredDelta = {
                  timestamp: message.delta.timestamp,
                  changes: filtered,
                };

                dispatch({
                  type: 'APPLY_DASHBOARD_DELTA',
                  payload: { delta: filteredDelta, view: 'filtered' },
                });
                if (message.delta.timestamp) {
                  dispatch({
                    type: 'SET_LAST_SYNC_TIMESTAMP',
                    payload: { timestamp: message.delta.timestamp, view: 'filtered' },
                  });
                }

                // Trigger an HTTP delta fetch for the filtered view so the
                // server returns properly per-channel filtered time-series.
                // The call is throttled so it won't flood the server.
                loadDashboardStats(false);
              }
            }
            break;
          case 'payload_captured':
            // Payload capture events are handled directly by the ChannelCapturePage component
            // No need to update global state here
            break;
          case 'refresh_dashboard':
            loadDashboardStats(true); // Force refresh, bypassing throttle
            break;
          default:
          // Unknown message type - silently ignore
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onclose = event => {
      // If this socket was already superseded, don't touch state or reconnect
      if (wsRef.current !== ws) return;
      //console.log(`[WebSocket] Connection closed - Code: ${event.code}, Reason: ${event.reason || 'none'}, Clean: ${event.wasClean}`);
      dispatch({ type: 'SET_WS_CONNECTION', payload: null });
      wsRef.current = null;

      // Check if close was due to authentication failure (code 1008 = policy violation, often used for auth failures)
      // or code 4401 (custom unauthorized code some servers use)
      if (event.code === 1008 || event.code === 4401 || event.code === 1002) {
        //console.error('[WebSocket] Closed due to authentication failure - redirecting to sign in');
        intentionalDisconnectRef.current = true;
        sessionManager.expireSession();
        return;
      }

      // If this was an intentional disconnect, don't try to reconnect
      if (intentionalDisconnectRef.current) {
        ////console.log('[WebSocket] Intentional disconnect - will not reconnect');
        dispatch({ type: 'SET_WS_STATUS', payload: 'DISCONNECTED' });
        return;
      }

      //console.log('[WebSocket] Checking session validity before reconnect...');

      // Check if session is still valid with the server (async operation)
      apiClient
        .fetch('/api/auth/check')
        .then(response => {
          if (response.status === 404) {
            //console.log('[WebSocket] Auth endpoint not found - passkey auth disabled, allowing reconnect');
            // Auth endpoint doesn't exist - passkey auth is disabled, allow reconnect
            return { authenticated: true };
          }
          if (response.status === 401) {
            //console.warn('[WebSocket] Session invalid (401) - logging out');
            // Session is invalid - return auth failure
            return { authenticated: false };
          }
          if (!response.ok) {
            // Server error (500, 502, etc.) - not an auth issue, server might be restarting
            //console.log(`[WebSocket] Server error ${response.status} - will retry connection`);
            throw new Error(`Server error: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          if (!data.authenticated) {
            //console.warn('[WebSocket] Session no longer valid - redirecting to login');
            sessionManager.expireSession();
            return;
          }
          //console.log('[WebSocket] Session valid, scheduling reconnect...');
          // Session is valid, proceed with reconnection logic
          scheduleReconnect();
        })
        .catch(error => {
          //console.error('[WebSocket] Error checking session validity:', error);
          // If we can't reach the server, it might be down/restarting
          // Don't clear the session - just try to reconnect later
          //console.log('[WebSocket] Server unreachable, will retry connection...');
          scheduleReconnect();
        });
    };

    // Helper function to schedule reconnection
    const scheduleReconnect = () => {
      //console.log('[WebSocket] Scheduling reconnect...');

      // Only set the "show modal" timeout if not already set
      // This prevents the modal from flickering when multiple reconnection attempts happen
      if (!disconnectTimeoutRef.current) {
        // Wait 3 seconds before showing the reconnecting modal
        disconnectTimeoutRef.current = setTimeout(() => {
          if (!wsRef.current) {
            //console.log('[WebSocket] Still disconnected after 3s, showing reconnecting modal');
            dispatch({ type: 'SET_SHOW_RECONNECTING_MODAL', payload: true });
          }
          disconnectTimeoutRef.current = null;
        }, 3000);
      }

      // Only set the "give up" timeout if not already set
      if (!fullDisconnectTimeoutRef.current) {
        // Set timeout to eventually hide modal and show disconnected if still not reconnected after extended period
        fullDisconnectTimeoutRef.current = setTimeout(() => {
          if (!wsRef.current) {
            //console.warn('[WebSocket] Still disconnected after 30s, hiding modal');
            dispatch({ type: 'SET_SHOW_RECONNECTING_MODAL', payload: false });
            dispatch({ type: 'SET_WS_STATUS', payload: 'DISCONNECTED' });
          }
          fullDisconnectTimeoutRef.current = null;
        }, 30000); // Show disconnected after 30 seconds of trying
      }

      // Always clear and restart the reconnection attempt timer
      // This ensures we keep trying even if previous attempts failed
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }

      // Attempt to reconnect after 1 second (faster reconnection for channel updates)
      reconnectTimeoutRef.current = setTimeout(() => {
        if (!wsRef.current) {
          //console.log('[WebSocket] Attempting reconnect now...');
          connectWebSocket();
        }
        reconnectTimeoutRef.current = null;
      }, 1000);
    };

    ws.onerror = error => {
      if (wsRef.current !== ws) return;
      console.error('[WebSocket] Error occurred:', error);
      dispatch({ type: 'SET_WS_STATUS', payload: 'ERROR' });
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadDashboardStats]);

  const disconnectWebSocket = React.useCallback(() => {
    //console.log('[WebSocket] Intentionally disconnecting...');
    // Set flag to prevent automatic reconnection
    intentionalDisconnectRef.current = true;

    // Clear any pending reconnection timeouts
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (disconnectTimeoutRef.current) {
      clearTimeout(disconnectTimeoutRef.current);
      disconnectTimeoutRef.current = null;
    }
    if (fullDisconnectTimeoutRef.current) {
      clearTimeout(fullDisconnectTimeoutRef.current);
      fullDisconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      dispatch({ type: 'SET_WS_CONNECTION', payload: null });
      dispatch({ type: 'SET_WS_STATUS', payload: 'DISCONNECTED' });
      dispatch({ type: 'SET_SHOW_RECONNECTING_MODAL', payload: false });
      wsRef.current = null;
    }
  }, []);

  // Actions
  const actions = {
    toggleTheme: () => {
      const newTheme = state.theme === 'light' ? 'dark' : 'light';
      dispatch({ type: 'SET_THEME', payload: newTheme });
      localStorage.setItem('dashboard-theme', newTheme);

      // Apply theme to body
      if (newTheme === 'dark') {
        document.body.classList.add('dark-theme');
      } else {
        document.body.classList.remove('dark-theme');
      }
      applyChartTheme(newTheme === 'dark');
    },

    toggleSidebar: () => {
      const next = !state.sidebarCollapsed;
      localStorage.setItem('dashboard-sidebar-collapsed', String(next));
      dispatch({ type: 'TOGGLE_SIDEBAR' });
    },

    loadDashboardStats,

    setDashboardFilters: (
      filters: {
        channelId?: string;
        gatewayId?: string;
        identityDid?: string;
      } | null
    ) => {
      // Update ref immediately BEFORE dispatch so it's available for loadDashboardStats
      dashboardFiltersRef.current = filters;

      // Dispatch to update state
      dispatch({ type: 'SET_DASHBOARD_FILTERS', payload: filters });
    },

    setActiveView: (view: 'global' | 'filtered') => {
      dispatch({ type: 'SET_ACTIVE_VIEW', payload: view });
    },

    loadSettings: async () => {
      dispatch({ type: 'SET_LOADING', payload: { key: 'settings', value: true } });
      dispatch({ type: 'SET_ERROR', payload: null });

      try {
        // Load effective settings (user overrides merged with system defaults)
        const settings = await apiClient.getUserSettings();
        dispatch({ type: 'SET_SETTINGS', payload: settings });

        // Also load the raw user overrides for the settings UI
        try {
          const overrides = await apiClient.getUserSettingsOverrides();
          dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: overrides });
        } catch {
          // User settings overrides not available (no auth or new feature)
          dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: null });
        }
      } catch (error) {
        console.error('[APPCONTEXT] Failed to load settings:', error);
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to load settings',
        });
        // Set default settings to prevent app crash
        dispatch({
          type: 'SET_SETTINGS',
          payload: {
            badge_threshold: 5,
            metrics_retention: 6,
            task_activity_window: 60,
            connections_window: 60,
            latency_window: 60,
            onboarding_channel_ttl_seconds: 30,
            refresh_interval_seconds: 5,
            log_timestamp_format: 'local',
            bucket_seconds: 30,
            payments_min_display: 10,
            feature_flags: {},
          },
        });
      } finally {
        dispatch({ type: 'SET_LOADING', payload: { key: 'settings', value: false } });
      }
    },

    updateSettings: async (settings: Partial<Settings>) => {
      try {
        await apiClient.updateSettings(settings);
        // Reload authoritative settings from the server instead of optimistic merge
        // (avoids leaking transient fields like prometheus_auth_password into state)
        await actions.loadSettings();
      } catch (error) {
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to update settings',
        });
        throw error;
      }
    },

    resetSettings: async () => {
      try {
        await apiClient.resetSettings();
        await actions.loadSettings(); // Reload settings after reset
      } catch (error) {
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to reset settings',
        });
        throw error;
      }
    },

    loadUserSettings: async () => {
      try {
        const overrides = await apiClient.getUserSettingsOverrides();
        dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: overrides });
      } catch {
        dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: null });
      }
    },

    updateUserSettings: async (settings: Partial<UserSettingsOverrides>) => {
      try {
        await apiClient.updateUserSettings(settings);
        await actions.loadSettings(); // Reload effective settings
      } catch (error) {
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to update user settings',
        });
        throw error;
      }
    },

    resetUserSettings: async () => {
      try {
        await apiClient.resetUserSettings();
        dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: null });
        await actions.loadSettings(); // Reload to get system defaults
      } catch (error) {
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to reset user settings',
        });
        throw error;
      }
    },

    truncateMetrics: async () => {
      try {
        const result = await apiClient.truncateMetrics();
        // Optionally reload dashboard stats to reflect changes (force immediate refresh)
        await loadDashboardStats(true);
        return result;
      } catch (error) {
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to truncate metrics',
        });
        throw error;
      }
    },

    setDashboardBucketOverride: (bucket: number | null) => {
      dispatch({ type: 'SET_DASHBOARD_BUCKET_OVERRIDE', payload: bucket });
    },

    connectWebSocket,
    disconnectWebSocket,
    setWsKeepAlive: (keep: boolean) => {
      wsKeepAliveRef.current = keep;
    },
    setWsSubscription: (sections: string[]) => {
      const label = sections.length ? sections.join(', ') : 'all';
      const prev = wsSubscriptionRef.current.length ? wsSubscriptionRef.current.join(', ') : 'all';
      wsSubscriptionRef.current = sections;
      // Send to the server immediately if connected
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'subscribe', sections }));
        console.log(`[WS] subscription changed: [${prev}] → [${label}]`);
      } else {
        console.log(`[WS] subscription queued (not connected): [${prev}] → [${label}]`);
      }
    },
  };

  // Initialize data and WebSocket on mount
  useEffect(() => {
    // Load initial data
    const loadInitialData = async () => {
      // Load settings first (needed to determine bucket_seconds for dashboard stats)
      // Use getUserSettings() to get user overrides merged with system defaults
      dispatch({ type: 'SET_LOADING', payload: { key: 'settings', value: true } });
      try {
        const settings = await apiClient.getUserSettings();
        settingsRef.current = settings; // Set ref immediately for loadDashboardStats
        dispatch({ type: 'SET_SETTINGS', payload: settings });

        // Also load user overrides for the settings UI
        try {
          const overrides = await apiClient.getUserSettingsOverrides();
          dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: overrides });
        } catch {
          dispatch({ type: 'SET_USER_SETTINGS_OVERRIDES', payload: null });
        }
      } catch (error) {
        console.error('Failed to load settings:', error);
        dispatch({
          type: 'SET_ERROR',
          payload: error instanceof Error ? error.message : 'Failed to load settings',
        });
      } finally {
        dispatch({ type: 'SET_LOADING', payload: { key: 'settings', value: false } });
      }

      // Load dashboard stats (uses settingsRef.current.bucket_seconds)
      await loadDashboardStats();
    };

    loadInitialData();

    // Don't connect websocket on mount - it will be connected after authentication check in App.tsx
    // This prevents connection attempts before we know if the user is authenticated

    return () => {
      // Clean up timeouts
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (disconnectTimeoutRef.current) {
        clearTimeout(disconnectTimeoutRef.current);
      }
      if (fullDisconnectTimeoutRef.current) {
        clearTimeout(fullDisconnectTimeoutRef.current);
      }
      disconnectWebSocket();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty dependency array - only run once on mount to prevent WebSocket reconnection loop

  // Pause WebSocket and polling when the browser tab is hidden to save server CPU.
  // Reconnect and force a full refresh when the tab becomes visible again.
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        if (wsKeepAliveRef.current) {
          console.log('[WebSocket] Tab hidden — keeping connection alive (wsKeepAlive)');
          return;
        }
        console.log('[WebSocket] Tab hidden — disconnecting to save server resources');
        disconnectWebSocket();
      } else {
        console.log('[WebSocket] Tab visible — reconnecting');
        connectWebSocket();
        // Force full refresh after returning to the tab so we don't miss anything
        loadDashboardStats(true);
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectWebSocket, disconnectWebSocket, loadDashboardStats]);

  const contextValue: AppContextType = {
    state,
    dispatch,
    getCurrentStats: () => {
      return state.activeView === 'global' ? state.globalState.stats : state.filteredState.stats;
    },
    actions,
  };

  return <AppContext.Provider value={contextValue}>{children}</AppContext.Provider>;
};
