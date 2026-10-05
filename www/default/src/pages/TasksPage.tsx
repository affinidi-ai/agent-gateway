import React, { useEffect, useRef, useMemo, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { topAndTail, formatDateTime, formatDuration } from '../utils/stringUtils';
import { useFabricResolver } from '../utils/useFabricResolver';
import { AppButton } from '../components/shared/AppButton';
import { AgentSurface, apiClient } from '../api';

const TasksPage: React.FC = () => {
  const navigate = useNavigate();
  const { state, actions, getCurrentStats } = useApp();
  const refreshInterval = useRef<NodeJS.Timeout | null>(null);

  // Surfaces lookup for grouping tasks under their owning surface.
  // Tasks reference a surface via `task.config_id` (the surface_id).
  const [surfaces, setSurfaces] = useState<AgentSurface[]>([]);
  const refetchSurfaces = useCallback(() => {
    apiClient
      .listSurfaces()
      .then(data => setSurfaces(data))
      .catch(() => {
        // Non-fatal: tasks panel still works without surface grouping.
      });
  }, []);
  useEffect(() => {
    refetchSurfaces();
  }, [refetchSurfaces]);

  const { surfaceById } = useMemo(() => {
    const byId = new Map<string, AgentSurface>();
    for (const s of surfaces) {
      byId.set(s.surface_id, s);
    }
    return { surfaceById: byId };
  }, [surfaces]);

  const resolveSurface = useCallback(
    (task: any): AgentSurface | undefined => {
      if (task?.config_id && surfaceById.has(task.config_id)) {
        return surfaceById.get(task.config_id);
      }
      return undefined;
    },
    [surfaceById]
  );

  // Collapsed surface-group state (group key -> collapsed?). Default collapsed:
  // new surface ids are added to `collapsedGroups` the first time we see them,
  // so users start with all groups closed but their toggles stick across renders.
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const seenGroups = useRef<Set<string>>(new Set());
  const toggleGroup = useCallback((key: string) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  // Tag filter (multi-select). When empty, all surfaces show. A tag matches
  // when the surface's `tags` array contains it.
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const allTags = useMemo(() => {
    const set = new Set<string>();
    for (const s of surfaces) {
      for (const t of s.tags || []) set.add(t);
    }
    return Array.from(set).sort();
  }, [surfaces]);
  const toggleTag = useCallback((tag: string) => {
    setSelectedTags(prev => {
      const next = new Set(prev);
      if (next.has(tag)) next.delete(tag);
      else next.add(tag);
      return next;
    });
  }, []);
  const clearTags = useCallback(() => setSelectedTags(new Set()), []);

  // Use useMemo to make stats reactive to state changes
  const stats = useMemo(() => getCurrentStats(), [state, getCurrentStats]);
  const tasksData = stats?.tasks;
  const tasks = tasksData?.tasks || [];
  const metrics = tasksData?.metrics || [];

  // Partition surface-owned tasks into ordered per-surface groups (AP + TPs).
  const { surfaceGroups } = useMemo(() => {
    const sorted = [...tasks].sort((a, b) =>
      (a.channel_name || '').toLowerCase().localeCompare((b.channel_name || '').toLowerCase())
    );
    const groupMap = new Map<string, { surface: AgentSurface; tasks: any[] }>();
    for (const t of sorted) {
      const surface = resolveSurface(t);
      if (selectedTags.size > 0) {
        if (!surface) continue;
        const tags = surface.tags || [];
        if (!tags.some(tag => selectedTags.has(tag))) continue;
      }
      if (surface) {
        const existing = groupMap.get(surface.surface_id);
        if (existing) {
          existing.tasks.push(t);
        } else {
          groupMap.set(surface.surface_id, { surface, tasks: [t] });
        }
      }
    }
    // AP first, then TPs alphabetically by alias.
    for (const g of groupMap.values()) {
      g.tasks.sort((a: any, b: any) => {
        const aTp = a.transit_point || '';
        const bTp = b.transit_point || '';
        if (!aTp && bTp) return -1;
        if (aTp && !bTp) return 1;
        return aTp.localeCompare(bTp);
      });
    }
    const groups = Array.from(groupMap.entries()).sort(([, ga], [, gb]) =>
      ga.surface.name.toLowerCase().localeCompare(gb.surface.name.toLowerCase())
    );
    return { surfaceGroups: groups };
  }, [tasks, resolveSurface, selectedTags]);

  useEffect(() => {
    const newKeys: string[] = [];
    for (const [key] of surfaceGroups) {
      if (!seenGroups.current.has(key)) {
        seenGroups.current.add(key);
        newKeys.push(key);
      }
    }
    if (newKeys.length === 0) return;
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      for (const k of newKeys) next.add(k);
      return next;
    });
  }, [surfaceGroups]);

  // If we see a task whose config_id references something we haven't
  // tried to look up yet, refetch the surfaces list once. Tasks can have
  // config_ids that are not present in the current surface
  // list, so remember which ids we've already probed to avoid retry loops.
  const probedConfigIds = useRef<Set<string>>(new Set());
  const refetching = useRef(false);
  useEffect(() => {
    if (refetching.current) return;
    const unresolved = tasks.find(
      (t: any) =>
        t?.config_id && !surfaceById.has(t.config_id) && !probedConfigIds.current.has(t.config_id)
    );
    if (!unresolved?.config_id) return;
    probedConfigIds.current.add(unresolved.config_id);
    refetching.current = true;
    apiClient
      .listSurfaces()
      .then(data => setSurfaces(data))
      .catch(() => {})
      .finally(() => {
        refetching.current = false;
      });
  }, [tasks, surfaceById]);

  const connectionPointTasksData = stats?.connection_point_tasks;
  const connectionPointTasks = connectionPointTasksData?.tasks || [];
  const connectionPointSummary = connectionPointTasksData?.summary;

  const visibleTasks = useMemo(
    () => surfaceGroups.flatMap(([, group]) => group.tasks),
    [surfaceGroups]
  );
  const visibleTaskIds = new Set(visibleTasks.map(task => task.task_id));

  // Resolve fabric:// task targets to "<gatewayName> / <surfaceName>".
  const fabricSeedUrls = useMemo(() => {
    const urls: string[] = [];
    for (const t of visibleTasks) if (t?.target_endpoint) urls.push(t.target_endpoint);
    return urls;
  }, [visibleTasks]);
  const { formatFabric } = useFabricResolver(fabricSeedUrls);

  const renderTargetEndpoint = useCallback(
    (endpoint?: string) => {
      if (!endpoint) return '-';
      const fab = formatFabric(endpoint);
      if (fab) return <span title={fab.title}>{fab.display}</span>;
      if (endpoint.startsWith('did:')) return topAndTail(endpoint, 16, 24);
      return endpoint;
    },
    [formatFabric]
  );

  // Auto-refresh every 5 seconds
  useEffect(() => {
    refreshInterval.current = setInterval(() => {
      // The data will update automatically via WebSocket
    }, 5000);

    return () => {
      if (refreshInterval.current) {
        clearInterval(refreshInterval.current);
      }
    };
  }, []);

  // Subscribe to everything except logs to reduce WS payload size
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return bytes.toFixed(0) + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  };

  // Duration formatting now handled by shared utility in stringUtils
  // Using short form for compact task display
  const formatTaskDuration = (ms: number): string => {
    return formatDuration(Math.floor(ms / 1000), undefined, true);
  };

  const formatTimeAgo = (date: Date): string => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSeconds < 60) {
      return 'Just now';
    } else if (diffMinutes < 60) {
      return `${diffMinutes}m ago`;
    } else if (diffHours < 24) {
      return `${diffHours}h ago`;
    } else {
      return `${diffDays}d ago`;
    }
  };

  // Create metrics map for visible surface tasks only.
  const metricsMap: Record<string, any> = {};
  metrics.forEach(metric => {
    if (metric?.task_id && visibleTaskIds.has(metric.task_id)) {
      metricsMap[metric.task_id] = metric;
    }
  });

  const aggregateThroughput = Object.values(metricsMap).reduce((total, metric) => {
    return total + (metric?.throughput_bytes_per_sec || 0);
  }, 0);
  const totalActiveConnections = visibleTasks.reduce(
    (total, task) => total + (task.active_connections || 0),
    0
  );
  const totalBytesTransferred = visibleTasks.reduce(
    (total, task) => total + (task.bytes_sent || 0) + (task.bytes_received || 0),
    0
  );

  return (
    <div className="container-fluid">
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-layer-group"></i> Surface Tasks
              </h6>
              <small className="text-muted">Activity scope: 60 seconds</small>
            </div>
            <div>
              <AppButton
                variant="primary"
                size="md"
                className="me-2 shadow-sm"
                onClick={() => window.location.reload()}
                iconStart={<i className="fas fa-sync-alt fa-sm" aria-hidden="true" />}
              >
                Refresh
              </AppButton>
            </div>
          </div>
          {allTags.length > 0 && (
            <div className="d-flex align-items-center flex-wrap mt-2" style={{ gap: '0.35rem' }}>
              <small className="text-muted me-1">
                <i className="fas fa-filter me-1" />
                Filter by tag:
              </small>
              {allTags.map(tag => {
                const active = selectedTags.has(tag);
                return (
                  <span
                    key={tag}
                    className={`badge ${active ? 'text-bg-primary' : 'text-bg-light'}`}
                    style={{ fontSize: '0.75rem', cursor: 'pointer' }}
                    onClick={() => toggleTag(tag)}
                    title={active ? `Remove '${tag}' filter` : `Filter to '${tag}'`}
                  >
                    {tag}
                  </span>
                );
              })}
              {selectedTags.size > 0 && (
                <AppButton
                  variant="link"
                  size="sm"
                  className="p-0 ms-2"
                  style={{ fontSize: '0.75rem', textDecoration: 'none' }}
                  onClick={clearTags}
                >
                  Clear
                </AppButton>
              )}
            </div>
          )}
        </div>
        <div className="card-body">
          {/* Task Summary Cards */}
          <div className="row mb-4">
            <div className="col-xl-3 col-md-6 mb-3">
              <div className="card border-left-primary h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                        Total Tasks
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {visibleTasks.length}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-tasks fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 mb-3">
              <div className="card border-left-info h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                        Active Connections
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {totalActiveConnections}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-network-wired fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 mb-3">
              <div className="card border-left-warning h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                        Total Data Transfer
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {formatBytes(totalBytesTransferred)}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-exchange-alt fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 mb-3">
              <div className="card border-left-success h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                        Aggregate Throughput
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {aggregateThroughput > 0
                          ? `${formatBytes(aggregateThroughput)}/s`
                          : '0 B/s'}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-tachometer-alt fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Tasks Table */}
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th>Surface</th>
                  <th>Listener / Target</th>
                  <th className="text-center">Status</th>
                  <th className="text-center">Uptime</th>
                  <th className="text-center">Connections</th>
                  <th className="text-center">Active</th>
                  <th className="text-center">Total Bytes</th>
                  <th className="text-center">Throughput</th>
                  <th className="text-center">Errors</th>
                  <th className="text-center">Last Activity</th>
                </tr>
              </thead>
              {tasks.length === 0 ? (
                <tbody>
                  <tr>
                    <td colSpan={10} className="text-center text-muted">
                      No running tasks
                    </td>
                  </tr>
                </tbody>
              ) : surfaceGroups.length === 0 ? (
                <tbody>
                  <tr>
                    <td colSpan={10} className="text-center text-muted">
                      {selectedTags.size > 0
                        ? 'No surfaces match the selected tags'
                        : 'No surface-owned tasks'}
                    </td>
                  </tr>
                </tbody>
              ) : (
                (() => {
                  return surfaceGroups.map(([groupKey, group]) => {
                    const collapsed = collapsedGroups.has(groupKey);
                    const aggBytes = group.tasks.reduce(
                      (sum, t) => sum + (t.bytes_sent || 0) + (t.bytes_received || 0),
                      0
                    );
                    const aggThroughput = group.tasks.reduce((sum, t) => {
                      const m = metricsMap[t.task_id || ''] || {};
                      return sum + (m.throughput_bytes_per_sec || 0);
                    }, 0);
                    const aggActive = group.tasks.reduce(
                      (sum, t) => sum + (t.active_connections || 0),
                      0
                    );
                    const aggErrors = group.tasks.reduce((sum, t) => sum + (t.error_count || 0), 0);
                    return (
                      <tbody key={groupKey}>
                        <tr
                          style={{
                            backgroundColor: 'rgba(74, 144, 226, 0.06)',
                            cursor: 'pointer',
                          }}
                          onClick={() => toggleGroup(groupKey)}
                        >
                          <td colSpan={10}>
                            <div className="d-flex align-items-center justify-content-between">
                              <div className="d-flex align-items-center" style={{ gap: '0.5rem' }}>
                                <i
                                  className={`fas fa-chevron-${collapsed ? 'right' : 'down'}`}
                                  style={{ fontSize: '0.75rem', width: '0.75rem' }}
                                />
                                <i className="fas fa-layer-group text-primary" />
                                <AppButton
                                  variant="link"
                                  size="sm"
                                  className="p-0 fw-bold text-primary"
                                  style={{ textDecoration: 'none' }}
                                  onClick={e => {
                                    e.stopPropagation();
                                    navigate(`/surfaces/${group.surface.surface_id}`);
                                  }}
                                  title="Open surface"
                                >
                                  {group.surface.name}
                                </AppButton>
                                {group.surface.tags?.map(tag => (
                                  <span
                                    key={tag}
                                    className="badge text-bg-light"
                                    style={{ fontSize: '0.7rem' }}
                                  >
                                    {tag}
                                  </span>
                                ))}
                                <span className="text-muted small">
                                  · {group.tasks.length}{' '}
                                  {group.tasks.length === 1 ? 'task' : 'tasks'}
                                </span>
                              </div>
                              <div
                                className="d-flex align-items-center small text-muted"
                                style={{ gap: '1rem' }}
                              >
                                <span title="Active connections">
                                  <i className="fas fa-network-wired me-1" />
                                  {aggActive}
                                </span>
                                <span title="Total bytes">
                                  <i className="fas fa-exchange-alt me-1" />
                                  {formatBytes(aggBytes)}
                                </span>
                                <span title="Aggregate throughput">
                                  <i className="fas fa-tachometer-alt me-1" />
                                  {aggThroughput > 0 ? `${formatBytes(aggThroughput)}/s` : '0 B/s'}
                                </span>
                                {aggErrors > 0 && (
                                  <span className="text-danger" title="Errors">
                                    <i className="fas fa-exclamation-circle me-1" />
                                    {aggErrors}
                                  </span>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                        {!collapsed &&
                          group.tasks.map((task: any, index: number) => {
                            const taskMetrics = metricsMap[task.task_id || ''] || {};

                            // Status badge
                            const getStatusBadge = () => {
                              switch (task.status) {
                                case 'running':
                                  return (
                                    <span className="badge text-bg-success">
                                      <i className="fas fa-play-circle"></i> Running
                                    </span>
                                  );
                                case 'starting':
                                  return (
                                    <span className="badge text-bg-info">
                                      <i className="fas fa-circle-notch fa-spin"></i> Starting
                                    </span>
                                  );
                                case 'stopping':
                                  return (
                                    <span className="badge text-bg-warning">
                                      <i className="fas fa-stop-circle"></i> Stopping
                                    </span>
                                  );
                                case 'error':
                                  return (
                                    <span className="badge text-bg-danger">
                                      <i className="fas fa-exclamation-circle"></i> Error
                                    </span>
                                  );
                                default:
                                  return <span className="badge text-bg-secondary">Unknown</span>;
                              }
                            };

                            // Calculate uptime
                            const getUptimeDisplay = () => {
                              if (!task.started_at) return <span className="text-muted">-</span>;
                              try {
                                const startedAt = new Date(task.started_at);
                                const now = new Date();
                                const uptimeMs = now.getTime() - startedAt.getTime();
                                return formatTaskDuration(uptimeMs);
                              } catch (e) {
                                return <span className="text-muted">-</span>;
                              }
                            };

                            // Format last activity
                            const getLastActivity = () => {
                              if (!task.last_activity)
                                return <span className="text-muted">Never</span>;
                              try {
                                return formatTimeAgo(new Date(task.last_activity));
                              } catch (e) {
                                return <span className="text-muted">Invalid date</span>;
                              }
                            };

                            // Format total bytes transferred
                            const getTotalBytes = () => {
                              const bytesSent =
                                typeof task.bytes_sent === 'number' ? task.bytes_sent : 0;
                              const bytesReceived =
                                typeof task.bytes_received === 'number' ? task.bytes_received : 0;
                              const totalBytes = bytesSent + bytesReceived;

                              return totalBytes > 0 ? (
                                formatBytes(totalBytes)
                              ) : (
                                <span className="text-muted">N/A</span>
                              );
                            };

                            // Error count
                            const errorCount =
                              typeof task.error_count === 'number' ? task.error_count : 0;
                            const getErrorBadge = () => {
                              return errorCount > 0 ? (
                                <span
                                  className="badge text-bg-danger"
                                  title={`${errorCount} error${errorCount !== 1 ? 's' : ''}`}
                                >
                                  {errorCount}
                                </span>
                              ) : (
                                <span className="text-muted">0</span>
                              );
                            };

                            return (
                              <tr key={task.task_id || index}>
                                <td className="text-muted small" style={{ paddingLeft: '2rem' }}>
                                  {task.transit_point ? (
                                    (() => {
                                      const tp = group.surface.transit?.points?.find(
                                        p => (p.alias || p.name) === task.transit_point
                                      );
                                      const label = tp?.name || task.transit_point;
                                      const proto = tp?.protocol;
                                      return (
                                        <div
                                          className="d-flex flex-column align-items-start"
                                          style={{ gap: '2px' }}
                                        >
                                          {label ? <strong>{label}</strong> : null}
                                          <div
                                            className="d-flex align-items-center"
                                            style={{ gap: '4px' }}
                                          >
                                            <span
                                              className="badge text-bg-secondary"
                                              title={`Transit point '${label}' (alias: ${task.transit_point})`}
                                              style={{ fontSize: '0.7rem' }}
                                            >
                                              Transit Point
                                            </span>
                                            {proto ? (
                                              <span
                                                className="badge text-bg-light"
                                                style={{ fontSize: '0.65rem' }}
                                              >
                                                {proto.toUpperCase()}
                                              </span>
                                            ) : null}
                                          </div>
                                        </div>
                                      );
                                    })()
                                  ) : (
                                    <div
                                      className="d-flex flex-column align-items-start"
                                      style={{ gap: '2px' }}
                                    >
                                      {(() => {
                                        // Prefer the AP's own name set in the
                                        // canvas builder (e.g. "Front door"),
                                        // mirroring how TP rows show the TP
                                        // name. Fall back to the surface name
                                        // when the AP has no override.
                                        const apNode = (group.surface as any)?.canvas?.nodes?.find(
                                          (n: any) => n?.type === 'access-point'
                                        );
                                        const apName =
                                          (apNode?.config?.name as string | undefined) ||
                                          group.surface.name;
                                        return apName ? <strong>{apName}</strong> : null;
                                      })()}
                                      <div
                                        className="d-flex align-items-center"
                                        style={{ gap: '4px' }}
                                      >
                                        <span
                                          className="badge text-bg-primary"
                                          title={`Access point (inbound) for surface '${group.surface.name}'`}
                                          style={{ fontSize: '0.7rem' }}
                                        >
                                          Access Point
                                        </span>
                                        <span
                                          className="badge text-bg-light"
                                          style={{ fontSize: '0.65rem' }}
                                        >
                                          {group.surface.access_point.protocol.toUpperCase()}
                                        </span>
                                      </div>
                                    </div>
                                  )}
                                </td>
                                <td>
                                  <div className="d-flex flex-column" style={{ gap: '2px' }}>
                                    <div className="small">
                                      <span className="text-muted me-1">Listener:</span>
                                      <code>
                                        {task.listen_address &&
                                        task.listen_address.startsWith('did:')
                                          ? topAndTail(task.listen_address, 16, 24)
                                          : task.listen_address || '-'}
                                      </code>
                                    </div>
                                    <div className="small">
                                      <span className="text-muted me-1">Target:</span>
                                      <code>{renderTargetEndpoint(task.target_endpoint)}</code>
                                    </div>
                                  </div>
                                </td>
                                <td className="text-center">{getStatusBadge()}</td>
                                <td
                                  className="text-center"
                                  title={
                                    task.started_at
                                      ? `Started: ${formatDateTime(task.started_at, true)}`
                                      : 'Start time unknown'
                                  }
                                >
                                  {getUptimeDisplay()}
                                </td>
                                <td className="text-center">
                                  {typeof task.total_connections === 'number' ? (
                                    task.total_connections
                                  ) : (
                                    <span className="text-muted">-</span>
                                  )}
                                </td>
                                <td className="text-center">
                                  {typeof task.active_connections === 'number' ? (
                                    task.active_connections > 0 ? (
                                      <span className="badge text-bg-info">
                                        {task.active_connections}
                                      </span>
                                    ) : (
                                      <span className="text-muted">0</span>
                                    )
                                  ) : (
                                    <span className="text-muted">-</span>
                                  )}
                                </td>
                                <td className="text-center">{getTotalBytes()}</td>
                                <td
                                  className="text-center"
                                  title={`Current throughput: ${taskMetrics.throughput_bytes_per_sec ? formatBytes(taskMetrics.throughput_bytes_per_sec) + '/sec' : 'No current activity'}`}
                                >
                                  {taskMetrics.throughput_bytes_per_sec &&
                                  taskMetrics.throughput_bytes_per_sec > 0 ? (
                                    `${formatBytes(taskMetrics.throughput_bytes_per_sec)}/s`
                                  ) : (
                                    <span className="text-muted">0 B/s</span>
                                  )}
                                </td>
                                <td className="text-center">{getErrorBadge()}</td>
                                <td className="text-center">
                                  <small>{getLastActivity()}</small>
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    );
                  });
                })()
              )}
            </table>
          </div>
        </div>
      </div>

      {/* Connection Point Tasks */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-plug"></i> Connection Point Tasks
              </h6>
              <small className="text-muted">
                WebSocket listeners for gateway connection points
              </small>
            </div>
          </div>
        </div>
        <div className="card-body">
          {/* Connection Point Summary Cards */}
          <div className="row mb-4">
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-primary h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                        Total Listeners
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.total_listeners || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-plug fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-success h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                        Connected
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.connected || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-check-circle fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-warning h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                        Reconnecting
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.reconnecting || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-sync-alt fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-danger h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-danger text-uppercase mb-1">
                        Failed
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.failed || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-exclamation-circle fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-info h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                        Messages
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.total_messages || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-envelope fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-2 col-md-4 mb-3">
              <div className="card border-left-danger h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col me-2">
                      <div className="text-xs font-weight-bold text-danger text-uppercase mb-1">
                        Errors
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {connectionPointSummary?.total_errors || 0}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-exclamation-triangle fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Connection Point Tasks Table */}
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th>Name</th>
                  <th className="text-center">Type</th>
                  <th>Gateway DID</th>
                  <th>Mediator DID</th>
                  <th className="text-center">Status</th>
                  <th className="text-center">Uptime</th>
                  <th className="text-center">Messages</th>
                  <th className="text-center">Errors</th>
                  <th className="text-center">Reconnect Attempts</th>
                  <th className="text-center">Last Activity</th>
                </tr>
              </thead>
              <tbody>
                {connectionPointTasks.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="text-center text-muted">
                      No active connection point listeners
                    </td>
                  </tr>
                ) : (
                  connectionPointTasks
                    .sort((a, b) =>
                      (a.name || '').toLowerCase().localeCompare((b.name || '').toLowerCase())
                    )
                    .map((task: any, index: number) => {
                      // Status badge
                      const getStatusBadge = () => {
                        switch (task.status) {
                          case 'connected':
                            return (
                              <span className="badge text-bg-success">
                                <i className="fas fa-check-circle"></i> Connected
                              </span>
                            );
                          case 'reconnecting':
                            return (
                              <span className="badge text-bg-warning">
                                <i className="fas fa-sync-alt fa-spin"></i> Reconnecting
                              </span>
                            );
                          case 'failed':
                            return (
                              <span className="badge text-bg-danger">
                                <i className="fas fa-exclamation-circle"></i> Failed
                              </span>
                            );
                          default:
                            return <span className="badge text-bg-secondary">Unknown</span>;
                        }
                      };

                      // Calculate uptime
                      const getUptimeDisplay = () => {
                        if (!task.started_at) return <span className="text-muted">-</span>;
                        try {
                          const startedAt = new Date(task.started_at);
                          const now = new Date();
                          const uptimeMs = now.getTime() - startedAt.getTime();
                          return formatTaskDuration(uptimeMs);
                        } catch (e) {
                          return <span className="text-muted">-</span>;
                        }
                      };

                      // Format last activity
                      const getLastActivity = () => {
                        if (!task.last_activity) return <span className="text-muted">Never</span>;
                        try {
                          return formatTimeAgo(new Date(task.last_activity));
                        } catch (e) {
                          return <span className="text-muted">Invalid date</span>;
                        }
                      };

                      // Get task type badge with appropriate icon and color
                      const getTaskTypeBadge = () => {
                        switch (task.task_type) {
                          case 'User-Created':
                            return (
                              <span
                                className="badge text-bg-success"
                                title="User-created connection point"
                              >
                                <i className="fas fa-user"></i> User
                              </span>
                            );
                          case 'OOB Inviter':
                            return (
                              <span
                                className="badge text-bg-info"
                                title="Permanent connection from OOB invitation (inviter side)"
                              >
                                <i className="fas fa-paper-plane"></i> OOB Inviter
                              </span>
                            );
                          case 'OOB Responder':
                            return (
                              <span
                                className="badge text-bg-warning"
                                title="Auto-created for receiving from OOB acceptor (inviter side)"
                              >
                                <i className="fas fa-reply"></i> OOB Responder
                              </span>
                            );
                          case 'OOB Acceptor':
                            return (
                              <span
                                className="badge text-bg-primary"
                                title="Gateway listener endpoint (acceptor side)"
                              >
                                <i className="fas fa-envelope-open"></i> OOB Acceptor
                              </span>
                            );
                          case 'System':
                            return (
                              <span
                                className="badge text-bg-secondary"
                                title="Legacy system-created connection point"
                              >
                                <i className="fas fa-cog"></i> System
                              </span>
                            );
                          default:
                            return (
                              <span className="badge text-bg-secondary">
                                <i className="fas fa-headphones"></i> {task.task_type || 'Unknown'}
                              </span>
                            );
                        }
                      };

                      return (
                        <tr key={task.id || index}>
                          <td>
                            <strong>{task.name || 'Unknown'}</strong>
                          </td>
                          <td className="text-center">{getTaskTypeBadge()}</td>
                          <td>
                            <code className="small">{topAndTail(task.gateway_did, 16, 24)}</code>
                          </td>
                          <td>
                            <code className="small">{topAndTail(task.mediator_did, 16, 24)}</code>
                          </td>
                          <td className="text-center">{getStatusBadge()}</td>
                          <td
                            className="text-center"
                            title={
                              task.started_at
                                ? `Started: ${formatDateTime(task.started_at, true)}`
                                : 'Start time unknown'
                            }
                          >
                            {getUptimeDisplay()}
                          </td>
                          <td className="text-center">
                            {typeof task.message_count === 'number' ? (
                              task.message_count > 0 ? (
                                <span className="badge text-bg-info">{task.message_count}</span>
                              ) : (
                                <span className="text-muted">0</span>
                              )
                            ) : (
                              <span className="text-muted">-</span>
                            )}
                          </td>
                          <td className="text-center">
                            {typeof task.error_count === 'number' && task.error_count > 0 ? (
                              <span
                                className="badge text-bg-danger"
                                title={`${task.error_count} error${task.error_count !== 1 ? 's' : ''}`}
                              >
                                {task.error_count}
                              </span>
                            ) : (
                              <span className="text-muted">0</span>
                            )}
                          </td>
                          <td className="text-center">
                            {typeof task.reconnect_attempts === 'number' &&
                            task.reconnect_attempts > 0 ? (
                              <span className="badge text-bg-warning">
                                {task.reconnect_attempts}
                              </span>
                            ) : (
                              <span className="text-muted">0</span>
                            )}
                          </td>
                          <td className="text-center">
                            <small>{getLastActivity()}</small>
                          </td>
                        </tr>
                      );
                    })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TasksPage;
