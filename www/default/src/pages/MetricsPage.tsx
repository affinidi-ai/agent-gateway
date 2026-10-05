import React, { useEffect, useState, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import FieldHelp from '../components/shared/FieldHelp';
import MetricsFlowVisualization from '../components/MetricsFlowVisualization';
import { formatDID } from '../utils/stringUtils';
import { FLOW_COLORS, UI_COLORS } from '../utils/uiPalette';

interface ConnectionDataPoint {
  timestamp: string;
  status: 'success' | 'failed' | 'gatewayfault';
  latency_ms?: number;
  identity_hash?: string;
  direction: 'request' | 'response';
  variant_alias?: string;
}

interface RuleValidationDataPoint {
  timestamp: string;
  accepted: boolean;
}

interface ChannelMetricsData {
  sources: {
    [source: string]: {
      [identity: string]: {
        [destination: string]: ConnectionDataPoint[];
      };
    };
  };
  rule_triggers: RuleValidationDataPoint[];
}

interface HierarchicalMetrics {
  connections: {
    [channelId: string]: ChannelMetricsData;
  };
}

interface Gateway {
  id: string;
  name: string;
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: 'active' | 'disabled' | 'pending' | 'failed' | 'awaiting-approval';
  created_at: string;
  updated_at: string;
}

const MetricsPage: React.FC = () => {
  const navigate = useNavigate();
  const { state, actions, getCurrentStats } = useApp();
  const [metrics, setMetrics] = useState<HierarchicalMetrics | null>(null);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedChannels, setExpandedChannels] = useState<Set<string>>(new Set());
  const [expandedSources, setExpandedSources] = useState<Set<string>>(new Set());
  const [expandedDestinations, setExpandedDestinations] = useState<Set<string>>(new Set());
  const [isLive, setIsLive] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stats = getCurrentStats();

  useEffect(() => {
    loadMetrics();
    loadGateways();
    // Subscribe to everything except logs to reduce WS payload size
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
  }, []);

  // Live-update timer
  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (isLive) {
      intervalRef.current = setInterval(loadMetrics, 30000);
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isLive]);

  const loadMetrics = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getHierarchicalMetrics();
      setMetrics(data);
    } catch (error) {
      console.error('Failed to load metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadGateways = async () => {
    try {
      const response = await apiClient.get('/gateways');
      setGateways(response.data || []);
    } catch (error) {
      console.error('Failed to load gateways:', error);
    }
  };

  const getChannelName = (channelId: string): string => {
    // First, check if it's a channel
    const channel = stats?.channels.find(ch => ch.config_id === channelId);
    if (channel?.name) {
      return channel.name;
    }

    // Fallback: show a shortened version of the ID if no name found
    return channelId.length > 16 ? `${channelId.substring(0, 8)}...` : channelId;
  };

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleString();
  };

  const getStatusBadgeClass = (status: string): string => {
    switch (status) {
      case 'success':
        return 'text-bg-success';
      case 'failed':
        return 'text-bg-danger';
      case 'gatewayfault':
        return 'text-bg-warning';
      default:
        return 'text-bg-secondary';
    }
  };

  const calculateStats = (dataPoints: ConnectionDataPoint[]) => {
    const total = dataPoints.length;
    const successful = dataPoints.filter(dp => dp.status === 'success').length;
    const failed = dataPoints.filter(dp => dp.status === 'failed').length;
    const faults = dataPoints.filter(dp => dp.status === 'gatewayfault').length;

    const latencies = dataPoints
      .filter(dp => dp.latency_ms !== null && dp.latency_ms !== undefined)
      .map(dp => dp.latency_ms!);

    const avgLatency =
      latencies.length > 0
        ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2)
        : 'N/A';

    return { total, successful, failed, faults, avgLatency };
  };

  const calculateRuleStats = (dataPoints: RuleValidationDataPoint[]) => {
    const total = dataPoints.length;
    const accepted = dataPoints.filter(dp => dp.accepted).length;
    const denied = total - accepted;
    const acceptRate = total > 0 ? ((accepted / total) * 100).toFixed(1) : '0';

    return { total, accepted, denied, acceptRate };
  };

  const toggleChannel = (channelId: string) => {
    setExpandedChannels(prev => {
      const next = new Set(prev);
      if (next.has(channelId)) {
        next.delete(channelId);
      } else {
        next.add(channelId);
      }
      return next;
    });
  };

  const toggleSource = (sourceKey: string) => {
    setExpandedSources(prev => {
      const next = new Set(prev);
      if (next.has(sourceKey)) {
        next.delete(sourceKey);
      } else {
        next.add(sourceKey);
      }
      return next;
    });
  };

  const toggleDestination = (destKey: string) => {
    setExpandedDestinations(prev => {
      const next = new Set(prev);
      if (next.has(destKey)) {
        next.delete(destKey);
      } else {
        next.add(destKey);
      }
      return next;
    });
  };

  // Calculate connection flow data for visualization
  const flowData = useMemo(() => {
    if (!metrics) {
      return {
        connections: [],
        gatewayName: 'Gateway',
      };
    }

    const connectionFlows: Array<{
      source: string;
      identity: string;
      target: string;
      channelId: string;
      channelName: string;
      successCount: number;
      failedCount: number;
      faultCount: number;
      totalCount: number;
      direction: 'request' | 'response';
    }> = [];

    Object.entries(metrics.connections).forEach(([channelId, channelData]) => {
      const channelName = getChannelName(channelId);

      Object.entries(channelData.sources).forEach(([source, identities]) => {
        Object.entries(identities).forEach(([identity, destinations]) => {
          Object.entries(destinations).forEach(([destination, dataPoints]) => {
            // Separate request and response data points
            const requestPoints = dataPoints.filter(dp => dp.direction === 'request');
            const responsePoints = dataPoints.filter(dp => dp.direction === 'response');

            // Only create flow if there are request points (responses are reverse flow)
            if (requestPoints.length > 0) {
              connectionFlows.push({
                source,
                identity,
                target: destination,
                channelId,
                channelName,
                successCount: requestPoints.filter(dp => dp.status === 'success').length,
                failedCount: requestPoints.filter(dp => dp.status === 'failed').length,
                faultCount: requestPoints.filter(dp => dp.status === 'gatewayfault').length,
                totalCount: requestPoints.length,
                direction: 'request' as const,
              });
            }

            // Add response flow if there are response points
            if (responsePoints.length > 0) {
              connectionFlows.push({
                source,
                identity,
                target: destination,
                channelId,
                channelName,
                successCount: responsePoints.filter(dp => dp.status === 'success').length,
                failedCount: responsePoints.filter(dp => dp.status === 'failed').length,
                faultCount: responsePoints.filter(dp => dp.status === 'gatewayfault').length,
                totalCount: responsePoints.length,
                direction: 'response' as const,
              });
            }
          });
        });
      });
    });

    return {
      connections: connectionFlows,
      gatewayName: 'Proxy Gateway',
      gateways: gateways.reduce(
        (acc, gw) => {
          acc[gw.id] = gw.name;
          return acc;
        },
        {} as Record<string, string>
      ),
      channels:
        stats?.channels?.map(ch => ({
          config_id: ch.config_id,
          name: ch.name,
          target_endpoint: ch.target_endpoint,
        })) || [],
    };
  }, [metrics, stats?.channels, gateways]);

  if (loading && !metrics) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: '400px' }}
        >
          <div className="spinner-border text-primary" role="status"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      {/* Flow Visualization */}
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between bg-gradient-primary">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-file-alt"></i> Request Flow Visualization
          </h6>
          <div className="d-flex gap-2">
            <AppButton
              variant="secondary"
              size="md"
              onClick={() => navigate('/metrics/configure')}
              iconStart={<i className="fas fa-cog fa-sm me-1" aria-hidden="true" />}
            >
              Integrated Metrics Configuration
            </AppButton>
            <AppButton
              variant={isLive ? 'secondary' : 'outline-secondary'}
              size="md"
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
              onClick={loadMetrics}
              loading={loading}
              loadingLabel="Refreshing..."
              disabled={loading}
              iconStart={<i className="fas fa-sync-alt fa-sm me-1" aria-hidden="true" />}
            >
              Refresh
            </AppButton>
          </div>
        </div>
        <div className="card-body">
          {flowData.connections.length > 0 ? (
            <MetricsFlowVisualization data={flowData} />
          ) : (
            <div className="text-center text-muted py-5">
              <i className="fas fa-project-diagram fa-3x mb-3 opacity-50"></i>
              <p>
                No connection flow data available yet. The graph will appear as agents make
                connections through the gateway.
              </p>
            </div>
          )}

          <div className="mt-4 pt-3 border-top">
            <div className="row">
              <div className="col-md-3">
                <div className="d-flex align-items-center mb-2">
                  <div
                    className="me-2 d-flex align-items-center justify-content-center"
                    style={{
                      width: '20px',
                      height: '20px',
                      backgroundColor: FLOW_COLORS.source,
                      borderRadius: '50%',
                    }}
                  >
                    <i className="fas fa-laptop" style={{ fontSize: '10px', color: 'white' }}></i>
                  </div>
                  <small className="text-muted">
                    <strong>Source IPs:</strong> Connection initiators
                  </small>
                </div>
              </div>
              <div className="col-md-3">
                <div className="d-flex align-items-center mb-2">
                  <div
                    className="me-2 d-flex align-items-center justify-content-center"
                    style={{
                      width: '20px',
                      height: '20px',
                      backgroundColor: FLOW_COLORS.identity,
                      borderRadius: '50%',
                    }}
                  >
                    <i
                      className="fas fa-user-shield"
                      style={{ fontSize: '10px', color: 'white' }}
                    ></i>
                  </div>
                  <small className="text-muted">
                    <strong>Agent Identities:</strong> Authenticated agents
                  </small>
                </div>
              </div>
              <div className="col-md-3">
                <div className="d-flex align-items-center mb-2">
                  <div
                    className="me-2 d-flex align-items-center justify-content-center"
                    style={{
                      width: '20px',
                      height: '20px',
                      backgroundColor: FLOW_COLORS.fabricGateway,
                      borderRadius: '50%',
                    }}
                  >
                    <i
                      className="fas fa-broadcast-tower"
                      style={{ fontSize: '10px', color: 'white' }}
                    ></i>
                  </div>
                  <small className="text-muted">
                    <strong>Gateway Channels:</strong> Routing
                  </small>
                </div>
              </div>
              <div className="col-md-3">
                <div className="d-flex align-items-center mb-2">
                  <div
                    className="me-2 d-flex align-items-center justify-content-center"
                    style={{
                      width: '20px',
                      height: '20px',
                      backgroundColor: UI_COLORS.success,
                      borderRadius: '50%',
                    }}
                  >
                    <i className="fas fa-server" style={{ fontSize: '10px', color: 'white' }}></i>
                  </div>
                  <small className="text-muted">
                    <strong>Target Agents:</strong> Connection receivers
                  </small>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Tree View */}
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-sitemap me-2"></i>
            Channel Metrics
          </h6>
        </div>
        <div className="card-body">
          {!metrics || Object.keys(metrics.connections).length === 0 ? (
            <div className="text-muted text-center py-5">
              <i className="fas fa-info-circle fa-3x mb-3"></i>
              <p>No metrics data available</p>
            </div>
          ) : (
            <div className="metrics-tree">
              {Object.keys(metrics.connections).map(channelId => {
                const channelData = metrics.connections[channelId];
                const isChannelExpanded = expandedChannels.has(channelId);
                // Prefer WS-pushed channel_stats for live connection count
                const wsChannelStat = stats?.metrics?.channel_stats?.find(
                  (cs: any) => cs.channel_config_id === channelId
                );
                const totalConnections = wsChannelStat
                  ? wsChannelStat.total_connections
                  : Object.values(channelData.sources).reduce(
                      (sum, identities) =>
                        sum +
                        Object.values(identities).reduce(
                          (s, dests) =>
                            s + Object.values(dests).reduce((ds, points) => ds + points.length, 0),
                          0
                        ),
                      0
                    );
                const ruleStats = calculateRuleStats(channelData.rule_triggers);

                return (
                  <div key={channelId} className="tree-node border-left border-primary mb-3">
                    {/* Channel Level */}
                    <div
                      className="tree-item p-3 bg-light border rounded cursor-pointer"
                      onClick={() => toggleChannel(channelId)}
                      style={{ cursor: 'pointer' }}
                    >
                      <div className="d-flex justify-content-between align-items-center">
                        <div>
                          <i
                            className={`fas fa-chevron-${isChannelExpanded ? 'down' : 'right'} me-2 text-primary`}
                          ></i>
                          <i className="fas fa-server me-2 text-primary"></i>
                          <strong>Channel: {getChannelName(channelId)}</strong>
                        </div>
                        <div>
                          <span className="badge text-bg-primary me-2">
                            <i className="fas fa-plug me-1"></i>
                            {totalConnections} connections
                          </span>
                          <span className="badge text-bg-info">
                            <i className="fas fa-shield-alt me-1"></i>
                            {ruleStats.total} rules
                          </span>
                        </div>
                      </div>

                      {/* Channel Summary Stats */}
                      {isChannelExpanded && (
                        <div className="mt-3 pt-3 border-top">
                          <div className="row">
                            <div className="col-md-6">
                              <small className="text-muted font-weight-bold">
                                <i className="fas fa-plug me-1"></i>
                                Network Connections (Proxy Attempts):
                              </small>
                              <div className="mt-1">
                                <span className="badge text-bg-light me-2">
                                  {Object.keys(channelData.sources).length} sources
                                </span>
                                <span className="badge text-bg-light">
                                  {Object.values(channelData.sources).reduce(
                                    (sum, dests) => sum + Object.keys(dests).length,
                                    0
                                  )}{' '}
                                  destinations
                                </span>
                              </div>
                            </div>
                            <div className="col-md-6">
                              <small className="text-muted font-weight-bold">
                                <i className="fas fa-shield-alt me-1"></i>
                                Rule Validations (Authorization):{' '}
                                <FieldHelp
                                  testId="field-help-rule-validations"
                                  ariaLabel="About Rule Validations"
                                >
                                  Security checks evaluating agent identity and claims before a
                                  connection is allowed through. Accept rate is the share of these
                                  checks that passed.
                                </FieldHelp>
                              </small>
                              <div className="mt-1">
                                <span className="badge text-bg-success me-2">
                                  <i className="fas fa-check me-1"></i>
                                  {ruleStats.accepted} accepted
                                </span>
                                <span className="badge text-bg-danger">
                                  <i className="fas fa-times me-1"></i>
                                  {ruleStats.denied} denied
                                </span>
                                <span className="ms-2 text-muted">
                                  ({ruleStats.acceptRate}% accept rate)
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Sources Level */}
                    {isChannelExpanded && (
                      <div className="ms-4 mt-2">
                        {Object.keys(channelData.sources).map(source => {
                          const sourceKey = `${channelId}-${source}`;
                          const isSourceExpanded = expandedSources.has(sourceKey);
                          const identities = channelData.sources[source];
                          let sourceConnectionCount = 0;
                          Object.values(identities).forEach(destinations => {
                            sourceConnectionCount += Object.values(destinations).reduce(
                              (sum, points) => sum + points.length,
                              0
                            );
                          });

                          return (
                            <div key={source} className="tree-node border-left border-info mb-2">
                              <div
                                className="tree-item p-2 bg-white border rounded cursor-pointer"
                                onClick={e => {
                                  e.stopPropagation();
                                  toggleSource(sourceKey);
                                }}
                                style={{ cursor: 'pointer' }}
                              >
                                <div className="d-flex justify-content-between align-items-center">
                                  <div>
                                    <i
                                      className={`fas fa-chevron-${isSourceExpanded ? 'down' : 'right'} me-2 text-info`}
                                    ></i>
                                    <i className="fas fa-laptop me-2 text-info"></i>
                                    <span className="font-weight-bold">{source}</span>
                                    <small className="text-muted ms-2">(source IP)</small>
                                  </div>
                                  <span className="badge text-bg-info">
                                    {sourceConnectionCount} connections
                                  </span>
                                </div>
                              </div>

                              {/* Identity Level */}
                              {isSourceExpanded && (
                                <div className="ms-4 mt-2">
                                  {Object.keys(identities).map(identity => {
                                    const identityKey = `${sourceKey}-${identity}`;
                                    const isIdentityExpanded =
                                      expandedDestinations.has(identityKey);
                                    const destinations = identities[identity];
                                    let identityConnectionCount = 0;
                                    Object.values(destinations).forEach(points => {
                                      identityConnectionCount += points.length;
                                    });

                                    return (
                                      <div
                                        key={identity}
                                        className="tree-node border-left border-warning mb-2"
                                      >
                                        <div
                                          className="tree-item p-2 bg-white border rounded cursor-pointer"
                                          onClick={e => {
                                            e.stopPropagation();
                                            toggleDestination(identityKey);
                                          }}
                                          style={{ cursor: 'pointer' }}
                                        >
                                          <div className="d-flex justify-content-between align-items-center">
                                            <div>
                                              <i
                                                className={`fas fa-chevron-${isIdentityExpanded ? 'down' : 'right'} me-2 text-warning`}
                                              ></i>
                                              <i className="fas fa-id-card me-2 text-warning"></i>
                                              <span className="font-weight-bold">
                                                {identity === 'anonymous'
                                                  ? 'Anonymous agent'
                                                  : formatDID(identity)}
                                              </span>
                                              <small className="text-muted ms-2">
                                                (agent identity)
                                              </small>
                                            </div>
                                            <span className="badge text-bg-warning">
                                              {identityConnectionCount} connections
                                            </span>
                                          </div>
                                        </div>

                                        {/* Destinations Level */}
                                        {isIdentityExpanded && (
                                          <div className="ms-4 mt-2">
                                            {Object.keys(destinations).map(destination => {
                                              const destKey = `${identityKey}-${destination}`;
                                              const isDestExpanded =
                                                expandedDestinations.has(destKey);
                                              const dataPoints = destinations[destination];
                                              const stats = calculateStats(dataPoints);

                                              return (
                                                <div
                                                  key={destination}
                                                  className="tree-node border-left border-success mb-2"
                                                >
                                                  <div
                                                    className="tree-item p-2 bg-white border rounded cursor-pointer"
                                                    onClick={e => {
                                                      e.stopPropagation();
                                                      toggleDestination(destKey);
                                                    }}
                                                    style={{ cursor: 'pointer' }}
                                                  >
                                                    <div className="d-flex justify-content-between align-items-center">
                                                      <div className="flex-grow-1">
                                                        <i
                                                          className={`fas fa-chevron-${isDestExpanded ? 'down' : 'right'} me-2 text-success`}
                                                        ></i>
                                                        <i className="fas fa-bullseye me-2 text-success"></i>
                                                        <span className="font-weight-bold">
                                                          {destination}
                                                        </span>
                                                      </div>
                                                      <div className="text-end">
                                                        <span className="badge text-bg-light me-1">
                                                          {stats.total} total
                                                        </span>
                                                        <span className="badge text-bg-success me-1">
                                                          <i className="fas fa-check"></i>{' '}
                                                          {stats.successful}
                                                        </span>
                                                        <span className="badge text-bg-danger me-1">
                                                          <i className="fas fa-times"></i>{' '}
                                                          {stats.failed}
                                                        </span>
                                                        <span className="badge text-bg-warning me-1">
                                                          <i className="fas fa-exclamation-triangle"></i>{' '}
                                                          {stats.faults}
                                                        </span>
                                                        <span className="badge text-bg-info">
                                                          <i className="fas fa-clock"></i>{' '}
                                                          {stats.avgLatency}ms avg
                                                        </span>
                                                      </div>
                                                    </div>
                                                  </div>

                                                  {/* Connection Details */}
                                                  {isDestExpanded && (
                                                    <div className="ms-4 mt-2 p-3 bg-light border rounded">
                                                      <h6 className="font-weight-bold mb-3">
                                                        <i className="fas fa-chart-line me-2"></i>
                                                        Recent Network Connections (
                                                        {dataPoints.length} total)
                                                      </h6>
                                                      <small className="text-muted d-block mb-2">
                                                        <i className="fas fa-info-circle me-1"></i>
                                                        Shows proxy connection attempts to the
                                                        destination (after rule validation)
                                                      </small>
                                                      <div
                                                        style={{
                                                          maxHeight: '300px',
                                                          overflowY: 'auto',
                                                        }}
                                                      >
                                                        {dataPoints
                                                          .slice(-20)
                                                          .reverse()
                                                          .map((point, idx) => (
                                                            <div
                                                              key={idx}
                                                              className="d-flex justify-content-between align-items-center mb-2 p-2 border-left border-3 bg-white"
                                                              style={{
                                                                borderLeftWidth: '3px',
                                                                borderLeftColor:
                                                                  point.status === 'success'
                                                                    ? UI_COLORS.success
                                                                    : point.status === 'failed'
                                                                      ? UI_COLORS.danger
                                                                      : UI_COLORS.warning,
                                                              }}
                                                            >
                                                              <div>
                                                                <span
                                                                  className={`badge ${getStatusBadgeClass(point.status)} me-2`}
                                                                >
                                                                  {point.status}
                                                                </span>
                                                                <small className="text-muted">
                                                                  {formatTimestamp(point.timestamp)}
                                                                </small>
                                                                {point.variant_alias && (
                                                                  <span className="badge text-bg-secondary ms-2">
                                                                    <i className="fas fa-code-branch me-1"></i>
                                                                    ${point.variant_alias}
                                                                  </span>
                                                                )}
                                                              </div>
                                                              {point.latency_ms !== null &&
                                                                point.latency_ms !== undefined && (
                                                                  <span className="badge text-bg-info">
                                                                    {point.latency_ms}ms
                                                                  </span>
                                                                )}
                                                            </div>
                                                          ))}
                                                      </div>
                                                    </div>
                                                  )}
                                                </div>
                                              );
                                            })}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {isChannelExpanded && (
                      <>
                        {/* Rule Triggers Section */}
                        {channelData.rule_triggers.length > 0 && (
                          <div className="tree-node border-left border-warning mt-3">
                            <div className="tree-item p-2 bg-white border rounded">
                              <div className="mb-2">
                                <div className="d-flex justify-content-between align-items-center">
                                  <div>
                                    <i className="fas fa-shield-alt me-2 text-warning"></i>
                                    <span className="font-weight-bold">
                                      Rule Validations (Authorization Layer)
                                    </span>
                                  </div>
                                  <div>
                                    <span className="badge text-bg-success me-1">
                                      {ruleStats.accepted} accepted
                                    </span>
                                    <span className="badge text-bg-danger">
                                      {ruleStats.denied} denied
                                    </span>
                                  </div>
                                </div>
                                <small className="text-muted d-block mt-1">
                                  <i className="fas fa-info-circle me-1"></i>
                                  Security checks evaluating agent identity & claims before proxy
                                  attempt
                                </small>
                              </div>
                              <div className="progress mb-2" style={{ height: '5px' }}>
                                <div
                                  className="progress-bar bg-success"
                                  role="progressbar"
                                  style={{ width: `${ruleStats.acceptRate}%` }}
                                />
                              </div>
                              <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                                {channelData.rule_triggers
                                  .slice(-15)
                                  .reverse()
                                  .map((point, idx) => (
                                    <div
                                      key={idx}
                                      className="d-flex justify-content-between align-items-center mb-1 p-1"
                                    >
                                      <span
                                        className={`badge ${point.accepted ? 'text-bg-success' : 'text-bg-danger'}`}
                                      >
                                        {point.accepted ? 'ACCEPT' : 'DENY'}
                                      </span>
                                      <small className="text-muted">
                                        {formatTimestamp(point.timestamp)}
                                      </small>
                                    </div>
                                  ))}
                              </div>
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Grafana Dashboard Info */}
      <div className="card shadow mb-4 border-left-primary">
        <div className="card-body">
          <div className="d-flex align-items-start">
            <div className="me-3 text-primary">
              <i className="fas fa-chart-line fa-3x"></i>
            </div>
            <div className="flex-grow-1">
              <h5 className="font-weight-bold text-primary mb-3">
                <i className="fas fa-external-link-alt me-2"></i>
                Advanced Metrics with Grafana & Prometheus
              </h5>
              <p className="text-gray-800 mb-3">
                For advanced metrics visualization with real-time dashboards, histograms, and
                alerting capabilities.
              </p>
              <AppButton
                variant="primary"
                size="sm"
                className="me-2 mb-2"
                onClick={() =>
                  window.open(
                    'http://localhost:3000/d/agent-gateway-agent-metrics-dashboard/agent-gateway-agent-metrics-dashboard',
                    '_blank',
                    'noopener,noreferrer'
                  )
                }
                iconStart={<i className="fas fa-chart-area fa-sm me-1" aria-hidden="true" />}
              >
                Open Grafana Dashboard
              </AppButton>
              <AppButton
                variant="outline-primary"
                size="sm"
                className="mb-2"
                data-bs-toggle="collapse"
                data-bs-target="#grafanaSetupInstructions"
                iconStart={<i className="fas fa-question-circle fa-sm me-1" aria-hidden="true" />}
              >
                Setup Instructions
              </AppButton>

              <div className="collapse mt-3" id="grafanaSetupInstructions">
                <div className="card bg-light border-0">
                  <div className="card-body">
                    <h6 className="font-weight-bold text-dark mb-3">
                      <i className="fas fa-cogs me-2"></i>
                      Running Prometheus & Grafana
                    </h6>
                    <p className="mb-3 text-gray-700">
                      The observability stack is located in the{' '}
                      <code className="text-dark">observability/prometheus-grafana-docker</code>{' '}
                      folder.
                    </p>

                    <div className="mb-3">
                      <strong className="text-dark">Step 1:</strong>{' '}
                      <span className="text-gray-700">Navigate to the observability directory</span>
                      <pre
                        className="bg-dark text-white p-3 rounded mt-2 mb-0"
                        style={{ fontSize: '0.9rem' }}
                      >
                        <code>cd observability/prometheus-grafana-docker</code>
                      </pre>
                    </div>

                    <div className="mb-3">
                      <strong className="text-dark">Step 2:</strong>{' '}
                      <span className="text-gray-700">Start the containers</span>
                      <pre
                        className="bg-dark text-white p-3 rounded mt-2 mb-0"
                        style={{ fontSize: '0.9rem' }}
                      >
                        <code>docker-compose up -d</code>
                      </pre>
                    </div>

                    <div className="mb-3">
                      <strong className="text-dark">Step 3:</strong>{' '}
                      <span className="text-gray-700">Access the services</span>
                      <ul className="mb-0 mt-2 text-gray-800">
                        <li className="mb-1">
                          <strong>Grafana:</strong>{' '}
                          <a
                            href="http://localhost:3000"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary"
                          >
                            http://localhost:3000
                          </a>{' '}
                          (admin/admin)
                        </li>
                        <li className="mb-1">
                          <strong>Prometheus:</strong>{' '}
                          <a
                            href="http://localhost:9090"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary"
                          >
                            http://localhost:9090
                          </a>
                        </li>
                        <li>
                          <strong>Metrics Endpoint:</strong>{' '}
                          <code className="text-dark">
                            https://localhost:8443/api/v1/metrics/prometheus
                          </code>
                        </li>
                      </ul>
                    </div>

                    <div className="alert alert-warning border-warning mb-0">
                      <small className="text-dark">
                        <i className="fas fa-exclamation-triangle me-2 text-warning"></i>
                        <strong>Note:</strong> Ensure the proxy server is running and Docker network{' '}
                        <code>agent-gateway</code> exists before starting.
                      </small>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CloudWatch Metrics Info */}
      <div className="card shadow mb-4 border-left-warning">
        <div className="card-body">
          <div className="d-flex align-items-start">
            <div className="me-3 text-warning">
              <i className="fab fa-aws fa-3x"></i>
            </div>
            <div className="flex-grow-1">
              <h5 className="font-weight-bold text-warning mb-3">
                <i className="fas fa-cloud me-2"></i>
                AWS CloudWatch Integration
              </h5>
              <p className="text-gray-800 mb-3">
                Send metrics to AWS CloudWatch for cloud-native monitoring, alerting, and
                dashboards.
              </p>
              <AppButton
                variant="warning"
                size="sm"
                className="text-white"
                data-bs-toggle="collapse"
                data-bs-target="#cloudwatchSetupInstructions"
                iconStart={<i className="fas fa-cog fa-sm me-1" aria-hidden="true" />}
              >
                Configuration Instructions
              </AppButton>

              <div className="collapse mt-3" id="cloudwatchSetupInstructions">
                <div className="card bg-light border-0">
                  <div className="card-body">
                    <h6 className="font-weight-bold text-dark mb-3">
                      <i className="fas fa-cogs me-2"></i>
                      Enabling CloudWatch Metrics
                    </h6>

                    <div className="mb-3">
                      <strong>Step 1:</strong> Configure AWS credentials
                      <p className="mt-1 mb-2 text-muted">
                        Set up AWS credentials using one of these methods:
                      </p>
                      <ul className="mb-2">
                        <li>
                          Environment variables: <code>AWS_ACCESS_KEY_ID</code>,{' '}
                          <code>AWS_SECRET_ACCESS_KEY</code>
                        </li>
                        <li>
                          AWS credentials file: <code>~/.aws/credentials</code>
                        </li>
                        <li>IAM role (when running on EC2, ECS, Lambda, etc.)</li>
                      </ul>
                    </div>

                    <div className="mb-3">
                      <strong>Step 2:</strong> Enable CloudWatch in config
                      <p className="mt-1 mb-2 text-muted">
                        Edit <code>config/config.toml</code> and add/update:
                      </p>
                      <pre className="bg-dark text-white p-2 rounded mt-1 mb-2">
                        <code>
                          [cloudwatch_metrics] enabled = true namespace = "A2AProxy" # region =
                          "us-east-1" # Optional, uses AWS config default if not specified
                        </code>
                      </pre>
                    </div>

                    <div className="mb-3">
                      <strong>Step 3:</strong> Restart the proxy
                      <p className="mt-1 mb-2 text-muted">
                        Restart the proxy server to apply the new configuration.
                      </p>
                    </div>

                    <div className="mb-3">
                      <strong>Step 4:</strong> View metrics in CloudWatch
                      <p className="mt-1 mb-2 text-muted">
                        Access the AWS CloudWatch console and navigate to your configured namespace
                        (default: <code>A2AProxy</code>).
                      </p>
                      <p className="mb-0 text-muted">
                        <strong>Available metrics:</strong>
                      </p>
                      <ul className="mb-0 mt-1">
                        <li>
                          <code>RequestCount</code> - Total number of requests
                        </li>
                        <li>
                          <code>SuccessCount</code> / <code>FailureCount</code> - Request outcomes
                        </li>
                        <li>
                          <code>SuccessRate</code> - Percentage of successful requests
                        </li>
                        <li>
                          <code>AverageLatency</code> - Request latency in milliseconds
                        </li>
                        <li>
                          <code>UniqueIdentities</code> - Number of unique agent identities
                        </li>
                        <li>
                          <code>RuleAcceptCount</code> / <code>RuleRejectCount</code> - Rule
                          validation results
                        </li>
                      </ul>
                    </div>

                    <div className="alert alert-info mb-0">
                      <small>
                        <i className="fas fa-info-circle me-1"></i>
                        <strong>Tip:</strong> Metrics are published every 5 seconds. CloudWatch
                        charges apply based on the number of custom metrics and API calls.
                      </small>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MetricsPage;
