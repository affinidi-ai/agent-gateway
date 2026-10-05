import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { useApp } from '../context/AppContext';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import {
  ConnectionHealthBadge,
  ConnectionRuntimeStatus,
  errorCodeLabel,
  reconnectAtLabel,
} from '../utils/connectionHealth';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { DeleteButton } from '../components/shared/DeleteButton';
import { EmptyState } from '../components/shared/EmptyState';
import FieldHelp from '../components/shared/FieldHelp';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';

const LOADING_STYLE: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  minHeight: '60vh',
};

interface Gateway {
  id: string;
  name: string;
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: 'active' | 'disabled' | 'pending' | 'failed' | 'awaiting-approval';
  created_at: string;
  updated_at: string;
  runtime_status?: ConnectionRuntimeStatus;
  /** Remote gateways: the issuer DID the peer attested; null until established. */
  issuer_did?: string | null;
  trusted_issuer_dids?: string[];
}

interface ConnectionPoint {
  id: string;
  gateway_id: string;
  mediator_id: string;
  name: string;
  description: string;
  oob_url: string;
  use_count: number;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  cp_type?: 'user' | 'system'; // Optional for backward compatibility
  secret?: string; // Optional secret for OOB connection validation
  exposed_channels?: string[]; // List of channel config IDs to expose
  enabled?: boolean; // Whether the connection point is enabled
  did_method?: string;
}

interface Mediator {
  id: string;
  name: string;
  description: string;
  did: string;
  status: string;
  created_at: string;
  updated_at: string;
  did_document?: any;
}

interface GatewaysPageProps {
  /** When provided, the page uses this in place of its internal search
   *  state and hides its top-level filter input. Used when the page is
   *  embedded inside the Connections tabbed page so a single shared
   *  filter above the tabs drives all tab contents.
   */
  externalSearchTerm?: string;
  /** Called whenever the filtered / total counts change. Used by the
   *  Connections wrapper to render a badge on the tab title.
   */
  onCountChange?: (filtered: number, total: number) => void;
  /** When provided (the Connections wrapper passes a div in the tab
   *  banner), the page's action buttons are rendered there via portal
   *  instead of inline above the list.
   */
  actionsContainer?: HTMLElement | null;
}

const GatewaysPage: React.FC<GatewaysPageProps> = ({ externalSearchTerm, onCountChange }) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const { actions, getCurrentStats } = useApp();
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [connectionPoints, setConnectionPoints] = useState<ConnectionPoint[]>([]);
  const [mediators, setMediators] = useState<Mediator[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingPubs, setLoadingPubs] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [hasSelfGateway, setHasSelfGateway] = useState(false);
  const [pingStatus, setPingStatus] = useState<{ [key: string]: 'pinging' | 'success' | 'failed' }>(
    {}
  );
  const [searchTerm, setSearchTerm] = useState('');
  const effectiveSearchTerm = externalSearchTerm ?? searchTerm;

  const fetchGateways = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/gateways');
      setGateways(response.data);
      setHasSelfGateway(response.data.some((g: Gateway) => g.gateway_type === 'self'));
    } catch (err: any) {
      setError(err.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchConnectionPoints = useCallback(async () => {
    try {
      setLoadingPubs(true);
      const response = await apiClient.get('/connection-points');
      setConnectionPoints(response.data);
    } catch (err: any) {
      console.error('Failed to load connection points:', err);
    } finally {
      setLoadingPubs(false);
    }
  }, []);

  const fetchMediators = useCallback(async () => {
    try {
      const response = await apiClient.get('/mediators');
      setMediators(response.data);
    } catch (err: any) {
      console.error('Failed to load mediators:', err);
    }
  }, []);

  useEffect(() => {
    fetchGateways();
    fetchConnectionPoints();
    fetchMediators();
  }, [fetchGateways, fetchConnectionPoints, fetchMediators]);

  // Subscribe to everything except logs to reduce WS payload size
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const mediatorMap = useMemo(() => new Map(mediators.map(m => [m.id, m])), [mediators]);

  const getMediatorById = useCallback(
    (mediatorId: string): Mediator | undefined => mediatorMap.get(mediatorId),
    [mediatorMap]
  );

  // Filter gateways based on search term
  const stats = getCurrentStats();
  const filteredGateways = useMemo(() => {
    const trimmedSearch = effectiveSearchTerm.trim();
    if (!trimmedSearch) return gateways;

    const searchLower = trimmedSearch.toLowerCase();
    const channels = stats?.channels || [];

    return gateways.filter(gateway => {
      // Search by name, description, ID, DID
      if (
        gateway.name?.toLowerCase().includes(searchLower) ||
        gateway.description?.toLowerCase().includes(searchLower) ||
        gateway.id?.toLowerCase().includes(searchLower) ||
        gateway.did?.toLowerCase().includes(searchLower)
      ) {
        return true;
      }

      // Check if any connection point for this gateway matches
      const hasMatchingConnectionPoint = connectionPoints.some(
        cp =>
          cp.gateway_id === gateway.id &&
          (cp.name?.toLowerCase().includes(searchLower) ||
            cp.description?.toLowerCase().includes(searchLower) ||
            cp.id?.toLowerCase().includes(searchLower) ||
            cp.oob_url?.toLowerCase().includes(searchLower))
      );

      if (hasMatchingConnectionPoint) {
        return true;
      }

      // For remote gateways, also search by connected channels via fabric
      // Check if any channel targets this gateway via fabric://gateway_id/...
      const hasConnectedChannel = channels.some(channel => {
        if (channel.target_endpoint?.startsWith('fabric://')) {
          const fabricPath = channel.target_endpoint.substring(9); // Remove 'fabric://'
          const [targetGatewayId] = fabricPath.split('/');
          return targetGatewayId === gateway.id;
        }
        return false;
      });

      if (hasConnectedChannel) {
        // Check if gateway ID matches search (partial match)
        return gateway.id.toLowerCase().includes(searchLower);
      }

      return false;
    });
  }, [gateways, effectiveSearchTerm, stats?.channels, connectionPoints]);

  // Filter connection points based on search term
  const filteredConnectionPoints = useMemo(() => {
    const trimmedSearch = effectiveSearchTerm.trim();
    if (!trimmedSearch) return connectionPoints;

    const searchLower = trimmedSearch.toLowerCase();
    return connectionPoints.filter(
      cp =>
        cp.name?.toLowerCase().includes(searchLower) ||
        cp.description?.toLowerCase().includes(searchLower) ||
        cp.id?.toLowerCase().includes(searchLower) ||
        cp.oob_url?.toLowerCase().includes(searchLower)
    );
  }, [connectionPoints, effectiveSearchTerm]);

  // Report filtered / total counts up when embedded.
  useEffect(() => {
    if (onCountChange) onCountChange(filteredGateways.length, gateways.length);
  }, [filteredGateways.length, gateways.length, onCountChange]);

  const handleDeleteGateway = useCallback(
    async (id: string) => {
      try {
        await apiClient.delete(`/gateways/${id}`);
        setSuccess('Gateway deleted successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchGateways();
      } catch (err: any) {
        setError(err.message || 'Failed to delete gateway');
      }
    },
    [fetchGateways]
  );

  const handleDeleteConnectionPoint = useCallback(
    async (id: string) => {
      try {
        await apiClient.delete(`/connection-points/${id}`);
        setSuccess('Connection point deleted successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchConnectionPoints();
      } catch (err: any) {
        setError(err.message || 'Failed to delete connection point');
      }
    },
    [fetchConnectionPoints]
  );

  const handleReconnectConnectionPoint = useCallback(
    async (id: string, event: React.MouseEvent) => {
      event.stopPropagation();
      try {
        await apiClient.post(`/connection-points/${id}/reconnect`, {});
        setSuccess('Reconnect requested');
        setTimeout(() => setSuccess(null), 3000);
        fetchConnectionPoints();
      } catch (err: any) {
        setError(err.message || 'Failed to reconnect connection point');
      }
    },
    [fetchConnectionPoints]
  );

  // Tooltip for a FAILED gateway badge, taken from a broken connection point.
  // Tooltip / reason for a FAILED gateway badge, from its derived runtime health.
  const gatewayFailureTooltip = useCallback((gateway: Gateway): string | undefined => {
    const rt = gateway.runtime_status;
    if (!rt || rt.status === 'connected') return undefined;
    const parts = [rt.error_message || errorCodeLabel(rt.error_code), reconnectAtLabel(rt)].filter(
      Boolean
    );
    return parts.length ? parts.join('; ') : undefined;
  }, []);

  const clearPingStatus = useCallback((id: string) => {
    setPingStatus(prev => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }, []);

  const handlePingGateway = useCallback(
    async (id: string, name: string, event: React.MouseEvent) => {
      event.stopPropagation();
      setPingStatus(prev => ({ ...prev, [id]: 'pinging' }));
      try {
        const response = await apiClient.post(`/gateways/${id}/ping`);
        if (response.data.success) {
          setPingStatus(prev => ({ ...prev, [id]: 'success' }));
          setSuccess(`Ping to "${name}" successful (${response.data.round_trip_ms}ms)`);
          setTimeout(() => {
            clearPingStatus(id);
            setSuccess(null);
          }, 3000);
        } else {
          setPingStatus(prev => ({ ...prev, [id]: 'failed' }));
          setError(`Ping to "${name}" failed: ${response.data.message}`);
          setTimeout(() => clearPingStatus(id), 3000);
        }
      } catch (err: any) {
        setPingStatus(prev => ({ ...prev, [id]: 'failed' }));
        setError(err.message || `Failed to ping gateway "${name}"`);
        setTimeout(() => clearPingStatus(id), 3000);
      }
    },
    [clearPingStatus]
  );

  const handleCopyUrl = useCallback((url: string) => {
    navigator.clipboard.writeText(url);
  }, []);

  const handleCopySecret = useCallback((secret: string) => {
    navigator.clipboard.writeText(secret);
  }, []);

  const isEmbedded = externalSearchTerm !== undefined;

  return (
    <div className={isEmbedded ? '' : 'container-fluid'}>
      {!isEmbedded && (
        <div className="mb-4">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Gateways..."
          />
        </div>
      )}
      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}
      {/* All Gateways Section */}
      {loading ? (
        <div style={LOADING_STYLE}>
          <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : gateways.length === 0 ? (
        <div className="card shadow mb-4">
          <div className="card-body">
            <EmptyState
              icon="fa-server"
              title="Add your first gateway"
              body="Add a remote gateway to route traffic across organisational boundaries. You'll need a Connection Point Link (an out-of-band, or OOB, connection URL) shared by that gateway's administrator, along with its connection secret."
              docsHref={DOCS_URL.connections}
            />
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-server"></i> Agent Gateways
                <Badge
                  value={filteredGateways.length}
                  suffix={effectiveSearchTerm ? ` of ${gateways.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${filteredGateways.length}${effectiveSearchTerm ? ` of ${gateways.length}` : ''} gateways`}
                />
              </h6>
              {hasPermission('gateways.edit') && (
                <>
                  <AppButton
                    variant="primary"
                    size="md"
                    onClick={e =>
                      guard('connections.gateways', () => navigate('/gateways/connect'), e)
                    }
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    Add Gateway
                  </AppButton>
                  {balloonNode}
                </>
              )}
            </div>
          </div>
          <div className="card-body">
            {filteredGateways.length === 0 ? (
              <div className="text-center">
                <div className="text-muted">
                  <i className="fas fa-search fa-3x mb-3"></i>
                  <p>No gateways match your search.</p>
                </div>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>
                        Type{' '}
                        <FieldHelp testId="field-help-gateway-type" ariaLabel="About Type">
                          LOCAL is this appliance. Its type can never change, though its name,
                          description, and status can be edited, and it can't be deleted. REMOTE is
                          another Agent Gateway appliance you've connected to.
                        </FieldHelp>
                      </th>
                      <th>Description</th>
                      <th>Created</th>
                      <th>Updated</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGateways.map(gateway => (
                      <tr
                        key={gateway.id}
                        onClick={() => {
                          if (
                            gateway.status !== 'pending' &&
                            gateway.status !== 'awaiting-approval'
                          ) {
                            navigate(`/gateways/${gateway.id}`);
                          }
                        }}
                        style={{
                          cursor:
                            gateway.status === 'pending' || gateway.status === 'awaiting-approval'
                              ? 'default'
                              : 'pointer',
                        }}
                      >
                        <td>{gateway.name}</td>
                        <td>
                          <span
                            className={`badge ${
                              gateway.gateway_type === 'self'
                                ? 'text-bg-info'
                                : gateway.gateway_type === 'remote'
                                  ? 'text-bg-success'
                                  : 'text-bg-warning'
                            }`}
                          >
                            {gateway.gateway_type === 'self'
                              ? ' LOCAL '
                              : gateway.gateway_type === 'remote'
                                ? ' REMOTE '
                                : 'Unknown'}
                          </span>
                        </td>
                        <td>
                          <small>{gateway.description}</small>
                        </td>
                        <td>
                          <small>{formatDateTime(gateway.created_at, true)}</small>
                        </td>
                        <td>
                          <small>{formatDateTime(gateway.updated_at, true)}</small>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              gateway.status === 'active'
                                ? 'text-bg-success'
                                : gateway.status === 'failed'
                                  ? 'text-bg-danger'
                                  : gateway.status === 'awaiting-approval'
                                    ? 'text-bg-warning'
                                    : gateway.status === 'pending'
                                      ? 'text-bg-warning'
                                      : 'text-bg-secondary'
                            }`}
                            title={
                              gateway.status === 'failed'
                                ? gatewayFailureTooltip(gateway)
                                : undefined
                            }
                          >
                            {gateway.status === 'awaiting-approval'
                              ? 'AWAITING APPROVAL'
                              : gateway.status === 'pending'
                                ? 'PENDING'
                                : gateway.status.toUpperCase()}
                          </span>
                          {gateway.status === 'failed' && gateway.runtime_status && (
                            <div className="text-muted" style={{ fontSize: '0.7rem' }}>
                              {gateway.runtime_status.error_message ||
                                errorCodeLabel(gateway.runtime_status.error_code)}
                              {reconnectAtLabel(gateway.runtime_status)
                                ? `; ${reconnectAtLabel(gateway.runtime_status)}`
                                : ''}
                            </div>
                          )}
                          {gateway.gateway_type === 'remote' &&
                            gateway.status === 'active' &&
                            !gateway.issuer_did &&
                            !(gateway.trusted_issuer_dids?.length ?? 0) && (
                              <span
                                className="badge text-bg-secondary ms-2"
                                title="No issuer DID is established or trusted for this connection; fabric requests from it are rejected until one is"
                                data-testid={`gateway-issuer-missing-${gateway.id}`}
                              >
                                ISSUER NOT ESTABLISHED
                              </span>
                            )}
                        </td>
                        <td className="align-middle">
                          <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                            {hasPermission('gateways.edit') && (
                              <>
                                {gateway.status === 'awaiting-approval' && (
                                  <AppButton
                                    variant="warning"
                                    size="sm"
                                    className="me-1"
                                    title="Approve Gateway Connection"
                                    aria-label={`Approve gateway ${gateway.name}`}
                                    onClick={e => {
                                      e.stopPropagation();
                                      navigate(`/gateways/${gateway.id}/approve`);
                                    }}
                                  >
                                    <i className="fas fa-check" aria-hidden="true"></i>
                                  </AppButton>
                                )}
                                {gateway.gateway_type !== 'self' &&
                                  gateway.status !== 'awaiting-approval' &&
                                  gateway.status !== 'pending' && (
                                    <AppButton
                                      style={{ marginLeft: '10px' }}
                                      title="Ping Gateway - Test connectivity"
                                      variant={
                                        pingStatus[gateway.id] === 'pinging'
                                          ? 'secondary'
                                          : pingStatus[gateway.id] === 'success'
                                            ? 'secondary'
                                            : pingStatus[gateway.id] === 'failed'
                                              ? 'danger'
                                              : 'secondary'
                                      }
                                      size="sm"
                                      onClick={e => handlePingGateway(gateway.id, gateway.name, e)}
                                      disabled={pingStatus[gateway.id] === 'pinging'}
                                      aria-label={`Ping gateway ${gateway.name}`}
                                    >
                                      {pingStatus[gateway.id] === 'pinging' ? (
                                        <span
                                          className="spinner-border spinner-border-sm"
                                          role="status"
                                          aria-hidden="true"
                                        ></span>
                                      ) : pingStatus[gateway.id] === 'success' ? (
                                        <i className="fas fa-check" aria-hidden="true"></i>
                                      ) : pingStatus[gateway.id] === 'failed' ? (
                                        <i className="fas fa-times" aria-hidden="true"></i>
                                      ) : (
                                        <i className="fas fa-heartbeat" aria-hidden="true"></i>
                                      )}
                                    </AppButton>
                                  )}
                                {gateway.status !== 'awaiting-approval' &&
                                  gateway.status !== 'pending' && (
                                    <AppButton
                                      variant="outline-primary"
                                      size="sm"
                                      style={{ marginLeft: '10px' }}
                                      title="Edit Gateway"
                                      className="me-1"
                                      aria-label={`Edit gateway ${gateway.name}`}
                                      onClick={() => navigate(`/gateways/${gateway.id}`)}
                                    >
                                      <i className="fas fa-edit" aria-hidden="true"></i>
                                    </AppButton>
                                  )}
                              </>
                            )}
                            {hasPermission('gateways.delete') &&
                              gateway.gateway_type !== 'self' && (
                                <DeleteButton
                                  onDelete={() => handleDeleteGateway(gateway.id)}
                                  className="btn-sm"
                                  title="Delete Gateway"
                                  style={{ marginLeft: '10px' }}
                                />
                              )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
      {/* Connection Points Section */}{' '}
      {!loading && (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-share-alt"></i> Connection Points
                <Badge
                  value={filteredConnectionPoints.length}
                  suffix={effectiveSearchTerm ? ` of ${connectionPoints.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${filteredConnectionPoints.length}${effectiveSearchTerm ? ` of ${connectionPoints.length}` : ''} connection points`}
                />
              </h6>
              {hasSelfGateway && hasPermission('gateways.edit') && (
                <>
                  <AppButton
                    variant="primary"
                    size="md"
                    onClick={e =>
                      guard('connections.connectionpoints', () => navigate('/gateways/publish'), e)
                    }
                  >
                    Create Connection Point
                  </AppButton>
                </>
              )}
            </div>
          </div>
          <div className="card-body">
            {loadingPubs ? (
              <div className="text-center py-3">
                <div className="spinner-border spinner-border-sm" role="status">
                  <span className="visually-hidden"></span>
                </div>
              </div>
            ) : connectionPoints.length === 0 ? (
              <EmptyState
                icon="fa-share-alt"
                title="Create your first connection point"
                body="Connection points let other Agent Gateway appliances reach your surfaces over the fabric (the gateway-to-gateway network this appliance participates in). Create one to expose a surface to a remote gateway."
                docsHref={DOCS_URL.connections}
              />
            ) : filteredConnectionPoints.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className="mb-0">No connection points match your search.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-sm table-hover">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>
                        DID Method{' '}
                        <FieldHelp
                          testId="field-help-connection-point-did-method"
                          ariaLabel="About DID Method"
                        >
                          The DID method this connection point uses for its own identity, which the
                          remote gateway connecting to it will resolve. did:peer needs no hosting;
                          did:webvh and did:web publish a resolvable document at a URL you control.
                        </FieldHelp>
                      </th>
                      <th>Mediator</th>
                      <th>Created</th>
                      <th>Last used</th>
                      <th>Expires</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredConnectionPoints.map(connectionPoint => {
                      const mediator = getMediatorById(connectionPoint.mediator_id);
                      const isExpired = connectionPoint.expires_at
                        ? new Date(connectionPoint.expires_at) < new Date()
                        : false;

                      return (
                        <tr
                          key={connectionPoint.id}
                          onClick={() => navigate(`/connection-points/${connectionPoint.id}`)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td>{connectionPoint.name}</td>
                          <td>
                            <small>{connectionPoint.description}</small>
                          </td>
                          <td>
                            <small>
                              {connectionPoint.did_method === 'peer'
                                ? 'did:peer'
                                : connectionPoint.did_method === 'webvh'
                                  ? 'did:webvh'
                                  : 'did:web'}
                            </small>
                          </td>
                          <td>
                            {mediator ? (
                              <AppButton
                                variant="link"
                                size="sm"
                                onClick={e => {
                                  e.stopPropagation();
                                  navigate('/connections?tab=mediators');
                                }}
                                className="p-0 align-baseline text-primary"
                              >
                                {mediator.name}
                              </AppButton>
                            ) : (
                              <span className="text-muted">Unknown</span>
                            )}
                          </td>
                          <td>
                            <small>{formatDateTime(connectionPoint.created_at, true)}</small>
                          </td>
                          <td>
                            <small>
                              {connectionPoint.last_used_at
                                ? formatDateTime(connectionPoint.last_used_at, true)
                                : '-'}
                            </small>
                          </td>
                          <td>
                            <small>
                              {connectionPoint.expires_at
                                ? formatDateTime(connectionPoint.expires_at, true)
                                : '-'}
                            </small>
                          </td>
                          <td>
                            {connectionPoint.enabled === false ? (
                              <span className="badge text-bg-warning">
                                <i className="fas fa-power-off"></i> DISABLED
                              </span>
                            ) : connectionPoint.runtime_status ? (
                              <ConnectionHealthBadge runtime={connectionPoint.runtime_status} />
                            ) : (
                              <span className={`badge badge-${isExpired ? 'danger' : 'success'}`}>
                                {isExpired ? 'EXPIRED' : 'VALID'}
                              </span>
                            )}
                          </td>
                          <td className="align-middle">
                            <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                              {hasPermission('gateways.edit') && (
                                <AppButton
                                  variant="outline-primary"
                                  size="sm"
                                  onClick={() =>
                                    navigate(`/connection-points/${connectionPoint.id}`)
                                  }
                                  title="Edit Connection Point"
                                  aria-label={`Edit connection point ${connectionPoint.name}`}
                                >
                                  <i className="fas fa-edit" aria-hidden="true"></i>
                                </AppButton>
                              )}
                              {hasPermission('gateways.edit') &&
                                connectionPoint.runtime_status &&
                                connectionPoint.runtime_status.status !== 'connected' && (
                                  <AppButton
                                    variant="outline-secondary"
                                    size="sm"
                                    style={{ marginLeft: '10px' }}
                                    onClick={e =>
                                      handleReconnectConnectionPoint(connectionPoint.id, e)
                                    }
                                    title="Retry connection now"
                                    aria-label={`Retry connection point ${connectionPoint.name}`}
                                  >
                                    <i className="fas fa-sync-alt" aria-hidden="true"></i>
                                  </AppButton>
                                )}
                              <AppButton
                                variant="secondary"
                                size="sm"
                                style={{ marginLeft: '10px' }}
                                onClick={() => handleCopyUrl(connectionPoint.oob_url)}
                                title="Copy Connection Point Link"
                                aria-label={`Copy link for ${connectionPoint.name}`}
                              >
                                <i className="fas fa-link" aria-hidden="true"></i>
                              </AppButton>
                              {connectionPoint.secret && (
                                <AppButton
                                  variant="secondary"
                                  size="sm"
                                  style={{ marginLeft: '10px' }}
                                  onClick={() => handleCopySecret(connectionPoint.secret!)}
                                  title="Copy Connection Point Secret"
                                  aria-label={`Copy secret for ${connectionPoint.name}`}
                                >
                                  <i className="fas fa-key" aria-hidden="true"></i>
                                </AppButton>
                              )}
                              {hasPermission('gateways.delete') && (
                                <DeleteButton
                                  onDelete={() => handleDeleteConnectionPoint(connectionPoint.id)}
                                  className="btn-sm"
                                  title="Delete connection point"
                                  style={{ marginLeft: '10px' }}
                                />
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default GatewaysPage;
