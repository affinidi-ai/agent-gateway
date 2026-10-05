import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { apiClient } from '../api';
import { Badge } from '../components/shared/Badge';
import { useApp } from '../context/AppContext';
import { usePermissions } from '../context/PermissionsContext';
import { AppButton } from '../components/shared/AppButton';
import { WS_DASHBOARD, WS_NONE } from '../utils/wsSubscriptions';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { EmptyState } from '../components/shared/EmptyState';
import { DOCS_URL } from '../config/docs';
import A2aProxiesSection from './ProxiesPage/A2aProxiesSection';
import type { A2aProxy } from './A2aProxyPage/types';
import { ExposureBadge, ManagedByBadge } from '../components/mcp-proxy/exposure';

interface McpProxy {
  id: string;
  name: string;
  description: string;
  channel_prefix: string;
  base_url: string;
  status: string;
  /** Absent on a gateway that predates it, which serves every proxy directly. */
  direct_access?: boolean;
  managed_by?: string | null;
  created_at: string;
}

const ProxiesPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { actions } = useApp();
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canViewMcpProxies = hasPermission('mcp_proxies.view');
  const canViewA2aProxies = hasPermission('a2a_proxies.view');
  const [mcpProxies, setMcpProxies] = useState<McpProxy[]>([]);
  const [a2aProxies, setA2aProxies] = useState<A2aProxy[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (!permissionsLoading) {
      loadProxies();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [permissionsLoading, canViewMcpProxies, canViewA2aProxies]);

  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadProxies = async () => {
    setLoading(true);
    const loads: Promise<void>[] = [];
    if (canViewMcpProxies) {
      loads.push(loadMcpProxies());
    } else {
      setMcpProxies([]);
    }
    if (canViewA2aProxies) {
      loads.push(loadA2aProxies());
    } else {
      setA2aProxies([]);
    }
    await Promise.all(loads);
    setLoading(false);
  };

  const loadMcpProxies = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/mcp-proxies');
      if (response.ok) {
        const data = await response.json();
        setMcpProxies(data);
      }
    } catch (error) {
      console.error('Failed to load MCP proxies:', error);
    }
  };

  const loadA2aProxies = async () => {
    try {
      const response = await apiClient.get<A2aProxy[]>('/a2a-proxies');
      setA2aProxies(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to load A2A proxies:', error);
      setA2aProxies([]);
    }
  };

  const handleDeleteMcpProxy = async (proxyId: string) => {
    try {
      const response = await apiClient.fetch(`/api/v1/mcp-proxies/${proxyId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        loadProxies();
      } else {
        const error = await response.json();
        alert(`Failed to delete MCP Proxy: ${error.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Failed to delete MCP proxy:', error);
      alert('Failed to delete MCP Proxy');
    }
  };

  const handleDeleteA2aProxy = async (proxyId: string) => {
    try {
      await apiClient.delete(`/a2a-proxies/${proxyId}`);
      loadProxies();
    } catch (error) {
      console.error('Failed to delete A2A proxy:', error);
      alert('Failed to delete A2A Proxy');
    }
  };

  const filteredMcpProxies = canViewMcpProxies
    ? mcpProxies.filter(
        proxy =>
          searchTerm === '' ||
          proxy.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          proxy.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
          proxy.channel_prefix.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : [];

  const renderMcpProxiesList = () => (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-plug"></i> MCP Proxies
          <Badge
            value={filteredMcpProxies.length}
            suffix={searchTerm ? ` of ${mcpProxies.length}` : undefined}
            className="ms-2"
            ariaLabel={`${filteredMcpProxies.length}${searchTerm ? ` of ${mcpProxies.length}` : ''} MCP proxies`}
          />
        </h6>
        {hasPermission('mcp_proxies.edit') && (
          <>
            <AppButton
              variant="primary"
              size="md"
              className="shadow-sm"
              onClick={e => guard('proxies.mcp', () => navigate('/proxies/mcp-proxies/wizard'), e)}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add MCP Proxy
            </AppButton>
            {balloonNode}
          </>
        )}
      </div>
      <div className="card-body">
        {mcpProxies.length === 0 ? (
          <EmptyState
            icon="fa-plug"
            title="No MCP Proxies yet"
            body="MCP Proxies turn a REST API into tools that AI agents can call safely. The gateway adds auth, policy, and trust checks in front of your API automatically. Create one to protect an upstream API your agents need to use."
            docsHref={DOCS_URL.mcpProxy}
          />
        ) : filteredMcpProxies.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No MCP Proxies match your search.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '20%' }}>Name</th>
                  <th style={{ width: '20%' }}>Description</th>
                  <th style={{ width: '12%' }}>Surface Prefix</th>
                  <th style={{ width: '10%' }}>Reachable</th>
                  <th style={{ width: '8%' }}>Status</th>
                  <th style={{ width: '12%' }}>Created</th>
                  <th style={{ width: '18%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredMcpProxies.map(proxy => (
                  <tr
                    key={proxy.id}
                    onClick={() => navigate(`/proxies/mcp-proxies/${proxy.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <strong>{proxy.name}</strong>
                      {proxy.managed_by ? <ManagedByBadge managedBy={proxy.managed_by} /> : null}
                    </td>
                    <td>{proxy.description}</td>
                    <td>
                      <code>{proxy.channel_prefix}</code>
                    </td>
                    <td>
                      <ExposureBadge directAccess={proxy.direct_access ?? true} />
                    </td>
                    <td>
                      <span
                        className={`badge badge-${proxy.status === 'active' ? 'success' : 'secondary'}`}
                      >
                        {proxy.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <small>{formatDateTime(proxy.created_at, true)}</small>
                    </td>
                    <td className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                      <AppButton
                        variant="primary"
                        size="sm"
                        className="shadow-sm"
                        onClick={e => {
                          e.stopPropagation();
                          navigate(`/proxies/mcp-proxies/${proxy.id}`);
                        }}
                        title="Edit"
                        aria-label={`Edit MCP Proxy ${proxy.name}`}
                        iconStart={<i className="fas fa-edit" aria-hidden="true" />}
                      />
                      <DeleteButton
                        onDelete={() => handleDeleteMcpProxy(proxy.id)}
                        className="btn-sm"
                        title={
                          proxy.managed_by
                            ? `Delete MCP Proxy - managed by ${proxy.managed_by}; deleting it here breaks what ${proxy.managed_by} set it up for`
                            : 'Delete MCP Proxy (will also remove all associated channels)'
                        }
                        confirmTitle={
                          proxy.managed_by
                            ? `Managed by ${proxy.managed_by}. Click again to delete anyway`
                            : undefined
                        }
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Proxies...."
          />
        </div>
      </div>

      {loading || permissionsLoading ? (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : (
        <>
          {canViewMcpProxies && renderMcpProxiesList()}
          {canViewA2aProxies && (
            <A2aProxiesSection
              proxies={a2aProxies}
              searchTerm={searchTerm}
              canEdit={hasPermission('a2a_proxies.edit')}
              canDelete={hasPermission('a2a_proxies.delete')}
              onDelete={handleDeleteA2aProxy}
            />
          )}
        </>
      )}
    </div>
  );
};

export default ProxiesPage;
