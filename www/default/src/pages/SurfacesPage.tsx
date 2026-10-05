import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { AgentSurface, apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';
import { usePermissions } from '../context/PermissionsContext';
import { useApp } from '../context/AppContext';
import { timeAgo } from '../utils/stringUtils';

/**
 * Surfaces list page.
 *
 * Single combined table across all protocols. Each row leads with a
 * Protocol badge column so operators can scan the inventory without
 * the page splitting into per-protocol cards. The clock icon in the
 * card header toggles a "active in last 5 minutes" filter that
 * applies across the whole list. Delete is performed from inside the
 * editor, not from the list.
 */
/** Session key holding the list filters so they survive navigating into a
 * surface and back (both browser back and the in-app back button, which
 * remount this page). */
const FILTERS_KEY = 'surfaces-list-filters';

function readSavedFilters(): { searchTerm: string; recentOnly: boolean } {
  try {
    const raw = sessionStorage.getItem(FILTERS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        searchTerm: typeof parsed.searchTerm === 'string' ? parsed.searchTerm : '',
        recentOnly: parsed.recentOnly === true,
      };
    }
  } catch {
    // Storage unavailable or corrupt — fall back to defaults.
  }
  return { searchTerm: '', recentOnly: false };
}

const SurfacesPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('surfaces.edit');
  const { getCurrentStats } = useApp();

  const [surfaces, setSurfaces] = useState<AgentSurface[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState(() => readSavedFilters().searchTerm);
  const [recentOnly, setRecentOnly] = useState(() => readSavedFilters().recentOnly);

  useEffect(() => {
    try {
      sessionStorage.setItem(FILTERS_KEY, JSON.stringify({ searchTerm, recentOnly }));
    } catch {
      // Storage unavailable — filters just won't persist.
    }
  }, [searchTerm, recentOnly]);

  const loadSurfaces = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.listSurfaces();
      setSurfaces(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load surfaces');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSurfaces();
  }, []);

  // The backend `AgentSurface` payload does not carry `last_activity`;
  // that value lives in the runtime `channel_stats` metrics keyed by
  // `channel_config_id` (= `surface_id`). Merge it in here so the
  // "Last used" column and the "recent activity" filter actually work.
  const stats = getCurrentStats();
  const lastActivityBySurface = useMemo(() => {
    const map: Record<string, string | null> = {};
    for (const cs of stats?.metrics?.channel_stats ?? []) {
      if (cs.last_activity) map[cs.channel_config_id] = cs.last_activity;
    }
    return map;
  }, [stats]);

  const enrichedSurfaces = useMemo(
    () =>
      surfaces.map(s => ({
        ...s,
        last_activity: s.last_activity ?? lastActivityBySurface[s.surface_id] ?? null,
      })),
    [surfaces, lastActivityBySurface]
  );

  const searched = useMemo(() => {
    if (!searchTerm.trim()) return enrichedSurfaces;
    const term = searchTerm.toLowerCase();
    // Mirrors the channels page intent: match ANY string-valued field on the
    // surface — top-level (name/description/surface_id/tags), access point
    // (listen_address/route/protocol), target (endpoint/auth ids), and every
    // transit point (name/alias/target_endpoint/protocol/listen_path/...).
    // The canvas blob is excluded because it stores layout metadata, not
    // anything an operator would search for.
    return enrichedSurfaces.filter(s => {
      const { canvas: _canvas, ...searchable } = s;
      try {
        return JSON.stringify(searchable).toLowerCase().includes(term);
      } catch {
        return false;
      }
    });
  }, [enrichedSurfaces, searchTerm]);

  const visible = useMemo(() => {
    if (!recentOnly) return searched;
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return searched.filter(s => !!s.last_activity && new Date(s.last_activity) >= fiveMinutesAgo);
  }, [searched, recentOnly]);

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
        }}
      >
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Surfaces..."
            wrapperStyle={{ marginRight: '0.5rem' }}
          />
          {searchTerm.trim() && (
            <div className="d-flex align-items-center ms-2" style={{ gap: '0.35rem' }}>
              {SURFACE_PROTOCOLS.map(p => {
                const count = searched.filter(s => s.access_point.protocol === p.key).length;
                if (count === 0) return null;
                return (
                  <Badge
                    key={p.key}
                    value={count}
                    prefix={p.label}
                    tone={
                      p.badgeClass === 'text-bg-primary'
                        ? 'primary'
                        : p.badgeClass === 'text-bg-warning'
                          ? 'warning'
                          : 'info'
                    }
                    size="sm"
                    ariaLabel={`${count} ${p.label} surfaces matching search`}
                  />
                );
              })}
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-circle me-2" />
          {error}
          <AppButton variant="outline-danger" size="sm" className="ms-3" onClick={loadSurfaces}>
            Retry
          </AppButton>
        </div>
      )}

      <SurfaceList
        allSurfaces={surfaces}
        visibleSurfaces={visible}
        searchTerm={searchTerm}
        recentOnly={recentOnly}
        onToggleRecent={() => setRecentOnly(prev => !prev)}
        onOpen={s => navigate(`/surfaces/${encodeURIComponent(s.surface_id)}`)}
        canEdit={canEdit}
        onAddSurface={() => navigate('/surfaces/new')}
      />
    </div>
  );
};

interface ProtocolMeta {
  key: 'a2a' | 'ap2' | 'mcp';
  label: string;
  badgeClass: string;
}

const SURFACE_PROTOCOLS: ProtocolMeta[] = [
  { key: 'a2a', label: 'A2A', badgeClass: 'text-bg-primary' },
  { key: 'ap2', label: 'AP2', badgeClass: 'text-bg-warning' },
  { key: 'mcp', label: 'MCP', badgeClass: 'text-bg-info' },
];

function protocolMetaFor(protocol: string): ProtocolMeta {
  return (
    SURFACE_PROTOCOLS.find(p => p.key === protocol) ?? {
      key: protocol as ProtocolMeta['key'],
      label: protocol.toUpperCase(),
      badgeClass: 'text-bg-secondary',
    }
  );
}

interface SurfaceListProps {
  allSurfaces: AgentSurface[];
  visibleSurfaces: AgentSurface[];
  searchTerm: string;
  recentOnly: boolean;
  onToggleRecent: () => void;
  onOpen: (s: AgentSurface) => void;
  canEdit: boolean;
  onAddSurface: () => void;
}

const SurfaceList: React.FC<SurfaceListProps> = ({
  allSurfaces,
  visibleSurfaces,
  searchTerm,
  recentOnly,
  onToggleRecent,
  onOpen,
  canEdit,
  onAddSurface,
}) => {
  const { guard, balloonNode } = useLimitGuard();
  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary d-flex justify-content-between align-items-center">
          <span>
            <i className="fas fa-layer-group me-2" />
            Agent Surfaces
            <Badge
              value={visibleSurfaces.length}
              suffix={searchTerm || recentOnly ? ` of ${allSurfaces.length}` : undefined}
              className="ms-2"
              ariaLabel={`${visibleSurfaces.length}${searchTerm || recentOnly ? ` of ${allSurfaces.length}` : ''} surfaces`}
            />
          </span>
          <span className="d-flex align-items-center" style={{ gap: '1.75rem' }}>
            <i
              className={`fas fa-clock ${recentOnly ? 'text-primary' : 'text-muted'}`}
              style={{ cursor: 'pointer', fontSize: '1.2rem' }}
              onClick={onToggleRecent}
              title={recentOnly ? 'Show all surfaces' : 'Show only surfaces active last 5 minutes'}
            ></i>
            {canEdit && (
              <>
                <AppButton
                  variant="primary"
                  size="md"
                  className="shadow-sm"
                  onClick={e => guard('surfaces.agent', onAddSurface, e)}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Surface
                </AppButton>
                {balloonNode}
              </>
            )}
          </span>
        </h6>
      </div>
      <div className="card-body">
        {allSurfaces.length === 0 ? (
          <EmptyState
            icon="fa-layer-group"
            title="Create your first Agent Surface"
            body="Agent Surfaces are the core routing unit of the gateway. Create one to define how requests are authenticated, policy-checked, and forwarded to your agent."
            docsHref={DOCS_URL.createFirstSurface}
          />
        ) : visibleSurfaces.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className={`fas ${recentOnly ? 'fa-clock' : 'fa-search'} fa-3x mb-3`} />
            <p>
              {recentOnly
                ? 'No surfaces were active in the last 5 minutes.'
                : 'No surfaces match your search.'}
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '6%' }}>Protocol</th>
                  <th style={{ width: '24%' }}>Surface</th>
                  <th style={{ width: '20%' }}>Access Point</th>
                  <th style={{ width: '25%' }}>Managed Agent</th>
                  <th style={{ width: '10%' }}>Transit Points</th>
                  <th style={{ width: '15%' }}>Last used</th>
                </tr>
              </thead>
              <tbody>
                {visibleSurfaces.map(surface => {
                  const meta = protocolMetaFor(surface.access_point.protocol);
                  const isInactive = surface.status !== 'active';
                  return (
                    <tr
                      key={surface.surface_id}
                      style={{ cursor: 'pointer', opacity: isInactive ? 0.55 : undefined }}
                      onClick={() => onOpen(surface)}
                    >
                      <td>
                        <span className={`badge ${meta.badgeClass}`}>{meta.label}</span>
                      </td>
                      <td>
                        <div>
                          <strong>{surface.name}</strong>
                          {isInactive && (
                            <span
                              className="badge text-bg-warning ms-2"
                              title={`Surface status: ${surface.status} — none of its routes are registered`}
                            >
                              <i className="fas fa-ban me-1" />
                              {surface.status === 'disabled' ? 'Disabled' : surface.status}
                            </span>
                          )}
                        </div>
                        {surface.description && (
                          <div style={{ fontSize: '0.8rem' }}>
                            <i>{surface.description}</i>
                          </div>
                        )}
                        {surface.tags && surface.tags.length > 0 && (
                          <div className="mt-1">
                            {surface.tags.map(tag => {
                              const isOnboarding = tag === 'system:onboarding';
                              return (
                                <span
                                  key={tag}
                                  className={`badge me-1 ${isOnboarding ? 'text-bg-warning' : 'text-bg-secondary'}`}
                                  style={{ fontSize: '0.65rem' }}
                                  title={
                                    isOnboarding
                                      ? 'Onboarding capture surface — proxy returns a placeholder response'
                                      : undefined
                                  }
                                >
                                  {isOnboarding && <i className="fas fa-user-plus me-1" />}
                                  {tag}
                                </span>
                              );
                            })}
                          </div>
                        )}
                      </td>
                      <td>
                        <code className="small">{surface.access_point.route}</code>
                      </td>
                      <td>
                        <code className="small">
                          {surface.target.endpoint.length > 40
                            ? surface.target.endpoint.substring(0, 40) + '…'
                            : surface.target.endpoint}
                        </code>
                      </td>
                      <td>
                        {surface.transit?.points?.length ? (
                          <span className="badge text-bg-primary">
                            {surface.transit.points.length}
                          </span>
                        ) : (
                          <span className="badge badge-none">None</span>
                        )}
                      </td>
                      <td>
                        <div style={{ fontSize: '0.8rem' }}>
                          {surface.last_activity ? (
                            timeAgo(surface.last_activity)
                          ) : (
                            <span className="text-muted"></span>
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
  );
};

export default SurfacesPage;
