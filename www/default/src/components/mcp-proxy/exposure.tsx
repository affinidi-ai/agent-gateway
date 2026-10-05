import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';

/** A surface that fronts an MCP proxy, as the dashboard lists it. */
export interface FrontingSurface {
  surface_id: string;
  name: string;
}

interface RawSurface {
  surface_id?: string;
  name?: string;
  target?: { endpoint?: string; mcp_proxy_id?: string | null };
}

/** The surfaces whose target is this proxy (`proxy://<id>` or `mcp_proxy_id`). */
export function surfacesFronting(surfaces: RawSurface[], proxyId: string): FrontingSurface[] {
  return surfaces
    .filter(
      s =>
        s.surface_id &&
        (s.target?.endpoint === `proxy://${proxyId}` || s.target?.mcp_proxy_id === proxyId)
    )
    .map(s => ({ surface_id: s.surface_id as string, name: s.name || (s.surface_id as string) }));
}

/**
 * The surfaces fronting a proxy. `null` while loading, and also when the
 * viewer cannot list surfaces - the list is then unknown rather than empty.
 */
export function useSurfacesFronting(proxyId: string | undefined): FrontingSurface[] | null {
  const { hasPermission, loading } = usePermissions();
  const canView = hasPermission('surfaces.view');
  const [surfaces, setSurfaces] = useState<FrontingSurface[] | null>(null);

  useEffect(() => {
    if (!proxyId || loading || !canView) {
      setSurfaces(null);
      return;
    }
    let live = true;
    apiClient
      .fetch('/api/v1/surfaces')
      .then(r => (r.ok ? r.json() : null))
      .then((data: RawSurface[] | null) => {
        if (live) setSurfaces(Array.isArray(data) ? surfacesFronting(data, proxyId) : null);
      })
      .catch(() => live && setSurfaces(null));
    return () => {
      live = false;
    };
  }, [proxyId, loading, canView]);

  return surfaces;
}

/** "Also serve on its own route" - off means only surfaces reach the proxy. */
export const DirectAccessSwitch: React.FC<{
  id: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}> = ({ id, checked, onChange }) => (
  <div className="mb-3">
    <div className="form-check form-switch mb-1">
      <input
        className="form-check-input"
        type="checkbox"
        role="switch"
        id={id}
        data-testid="mcp-proxy-direct-access"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
      />
      <label className="form-check-label font-weight-bold" htmlFor={id}>
        Also serve on its own route (no sign-in)
      </label>
    </div>
    {checked ? (
      <div className="alert alert-warning mb-0 py-2 small" data-testid="mcp-proxy-direct-warning">
        <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
        Anyone who can reach the route below can call every tool, with no sign-in or policy applied.
        Turn this off to serve the proxy only through surfaces that target it, where caller
        authentication, policies and tool gating apply.
      </div>
    ) : (
      <small className="form-text text-muted d-block">
        Served only through surfaces that target it. The route settings below are not used while
        this is off.
      </small>
    )}
  </div>
);

/** Where a surface-only proxy can be called from, in place of its route. */
export const SurfaceOnlyNotice: React.FC<{ surfaces: FrontingSurface[] | null }> = ({
  surfaces,
}) => (
  <div
    className="alert alert-info mb-3"
    style={{ fontSize: '14px' }}
    data-testid="mcp-proxy-surface-only"
  >
    <i className="fas fa-shield-alt me-2" aria-hidden="true" />
    <strong>Only through surfaces.</strong> This proxy has no route of its own; callers reach it
    through a surface that targets it, where that surface&apos;s authentication and policies apply.
    {surfaces === null ? null : surfaces.length === 0 ? (
      <div className="mt-2">No surface targets this proxy yet, so nothing can call it.</div>
    ) : (
      <div className="mt-2">
        Fronted by{' '}
        {surfaces.map((s, i) => (
          <React.Fragment key={s.surface_id}>
            {i > 0 ? ', ' : null}
            <Link to={`/surfaces/${encodeURIComponent(s.surface_id)}`}>{s.name}</Link>
          </React.Fragment>
        ))}
        .
      </div>
    )}
  </div>
);

/** A proxy another product maintains through the API. */
export const ManagedByBanner: React.FC<{ managedBy: string }> = ({ managedBy }) => (
  <div
    className="alert alert-secondary mb-3"
    style={{ fontSize: '14px' }}
    data-testid="mcp-proxy-managed-by"
  >
    <i className="fas fa-robot me-2" aria-hidden="true" />
    <strong>Managed by {managedBy}.</strong> {managedBy} created this proxy and keeps it up to date,
    so changes made here may be overwritten the next time it does. Deleting it breaks whatever{' '}
    {managedBy} set it up for; remove it from {managedBy} instead.
  </div>
);

export const ManagedByBadge: React.FC<{ managedBy: string }> = ({ managedBy }) => (
  <span className="badge badge-secondary ms-2" title={`Created and maintained by ${managedBy}`}>
    <i className="fas fa-robot me-1" aria-hidden="true" />
    {managedBy}
  </span>
);

/** How the proxy can be reached, for the Proxies list. */
export const ExposureBadge: React.FC<{ directAccess: boolean }> = ({ directAccess }) =>
  directAccess ? (
    <span
      className="badge badge-warning"
      title="Also served on its own route, where no sign-in or policy applies"
    >
      Direct + surfaces
    </span>
  ) : (
    <span className="badge badge-info" title="Served only through surfaces that target it">
      Surfaces only
    </span>
  );
