import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { DefaultSigningPicker, type ConfiguredDefault } from './DefaultSigningPicker';

interface DefaultResolution {
  backend: string;
  /** Operator-facing explanation, computed server-side. */
  reason: string;
  explicit: boolean;
  fallback_from?: string;
}

interface VtaStatus {
  enabled: boolean;
  tier: string;
  custody_claim: boolean;
  default_resolution?: DefaultResolution;
}

const configuredDefault = (backend?: string): ConfiguredDefault =>
  backend === 'local' || !backend ? 'local' : 'vta';

/**
 * Key management, collapsed out of the default path (VTA-26).
 *
 * A gateway is not asked anything about keys or agents: it keeps signing with
 * its local key by default and reports that here. Everything configurable lives behind
 * this disclosure so the easy path stays easy, and so an operator who *does*
 * care can see which backend is active, why, and how to change it — without
 * reading config or code.
 */
export const KeyManagementSettingsSection: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [expanded, setExpanded] = useState(false);
  const [status, setStatus] = useState<VtaStatus | null>(null);
  const [chosen, setChosen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canViewConnections = hasPermission('vta_connections.view');
  const canEditSettings = hasPermission('settings.edit');

  const load = useCallback(async () => {
    try {
      const response = await apiClient.fetch('/api/v1/vta/status');
      if (!response.ok) throw new Error(response.statusText);
      setStatus(await response.json());
      setError(null);
      // The status reports what the configuration resolves to. A default chosen
      // here is stored apart from it and wins, so it is read too.
      try {
        const [settingsResponse, connectionsResponse] = await Promise.all([
          apiClient.fetch('/api/v1/settings'),
          apiClient.fetch('/api/v1/vta/connections'),
        ]);
        const settings = settingsResponse.ok ? await settingsResponse.json() : null;
        const connections = connectionsResponse.ok ? await connectionsResponse.json() : [];
        const id = settings?.default_signing?.connection_id ?? null;
        const named = id ? connections.find((c: { id: string }) => c.id === id) : null;
        setChosen(id ? (named?.name ?? id) : null);
      } catch {
        setChosen(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read the signing status.');
    }
  }, []);

  useEffect(() => {
    // Only fetch once opened: the default path must not pay for a section
    // nobody looked at.
    if (expanded && !status && !error) void load();
  }, [expanded, status, error, load]);

  const toggle = () => setExpanded(open => !open);

  return (
    <div className="card shadow mb-4" data-testid="key-management-settings">
      <div
        className="card-header py-3 cursor-pointer"
        onClick={toggle}
        onKeyDown={event => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggle();
          }
        }}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-controls="key-management-settings-content"
        data-testid="key-management-settings-toggle"
      >
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas fa-chevron-${expanded ? 'down' : 'right'} me-2`} aria-hidden="true" />
          <i className="fas fa-key me-2" aria-hidden="true" />
          Key management
        </h6>
      </div>
      {expanded && (
        <div className="card-body" id="key-management-settings-content">
          {error && (
            <div className="alert alert-danger py-2">
              <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
              {error}
            </div>
          )}
          {status && (
            <>
              <dl className="row small">
                <dt className="col-sm-4">Signing with</dt>
                <dd className="col-sm-8" data-testid="key-management-settings-signing-with">
                  <code>
                    {chosen ??
                      status.default_resolution?.backend ??
                      (status.enabled ? 'vta' : 'local')}
                  </code>
                  {!chosen && status.default_resolution?.explicit === false && (
                    <span className="badge text-bg-secondary ms-2">default</span>
                  )}
                </dd>
                <dt className="col-sm-4">Why</dt>
                <dd className="col-sm-8 text-muted">
                  {chosen
                    ? 'Chosen below as the appliance default. A surface with its own signing key is not affected.'
                    : (status.default_resolution?.reason ?? 'No signing backend is configured.')}
                </dd>
                <dt className="col-sm-4">Deployment</dt>
                <dd className="col-sm-8">
                  {status.tier}
                  {!status.custody_claim && (
                    <span className="text-muted"> — not a key custody tier</span>
                  )}
                </dd>
              </dl>

              {status.default_resolution?.fallback_from && (
                <div className="alert alert-warning py-2" role="status">
                  <i className="fas fa-triangle-exclamation me-2" aria-hidden="true" />
                  The <code>{status.default_resolution.fallback_from}</code> agent was not
                  available, so this gateway fell back to its own local key. Nothing was migrated.
                </div>
              )}

              <p className="small text-muted">
                Changing the backend never migrates or deletes an existing key. Surfaces move one at
                a time, and both keys stay published so nothing already signed stops verifying.
              </p>

              {canEditSettings && canViewConnections && (
                <DefaultSigningPicker
                  configuredDefault={configuredDefault(status.default_resolution?.backend)}
                  onChanged={() => {
                    // The strip above reports what is actually in force, so it is
                    // re-read rather than assumed from the choice. The picker stays
                    // mounted, or its confirmation would vanish with it.
                    void load();
                  }}
                />
              )}

              {canViewConnections && (
                <AppButton
                  variant="outline-primary"
                  size="sm"
                  onClick={() => navigate('/trust-agent')}
                  iconStart={<i className="fas fa-link me-1" aria-hidden="true" />}
                >
                  Connect my own VTA
                </AppButton>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
