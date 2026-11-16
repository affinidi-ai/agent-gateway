import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { ROUTES } from '../../routes';
import { ControlKeyCard } from './ControlKeyCard';
import { DefaultSigningPicker, type ConfiguredDefault } from './DefaultSigningPicker';
import { VtaTierBanner } from './VtaTierBanner';
import type { VtaDeploymentStatus } from './types';

const configuredDefault = (backend?: string): ConfiguredDefault =>
  backend === 'local' || !backend ? 'local' : 'vta';

/**
 * The Key Management tab of Connections: which backend signs for this gateway, why, and how to
 * change it, and the control key the gateway signs in to its trust agent with.
 *
 * A gateway is not asked anything about keys or agents: it keeps signing with its own key by
 * default and reports that here. An operator who does care can see which backend is in force and
 * why, without reading configuration or code.
 */
export const KeyManagementPanel: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [status, setStatus] = useState<VtaDeploymentStatus | null>(null);
  const [chosen, setChosen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canViewConnections = hasPermission('vta_connections.view');
  const canEditConnections = hasPermission('vta_connections.edit');
  const canEditSettings = hasPermission('settings.edit');
  const canRotateKeys = hasPermission('key_management.edit');

  const load = useCallback(async () => {
    try {
      const response = await apiClient.fetch('/api/v1/vta/status');
      if (!response.ok) throw new Error(response.statusText);
      setStatus(await response.json());
      setError(null);
      // The status reports what the configuration resolves to. A default chosen here is stored
      // apart from it and wins, so it is read too.
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
    void load();
  }, [load]);

  return (
    <div data-testid="key-management-panel">
      {error && (
        <div className="alert alert-danger py-2" data-testid="key-management-error">
          <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
          {error}
        </div>
      )}

      {status && (
        <>
          <VtaTierBanner deployment={status} />

          {status.control_key && (
            <ControlKeyCard
              controlKey={status.control_key}
              canRotate={canRotateKeys}
              onRotated={load}
            />
          )}

          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-key me-2" aria-hidden="true" />
                Signing
              </h6>
            </div>
            <div className="card-body">
              <dl className="row small">
                <dt className="col-sm-4">Signing with</dt>
                <dd className="col-sm-8" data-testid="key-management-signing-with">
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
                    // The strip above reports what is actually in force, so it is re-read rather
                    // than assumed from the choice. The picker stays mounted, or its confirmation
                    // would vanish with it.
                    void load();
                  }}
                />
              )}

              {canEditConnections && (
                <AppButton
                  variant="outline-primary"
                  size="sm"
                  data-testid="key-management-connect-button"
                  onClick={() => navigate(ROUTES.TRUST_AGENT_CONNECT)}
                  iconStart={<i className="fas fa-link me-1" aria-hidden="true" />}
                >
                  Connect my own trust agent
                </AppButton>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
