import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { SurfaceSigningSection } from '../../components/surface-builder/elements/surface/SurfaceSigningSection';
import {
  isSigningEmpty,
  type SurfaceSigning,
} from '../../components/surface-builder/elements/types';
import { ROUTES } from '../../routes';

/**
 * Settings → Security → Audit signing: the gateway-wide default signing key source, which every
 * surface and issuer that sets none of its own follows. Stored as `default_signing` in the
 * settings; an empty block hands signing back to what the configuration resolves to.
 */
export const AuditSigningSection: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('settings.edit');
  const canConnect = hasPermission('vta_connections.edit');

  const [signing, setSigning] = useState<SurfaceSigning | undefined>(undefined);
  const [stored, setStored] = useState<SurfaceSigning | undefined>(undefined);
  const [loaded, setLoaded] = useState(false);
  const [remotePending, setRemotePending] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const response = await apiClient.fetch('/api/v1/settings');
      if (!response.ok) throw new Error(response.statusText);
      const settings = await response.json();
      const current = isSigningEmpty(settings?.default_signing)
        ? undefined
        : (settings.default_signing as SurfaceSigning);
      setSigning(current);
      setStored(current);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read the audit signing settings.');
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const choose = (value: SurfaceSigning | undefined) => {
    setSigning(value);
    setSaved(false);
  };

  const changed = JSON.stringify(signing ?? null) !== JSON.stringify(stored ?? null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/settings', {
        // The settings write route is POST, not PUT.
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ default_signing: isSigningEmpty(signing) ? {} : signing }),
      });
      if (!response.ok) throw new Error((await response.text()) || response.statusText);
      setStored(signing);
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the audit signing settings.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card shadow mb-3" data-testid="audit-signing-settings">
      <div className="card-header py-3 d-flex align-items-center gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-key me-2" aria-hidden="true" />
          Audit signing
        </h6>
        <span className="badge text-bg-secondary" data-testid="audit-signing-scope">
          Gateway-wide default
        </span>
      </div>
      <div className="card-body">
        {error && (
          <div className="alert alert-danger py-2" role="alert" data-testid="audit-signing-error">
            {error}
          </div>
        )}
        {loaded && (
          <>
            <SurfaceSigningSection
              subject="gateway"
              signing={signing}
              setSigning={choose}
              disabled={!canEdit || saving}
              onRemotePendingChange={setRemotePending}
              actions={
                canConnect ? (
                  <AppButton
                    variant="outline-primary"
                    size="sm"
                    className="text-nowrap"
                    data-testid="audit-signing-connect-button"
                    onClick={() => navigate(ROUTES.TRUST_AGENT_CONNECT)}
                    iconStart={<i className="fas fa-link me-1" aria-hidden="true" />}
                  >
                    Connect my own VTA
                  </AppButton>
                ) : null
              }
            />
            {canEdit && (
              <div className="d-flex align-items-center gap-2">
                <AppButton
                  variant="primary"
                  size="sm"
                  data-testid="audit-signing-save-button"
                  disabled={!changed || saving || remotePending}
                  onClick={() => void save()}
                >
                  {saving ? 'Saving…' : 'Save'}
                </AppButton>
                {saved && (
                  <span className="small text-success" data-testid="audit-signing-saved">
                    <i className="fas fa-check me-1" aria-hidden="true" />
                    Saved
                  </span>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
