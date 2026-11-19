import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { WarningDialog } from '../../components/shared/WarningDialog';
import { SurfaceSigningSection } from '../../components/surface-builder/elements/surface/SurfaceSigningSection';
import {
  isSigningEmpty,
  type SurfaceSigning,
} from '../../components/surface-builder/elements/types';
import { ROUTES } from '../../routes';

const EFFECTS = [
  'Tokens, ID-JAGs, credentials, payment evidence and the issuer attestation sent to peers are signed with the new source for every surface and issuer that sets none of its own, so what they issue from now on carries its issuer DID.',
  'Fabric peers and verifiers must trust the new issuer DID before they accept what it signs.',
  'Tokens and credentials already issued keep the key that signed them, and verify only while that key is still published.',
];

/**
 * Settings → Security → Gateway signing: the gateway-wide default signing key source, which every
 * surface and issuer that sets none of its own follows. Stored as `default_signing` in the
 * settings; an empty block hands signing back to what the configuration resolves to.
 */
export const GatewaySigningSection: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('settings.edit') && hasPermission('key_management.edit');
  const canConnect = hasPermission('vta_connections.edit');

  const [signing, setSigning] = useState<SurfaceSigning | undefined>(undefined);
  const [stored, setStored] = useState<SurfaceSigning | undefined>(undefined);
  const [loaded, setLoaded] = useState(false);
  const [remotePending, setRemotePending] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [confirming, setConfirming] = useState(false);
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
      setError(e instanceof Error ? e.message : 'Could not read the gateway signing settings.');
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
    setConfirming(false);
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
      setError(e instanceof Error ? e.message : 'Could not save the gateway signing settings.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card shadow mb-3" data-testid="gateway-signing-settings">
      <div className="card-header py-3 d-flex align-items-center gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-key me-2" aria-hidden="true" />
          Gateway signing
        </h6>
        <span className="badge text-bg-secondary" data-testid="gateway-signing-scope">
          Gateway-wide default
        </span>
      </div>
      <div className="card-body">
        {error && (
          <div className="alert alert-danger py-2" role="alert" data-testid="gateway-signing-error">
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
                    data-testid="gateway-signing-connect-button"
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
                  data-testid="gateway-signing-save-button"
                  disabled={!changed || saving || remotePending}
                  onClick={() => setConfirming(true)}
                >
                  {saving ? 'Saving…' : 'Save'}
                </AppButton>
                {saved && (
                  <span className="small text-success" data-testid="gateway-signing-saved">
                    <i className="fas fa-check me-1" aria-hidden="true" />
                    Saved
                  </span>
                )}
              </div>
            )}
          </>
        )}
      </div>
      {confirming && (
        <WarningDialog
          testId="gateway-signing-confirm-dialog"
          title="Change gateway signing"
          onClose={() => setConfirming(false)}
          footer={
            <>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-warning"
                data-testid="gateway-signing-confirm-dialog-confirm"
                onClick={() => void save()}
              >
                Change gateway signing
              </button>
            </>
          }
        >
          <p>This changes what signs for the whole gateway:</p>
          <ul className="mb-0">
            {EFFECTS.map(effect => (
              <li key={effect}>{effect}</li>
            ))}
          </ul>
        </WarningDialog>
      )}
    </div>
  );
};
