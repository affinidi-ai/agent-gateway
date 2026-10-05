import React, { useEffect, useState } from 'react';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import type { OutboundCredentialFormRow } from '../_shared/OutboundCredentialsListSection';
import { apiClient } from '../../../../api';

interface ProviderInfo {
  id: string;
  name: string;
  callback_url?: string;
}

/**
 * Sidebar panel — small summary plus a button that opens the full-area
 * editor. The actual binding/workload-binding tables are too large for
 * the 280–600px sidebar, so they live in {@link CredentialDelegationFullscreenPanel}.
 */
const CredentialDelegationPanel: React.FC<ConfigPanelProps> = ({
  config,
  openFullscreenEditor,
}) => {
  const rows: OutboundCredentialFormRow[] = Array.isArray(config?.outbound_credentials_form)
    ? (config.outbound_credentials_form as OutboundCredentialFormRow[])
    : [];

  // Look up callback URLs for the bound providers so the operator can see
  // — without opening the fullscreen editor — where OAuth tokens come back
  // into the gateway for this surface.
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  useEffect(() => {
    let alive = true;
    apiClient
      .fetch('/api/v1/credential-providers')
      .then(r => (r.ok ? r.json() : []))
      .then((data: ProviderInfo[]) => {
        if (alive) setProviders(Array.isArray(data) ? data : []);
      })
      .catch(() => {
        if (alive) setProviders([]);
      });
    return () => {
      alive = false;
    };
  }, []);

  const boundProviders = rows
    .map(r => providers.find(p => p.id === r.credential_provider_id))
    .filter((p): p is ProviderInfo => !!p);

  return (
    <>
      <InfoBanner
        title="Credential Delegation"
        icon="fa-circle-info"
        collapsible={false}
        summary={
          <>
            Binds external credential providers (OAuth, API key, etc.) to this surface so the
            gateway can attach cached tokens to outbound calls on the caller&apos;s behalf — or
            signal <code>consent_required</code> back when no token is held.
          </>
        }
      />

      <div className="config-section">
        <label>Outbound credential bindings</label>
        <div className="small text-muted">
          {rows.length === 0
            ? 'No bindings configured.'
            : `${rows.length} binding${rows.length === 1 ? '' : 's'} configured.`}
        </div>
      </div>

      {boundProviders.length > 0 && (
        <InfoBanner
          title="Gateway-held credentials"
          icon="fa-shield-halved"
          collapsible={false}
          summary="Tokens returned to the callback URL below are stored on the gateway and re-injected automatically onto outbound calls. The calling agent never sees the user's credentials."
        >
          {boundProviders.map(p => (
            <div key={p.id} style={{ fontSize: 11, marginBottom: 4 }}>
              <div style={{ fontWeight: 600 }}>{p.name}</div>
              {p.callback_url ? (
                <code style={{ wordBreak: 'break-all' }}>{p.callback_url}</code>
              ) : (
                <span className="fst-italic text-muted">No callback URL configured</span>
              )}
            </div>
          ))}
        </InfoBanner>
      )}
      <div className="config-section">
        <button
          type="button"
          className="btn btn-sm btn-primary w-100"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
        >
          <i className="fas fa-id-card me-2" />
          Configure Delegation…
        </button>
      </div>
    </>
  );
};

export default CredentialDelegationPanel;
