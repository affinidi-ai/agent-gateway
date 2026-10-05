import React from 'react';
import type { ConfigPanelProps } from '../types';
import OutboundCredentialsListSection, {
  type OutboundCredentialFormRow,
} from '../_shared/OutboundCredentialsListSection';

/**
 * Full-area editor for the Credential Delegation element. Mirrors the
 * channel editor's "Credentials" tab (`OutboundCredentialsTab.tsx`)
 * with a single card:
 *   1. Outbound Credential Delegation — provider bindings table.
 *
 * Card chrome (`card shadow mb-4`, `card-header py-3`, `h6 m-0
 * font-weight-bold text-primary`) matches the channel tabs so a user
 * jumping between channel and surface editors sees identical UI.
 */
const CredentialDelegationFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const rows: OutboundCredentialFormRow[] = Array.isArray(config?.outbound_credentials_form)
    ? (config.outbound_credentials_form as OutboundCredentialFormRow[])
    : [];

  return (
    <div className="container-fluid py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="mb-1">
            <i className="fas fa-id-card me-2 text-primary" />
            Credential Delegation
          </h4>
          <div className="text-muted small">
            Configure outbound credential bindings for the Managed Agent → External arrow.
          </div>
        </div>
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          onClick={() => closeFullscreenEditor?.()}
          disabled={!closeFullscreenEditor}
        >
          <i className="fas fa-times me-1" />
          Close
        </button>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-id-card me-2" />
            Outbound Credential Delegation
          </h6>
        </div>
        <div className="card-body">
          <p className="text-muted small mb-3">
            Bind credential providers to the outbound call. On each request the gateway looks up a
            cached token for the authenticated caller and injects it (Authorization header, custom
            header, or meta field). If no token is available the gateway responds with{' '}
            <code>consent_required</code> so the caller can launch the provider's OAuth flow.
          </p>
          <OutboundCredentialsListSection
            rows={rows}
            onChange={next => updateField('outbound_credentials_form', next)}
          />
        </div>
      </div>
    </div>
  );
};

export default CredentialDelegationFullscreenPanel;
