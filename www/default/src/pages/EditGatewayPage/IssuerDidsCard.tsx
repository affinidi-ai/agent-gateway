import React, { useState } from 'react';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';

export type IssuerDidSource = 'handshake' | 'exchange';

/** Issuer DIDs of a remote gateway connection, as `GET /gateways/{id}` returns them. */
export interface GatewayIssuerDids {
  issuer_did: string | null;
  issuer_did_source: IssuerDidSource | null;
  trusted_issuer_dids: string[];
}

export function issuerDidsFromGateway(gateway: {
  issuer_did?: string | null;
  issuer_did_source?: IssuerDidSource | null;
  trusted_issuer_dids?: string[] | null;
}): GatewayIssuerDids {
  return {
    issuer_did: gateway.issuer_did ?? null,
    issuer_did_source: gateway.issuer_did_source ?? null,
    trusted_issuer_dids: gateway.trusted_issuer_dids ?? [],
  };
}

const SOURCE_LABEL: Record<IssuerDidSource, string> = {
  handshake: 'Pairing handshake',
  exchange: 'Issuer exchange',
};

interface IssuerDidsCardProps {
  gatewayId: string;
  value: GatewayIssuerDids;
  onChange: (value: GatewayIssuerDids) => void;
}

/**
 * Issuer DIDs a remote gateway's identity presentations may come from: the
 * one the peer proved through its issuer attestation (established by the
 * gateway, read-only here) and the ones an operator trusts for this
 * connection only.
 */
const IssuerDidsCard: React.FC<IssuerDidsCardProps> = ({ gatewayId, value, onChange }) => {
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('gateways.edit');
  const [newIssuerDid, setNewIssuerDid] = useState('');
  const [addError, setAddError] = useState('');
  const [busy, setBusy] = useState<'request' | 'forget' | 'add' | null>(null);

  const requestIssuer = async () => {
    setBusy('request');
    try {
      const response = await apiClient.post(`/gateways/${gatewayId}/issuer`);
      onChange({ ...value, issuer_did: response.data.issuer_did, issuer_did_source: 'exchange' });
      showToast('success', 'Issuer DID established from the peer gateway');
    } catch (err) {
      showToast('error', getErrorMessage(err, 'The peer gateway did not attest its issuer DID'));
    } finally {
      setBusy(null);
    }
  };

  const forgetIssuer = async () => {
    setBusy('forget');
    try {
      const response = await apiClient.delete(`/gateways/${gatewayId}/issuer`);
      onChange(issuerDidsFromGateway(response.data));
      showToast('success', 'Issuer DID forgotten; it is re-established on the next exchange');
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to forget the issuer DID'));
    } finally {
      setBusy(null);
    }
  };

  const addTrustedIssuer = async () => {
    const issuerDid = newIssuerDid.trim();
    if (!issuerDid.startsWith('did:')) {
      setAddError('Enter a DID, for example did:web:gateway.example');
      return;
    }
    setAddError('');
    setBusy('add');
    try {
      const response = await apiClient.post(`/gateways/${gatewayId}/trusted-issuers`, {
        issuer_did: issuerDid,
      });
      onChange(issuerDidsFromGateway(response.data));
      setNewIssuerDid('');
    } catch (err) {
      setAddError(getErrorMessage(err, 'Failed to trust the issuer DID'));
    } finally {
      setBusy(null);
    }
  };

  const removeTrustedIssuer = async (issuerDid: string) => {
    try {
      const response = await apiClient.delete(
        `/gateways/${gatewayId}/trusted-issuers/${encodeURIComponent(issuerDid)}`
      );
      onChange(issuerDidsFromGateway(response.data));
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to remove the trusted issuer DID'));
    }
  };

  return (
    <div className="card shadow-sm mb-4" data-testid="gateway-issuer-dids-card">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-fingerprint"></i> Issuer DIDs
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-3">
          <i className="fas fa-info-circle me-2"></i> Identity presentations arriving over this
          connection are attributed only when they were issued by one of these DIDs.
        </p>

        <div className="mb-4">
          <div className="small text-muted mb-1">Established issuer DID</div>
          {value.issuer_did ? (
            <div className="d-flex flex-wrap align-items-center gap-2">
              <code style={{ fontSize: '0.85rem' }} data-testid="gateway-issuer-did">
                {value.issuer_did}
              </code>
              {value.issuer_did_source && (
                <Badge tone="success" size="sm" value={SOURCE_LABEL[value.issuer_did_source]} />
              )}
              {canEdit && (
                <DeleteButton
                  variant="warning"
                  onDelete={forgetIssuer}
                  disabled={busy !== null}
                  title="Forget this issuer DID; it is re-established on the next exchange"
                  confirmTitle="Click again to forget the established issuer DID"
                  data-testid="gateway-issuer-forget-button"
                >
                  <i className="fas fa-eraser"></i> Forget
                </DeleteButton>
              )}
            </div>
          ) : (
            <div className="d-flex flex-wrap align-items-center gap-2">
              <Badge tone="warning" size="sm" value="Not established" />
              <span className="small text-muted">
                Fabric requests from this gateway are rejected until its issuer DID is established
                or an issuer DID is trusted below.
              </span>
              {canEdit && (
                <AppButton
                  variant="outline-primary"
                  size="sm"
                  onClick={requestIssuer}
                  loading={busy === 'request'}
                  loadingLabel="Requesting..."
                  disabled={busy !== null}
                  iconStart={<i className="fas fa-sync-alt"></i>}
                  data-testid="gateway-issuer-request-button"
                >
                  Request from peer
                </AppButton>
              )}
            </div>
          )}
        </div>

        <div>
          <div className="small text-muted mb-1">Trusted issuer DIDs for this connection</div>
          {value.trusted_issuer_dids.length === 0 ? (
            <p className="small text-muted mb-2" data-testid="gateway-trusted-issuers-empty">
              None. Add one only when this peer relays presentations issued by another gateway you
              trust; it applies to this connection alone.
            </p>
          ) : (
            <ul className="list-unstyled mb-2">
              {value.trusted_issuer_dids.map(issuerDid => (
                <li
                  key={issuerDid}
                  className="d-flex align-items-center gap-2 mb-1"
                  data-testid={`gateway-trusted-issuer-row-${issuerDid}`}
                >
                  <code style={{ fontSize: '0.85rem' }}>{issuerDid}</code>
                  <Badge tone="secondary" size="sm" value="Operator" />
                  {canEdit && (
                    <DeleteButton
                      onDelete={() => removeTrustedIssuer(issuerDid)}
                      title="Stop trusting this issuer DID on this connection"
                      confirmTitle="Click again to remove this trusted issuer DID"
                      aria-label={`Remove trusted issuer ${issuerDid}`}
                      data-testid={`gateway-trusted-issuer-remove-button-${issuerDid}`}
                    >
                      <i className="fas fa-trash"></i>
                    </DeleteButton>
                  )}
                </li>
              ))}
            </ul>
          )}
          {canEdit && (
            <form
              className="d-flex flex-wrap align-items-start gap-2"
              onSubmit={event => {
                event.preventDefault();
                void addTrustedIssuer();
              }}
            >
              <div className="flex-grow-1" style={{ minWidth: '16rem' }}>
                <label htmlFor="gateway-trusted-issuer-input" className="visually-hidden">
                  Issuer DID to trust on this connection
                </label>
                <input
                  id="gateway-trusted-issuer-input"
                  className={`form-control form-control-sm ${addError ? 'is-invalid' : ''}`}
                  placeholder="did:web:gateway.example"
                  value={newIssuerDid}
                  onChange={event => {
                    setNewIssuerDid(event.target.value);
                    setAddError('');
                  }}
                  disabled={busy !== null}
                  data-testid="gateway-trusted-issuer-input"
                />
                {addError && <div className="invalid-feedback d-block">{addError}</div>}
              </div>
              <AppButton
                type="submit"
                variant="outline-primary"
                size="sm"
                loading={busy === 'add'}
                loadingLabel="Adding..."
                disabled={busy !== null || !newIssuerDid.trim()}
                iconStart={<i className="fas fa-plus"></i>}
                data-testid="gateway-trusted-issuer-add-button"
              >
                Trust issuer
              </AppButton>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default IssuerDidsCard;
