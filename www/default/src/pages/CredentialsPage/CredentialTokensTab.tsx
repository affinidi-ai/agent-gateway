import React, { useEffect, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { useTwoStepDelete } from '../../hooks/useTwoStepDelete';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import PaginationControls from './PaginationControls';
import { DelegationToken, consentEnd, consentState, timeLeft } from './delegatedAccess';

interface CredentialTokensTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  /** Opens the delegation audit of one user identity hash; no link is shown without it. */
  onViewActivity?: (userHash: string) => void;
}

const PAGE_SIZE = 10;

interface RevokeUserButtonProps {
  token: DelegationToken;
  onRevoke: () => Promise<void>;
}

/** Revokes every delegation of a row's user, on a second click that confirms the first. */
const RevokeUserButton: React.FC<RevokeUserButtonProps> = ({ token, onRevoke }) => {
  const { isConfirming, isProcessing, handleClick, buttonRef } = useTwoStepDelete(onRevoke);
  const user = topAndTail(token.user_identity_hash, 8, 8);
  const icon = isProcessing
    ? 'fa-spinner fa-spin'
    : isConfirming
      ? 'fa-exclamation-triangle'
      : 'fa-ban';
  return (
    <button
      ref={buttonRef}
      type="button"
      className="btn btn-link btn-sm p-0 ms-1 border-0 text-warning text-decoration-none"
      data-testid={`credential-token-revoke-user-button-${token.id}`}
      title={
        isConfirming
          ? 'Click again to revoke every delegation of this user'
          : 'Revoke all for this user'
      }
      aria-label={
        isConfirming
          ? `Click again to revoke all delegations for user ${user}`
          : `Revoke all delegations for user ${user}`
      }
      disabled={isProcessing}
      onClick={handleClick}
    >
      <i className={`fas ${icon} fa-xs`} aria-hidden="true" />
      {isConfirming && <span className="ms-1 small">Click again to revoke all</span>}
    </button>
  );
};

const CredentialTokensTab: React.FC<CredentialTokensTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
  onViewActivity,
}) => {
  const { hasPermission } = usePermissions();
  const [tokens, setTokens] = useState<DelegationToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const [tokensPage, setTokensPage] = useState(1);
  const [expandedTokenId, setExpandedTokenId] = useState<string | null>(null);

  const canEditTokens = hasPermission('settings.edit');

  useEffect(() => {
    loadTokens();
  }, []);

  useEffect(() => {
    setTokensPage(1);
  }, [searchTerm]);

  const loadTokens = async () => {
    setLoading(true);
    try {
      const response = await apiClient.fetch('/api/v1/delegation-vault');
      if (response.ok) {
        const data: DelegationToken[] = await response.json();
        setTokens(data);
      }
    } catch (error) {
      console.error('Failed to load delegation tokens:', error);
      setTokens([]);
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeToken = async (token: DelegationToken) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/${encodeURIComponent(token.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) throw new Error(`Revoke failed: ${response.statusText}`);
      setTokens(prev => prev.filter(t => t.id !== token.id));
      showToast('Delegation revoked', 'success');
    } catch (e: any) {
      showToast(`Failed to revoke: ${e.message}`, 'error');
    }
  };

  const handleRevokeByUser = async (userHash: string) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/by-user/${encodeURIComponent(userHash)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) throw new Error(`Bulk revoke failed: ${response.statusText}`);
      setTokens(prev => prev.filter(t => t.user_identity_hash !== userHash));
      showToast('All delegations for user revoked', 'success');
    } catch (e: any) {
      showToast(`Failed to revoke: ${e.message}`, 'error');
    }
  };

  const fmtDate = (d: string | null) => (d ? formatDateTime(d, true) : '—');

  /** The end of a token's consent: as a sentence for the list, or as a value for the detail. */
  const consentEndText = (token: DelegationToken, form: 'sentence' | 'value') => {
    const end = consentEnd(token.consent_expires_at);
    if (!end) return 'No time limit';
    const date = formatDateTime(end, true);
    if (consentState(end, new Date()) === 'ended') {
      return form === 'sentence' ? `Ended ${date}` : `${date} (ended)`;
    }
    const left = timeLeft(end, new Date());
    return form === 'sentence' ? `Ends ${date} (${left})` : `${date} (${left})`;
  };

  const getStatusBadge = (token: DelegationToken) => {
    const consent = consentState(consentEnd(token.consent_expires_at), new Date());
    if (consent === 'ended') return <span className="badge text-bg-secondary">Consent ended</span>;
    if (consent === 'ending_soon')
      return <span className="badge text-bg-warning">Ending soon</span>;
    if (token.is_expired && token.can_refresh)
      return <span className="badge text-bg-warning">Expired (refreshable)</span>;
    if (token.is_expired) return <span className="badge text-bg-danger">Expired</span>;
    return <span className="badge text-bg-success">Active</span>;
  };

  const consentEnded = (t: DelegationToken) =>
    consentState(consentEnd(t.consent_expires_at), new Date()) === 'ended';
  const consentEndedTokens = tokens.filter(consentEnded).length;
  const usable = tokens.filter(t => !consentEnded(t));
  const activeTokens = usable.filter(t => !t.is_expired).length;
  const expiredRefreshable = usable.filter(t => t.is_expired && t.can_refresh).length;
  const expiredNoRefresh = usable.filter(t => t.is_expired && !t.can_refresh).length;

  const filteredTokens = tokens.filter(t => {
    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return true;

    const searchLower = trimmedSearch.toLowerCase();
    return (
      t.provider_id.toLowerCase().includes(searchLower) ||
      t.agent_did.toLowerCase().includes(searchLower) ||
      t.user_identity_hash.toLowerCase().includes(searchLower) ||
      t.scopes.some(scope => scope.toLowerCase().includes(searchLower))
    );
  });

  useEffect(() => {
    onFilteredCountChange?.(filteredTokens.length);
  }, [filteredTokens.length, onFilteredCountChange]);

  const pagedTokens = filteredTokens.slice((tokensPage - 1) * PAGE_SIZE, tokensPage * PAGE_SIZE);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-lock"></i> Credential Delegation Tokens
          <Badge
            value={filteredTokens.length}
            suffix={searchTerm ? ` of ${tokens.length}` : undefined}
            className="ms-2"
            ariaLabel={`${filteredTokens.length}${searchTerm ? ` of ${tokens.length}` : ''} delegation tokens`}
          />
          {tokens.length > 0 && (
            <>
              <span className="badge text-bg-success ms-2" style={{ verticalAlign: 'middle' }}>
                {activeTokens} active
              </span>
              {expiredRefreshable > 0 && (
                <span className="badge text-bg-warning ms-2" style={{ verticalAlign: 'middle' }}>
                  {expiredRefreshable} refreshable
                </span>
              )}
              {expiredNoRefresh > 0 && (
                <span className="badge text-bg-danger ms-2" style={{ verticalAlign: 'middle' }}>
                  {expiredNoRefresh} expired
                </span>
              )}
              {consentEndedTokens > 0 && (
                <span
                  className="badge text-bg-secondary ms-2"
                  style={{ verticalAlign: 'middle' }}
                  data-testid="credential-tokens-consent-ended-count"
                >
                  {consentEndedTokens} consent ended
                </span>
              )}
            </>
          )}
        </h6>
      </div>
      <div className="card-body">
        {loading ? (
          <div className="text-center py-5">
            <div className="spinner-border text-primary" role="status"></div>
          </div>
        ) : tokens.length === 0 ? (
          <EmptyState
            icon="fa-lock"
            title="No delegation tokens yet"
            body="Delegation tokens let a caller act on behalf of a credential holder. They appear here once per-caller credential delegation is configured."
            docsHref={DOCS_URL.credentialDelegation}
          />
        ) : filteredTokens.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No tokens match your search.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Agent</th>
                  <th>User</th>
                  <th>Scopes</th>
                  <th>Status</th>
                  <th>Consented</th>
                  <th>Last Used</th>
                  <th>Token Expires</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {pagedTokens.map(token => (
                  <React.Fragment key={token.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
                      data-testid={`credential-token-row-${token.id}`}
                      className={expandedTokenId === token.id ? 'table-active' : ''}
                      onClick={() =>
                        setExpandedTokenId(expandedTokenId === token.id ? null : token.id)
                      }
                    >
                      <td>
                        <i
                          className={`fas fa-chevron-${expandedTokenId === token.id ? 'down' : 'right'} me-2 text-muted`}
                          style={{ fontSize: '0.7rem' }}
                        ></i>
                        <strong>{token.provider_id}</strong>
                      </td>
                      <td>
                        <code className="text-muted" title={token.agent_did}>
                          {topAndTail(token.agent_did, 12, 12)}
                        </code>
                      </td>
                      <td>
                        <code className="text-muted" title={token.user_identity_hash}>
                          {topAndTail(token.user_identity_hash, 8, 8)}
                        </code>
                        {canEditTokens && (
                          <RevokeUserButton
                            token={token}
                            onRevoke={() => handleRevokeByUser(token.user_identity_hash)}
                          />
                        )}
                      </td>
                      <td>
                        {token.scopes.map(scope => (
                          <span key={scope} className="badge text-bg-secondary me-1">
                            {scope}
                          </span>
                        ))}
                      </td>
                      <td>{getStatusBadge(token)}</td>
                      <td>
                        <small>{fmtDate(token.consent_granted_at)}</small>
                        <div
                          className="small text-muted"
                          data-testid={`credential-token-consent-end-${token.id}`}
                        >
                          {consentEndText(token, 'sentence')}
                        </div>
                      </td>
                      <td>
                        <small>{fmtDate(token.last_used_at)}</small>
                      </td>
                      <td>
                        <small>{fmtDate(token.expires_at)}</small>
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        {canEditTokens && (
                          <DeleteButton
                            data-testid={`credential-token-revoke-button-${token.id}`}
                            onDelete={() => handleRevokeToken(token)}
                            className="btn-sm"
                            title="Revoke delegation"
                          />
                        )}
                      </td>
                    </tr>
                    {expandedTokenId === token.id && (
                      <tr className="expanded-detail-row">
                        <td colSpan={9} className="p-0">
                          <div className="px-4 py-3" style={{ borderTop: 'none' }}>
                            <div className="row g-3">
                              <div className="col-md-6">
                                <table
                                  className="table table-sm table-borderless mb-0"
                                  style={{ fontSize: '0.85rem' }}
                                >
                                  <tbody>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ width: '140px', whiteSpace: 'nowrap' }}
                                      >
                                        Token ID
                                      </td>
                                      <td>
                                        <code>{token.id}</code>
                                        <CopyButton text={token.id} title="Copy Token ID" />
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Provider ID
                                      </td>
                                      <td>
                                        <strong>{token.provider_id}</strong>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Credential Provider
                                      </td>
                                      <td>
                                        <code>{token.credential_provider_id}</code>
                                        <CopyButton
                                          text={token.credential_provider_id}
                                          title="Copy Credential Provider"
                                        />
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Token Type
                                      </td>
                                      <td>
                                        <span className="badge text-bg-info">
                                          {token.token_type}
                                        </span>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Agent DID
                                      </td>
                                      <td>
                                        <code style={{ wordBreak: 'break-all' }}>
                                          {token.agent_did}
                                        </code>
                                        <CopyButton text={token.agent_did} title="Copy Agent DID" />
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        User Identity
                                      </td>
                                      <td>
                                        <code style={{ wordBreak: 'break-all' }}>
                                          {token.user_identity_hash}
                                        </code>
                                        <CopyButton
                                          text={token.user_identity_hash}
                                          title="Copy User Identity"
                                        />
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Scopes
                                      </td>
                                      <td>
                                        {token.scopes.map(scope => (
                                          <span
                                            key={scope}
                                            className="badge text-bg-secondary me-1"
                                          >
                                            {scope}
                                          </span>
                                        ))}
                                      </td>
                                    </tr>
                                  </tbody>
                                </table>
                              </div>
                              <div className="col-md-6">
                                <table
                                  className="table table-sm table-borderless mb-0"
                                  style={{ fontSize: '0.85rem' }}
                                >
                                  <tbody>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ width: '140px', whiteSpace: 'nowrap' }}
                                      >
                                        Status
                                      </td>
                                      <td>{getStatusBadge(token)}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Can Refresh
                                      </td>
                                      <td>
                                        {token.can_refresh ? (
                                          <span className="badge text-bg-success">Yes</span>
                                        ) : (
                                          <span className="badge text-bg-secondary">No</span>
                                        )}
                                      </td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Consented
                                      </td>
                                      <td>{fmtDate(token.consent_granted_at)}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Consent Ends
                                      </td>
                                      <td>{consentEndText(token, 'value')}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Token Expires
                                      </td>
                                      <td>{fmtDate(token.expires_at)}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Last Used
                                      </td>
                                      <td>{fmtDate(token.last_used_at)}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Created
                                      </td>
                                      <td>{fmtDate(token.created_at)}</td>
                                    </tr>
                                    <tr>
                                      <td
                                        className="text-muted fw-semibold"
                                        style={{ whiteSpace: 'nowrap' }}
                                      >
                                        Updated
                                      </td>
                                      <td>{fmtDate(token.updated_at)}</td>
                                    </tr>
                                  </tbody>
                                </table>
                                {onViewActivity && (
                                  <AppButton
                                    variant="link"
                                    size="sm"
                                    className="p-0 mt-2"
                                    data-testid={`credential-token-view-activity-button-${token.id}`}
                                    onClick={() => onViewActivity(token.user_identity_hash)}
                                    iconStart={
                                      <i className="fas fa-clipboard-list" aria-hidden="true" />
                                    }
                                  >
                                    View this user's delegation audit
                                  </AppButton>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            <PaginationControls
              page={tokensPage}
              pageSize={PAGE_SIZE}
              total={filteredTokens.length}
              onPageChange={setTokensPage}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default CredentialTokensTab;
