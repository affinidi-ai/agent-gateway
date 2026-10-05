import React, { useEffect, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';

interface DelegationToken {
  id: string;
  agent_did: string;
  user_identity_hash: string;
  credential_provider_id: string;
  provider_id: string;
  token_type: string;
  scopes: string[];
  expires_at: string | null;
  consent_granted_at: string;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  is_expired: boolean;
  can_refresh: boolean;
}

interface CredentialTokensTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const PAGE_SIZE = 10;

const CredentialTokensTab: React.FC<CredentialTokensTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
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
    if (!window.confirm(`Revoke ALL delegations for user ${userHash.substring(0, 16)}…?`)) return;
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

  const getStatusBadge = (token: DelegationToken) => {
    if (token.is_expired && token.can_refresh)
      return <span className="badge text-bg-warning">Expired (refreshable)</span>;
    if (token.is_expired) return <span className="badge text-bg-danger">Expired</span>;
    return <span className="badge text-bg-success">Active</span>;
  };

  const activeTokens = tokens.filter(t => !t.is_expired).length;
  const expiredRefreshable = tokens.filter(t => t.is_expired && t.can_refresh).length;
  const expiredNoRefresh = tokens.filter(t => t.is_expired && !t.can_refresh).length;

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

  const totalPages = Math.max(1, Math.ceil(filteredTokens.length / PAGE_SIZE));
  const pagedTokens = filteredTokens.slice((tokensPage - 1) * PAGE_SIZE, tokensPage * PAGE_SIZE);

  const PaginationControls: React.FC = () => {
    if (totalPages <= 1) return null;
    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {(tokensPage - 1) * PAGE_SIZE + 1}–
          {Math.min(tokensPage * PAGE_SIZE, filteredTokens.length)} of {filteredTokens.length}
        </small>
        <nav>
          <ul className="pagination pagination-sm mb-0">
            <li className={`page-item ${tokensPage <= 1 ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => setTokensPage(tokensPage - 1)}>
                &lsaquo;
              </button>
            </li>
            {Array.from({ length: totalPages }, (_, i) => i + 1)
              .filter(p => p === 1 || p === totalPages || Math.abs(p - tokensPage) <= 1)
              .reduce<(number | '...')[]>((acc, p, idx, arr) => {
                if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('...');
                acc.push(p);
                return acc;
              }, [])
              .map((p, idx) =>
                p === '...' ? (
                  <li key={`ellipsis-${idx}`} className="page-item disabled">
                    <span className="page-link">…</span>
                  </li>
                ) : (
                  <li key={p} className={`page-item ${p === tokensPage ? 'active' : ''}`}>
                    <button className="page-link" onClick={() => setTokensPage(p as number)}>
                      {p}
                    </button>
                  </li>
                )
              )}
            <li className={`page-item ${tokensPage >= totalPages ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => setTokensPage(tokensPage + 1)}>
                &rsaquo;
              </button>
            </li>
          </ul>
        </nav>
      </div>
    );
  };

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
                  <th>Expires</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {pagedTokens.map(token => (
                  <React.Fragment key={token.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
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
                          <AppButton
                            variant="link"
                            size="sm"
                            className="p-0 ms-1 border-0"
                            title="Revoke all for this user"
                            onClick={e => {
                              e.stopPropagation();
                              handleRevokeByUser(token.user_identity_hash);
                            }}
                            aria-label={`Revoke all delegations for user ${topAndTail(token.user_identity_hash, 8, 8)}`}
                            iconStart={
                              <i className="fas fa-ban text-warning fa-xs" aria-hidden="true" />
                            }
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
                                        Expires
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
            <PaginationControls />
          </div>
        )}
      </div>
    </div>
  );
};

export default CredentialTokensTab;
