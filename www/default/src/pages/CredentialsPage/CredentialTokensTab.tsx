import React, { useEffect, useRef, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { TwoStepButton } from '../../components/shared/TwoStepButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { showToast } from '../../utils/toaster';
import { getErrorMessage } from '../../utils/apiError';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { DOCS_URL } from '../../config/docs';
import AgentName from './AgentName';
import ConsentLimitPanel from './ConsentLimitPanel';
import CredentialTokenDetail, { TokenStatusBadge } from './CredentialTokenDetail';
import PaginationControls, { clampPage } from './PaginationControls';
import VaultReadError from './VaultReadError';
import {
  DelegationToken,
  canLimitConsent,
  consentEndSentence,
  matchesSearch,
  providerName,
  renewsAutomatically,
  revokeAllLabel,
  shownTime,
  tokenStatus,
} from './delegatedAccess';
import { DelegationVault } from './useDelegationVault';

interface CredentialTokensTabProps {
  /** The vault the Credentials page loaded, the same one the Delegated Access tab shows. */
  vault: DelegationVault;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  /** Opens the delegation audit of one user identity hash; no link is shown without it. */
  onViewActivity?: (userHash: string) => void;
}

const PAGE_SIZE = 10;

const CredentialTokensTab: React.FC<CredentialTokensTabProps> = ({
  vault,
  externalSearchTerm,
  onFilteredCountChange,
  onViewActivity,
}) => {
  const { hasPermission } = usePermissions();
  const { tokens, providers, loading, vaultError } = vault;
  const [page, setPage] = useState(1);
  const [expandedTokenId, setExpandedTokenId] = useState<string | null>(null);
  const [limitingTokenId, setLimitingTokenId] = useState<string | null>(null);
  const limitButtonRef = useRef<HTMLButtonElement>(null);
  const searchTerm = (externalSearchTerm ?? '').trim().toLowerCase();
  const canManage = hasPermission('delegation_vault.delete');
  const columns = canManage ? 9 : 8;

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const now = new Date();
  const shown = tokens.filter(token => matchesSearch(token, providers, searchTerm));
  const shownPage = clampPage(page, PAGE_SIZE, shown.length);
  const paged = shown.slice((shownPage - 1) * PAGE_SIZE, shownPage * PAGE_SIZE);

  useEffect(() => {
    onFilteredCountChange?.(shown.length);
  }, [shown.length, onFilteredCountChange]);

  const revoke = async (token: DelegationToken) => {
    try {
      await vault.revoke(token.id);
      showToast('success', 'Delegation revoked');
    } catch (error) {
      showToast('error', `Not revoked: ${getErrorMessage(error)}`);
    }
  };

  const revokeUser = async (userHash: string) => {
    try {
      await vault.revokeUser(userHash);
      showToast('success', 'All delegations for user revoked');
    } catch (error) {
      showToast('error', `Not revoked: ${getErrorMessage(error)}`);
    }
  };

  const limit = async (token: DelegationToken, limitSecs: number) => {
    const end = await vault.limitConsent(token.id, limitSecs);
    showToast(
      'success',
      `Limit saved. ${providerName(token, providers)} access ends ${formatDateTime(end, true)}.`
    );
  };

  /** Closes the open limit panel and returns the focus to the button that opened it. */
  const closeLimit = () => {
    limitButtonRef.current?.focus();
    setLimitingTokenId(null);
  };

  const delegationsOf = (userHash: string) =>
    tokens.filter(held => held.user_identity_hash === userHash).length;

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-lock"></i> Credential Delegation Tokens
        </h6>
      </div>
      <div className="card-body">
        {loading ? (
          <div className="text-center py-5">
            <div className="spinner-border text-primary" role="status"></div>
          </div>
        ) : vaultError ? (
          <VaultReadError
            error={vaultError}
            onRetry={vault.reload}
            testId="credential-tokens-read-error"
          />
        ) : tokens.length === 0 ? (
          <EmptyState
            icon="fa-lock"
            title="No delegation tokens yet"
            body="Delegation tokens let a caller act on behalf of a credential holder. They appear here once per-caller credential delegation is configured."
            docsHref={DOCS_URL.credentialDelegation}
          />
        ) : shown.length === 0 ? (
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
                  <th>Access Token</th>
                  {canManage && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {paged.map(token => {
                  const provider = providers[token.credential_provider_id];
                  const name = providerName(token, providers);
                  const user = topAndTail(token.user_identity_hash, 8, 8);
                  const revokeAll = revokeAllLabel(delegationsOf(token.user_identity_hash));
                  const expanded = expandedTokenId === token.id;
                  const limiting = limitingTokenId === token.id;
                  const toggleExpanded = () => setExpandedTokenId(expanded ? null : token.id);
                  return (
                    <React.Fragment key={token.id}>
                      <tr
                        style={{ cursor: 'pointer' }}
                        data-testid={`credential-token-row-${token.id}`}
                        className={expanded ? 'table-active' : ''}
                        onClick={toggleExpanded}
                      >
                        <td>
                          <AppButton
                            variant="link"
                            size="sm"
                            className="p-0 me-2 text-muted"
                            aria-expanded={expanded}
                            aria-controls={`credential-token-detail-${token.id}`}
                            aria-label={`Details of ${name} access for user ${user}`}
                            data-testid={`credential-token-expand-button-${token.id}`}
                            onClick={event => {
                              event.stopPropagation();
                              toggleExpanded();
                            }}
                          >
                            <i
                              className={`fas fa-chevron-${expanded ? 'down' : 'right'}`}
                              style={{ fontSize: '0.7rem' }}
                              aria-hidden="true"
                            />
                          </AppButton>
                          <strong>{name}</strong>
                        </td>
                        <td>
                          <AgentName did={token.agent_did} />
                        </td>
                        <td>
                          <div className="d-flex flex-wrap align-items-center gap-1">
                            <code className="text-muted" title={token.user_identity_hash}>
                              {user}
                            </code>
                            {canManage && (
                              <TwoStepButton
                                icon="fa-ban"
                                confirmAs="danger"
                                confirmLabel={revokeAll}
                                title="Revoke all for this user"
                                confirmTitle="Click again to revoke every delegation of this user"
                                ariaLabel={`Revoke all delegations for user ${user}`}
                                confirmAriaLabel={`${revokeAll} User ${user}`}
                                className="btn btn-link btn-sm p-0 border-0 text-warning text-decoration-none"
                                data-testid={`credential-token-revoke-user-button-${token.id}`}
                                onConfirm={() => revokeUser(token.user_identity_hash)}
                              />
                            )}
                          </div>
                        </td>
                        <td>
                          {token.scopes.map(scope => (
                            <span key={scope} className="badge text-bg-secondary me-1">
                              {scope}
                            </span>
                          ))}
                        </td>
                        <td>
                          <TokenStatusBadge status={tokenStatus(token, now)} />
                        </td>
                        <td>
                          <small>{shownTime(token.consent_granted_at)}</small>
                          <div
                            className="small text-muted"
                            data-testid={`credential-token-consent-end-${token.id}`}
                          >
                            {consentEndSentence(token, now)}
                          </div>
                        </td>
                        <td>
                          <small>{shownTime(token.last_used_at)}</small>
                        </td>
                        <td data-testid={`credential-token-access-token-${token.id}`}>
                          <small>{shownTime(token.expires_at)}</small>
                          {renewsAutomatically(token, provider, now) && (
                            <div className="small text-muted">Renews automatically</div>
                          )}
                        </td>
                        {canManage && (
                          <td onClick={event => event.stopPropagation()}>
                            <div className="d-grid gap-1">
                              {canLimitConsent(token, provider, now) && (
                                <AppButton
                                  ref={limiting ? limitButtonRef : undefined}
                                  variant="outline-primary"
                                  size="sm"
                                  className="text-nowrap"
                                  title="Set how long after its consent this delegation ends"
                                  aria-expanded={limiting}
                                  aria-controls={`credential-token-limit-panel-${token.id}`}
                                  data-testid={`credential-token-limit-button-${token.id}`}
                                  onClick={() => setLimitingTokenId(limiting ? null : token.id)}
                                >
                                  Limit duration
                                </AppButton>
                              )}
                              <TwoStepButton
                                label="Revoke"
                                confirmAs="danger"
                                confirmLabel={`Revoke ${name} access?`}
                                title="Revoke delegation"
                                confirmTitle="Click again to revoke this delegation"
                                className="btn btn-outline-danger btn-sm text-nowrap flex-grow-1"
                                cancelTestId={`credential-token-revoke-cancel-button-${token.id}`}
                                data-testid={`credential-token-revoke-button-${token.id}`}
                                onConfirm={() => revoke(token)}
                              />
                            </div>
                          </td>
                        )}
                      </tr>
                      {limiting && (
                        <tr className="expanded-detail-row">
                          <td colSpan={columns} className="p-0">
                            <ConsentLimitPanel
                              token={token}
                              providerName={name}
                              onSave={limitSecs => limit(token, limitSecs)}
                              onClose={closeLimit}
                            />
                          </td>
                        </tr>
                      )}
                      {expanded && (
                        <tr className="expanded-detail-row">
                          <td colSpan={columns} className="p-0">
                            <CredentialTokenDetail
                              token={token}
                              now={now}
                              onViewActivity={onViewActivity}
                            />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
            <PaginationControls
              page={shownPage}
              pageSize={PAGE_SIZE}
              total={shown.length}
              onPageChange={setPage}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default CredentialTokensTab;
