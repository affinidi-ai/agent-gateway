import React, { useEffect, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { TwoStepButton } from '../../components/shared/TwoStepButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { showToast } from '../../utils/toaster';
import { getErrorMessage } from '../../utils/apiError';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { consentLimitLabel, takesConsent } from '../../utils/consentLimit';
import { DOCS_URL } from '../../config/docs';
import AgentName from './AgentName';
import PaginationControls, { clampPage } from './PaginationControls';
import VaultReadError from './VaultReadError';
import {
  DelegationToken,
  consentEnd,
  consentLimitSecs,
  consentState,
  isActiveDelegation,
  matchesSearch,
  providerName,
  shownTime,
  timeLeft,
} from './delegatedAccess';
import { DelegationVault } from './useDelegationVault';

interface DelegatedAccessTabProps {
  /** The vault the Credentials page loaded, the same one the Credential Tokens tab shows. */
  vault: DelegationVault;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  /** Opens the delegation audit, where ended and revoked access is recorded; no button without it. */
  onViewHistory?: () => void;
}

const PAGE_SIZE = 10;

const DelegatedAccessTab: React.FC<DelegatedAccessTabProps> = ({
  vault,
  externalSearchTerm,
  onFilteredCountChange,
  onViewHistory,
}) => {
  const { hasPermission } = usePermissions();
  const { tokens, providers, loading, vaultError } = vault;
  const [page, setPage] = useState(1);
  const searchTerm = (externalSearchTerm ?? '').trim().toLowerCase();
  const canRevoke = hasPermission('delegation_vault.delete');

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const systemOf = (token: DelegationToken) => providerName(token, providers);

  /**
   * A token of a provider nobody consents to is a service token, not a person's delegation. One
   * whose provider is unknown is listed, since its provider may only be unreadable.
   */
  const consentedTo = (token: DelegationToken) => {
    const type = providers[token.credential_provider_id]?.provider_type;
    return !type || takesConsent(type);
  };

  const now = new Date();
  const active = tokens.filter(token => consentedTo(token) && isActiveDelegation(token, now));
  const endingSoon = active.filter(
    token => consentState(consentEnd(token.consent_expires_at), now) === 'ending_soon'
  ).length;
  const shown = active.filter(token => matchesSearch(token, providers, searchTerm));
  const shownPage = clampPage(page, PAGE_SIZE, shown.length);
  const paged = shown.slice((shownPage - 1) * PAGE_SIZE, shownPage * PAGE_SIZE);

  useEffect(() => {
    onFilteredCountChange?.(shown.length);
  }, [shown.length, onFilteredCountChange]);

  const revoke = async (token: DelegationToken) => {
    try {
      await vault.revoke(token.id);
      showToast('success', 'Access revoked');
    } catch (error) {
      showToast('error', `Not revoked: ${getErrorMessage(error)}`);
    }
  };

  return (
    <div className="card shadow mb-4" data-testid="delegated-access-card">
      <div className="card-header py-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-user-check"></i> Delegated Access
          {!vaultError && (
            <Badge
              value={shown.length}
              suffix={searchTerm ? ` of ${active.length}` : undefined}
              className="ms-2"
              ariaLabel={`${shown.length}${searchTerm ? ` of ${active.length}` : ''} active delegations`}
            />
          )}
          {endingSoon > 0 && (
            <span
              className="badge text-bg-warning ms-2"
              style={{ verticalAlign: 'middle' }}
              data-testid="delegated-access-ending-soon-count"
            >
              {endingSoon} ending soon
            </span>
          )}
        </h6>
        <div className="d-flex align-items-center gap-2">
          <small className="text-muted">
            Active access only. Ended and revoked access is in the history.
          </small>
          {onViewHistory && (
            <AppButton
              variant="secondary"
              size="sm"
              data-testid="delegated-access-history-button"
              onClick={onViewHistory}
              iconStart={<i className="fas fa-clock-rotate-left" aria-hidden="true" />}
            >
              History
            </AppButton>
          )}
        </div>
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
            testId="delegated-access-read-error"
          />
        ) : active.length === 0 ? (
          <EmptyState
            icon="fa-user-check"
            title="No active delegated access"
            body="An entry appears here while a person's consent lets an agent act for them in another system. Access that ended or was revoked is in the history."
            docsHref={DOCS_URL.credentialDelegation}
          />
        ) : shown.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No active access matches your search.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>User</th>
                  <th>System</th>
                  <th>Agent</th>
                  <th>Access</th>
                  <th>Status</th>
                  <th>Ends</th>
                  <th>Last Used</th>
                  {canRevoke && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {paged.map(token => {
                  const end = consentEnd(token.consent_expires_at);
                  const limitSecs = consentLimitSecs(token);
                  return (
                    <tr key={token.id} data-testid={`delegated-access-row-${token.id}`}>
                      <td>
                        <code className="text-muted" title={token.user_identity_hash}>
                          {topAndTail(token.user_identity_hash, 8, 8)}
                        </code>
                      </td>
                      <td>
                        <strong>{systemOf(token)}</strong>
                        {providers[token.credential_provider_id]?.deactivated_at && (
                          <span
                            className="badge text-bg-secondary ms-2"
                            title="This provider is deactivated. Access already given keeps working; nobody can consent to it again."
                            data-testid={`delegated-access-provider-deactivated-${token.id}`}
                          >
                            No new consent
                          </span>
                        )}
                      </td>
                      <td>
                        <AgentName did={token.agent_did} />
                      </td>
                      <td>
                        {token.scopes.map(scope => (
                          <span key={scope} className="badge text-bg-secondary me-1">
                            {scope}
                          </span>
                        ))}
                      </td>
                      <td>
                        {consentState(end, now) === 'ending_soon' ? (
                          <span className="badge text-bg-warning">Ending soon</span>
                        ) : (
                          <span className="badge text-bg-success">Active</span>
                        )}
                      </td>
                      <td data-testid={`delegated-access-ends-${token.id}`}>
                        {end ? (
                          <>
                            <span>{timeLeft(end, now)}</span>
                            {limitSecs !== null && (
                              <div className="small text-muted">{consentLimitLabel(limitSecs)}</div>
                            )}
                            <div className="small text-muted">{formatDateTime(end, true)}</div>
                          </>
                        ) : (
                          <span className="text-muted">No time limit</span>
                        )}
                      </td>
                      <td>
                        <small>{shownTime(token.last_used_at)}</small>
                      </td>
                      {canRevoke && (
                        <td>
                          <TwoStepButton
                            label="Revoke"
                            confirmAs="danger"
                            confirmLabel={`Revoke ${systemOf(token)} access?`}
                            title="Revoke access"
                            confirmTitle="Click again to revoke this access"
                            className="btn btn-outline-danger btn-sm text-nowrap"
                            cancelTestId={`delegated-access-revoke-cancel-button-${token.id}`}
                            data-testid={`delegated-access-revoke-button-${token.id}`}
                            onConfirm={() => revoke(token)}
                          />
                        </td>
                      )}
                    </tr>
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

export default DelegatedAccessTab;
