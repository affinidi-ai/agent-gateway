import React, { useEffect, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { DOCS_URL } from '../../config/docs';
import PaginationControls from './PaginationControls';
import {
  DelegationToken,
  consentEnd,
  consentState,
  isActiveDelegation,
  timeLeft,
} from './delegatedAccess';

interface ProviderSummary {
  id: string;
  name: string;
  provider_type?: string;
  /** Set once the provider takes no new consent. */
  deactivated_at?: string | null;
}

interface DelegatedAccessTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  /** Opens the delegation audit, where ended and revoked access is recorded; no button without it. */
  onViewHistory?: () => void;
}

const PAGE_SIZE = 10;

const DelegatedAccessTab: React.FC<DelegatedAccessTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
  onViewHistory,
}) => {
  const { hasPermission } = usePermissions();
  const [tokens, setTokens] = useState<DelegationToken[]>([]);
  const [providers, setProviders] = useState<Record<string, ProviderSummary>>({});
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const searchTerm = (externalSearchTerm ?? '').trim().toLowerCase();
  const canRevoke = hasPermission('settings.edit');

  useEffect(() => {
    let alive = true;
    const listOf = async <T,>(url: string): Promise<T[]> => {
      try {
        const response = await apiClient.fetch(url);
        const data = response.ok ? await response.json() : [];
        return Array.isArray(data) ? data : [];
      } catch {
        return [];
      }
    };
    Promise.all([
      listOf<DelegationToken>('/api/v1/delegation-vault'),
      listOf<ProviderSummary>('/api/v1/credential-providers'),
    ]).then(([vault, known]) => {
      if (!alive) return;
      setTokens(vault);
      setProviders(Object.fromEntries(known.map(provider => [provider.id, provider])));
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const systemOf = (token: DelegationToken) =>
    providers[token.credential_provider_id]?.name ?? token.provider_id;

  /** A token of a provider nobody consents to is a service token, not a person's delegation. */
  const consentedTo = (token: DelegationToken) => {
    const type = providers[token.credential_provider_id]?.provider_type;
    return !type || type === 'oauth2_authorization_code';
  };

  const now = new Date();
  const active = tokens.filter(token => consentedTo(token) && isActiveDelegation(token, now));
  const endingSoon = active.filter(
    token => consentState(consentEnd(token.consent_expires_at), now) === 'ending_soon'
  ).length;
  const shown = active.filter(
    token =>
      !searchTerm ||
      systemOf(token).toLowerCase().includes(searchTerm) ||
      token.provider_id.toLowerCase().includes(searchTerm) ||
      token.agent_did.toLowerCase().includes(searchTerm) ||
      token.user_identity_hash.toLowerCase().includes(searchTerm) ||
      token.scopes.some(scope => scope.toLowerCase().includes(searchTerm))
  );
  const paged = shown.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    onFilteredCountChange?.(shown.length);
  }, [shown.length, onFilteredCountChange]);

  const revoke = async (token: DelegationToken) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/${encodeURIComponent(token.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) throw new Error(`Revoke failed: ${response.statusText}`);
      setTokens(prev => prev.filter(t => t.id !== token.id));
      showToast('success', 'Access revoked');
    } catch (e: any) {
      showToast('error', `Failed to revoke: ${e.message}`);
    }
  };

  return (
    <div className="card shadow mb-4" data-testid="delegated-access-card">
      <div className="card-header py-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-user-check"></i> Delegated Access
          <Badge
            value={shown.length}
            suffix={searchTerm ? ` of ${active.length}` : undefined}
            className="ms-2"
            ariaLabel={`${shown.length}${searchTerm ? ` of ${active.length}` : ''} active delegations`}
          />
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
                        <code className="text-muted" title={token.agent_did}>
                          {topAndTail(token.agent_did, 12, 12)}
                        </code>
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
                            <div className="small text-muted">{formatDateTime(end, true)}</div>
                          </>
                        ) : (
                          <span className="text-muted">No time limit</span>
                        )}
                      </td>
                      <td>
                        <small>
                          {token.last_used_at ? formatDateTime(token.last_used_at, true) : '—'}
                        </small>
                      </td>
                      {canRevoke && (
                        <td>
                          <DeleteButton
                            data-testid={`delegated-access-revoke-button-${token.id}`}
                            onDelete={() => revoke(token)}
                            className="btn-sm"
                            title="Revoke access"
                            confirmTitle="Click again to revoke this access"
                          />
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <PaginationControls
              page={page}
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
