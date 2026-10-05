import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { EmptyState } from '../../components/shared/EmptyState';
import AccessTokenRow from './AccessTokenRow';
import { useAccessTokenList } from './useAccessTokenList';

interface AccessTokensTabProps {
  searchTerm: string;
}

const AccessTokensTab: React.FC<AccessTokensTabProps> = ({ searchTerm }) => {
  const list = useAccessTokenList(searchTerm);

  return (
    <div className="card shadow mb-4" data-testid="access-tokens-tab">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-user-lock me-1" aria-hidden="true" /> Access Tokens (PAT)
          <Badge
            value={list.filtered.length}
            className="ms-2"
            ariaLabel={`${list.filtered.length} access tokens`}
          />
        </h6>
        <div className="d-flex align-items-center gap-3">
          <div className="form-check form-switch m-0">
            <input
              className="form-check-input"
              id="access-token-show-revoked"
              type="checkbox"
              checked={list.showRevoked}
              onChange={event => list.setShowRevoked(event.target.checked)}
              data-testid="access-token-show-revoked"
            />
            <label className="form-check-label small" htmlFor="access-token-show-revoked">
              Show revoked
            </label>
          </div>
          {list.canEdit && (
            <AppButton
              variant="primary"
              onClick={list.openCreate}
              iconStart={<i className="fas fa-plus me-1" aria-hidden="true" />}
              data-testid="access-token-new-button"
            >
              New Access Token
            </AppButton>
          )}
        </div>
      </div>
      <div className="card-body">
        {list.loading ? (
          <div className="text-center py-5" data-testid="access-token-loading">
            <div className="spinner-border text-primary" role="status" />
          </div>
        ) : list.error ? (
          <div className="alert alert-danger" data-testid="access-token-error">
            {list.error}
          </div>
        ) : list.tokens.length === 0 ? (
          <EmptyState
            icon="fa-user-lock"
            title="No access tokens yet"
            body="Access tokens let automation call the management API without an interactive session."
            ctaLabel={list.canEdit ? 'New Access Token' : undefined}
            ctaIcon="fa-plus"
            onCtaClick={list.canEdit ? list.openCreate : undefined}
          />
        ) : list.filtered.length === 0 ? (
          <div className="text-center text-muted py-5" data-testid="access-token-empty-filter">
            No access tokens match the current filters.
          </div>
        ) : (
          <>
            <div className="table-responsive">
              <table className="table table-hover align-middle">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Scopes</th>
                    <th>Status</th>
                    <th>Last used</th>
                    <th>Expires</th>
                    <th>Created</th>
                    {list.canRevoke && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {list.paged.map(token => (
                    <AccessTokenRow
                      key={token.id}
                      token={token}
                      canRevoke={list.canRevoke}
                      onOpen={() => list.openEdit(token)}
                      onRevoke={() => list.revoke(token.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            {list.totalPages > 1 && (
              <div className="d-flex justify-content-end gap-2">
                <AppButton
                  variant="outline-secondary"
                  disabled={list.currentPage === 1}
                  onClick={() => list.setPage(list.currentPage - 1)}
                  data-testid="access-token-previous-page"
                >
                  Previous
                </AppButton>
                <span className="small align-self-center">
                  Page {list.currentPage} of {list.totalPages}
                </span>
                <AppButton
                  variant="outline-secondary"
                  disabled={list.currentPage === list.totalPages}
                  onClick={() => list.setPage(list.currentPage + 1)}
                  data-testid="access-token-next-page"
                >
                  Next
                </AppButton>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default AccessTokensTab;
