import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import type { AccessTokenMeta } from '../../types';
import { formatDateTime } from '../../utils/stringUtils';

interface BoundUser {
  first_name?: string;
  last_name?: string;
  email?: string;
  username?: string;
}

interface AccessTokenSidebarProps {
  meta: AccessTokenMeta | null;
}

const AccessTokenSidebar: React.FC<AccessTokenSidebarProps> = ({ meta }) => {
  const revoked = Boolean(meta?.revoked_at);
  const statusVariant = revoked ? 'danger' : meta?.active ? 'success' : 'secondary';
  const statusLabel = revoked ? 'Revoked' : meta?.active ? 'Active' : 'Expired';
  const boundUserId = meta?.user_id;
  const [boundUser, setBoundUser] = useState<BoundUser | null>(null);

  useEffect(() => {
    if (!boundUserId) {
      setBoundUser(null);
      return;
    }

    let cancelled = false;
    apiClient
      .get<BoundUser>(`/users/${boundUserId}`)
      .then(({ data }) => {
        if (!cancelled) setBoundUser(data);
      })
      .catch(() => {
        if (!cancelled) setBoundUser(null);
      });

    return () => {
      cancelled = true;
    };
  }, [boundUserId]);

  const boundUserName = boundUser
    ? [boundUser.first_name, boundUser.last_name].filter(Boolean).join(' ').trim() ||
      boundUser.email ||
      boundUser.username ||
      ''
    : '';

  return (
    <>
      {meta && (
        <div className="card shadow mb-4" data-testid="access-token-details-card">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-clock me-2" aria-hidden="true" />
              Access Token Details
            </h6>
          </div>
          <div className="card-body">
            <div className="mb-2">
              <strong className="text-muted">Bound user</strong>
              <div style={{ fontSize: '0.9em' }} data-testid="access-token-bound-user">
                {boundUserName ? (
                  <>
                    <div className="fw-semibold">{boundUserName}</div>
                    {boundUser?.email && boundUser.email !== boundUserName && (
                      <div className="text-muted">{boundUser.email}</div>
                    )}
                    <code className="text-muted d-block mt-1" style={{ fontSize: '0.85em' }}>
                      {meta.user_id}
                    </code>
                  </>
                ) : (
                  <code>{meta.user_id}</code>
                )}
              </div>
            </div>
            <div className="mb-2">
              <strong className="text-muted">Status</strong>
              <div style={{ fontSize: '0.9em' }}>
                <span className={`badge text-bg-${statusVariant}`}>{statusLabel}</span>
              </div>
            </div>
            <div className="mb-2">
              <strong className="text-muted">Created</strong>
              <div style={{ fontSize: '0.9em' }}>{formatDateTime(meta.created_at, true)}</div>
            </div>
            <div className="mb-2">
              <strong className="text-muted">Last used</strong>
              <div style={{ fontSize: '0.9em' }}>
                {meta.last_used_at ? formatDateTime(meta.last_used_at, true) : 'Never'}
              </div>
            </div>
            <div>
              <strong className="text-muted">Expires</strong>
              <div style={{ fontSize: '0.9em' }}>
                {meta.expires_at ? formatDateTime(meta.expires_at, true) : 'Never'}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card shadow mb-4" data-testid="access-token-about-card">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-info-circle me-2" aria-hidden="true" />
            About Access Tokens
          </h6>
        </div>
        <div className="card-body">
          <h6 className="font-weight-bold">What are access tokens?</h6>
          <p style={{ fontSize: '0.9em' }}>
            Personal access tokens (PATs) are long-lived bearer credentials that authenticate a
            service account to the management API without an interactive session.
          </p>

          <h6 className="font-weight-bold mt-3">Using a token</h6>
          <p style={{ fontSize: '0.9em' }}>Send it as a bearer token on the management API:</p>
          <code className="d-block p-2 bg-light rounded mb-3">
            Authorization: Bearer &lt;token&gt;
          </code>

          <h6 className="font-weight-bold mt-3">Scopes &amp; the bound user</h6>
          <p style={{ fontSize: '0.9em' }}>
            A token is bound to the admin who creates it (shown as <strong>Bound user</strong>) and
            can never exceed that user&apos;s <strong>role</strong> — administrator, power user, or
            user. Its effective permissions are the intersection of that role and the scopes you
            pick, so scopes only <em>narrow</em>, never widen.
          </p>
          <p className="mb-0" style={{ fontSize: '0.9em' }}>
            Leave scopes empty to grant the bound user&apos;s full role. To change what is possible
            at all, update that user&apos;s role on their account page.
          </p>
        </div>
      </div>
    </>
  );
};

export default AccessTokenSidebar;
