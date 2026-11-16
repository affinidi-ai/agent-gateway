import React from 'react';

export const REVOKED_IDENTITY_MESSAGE =
  'This identity is no longer in use: its API key was revoked or deleted, or its surface was deleted.';

/** Same look as a revoked key's status on the API key table: solid red, white text. */
export const RevokedIdentityBadge: React.FC<{ className?: string }> = ({ className }) => (
  <span
    className={['badge text-bg-danger', className].filter(Boolean).join(' ')}
    title={REVOKED_IDENTITY_MESSAGE}
    data-testid="identities-revoked-badge"
  >
    Revoked
  </span>
);

export const RevokedIdentityInfo: React.FC<{ className?: string }> = ({ className }) => (
  <div
    className={['alert alert-danger', className].filter(Boolean).join(' ')}
    role="status"
    data-testid="identity-revoked-info"
  >
    <i className="fas fa-ban me-2" aria-hidden="true"></i>
    {REVOKED_IDENTITY_MESSAGE}
  </div>
);
