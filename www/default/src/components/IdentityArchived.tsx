import React from 'react';
import { Badge } from './shared/Badge';

export const ARCHIVED_IDENTITY_MESSAGE =
  'This identity is no longer in use because the associated surface has been deleted.';

export const ArchivedIdentityBadge: React.FC<{ className?: string }> = ({ className }) => (
  <Badge
    tone="secondary"
    size="sm"
    value="Archived"
    className={className}
    title={ARCHIVED_IDENTITY_MESSAGE}
    data-testid="identities-archived-badge"
  />
);

export const ArchivedIdentityInfo: React.FC<{ className?: string }> = ({ className }) => (
  <div
    className={['alert alert-info', className].filter(Boolean).join(' ')}
    role="status"
    data-testid="identity-archived-info"
  >
    <i className="fas fa-info-circle me-2" aria-hidden="true"></i>
    {ARCHIVED_IDENTITY_MESSAGE}
  </div>
);
