import React from 'react';
import { Badge } from '../../components/shared/Badge';
import type { IdentityOrigin } from '../../types';

const ORIGIN_BADGES: Record<
  IdentityOrigin,
  { label: string; icon: string; tone: 'info' | 'warning'; title: string }
> = {
  managed: {
    label: 'Managed Agent',
    icon: 'fa-robot',
    tone: 'info',
    title: 'Identity the gateway manages for one of its surfaces',
  },
  external_caller: {
    label: 'External Caller',
    icon: 'fa-user-secret',
    tone: 'warning',
    title: 'Identity presented by a caller outside this gateway',
  },
};

interface IdentityOriginBadgeProps {
  origin?: IdentityOrigin;
}

export const IdentityOriginBadge: React.FC<IdentityOriginBadgeProps> = ({ origin }) => {
  if (!origin || !ORIGIN_BADGES[origin]) return null;
  const { label, icon, tone, title } = ORIGIN_BADGES[origin];
  return (
    <Badge
      tone={tone}
      size="sm"
      title={title}
      data-testid={`identities-origin-${origin}`}
      prefix={<i className={`fas ${icon} me-1`} aria-hidden="true"></i>}
      value={label}
    />
  );
};

export default IdentityOriginBadge;
