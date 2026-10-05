import React from 'react';
import type { AccessTokenMeta } from '../../types';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';
import { DeleteButton } from '../../components/shared/DeleteButton';

interface AccessTokenRowProps {
  token: AccessTokenMeta;
  canRevoke: boolean;
  onOpen: () => void;
  onRevoke: () => void;
}

const status = (token: AccessTokenMeta) => {
  if (token.revoked_at) return { label: 'Revoked', className: 'text-bg-danger' };
  if (!token.active) return { label: 'Expired', className: 'text-bg-warning' };
  return { label: 'Active', className: 'text-bg-success' };
};

const AccessTokenRow: React.FC<AccessTokenRowProps> = ({ token, canRevoke, onOpen, onRevoke }) => {
  const tokenStatus = status(token);
  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onOpen();
    }
  };

  return (
    <tr
      className="cursor-pointer"
      onClick={onOpen}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="link"
      aria-label={`Edit access token ${token.name}`}
      data-testid={`access-token-row-${token.id}`}
    >
      <td>
        <strong>{token.name}</strong>
        {token.description && <div className="text-muted small">{token.description}</div>}
      </td>
      <td>
        {token.scopes.length === 0 ? (
          <span className="text-muted small">Full role</span>
        ) : (
          <>
            {token.scopes.slice(0, 3).map(scope => (
              <span className="badge text-bg-secondary me-1" key={scope}>
                {scope}
              </span>
            ))}
            {token.scopes.length > 3 && <span className="small">+{token.scopes.length - 3}</span>}
          </>
        )}
      </td>
      <td>
        <span className={`badge ${tokenStatus.className}`}>{tokenStatus.label}</span>
      </td>
      <td>
        <small
          title={token.last_used_at ? formatDateTime(token.last_used_at, true) : undefined}
          data-testid={`access-token-last-used-${token.id}`}
        >
          {token.last_used_at ? timeAgo(token.last_used_at) : 'Never'}
        </small>
      </td>
      <td>
        <small data-testid={`access-token-expires-${token.id}`}>
          {token.expires_at ? formatDateTime(token.expires_at, true) : 'Never'}
        </small>
      </td>
      <td>
        <small
          title={formatDateTime(token.created_at, true)}
          data-testid={`access-token-created-${token.id}`}
        >
          {timeAgo(token.created_at)}
        </small>
      </td>
      {canRevoke && (
        <td onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}>
          <DeleteButton
            onDelete={onRevoke}
            title="Revoke access token"
            disabled={Boolean(token.revoked_at)}
            data-testid={`access-token-revoke-${token.id}`}
          />
        </td>
      )}
    </tr>
  );
};

export default AccessTokenRow;
