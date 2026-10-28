import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { formatDateTime } from '../../utils/stringUtils';
import {
  TRANSPORT_LABELS,
  isOverPrivileged,
  isUsable,
  presentPairing,
} from './vtaConnectionHelpers';
import type { VtaConnection } from './types';

interface VtaConnectionsListProps {
  connections: VtaConnection[];
  busyId: string | null;
  canEdit: boolean;
  canDelete: boolean;
  onOpen: (connection: VtaConnection) => void;
  onVerify: (connection: VtaConnection) => void;
  onRevoke: (connection: VtaConnection) => void;
}

export const VtaConnectionsList: React.FC<VtaConnectionsListProps> = ({
  connections,
  busyId,
  canEdit,
  canDelete,
  onOpen,
  onVerify,
  onRevoke,
}) => (
  <div className="table-responsive">
    <table className="table table-hover table-sm" width="100%" cellSpacing="0">
      <thead>
        <tr>
          <th>Name</th>
          <th>Agent</th>
          <th>Transport</th>
          <th>Status</th>
          <th>Last verified</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {connections.map(connection => {
          const presentation = presentPairing(connection.pairing.state);
          const overPrivileged = isOverPrivileged(connection.pairing);
          return (
            <tr
              key={connection.id}
              // The whole row opens the editor, matching the Access Tokens
              // list: no separate edit icon.
              tabIndex={0}
              role="button"
              style={{ cursor: 'pointer' }}
              onClick={() => onOpen(connection)}
              onKeyDown={event => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  onOpen(connection);
                }
              }}
            >
              <td>
                <div className="fw-semibold">{connection.name}</div>
                {connection.description && (
                  <div className="small text-muted">{connection.description}</div>
                )}
                {!connection.enabled && <span className="badge bg-secondary mt-1">Disabled</span>}
              </td>
              <td>
                <code className="small">{connection.vta_did}</code>
                {connection.default_context_id && (
                  <div className="small text-muted">context: {connection.default_context_id}</div>
                )}
              </td>
              <td>
                {TRANSPORT_LABELS[connection.transport]}
                <div className="small text-muted">{connection.endpoint}</div>
              </td>
              <td>
                <span className={`badge bg-${presentation.tone}`}>
                  <i className={`fas ${presentation.icon} me-1`} aria-hidden="true" />
                  {presentation.label}
                </span>
                {!isUsable(connection) && (
                  <div className="small text-muted mt-1">{presentation.hint}</div>
                )}
                {overPrivileged && (
                  <div className="small text-danger mt-1">
                    <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
                    Over-privileged grant ({connection.pairing.granted_role})
                  </div>
                )}
              </td>
              <td className="small text-muted">
                {connection.pairing.last_verified_at
                  ? formatDateTime(connection.pairing.last_verified_at)
                  : '—'}
              </td>
              <td onClick={event => event.stopPropagation()}>
                {canEdit && (
                  <AppButton
                    variant="outline-primary"
                    size="sm"
                    className="me-2"
                    disabled={busyId === connection.id}
                    onClick={() => onVerify(connection)}
                  >
                    {busyId === connection.id ? 'Checking…' : 'Verify'}
                  </AppButton>
                )}
                {canDelete && connection.pairing.state !== 'revoked' && (
                  <AppButton
                    variant="outline-danger"
                    size="sm"
                    disabled={busyId === connection.id}
                    onClick={() => onRevoke(connection)}
                  >
                    Revoke
                  </AppButton>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
