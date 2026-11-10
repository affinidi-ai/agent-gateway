import React, { useState } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { formatDateTime } from '../../utils/stringUtils';
import {
  TRANSPORT_LABELS,
  isOverPrivileged,
  canRevoke,
  canVerify,
  canRotateControlKey,
  isRotatingControlKey,
  isUsable,
  presentPairing,
} from './vtaConnectionHelpers';
import type { VtaConnection } from './types';

interface VtaConnectionsListProps {
  connections: VtaConnection[];
  busyId: string | null;
  canEdit: boolean;
  canDelete: boolean;
  /** Whether the user may manage keys (`key_management.edit`). */
  canRotateKeys: boolean;
  onOpen: (connection: VtaConnection) => void;
  onVerify: (connection: VtaConnection) => void;
  onRevoke: (connection: VtaConnection) => void;
  onRotateKey: (connection: VtaConnection) => void;
  onCancelRotation: (connection: VtaConnection) => void;
}

export const VtaConnectionsList: React.FC<VtaConnectionsListProps> = ({
  connections,
  busyId,
  canEdit,
  canDelete,
  canRotateKeys,
  onOpen,
  onVerify,
  onRevoke,
  onRotateKey,
  onCancelRotation,
}) => {
  const [confirming, setConfirming] = useState<string | null>(null);
  return (
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
            const hasWebvhIdentity = (connection.control_did ?? '').startsWith('did:webvh:');
            const keyState = connection.control_key_state;
            const rotating = isRotatingControlKey(connection);
            return (
              <React.Fragment key={connection.id}>
                <tr
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
                    {!connection.enabled && (
                      <span className="badge bg-secondary mt-1">Disabled</span>
                    )}
                  </td>
                  <td>
                    <code className="small">{connection.vta_did}</code>
                    {connection.default_context_id && (
                      <div className="small text-muted">
                        context: {connection.default_context_id}
                      </div>
                    )}
                    {hasWebvhIdentity && (
                      <div className="small text-muted mt-1" data-testid="vta-row-control-key">
                        Control key {(keyState?.verification_method ?? '#key-1').replace('#', '')}
                        {' · '}
                        <span data-testid="vta-row-control-key-rotated-at">
                          {keyState?.rotated_at
                            ? `Rotated ${formatDateTime(keyState.rotated_at)}`
                            : 'Never rotated'}
                        </span>
                      </div>
                    )}
                    {rotating && (
                      <div
                        className="small text-warning mt-1"
                        data-testid="vta-row-rotation-status"
                      >
                        <i className="fas fa-rotate me-1" aria-hidden="true" />
                        Rotating control key…
                      </div>
                    )}
                    {keyState?.last_error && (
                      <div className="small text-danger mt-1" data-testid="vta-row-rotation-error">
                        {keyState.last_error}
                      </div>
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
                    {canEdit && canVerify(connection) && (
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
                    {canRotateKeys && canRotateControlKey(connection) && (
                      <AppButton
                        variant="outline-secondary"
                        size="sm"
                        className="me-2"
                        disabled={busyId === connection.id}
                        onClick={() => setConfirming(connection.id)}
                        data-testid="vta-row-rotate-control-key"
                      >
                        Rotate control key
                      </AppButton>
                    )}
                    {canRotateKeys && rotating && keyState?.rotation?.phase !== 'switched' && (
                      <AppButton
                        variant="outline-secondary"
                        size="sm"
                        className="me-2"
                        disabled={busyId === connection.id}
                        onClick={() => onCancelRotation(connection)}
                        data-testid="vta-row-rotate-cancel"
                      >
                        Cancel rotation
                      </AppButton>
                    )}
                    {canDelete && canRevoke(connection) && (
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
                {confirming === connection.id && (
                  <tr data-testid="vta-row-rotate-confirm-row">
                    <td colSpan={6}>
                      <div className="alert alert-warning mb-0" role="alertdialog">
                        <p className="mb-2" data-testid="vta-row-rotate-confirm-text">
                          The gateway adds a new key to this connection&apos;s DID, signs in with
                          it, then removes the old one. The DID and the grant on the trust agent do
                          not change. The trust agent may keep accepting the old key for up to its
                          DID cache time (60 seconds by default) afterwards.
                        </p>
                        <AppButton
                          variant="primary"
                          size="sm"
                          className="me-2"
                          onClick={() => {
                            setConfirming(null);
                            onRotateKey(connection);
                          }}
                          data-testid="vta-row-rotate-confirm"
                        >
                          Rotate now
                        </AppButton>
                        <AppButton
                          variant="outline-secondary"
                          size="sm"
                          onClick={() => setConfirming(null)}
                          data-testid="vta-row-rotate-confirm-cancel"
                        >
                          Cancel
                        </AppButton>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
