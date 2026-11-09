import React, { useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { getErrorMessage } from '../../utils/apiError';

export type ApiKeyAction = 'delete' | 'revoke';

interface ActionCopy {
  title: string;
  question: string;
  consequence: string;
  confirmClass: string;
  confirmIcon: string;
  done: string;
  failed: string;
  fallbackError: string;
  run: (agentId: string, keyId: string) => Promise<void>;
}

const ACTIONS: Record<ApiKeyAction, ActionCopy> = {
  delete: {
    title: 'Delete API key',
    question: 'Delete',
    consequence:
      "Callers using this key will be refused. Surfaces that use it will stop working until you pick another key. You can't undo this.",
    confirmClass: 'btn-danger',
    confirmIcon: 'fa-trash',
    done: 'API key deleted',
    failed: 'Delete failed',
    fallbackError: 'Failed to delete API key',
    run: (agentId, keyId) => apiClient.deleteApiKey(agentId, keyId),
  },
  revoke: {
    title: 'Revoke API key',
    question: 'Revoke',
    consequence:
      "Surfaces that use this key will stop serving until you select another key. A revoked key can't be restored, and selecting a new key gives the surface a new DID.",
    confirmClass: 'btn-warning',
    confirmIcon: 'fa-ban',
    done: 'API key revoked',
    failed: 'Revoke failed',
    fallbackError: 'Failed to revoke API key',
    run: (agentId, keyId) => apiClient.revokeApiKey(agentId, keyId, 'dashboard'),
  },
};

interface ApiKeyActionDialogProps {
  action: ApiKeyAction;
  keyId: string;
  clientId?: string;
  onCancel: () => void;
  onConfirm: () => Promise<void>;
}

/** Confirmation before deleting or revoking an API key, naming what happens to the surfaces using it. */
export const ApiKeyActionDialog: React.FC<ApiKeyActionDialogProps> = ({
  action,
  keyId,
  clientId,
  onCancel,
  onConfirm,
}) => {
  const [running, setRunning] = useState(false);
  const copy = ACTIONS[action];
  const testId = `api-key-${action}-dialog`;

  const confirm = async () => {
    setRunning(true);
    try {
      await onConfirm();
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <div
        className="modal fade show"
        style={{ display: 'block' }}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${testId}-title`}
        data-testid={testId}
      >
        <div className="modal-dialog modal-dialog-centered">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id={`${testId}-title`}>
                <i className="fas fa-triangle-exclamation me-2 text-danger" aria-hidden="true" />
                {copy.title}
              </h5>
              <button type="button" className="btn-close" onClick={onCancel} aria-label="Close" />
            </div>
            <div className="modal-body">
              <p>
                {copy.question} {clientId ? <strong>{clientId}</strong> : null} <code>{keyId}</code>
                ?
              </p>
              <p className="mb-0">{copy.consequence}</p>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                Cancel
              </button>
              <button
                type="button"
                className={`btn ${copy.confirmClass}`}
                data-testid={`${testId}-confirm`}
                disabled={running}
                onClick={confirm}
              >
                {running ? (
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  />
                ) : (
                  <i className={`fas ${copy.confirmIcon} me-1`} aria-hidden="true" />
                )}
                {copy.title}
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show" />
    </>
  );
};

interface PendingAction {
  agentId: string;
  keyId: string;
  clientId?: string;
}

/**
 * Asks for confirmation with `dialog`, then deletes or revokes the API key.
 * `onDone` runs after it succeeds; a failure shows an error toast.
 */
export function useApiKeyAction(action: ApiKeyAction, onDone: () => void) {
  const [pending, setPending] = useState<PendingAction | null>(null);
  const copy = ACTIONS[action];

  const request = (agentId: string, keyId: string, clientId?: string) => {
    setPending({ agentId, keyId, clientId });
  };

  const confirm = async () => {
    if (!pending) return;
    try {
      await copy.run(pending.agentId, pending.keyId);
      setPending(null);
      showToast('success', copy.done);
      onDone();
    } catch (error) {
      setPending(null);
      console.error(`${copy.fallbackError}:`, error);
      showToast('error', `${copy.failed}: ${getErrorMessage(error, copy.fallbackError)}`, {
        autoRemove: false,
      });
    }
  };

  const dialog = pending ? (
    <ApiKeyActionDialog
      action={action}
      keyId={pending.keyId}
      clientId={pending.clientId}
      onCancel={() => setPending(null)}
      onConfirm={confirm}
    />
  ) : null;

  return { request, dialog };
}
