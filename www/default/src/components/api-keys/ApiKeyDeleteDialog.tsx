import React, { useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { getErrorMessage } from '../../utils/apiError';

interface ApiKeyDeleteDialogProps {
  keyId: string;
  clientId?: string;
  onCancel: () => void;
  onConfirm: () => Promise<void>;
}

/** Confirmation before deleting an API key, naming what happens to the surfaces using it. */
export const ApiKeyDeleteDialog: React.FC<ApiKeyDeleteDialogProps> = ({
  keyId,
  clientId,
  onCancel,
  onConfirm,
}) => {
  const [deleting, setDeleting] = useState(false);

  const confirm = async () => {
    setDeleting(true);
    try {
      await onConfirm();
    } finally {
      setDeleting(false);
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
        aria-labelledby="api-key-delete-dialog-title"
        data-testid="api-key-delete-dialog"
      >
        <div className="modal-dialog modal-dialog-centered">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="api-key-delete-dialog-title">
                <i className="fas fa-triangle-exclamation me-2 text-danger" aria-hidden="true" />
                Delete API key
              </h5>
              <button type="button" className="btn-close" onClick={onCancel} aria-label="Close" />
            </div>
            <div className="modal-body">
              <p>
                Delete {clientId ? <strong>{clientId}</strong> : null} <code>{keyId}</code>?
              </p>
              <p className="mb-0">
                Callers presenting this key are refused. Any surface whose Identity uses this key
                becomes Unconfigured and stops serving requests until you select another API key for
                it. This can&apos;t be undone.
              </p>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                data-testid="api-key-delete-dialog-confirm"
                disabled={deleting}
                onClick={confirm}
              >
                {deleting ? (
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  />
                ) : (
                  <i className="fas fa-trash me-1" aria-hidden="true" />
                )}
                Delete API key
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show" />
    </>
  );
};

interface PendingDelete {
  agentId: string;
  keyId: string;
  clientId?: string;
}

/**
 * Asks for confirmation with `dialog`, then deletes the API key. `onDeleted`
 * runs after a delete; a failed delete shows an error toast.
 */
export function useApiKeyDelete(onDeleted: () => void) {
  const [pending, setPending] = useState<PendingDelete | null>(null);

  const requestDelete = (agentId: string, keyId: string, clientId?: string) => {
    setPending({ agentId, keyId, clientId });
  };

  const confirmDelete = async () => {
    if (!pending) return;
    try {
      await apiClient.deleteApiKey(pending.agentId, pending.keyId);
      setPending(null);
      showToast('success', 'API key deleted');
      onDeleted();
    } catch (error) {
      setPending(null);
      console.error('Failed to delete API key:', error);
      showToast('error', `Delete failed: ${getErrorMessage(error, 'Failed to delete API key')}`, {
        autoRemove: false,
      });
    }
  };

  const dialog = pending ? (
    <ApiKeyDeleteDialog
      keyId={pending.keyId}
      clientId={pending.clientId}
      onCancel={() => setPending(null)}
      onConfirm={confirmDelete}
    />
  ) : null;

  return { requestDelete, dialog };
}
