import React from 'react';
import { ReferenceConflict } from '../../utils/referenceConflict';
import ReferenceList from './ReferenceList';
import { WarningDialog } from './WarningDialog';

interface ConfirmDeleteSecretModalProps {
  secretName: string;
  conflict: ReferenceConflict;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/**
 * Asks before deleting a secret other resources still use; confirming forces the delete. While
 * the delete runs the buttons stay focusable and ignore clicks, so focus stays in the dialog.
 */
const ConfirmDeleteSecretModal: React.FC<ConfirmDeleteSecretModalProps> = ({
  secretName,
  conflict,
  busy,
  onCancel,
  onConfirm,
}) => {
  const cancel = busy ? undefined : onCancel;
  return (
    <WarningDialog
      testId="confirm-delete-secret-modal"
      title={`Delete secret "${secretName}"?`}
      onClose={() => cancel?.()}
      footer={
        <>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={cancel}
            aria-disabled={busy}
            autoFocus
            data-testid="confirm-delete-secret-cancel"
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={busy ? undefined : onConfirm}
            aria-disabled={busy}
            data-testid="confirm-delete-secret-confirm"
          >
            {busy ? 'Deleting…' : 'Delete secret anyway'}
          </button>
        </>
      }
    >
      <p>
        This secret is in use. Deleting it anyway leaves these without it, and they stop working
        until you pick another secret:
      </p>
      <ReferenceList conflict={conflict} testId="confirm-delete-secret-references" />
    </WarningDialog>
  );
};

export default ConfirmDeleteSecretModal;
