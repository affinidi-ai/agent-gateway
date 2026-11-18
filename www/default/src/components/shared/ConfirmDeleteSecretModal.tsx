import React from 'react';
import { Button, Modal } from 'react-bootstrap';
import { ReferenceConflict } from '../../utils/referenceConflict';
import ReferenceList from './ReferenceList';

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
}) => (
  <Modal
    show
    onHide={busy ? undefined : onCancel}
    centered
    aria-labelledby="confirm-delete-secret-title"
    data-testid="confirm-delete-secret-modal"
  >
    <Modal.Header closeButton>
      <Modal.Title id="confirm-delete-secret-title">Delete secret "{secretName}"?</Modal.Title>
    </Modal.Header>
    <Modal.Body>
      <p>
        This secret is in use. Deleting it anyway leaves these without it, and they stop working
        until you pick another secret:
      </p>
      <ReferenceList conflict={conflict} testId="confirm-delete-secret-references" />
    </Modal.Body>
    <Modal.Footer>
      <Button
        variant="secondary"
        onClick={busy ? undefined : onCancel}
        aria-disabled={busy}
        autoFocus
        data-testid="confirm-delete-secret-cancel"
      >
        Cancel
      </Button>
      <Button
        variant="danger"
        onClick={busy ? undefined : onConfirm}
        aria-disabled={busy}
        data-testid="confirm-delete-secret-confirm"
      >
        {busy ? 'Deleting…' : 'Delete secret anyway'}
      </Button>
    </Modal.Footer>
  </Modal>
);

export default ConfirmDeleteSecretModal;
