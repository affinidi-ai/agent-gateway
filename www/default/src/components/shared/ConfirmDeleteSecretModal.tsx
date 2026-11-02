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

/** Asks before deleting a secret other resources still use; confirming forces the delete. */
const ConfirmDeleteSecretModal: React.FC<ConfirmDeleteSecretModalProps> = ({
  secretName,
  conflict,
  busy,
  onCancel,
  onConfirm,
}) => (
  <Modal show onHide={onCancel} centered data-testid="confirm-delete-secret-modal">
    <Modal.Header closeButton>
      <Modal.Title>Delete secret "{secretName}"?</Modal.Title>
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
        onClick={onCancel}
        disabled={busy}
        data-testid="confirm-delete-secret-cancel"
      >
        Cancel
      </Button>
      <Button
        variant="danger"
        onClick={onConfirm}
        disabled={busy}
        data-testid="confirm-delete-secret-confirm"
      >
        Delete secret anyway
      </Button>
    </Modal.Footer>
  </Modal>
);

export default ConfirmDeleteSecretModal;
