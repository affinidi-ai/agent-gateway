import React from 'react';
import { WarningDialog } from '../shared/WarningDialog';

interface SurfaceDeleteDialogProps {
  surfaceName: string;
  deleting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const TEST_ID = 'surface-delete-dialog';

/** Confirmation before a surface is permanently deleted, naming the surface. */
export const SurfaceDeleteDialog: React.FC<SurfaceDeleteDialogProps> = ({
  surfaceName,
  deleting,
  onCancel,
  onConfirm,
}) => (
  <WarningDialog
    testId={TEST_ID}
    title="Delete Surface?"
    onClose={onCancel}
    footer={
      <>
        <button type="button" className="btn btn-secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-danger"
          data-testid={`${TEST_ID}-confirm`}
          disabled={deleting}
          onClick={onConfirm}
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
          Delete surface
        </button>
      </>
    }
  >
    <p>
      You are about to permanently delete <strong>{surfaceName}</strong> and all associated
      configuration. This action cannot be undone.
    </p>
    <p className="mb-0">Are you sure you want to continue?</p>
  </WarningDialog>
);
