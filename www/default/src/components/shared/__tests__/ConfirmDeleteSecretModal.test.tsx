import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConfirmDeleteSecretModal from '../ConfirmDeleteSecretModal';

const conflict = {
  message: 'In use',
  references: [{ kind: 'surface', id: 's-1', name: 'Orders' }],
  hiddenReferences: 2,
};

const renderModal = (busy: boolean) => {
  const onCancel = jest.fn();
  const onConfirm = jest.fn();
  render(
    <ConfirmDeleteSecretModal
      secretName="partner-key"
      conflict={conflict}
      busy={busy}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  );
  return { onCancel, onConfirm };
};

describe('ConfirmDeleteSecretModal', () => {
  it('names the secret and what uses it, and forces the delete only on confirm', () => {
    const { onCancel, onConfirm } = renderModal(false);
    expect(screen.getByRole('dialog')).toHaveAccessibleName('Delete secret "partner-key"?');
    expect(screen.getByTestId('confirm-delete-secret-references')).toHaveTextContent(
      'Surface: Orders'
    );
    expect(screen.getByTestId('confirm-delete-secret-references-hidden')).toHaveTextContent(
      'and 2 more you cannot view'
    );
    expect(onConfirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId('confirm-delete-secret-confirm'));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByTestId('confirm-delete-secret-cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('is the shared warning dialog, with focus on Cancel and a close button that cancels', () => {
    const { onCancel } = renderModal(false);
    const dialog = screen.getByTestId('confirm-delete-secret-modal');
    expect(dialog).toHaveAttribute('role', 'dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'confirm-delete-secret-modal-title');
    expect(
      within(dialog).getByRole('heading', { name: 'Delete secret "partner-key"?' })
    ).toBeInTheDocument();
    expect(screen.getByTestId('confirm-delete-secret-cancel')).toHaveFocus();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('keeps its buttons focusable and ignores clicks while the delete runs', () => {
    const { onCancel, onConfirm } = renderModal(true);
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    const confirm = screen.getByTestId('confirm-delete-secret-confirm');
    const cancel = screen.getByTestId('confirm-delete-secret-cancel');
    expect(confirm).toHaveAttribute('aria-disabled', 'true');
    expect(cancel).toHaveAttribute('aria-disabled', 'true');
    expect(confirm).not.toBeDisabled();
    expect(confirm).toHaveTextContent('Deleting…');
    fireEvent.click(confirm);
    fireEvent.click(cancel);
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });
});
