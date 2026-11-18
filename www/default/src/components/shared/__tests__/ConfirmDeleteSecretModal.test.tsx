import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
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

  it('keeps its buttons focusable and ignores clicks while the delete runs', () => {
    const { onCancel, onConfirm } = renderModal(true);
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
