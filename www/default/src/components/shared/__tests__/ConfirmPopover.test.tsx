import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConfirmPopover from '../ConfirmPopover';

const anchors: HTMLElement[] = [];

const renderPopover = (props: Partial<React.ComponentProps<typeof ConfirmPopover>> = {}) => {
  const anchor = document.createElement('button');
  document.body.appendChild(anchor);
  anchors.push(anchor);
  const onConfirm = jest.fn();
  const onCancel = jest.fn();
  const { unmount } = render(
    <ConfirmPopover
      anchor={anchor}
      testId="thing-delete-confirm"
      title="Delete thing?"
      confirmLabel="Delete"
      confirmVariant="danger"
      onConfirm={onConfirm}
      onCancel={onCancel}
      {...props}
    >
      This cannot be undone.
    </ConfirmPopover>
  );
  return { anchor, onConfirm, onCancel, unmount };
};

describe('ConfirmPopover', () => {
  afterEach(() => {
    anchors.splice(0).forEach(anchor => anchor.remove());
  });

  it('is a dialog named by its title under the given test id', async () => {
    renderPopover();

    const dialog = await screen.findByRole('dialog', { name: 'Delete thing?' });

    expect(dialog).toHaveAttribute('data-testid', 'thing-delete-confirm');
    expect(dialog).toHaveTextContent('This cannot be undone.');
  });

  it('confirms on the confirm button and cancels on Cancel', async () => {
    const { onConfirm, onCancel } = renderPopover();

    fireEvent.click(await screen.findByTestId('thing-delete-confirm-confirm'));
    fireEvent.click(screen.getByTestId('thing-delete-confirm-cancel'));

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('cancels on Escape and on a click outside, but not on a click on its anchor', async () => {
    const { anchor, onCancel } = renderPopover();
    await screen.findByRole('dialog');

    fireEvent.mouseDown(anchor);
    expect(onCancel).not.toHaveBeenCalled();

    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.mouseDown(document.body);
    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it('locks both buttons and ignores Escape while busy', async () => {
    const { onCancel } = renderPopover({ busy: true });

    expect(await screen.findByTestId('thing-delete-confirm-confirm')).toBeDisabled();
    expect(screen.getByTestId('thing-delete-confirm-cancel')).toBeDisabled();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('shows the given icon, in red for a danger confirmation', async () => {
    renderPopover({ icon: 'fa-triangle-exclamation' });

    const dialog = await screen.findByRole('dialog');

    expect(dialog).toContainHTML('fas fa-triangle-exclamation me-2 text-danger');
  });

  it('focuses Cancel when it opens and returns focus to the anchor when it closes', async () => {
    const { anchor, unmount } = renderPopover();

    expect(await screen.findByTestId('thing-delete-confirm-cancel')).toHaveFocus();
    unmount();

    expect(anchor).toHaveFocus();
  });

  it('keeps every key from reaching a window listener while open', async () => {
    const windowKeys = jest.fn();
    window.addEventListener('keydown', windowKeys);
    renderPopover();
    await screen.findByRole('dialog');

    fireEvent.keyDown(screen.getByTestId('thing-delete-confirm-cancel'), { key: 'Backspace' });
    fireEvent.keyDown(document, { key: 's', metaKey: true });
    window.removeEventListener('keydown', windowKeys);

    expect(windowKeys).not.toHaveBeenCalled();
  });
});
