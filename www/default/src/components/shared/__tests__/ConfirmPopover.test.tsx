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
  render(
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
  return { anchor, onConfirm, onCancel };
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

  it('shows the given icon', async () => {
    renderPopover({ icon: 'fa-triangle-exclamation text-danger' });

    const dialog = await screen.findByRole('dialog');

    expect(dialog).toContainHTML('fas fa-triangle-exclamation text-danger me-2');
  });
});
