import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConfirmPopover, { placeConfirmPopover } from '../ConfirmPopover';

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

    // Cancel is focused by an effect that runs after the balloon is placed, and
    // findByTestId resolves as soon as it is in the DOM, so wait for the focus.
    const cancel = await screen.findByTestId('thing-delete-confirm-cancel');
    await waitFor(() => expect(cancel).toHaveFocus());
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

const rectAt = (left: number, top: number, width = 32, height = 32) =>
  ({
    left,
    top,
    width,
    height,
    right: left + width,
    bottom: top + height,
    x: left,
    y: top,
    toJSON: () => ({}),
  }) as DOMRect;

describe('placeConfirmPopover', () => {
  const viewport = { width: 1280, height: 720 };
  const size = { width: 300, height: 160 };
  const anchorAt = (left: number, top: number) => rectAt(left, top);

  it('opens to the left of an anchor with room on its left, centred on it', () => {
    expect(placeConfirmPopover(anchorAt(900, 300), size, viewport)).toEqual({
      left: 900 - 12 - 300,
      top: 316 - 80,
      side: 'left',
      tailTop: 80,
    });
  });

  it('opens to the right of an anchor too close to the left edge', () => {
    const placement = placeConfirmPopover(anchorAt(180, 300), size, viewport);

    expect(placement.side).toBe('right');
    expect(placement.left).toBe(180 + 32 + 12);
  });

  it('stays inside the bottom of the viewport and keeps the tail on the anchor', () => {
    const placement = placeConfirmPopover(anchorAt(180, 680), size, viewport);

    expect(placement.top).toBe(720 - 160 - 8);
    expect(placement.top + placement.tailTop).toBe(696);
  });

  it('stays inside the top of the viewport', () => {
    expect(placeConfirmPopover(anchorAt(900, 0), size, viewport).top).toBe(8);
  });

  it('stays inside the viewport when neither side has room', () => {
    const placement = placeConfirmPopover(anchorAt(150, 300), size, { width: 400, height: 720 });

    expect(placement.left).toBeGreaterThanOrEqual(8);
    expect(placement.left + size.width).toBeLessThanOrEqual(400 - 8);
  });
});

describe('ConfirmPopover placement', () => {
  afterEach(() => {
    anchors.splice(0).forEach(anchor => anchor.remove());
  });

  it('flips to the right of an anchor near the left edge of the window', async () => {
    const { anchor } = renderPopover();
    jest.spyOn(anchor, 'getBoundingClientRect').mockReturnValue(rectAt(40, 300));

    const dialog = await screen.findByRole('dialog');

    await waitFor(() => expect(dialog).toHaveClass('confirm-popover--right'));
    expect(dialog).toHaveStyle({ left: `${40 + 32 + 12}px` });
  });

  it('opens to the left of an anchor with room on its left', async () => {
    const { anchor } = renderPopover();
    jest.spyOn(anchor, 'getBoundingClientRect').mockReturnValue(rectAt(900, 300));

    const dialog = await screen.findByRole('dialog');

    await waitFor(() => expect(dialog).toHaveClass('confirm-popover--left'));
    expect(dialog).toHaveStyle({ left: `${900 - 12 - 300}px` });
  });
});
