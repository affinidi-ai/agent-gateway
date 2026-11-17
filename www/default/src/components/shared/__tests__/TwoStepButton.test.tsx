import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { TwoStepButton } from '../TwoStepButton';

const renderButton = (props: Partial<React.ComponentProps<typeof TwoStepButton>> = {}) => {
  const onConfirm = jest.fn();
  render(
    <TwoStepButton
      onConfirm={onConfirm}
      icon="fa-ban"
      confirmLabel="Click again to revoke all"
      title="Revoke all"
      confirmTitle="Click again to revoke all of them"
      className="btn btn-link btn-sm text-warning"
      data-testid="two-step"
      {...props}
    />
  );
  return { onConfirm, button: () => screen.getByTestId('two-step') };
};

describe('TwoStepButton', () => {
  it('asks inline with a warning icon by default, and acts on the second click', async () => {
    const { onConfirm, button } = renderButton();

    fireEvent.click(button());
    expect(button()).toHaveTextContent('Click again to revoke all');
    expect(button()).toHaveClass('text-warning');
    expect(button().innerHTML).toContain('fa-exclamation-triangle');
    expect(onConfirm).not.toHaveBeenCalled();

    fireEvent.click(button());
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1));
  });

  it('asks as a danger button that reads the confirm label', async () => {
    const { onConfirm, button } = renderButton({
      confirmAs: 'danger',
      confirmLabel: 'Revoke all 2 for this user?',
    });

    fireEvent.click(button());
    expect(button()).toHaveTextContent(/^Revoke all 2 for this user\?$/);
    expect(button()).toHaveClass('btn', 'btn-danger', 'btn-sm');
    expect(button()).not.toHaveClass('text-warning');
    expect(button().innerHTML).not.toContain('fa-exclamation-triangle');
    expect(button().innerHTML).not.toContain('small');

    fireEvent.click(button());
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(button()).toHaveClass('text-warning'));
  });

  it('asks no more after Escape, and acts on nothing', () => {
    const { onConfirm, button } = renderButton({
      confirmAs: 'danger',
      confirmLabel: 'Revoke all 2 for this user?',
    });
    fireEvent.click(button());
    expect(button()).toHaveTextContent(/^Revoke all 2 for this user\?$/);

    fireEvent.keyDown(document, { key: 'Enter' });
    expect(button()).toHaveClass('btn-danger');
    fireEvent.keyDown(document, { key: 'Escape' });

    expect(button()).toHaveClass('text-warning');
    expect(button()).not.toHaveClass('btn-danger');
    expect(button()).toHaveAccessibleName('Revoke all');
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('names a danger confirm by what it reads', () => {
    const { button } = renderButton({ confirmAs: 'danger', confirmLabel: 'Revoke GitHub access?' });

    fireEvent.click(button());
    expect(button()).toHaveAccessibleName('Revoke GitHub access?');
  });

  it('shows a text button without an icon', () => {
    const { button } = renderButton({ icon: undefined, label: 'Revoke' });

    expect(button()).toHaveTextContent(/^Revoke$/);
    expect(button().innerHTML).not.toContain('fa-');
    expect(button().innerHTML).not.toContain('small');
  });

  it('offers Cancel beside the confirm, which asks no more and acts on nothing', () => {
    const { onConfirm, button } = renderButton({
      icon: undefined,
      label: 'Revoke',
      confirmAs: 'danger',
      confirmLabel: 'Revoke GitHub access?',
      cancelTestId: 'two-step-cancel',
    });
    expect(screen.queryByTestId('two-step-cancel')).toBeNull();

    fireEvent.click(button());
    const cancel = screen.getByTestId('two-step-cancel');
    expect(cancel).toHaveTextContent(/^Cancel$/);
    fireEvent.mouseDown(cancel);
    fireEvent.click(cancel);

    expect(screen.queryByTestId('two-step-cancel')).toBeNull();
    expect(button()).toHaveTextContent(/^Revoke$/);
    expect(button()).toHaveFocus();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  describe('once it listens for a click elsewhere', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    const asking = () => {
      const view = renderButton({
        icon: undefined,
        label: 'Revoke',
        confirmAs: 'danger',
        confirmLabel: 'Revoke GitHub access?',
        cancelTestId: 'two-step-cancel',
      });
      fireEvent.click(view.button());
      act(() => {
        jest.advanceTimersByTime(100);
      });
      return view;
    };

    it('asks no more after a press elsewhere', () => {
      const { onConfirm, button } = asking();

      fireEvent.mouseDown(document.body);

      expect(button()).toHaveTextContent(/^Revoke$/);
      expect(onConfirm).not.toHaveBeenCalled();
    });

    it('keeps asking while Cancel is pressed, so that Cancel returns the focus', () => {
      const { button } = asking();
      const cancel = screen.getByTestId('two-step-cancel');

      fireEvent.mouseDown(cancel);
      expect(screen.getByTestId('two-step-cancel')).toBeInTheDocument();
      fireEvent.click(cancel);

      expect(button()).toHaveTextContent(/^Revoke$/);
      expect(button()).toHaveFocus();
    });
  });
});
