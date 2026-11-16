import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
});
