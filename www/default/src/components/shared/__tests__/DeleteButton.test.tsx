import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { DeleteButton } from '../DeleteButton';

describe('DeleteButton confirm notice', () => {
  it('keeps the status region mounted and fills it during the confirm step only', () => {
    const onDelete = jest.fn();
    render(<DeleteButton onDelete={onDelete} confirmNotice="Record is kept." />);

    const region = screen.getByRole('status');
    expect(region.textContent).toBe('');

    fireEvent.click(screen.getByRole('button'));

    expect(screen.getByRole('status')).toBe(region);
    expect(region).toHaveTextContent('Record is kept.');
    expect(onDelete).not.toHaveBeenCalled();
  });

  it('empties the notice again when the confirm step is cancelled', () => {
    render(<DeleteButton onDelete={jest.fn()} confirmNotice="Record is kept." />);

    fireEvent.click(screen.getByRole('button'));
    fireEvent.keyDown(document, { key: 'Escape' });

    expect(screen.getByTestId('delete-confirm-notice').textContent).toBe('');
  });

  it('shows no notice when none is given', () => {
    render(<DeleteButton onDelete={jest.fn()} />);

    fireEvent.click(screen.getByRole('button'));

    expect(screen.queryByTestId('delete-confirm-notice')).toBeNull();
  });
});
