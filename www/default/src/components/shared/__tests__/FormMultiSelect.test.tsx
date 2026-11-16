import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import FormMultiSelect from '../FormMultiSelect';

const OPTIONS = [
  { value: 'grp', label: 'Group', disabled: true },
  { value: 'a', label: 'Alpha', description: 'First' },
  { value: 'b', label: 'Beta' },
];

describe('FormMultiSelect', () => {
  it('shows the check after the label of selected options only', () => {
    render(<FormMultiSelect values={['a']} options={OPTIONS} onToggle={jest.fn()} testid="ms" />);
    fireEvent.click(screen.getByTestId('ms'));

    const alpha = screen.getByTestId('ms-option-a');
    const check = screen.getByTestId('ms-option-a-check');
    expect(alpha).toHaveAttribute('aria-selected', 'true');
    expect(check).toHaveClass('fa-check');
    expect(
      within(alpha).getByText('Alpha').compareDocumentPosition(check) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();

    expect(screen.queryByTestId('ms-option-b-check')).not.toBeInTheDocument();
    expect(screen.queryByTestId('ms-option-grp-check')).not.toBeInTheDocument();
  });
});
