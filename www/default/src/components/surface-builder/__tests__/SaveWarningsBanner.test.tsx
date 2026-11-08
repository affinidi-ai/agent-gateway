import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import SaveWarningsBanner from '../SaveWarningsBanner';

describe('SaveWarningsBanner', () => {
  it('shows nothing without warnings', () => {
    const { container } = render(<SaveWarningsBanner warnings={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('lists every warning, not only those of one Transit Point', () => {
    render(
      <SaveWarningsBanner warnings={["Transit Point 'a' is open", "Transit Point 'b' is open"]} />
    );
    const banner = screen.getByTestId('surface-save-warnings');
    expect(banner).toHaveTextContent("Transit Point 'a' is open");
    expect(banner).toHaveTextContent("Transit Point 'b' is open");
    expect(banner).toHaveTextContent('warnings');
  });

  it('goes on dismissal and returns for the next save', () => {
    const first = ["Transit Point 'a' is open"];
    const { rerender } = render(<SaveWarningsBanner warnings={first} />);
    fireEvent.click(screen.getByLabelText('Dismiss warnings'));
    expect(screen.queryByTestId('surface-save-warnings')).toBeNull();
    rerender(<SaveWarningsBanner warnings={["Transit Point 'a' is open"]} />);
    expect(screen.getByTestId('surface-save-warnings')).toBeInTheDocument();
  });
});
