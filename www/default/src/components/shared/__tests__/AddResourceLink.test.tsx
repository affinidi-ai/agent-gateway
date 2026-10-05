import { render, screen } from '@testing-library/react';
import AddResourceLink from '../AddResourceLink';

describe('AddResourceLink', () => {
  it('renders an anchor that opens the destination in a new tab', () => {
    render(
      <AddResourceLink to="/surfaces/new" testid="add-surface">
        Add Agent Surface
      </AddResourceLink>
    );

    const link = screen.getByTestId('add-surface');
    expect(link.tagName).toBe('A');
    expect(link).toHaveAttribute('href', '/surfaces/new');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noreferrer noopener');
    expect(link).toHaveTextContent('Add Agent Surface');
  });

  it('applies the caller-supplied className', () => {
    render(
      <AddResourceLink to="/secrets/new" testid="add-secret" className="alert-link fw-bold">
        Add secret
      </AddResourceLink>
    );

    expect(screen.getByTestId('add-secret')).toHaveClass('alert-link', 'fw-bold');
  });
});
