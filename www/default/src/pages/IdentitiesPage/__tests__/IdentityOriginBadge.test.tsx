import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IdentityOriginBadge } from '../IdentityOriginBadge';

describe('IdentityOriginBadge', () => {
  it('labels managed identities as Managed Agent', () => {
    render(<IdentityOriginBadge origin="managed" />);

    expect(screen.getByTestId('identities-origin-managed')).toHaveTextContent('Managed Agent');
  });

  it('labels callers as External Caller', () => {
    render(<IdentityOriginBadge origin="external_caller" />);

    expect(screen.getByTestId('identities-origin-external_caller')).toHaveTextContent(
      'External Caller'
    );
  });

  it('renders nothing when the origin is unknown', () => {
    const { container } = render(<IdentityOriginBadge />);

    expect(container).toBeEmptyDOMElement();
  });
});
