import React from 'react';
import { render, screen } from '@testing-library/react';
import { ProtocolBadge, protocolMetaFor } from '../ProtocolBadge';

describe('ProtocolBadge', () => {
  it.each([
    ['a2a', 'A2A', 'text-bg-primary'],
    ['ap2', 'AP2', 'text-bg-warning'],
    ['mcp', 'MCP', 'text-bg-info'],
  ])('shows %s as %s in %s', (protocol, label, badgeClass) => {
    render(<ProtocolBadge protocol={protocol} data-testid="badge" />);
    const badge = screen.getByTestId('badge');
    expect(badge).toHaveTextContent(new RegExp(`^${label}$`));
    expect(badge).toHaveClass('badge', badgeClass);
  });

  it('shows another protocol upper-cased in the secondary colour', () => {
    render(<ProtocolBadge protocol="didcomm" data-testid="badge" />);
    const badge = screen.getByTestId('badge');
    expect(badge).toHaveTextContent(/^DIDCOMM$/);
    expect(badge).toHaveClass('badge', 'text-bg-secondary');
    expect(badge).not.toHaveClass('text-bg-primary');
  });

  it('returns the same meta for a known protocol', () => {
    expect(protocolMetaFor('ap2')).toEqual({
      key: 'ap2',
      label: 'AP2',
      badgeClass: 'text-bg-warning',
    });
  });
});
