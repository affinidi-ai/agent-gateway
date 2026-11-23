import React from 'react';
import { render, screen } from '@testing-library/react';
import { knownProtocolMeta, ProtocolBadge, protocolMetaFor } from '../ProtocolBadge';

describe('ProtocolBadge', () => {
  it.each([
    ['a2a', 'A2A', 'text-bg-primary'],
    ['ap2', 'AP2', 'text-bg-warning'],
    ['mcp', 'MCP', 'text-bg-info'],
    ['didcomm', 'DIDComm', 'text-bg-success'],
  ])('shows %s as %s in %s', (protocol, label, badgeClass) => {
    render(<ProtocolBadge protocol={protocol} data-testid="badge" />);
    const badge = screen.getByTestId('badge');
    expect(badge).toHaveTextContent(new RegExp(`^${label}$`));
    expect(badge).toHaveClass('badge', badgeClass);
  });

  it('shows another protocol upper-cased in the secondary colour', () => {
    render(<ProtocolBadge protocol="http" data-testid="badge" />);
    const badge = screen.getByTestId('badge');
    expect(badge).toHaveTextContent(/^HTTP$/);
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

  it('knows no meta for an unknown protocol', () => {
    expect(knownProtocolMeta('didcomm')?.label).toBe('DIDComm');
    expect(knownProtocolMeta('future-proto')).toBeUndefined();
  });
});
