import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import GatewayStatusCell, { gatewayFailureTooltip } from '../GatewayStatusCell';

const base = {
  id: 'gw-1',
  gateway_type: 'remote' as const,
  peer_last_seen_at: null,
};

describe('GatewayStatusCell', () => {
  it('names an awaiting-approval gateway in words and shows no last contact', () => {
    render(<GatewayStatusCell gateway={{ ...base, status: 'awaiting-approval' }} />);

    expect(screen.getByTestId('gateway-status-gw-1')).toHaveTextContent('AWAITING APPROVAL');
    expect(screen.getByTestId('gateway-status-gw-1')).toHaveClass('text-bg-warning');
    expect(screen.queryByTestId('gateway-peer-last-seen-gw-1')).not.toBeInTheDocument();
  });

  it('shows a failed gateway with its reason and when the peer was last heard from', () => {
    render(
      <GatewayStatusCell
        gateway={{
          ...base,
          status: 'failed',
          runtime_status: { status: 'failed', error_code: 'MEDIATOR_UNREACHABLE' },
        }}
      />
    );

    const badge = screen.getByTestId('gateway-status-gw-1');
    expect(badge).toHaveTextContent('FAILED');
    expect(badge).toHaveClass('text-bg-danger');
    expect(badge).toHaveAttribute('title', 'Mediator is unreachable');
    expect(screen.getByText('Mediator is unreachable')).toBeInTheDocument();
    expect(screen.getByTestId('gateway-peer-last-seen-gw-1')).toHaveTextContent(
      'Peer not heard from since this gateway started'
    );
  });

  it('has no failure tooltip while connected', () => {
    expect(gatewayFailureTooltip({ status: 'connected' })).toBeUndefined();
    expect(gatewayFailureTooltip(undefined)).toBeUndefined();
    expect(gatewayFailureTooltip({ status: 'failed', error_message: 'down' })).toBe('down');
  });
});
