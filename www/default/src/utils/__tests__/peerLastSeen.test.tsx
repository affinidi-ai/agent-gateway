import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { PeerLastSeen } from '../connectionHealth';

describe('PeerLastSeen', () => {
  it('shows how long ago the peer was heard from, with the exact time on hover', () => {
    const at = new Date(Date.now() - 3 * 60 * 1000).toISOString();
    render(<PeerLastSeen gatewayId="gw-1" peerLastSeenAt={at} />);

    expect(screen.getByTestId('gateway-peer-last-seen-gw-1')).toHaveTextContent(/^Peer seen /);
    expect(screen.getByText(/^Peer seen /)).toHaveAttribute('title');
  });

  it('says the peer has not been heard from when there is no contact yet', () => {
    render(<PeerLastSeen gatewayId="gw-2" peerLastSeenAt={null} />);

    expect(screen.getByTestId('gateway-peer-last-seen-gw-2')).toHaveTextContent(
      'Peer not heard from since this gateway started'
    );
  });
});
