import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import IdentityDetailsModal from '../IdentityDetailsModal';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));

const identity = {
  did: 'did:key:agent',
  identity_hash: 'hash-agent',
  created_at: '2026-01-01T00:00:00Z',
  channel_config_id: 'surface-1',
};

const renderModal = (value: Record<string, unknown>) =>
  render(
    <MemoryRouter>
      <IdentityDetailsModal identity={value} onClose={jest.fn()} />
    </MemoryRouter>
  );

describe('IdentityDetailsModal revoked identity', () => {
  it('explains that an identity whose API key was revoked or deleted is no longer in use', () => {
    renderModal({ ...identity, revoked: true });

    expect(screen.getByTestId('identity-revoked-info')).toHaveTextContent(
      'This identity is no longer in use: its API key was revoked or deleted, or its surface was deleted.'
    );
  });

  it('shows no revoked message for an identity in use', () => {
    renderModal(identity);

    expect(screen.queryByTestId('identity-revoked-info')).not.toBeInTheDocument();
  });
});
