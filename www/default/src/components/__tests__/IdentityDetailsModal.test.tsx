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

describe('IdentityDetailsModal archived identity', () => {
  it('explains that an archived identity is no longer in use', () => {
    renderModal({ ...identity, archived: true });

    expect(screen.getByTestId('identity-archived-info')).toHaveTextContent(
      'This identity is no longer in use because the associated surface has been deleted.'
    );
  });

  it('shows no archived message for an identity in use', () => {
    renderModal(identity);

    expect(screen.queryByTestId('identity-archived-info')).not.toBeInTheDocument();
  });
});
