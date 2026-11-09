import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { VtaConnectionsList } from './VtaConnectionsList';
import type { VtaConnection } from './types';

const connection = (id: string, state: VtaConnection['pairing']['state']): VtaConnection =>
  ({
    id,
    name: id === 'vta-bootstrap' ? 'Bootstrap VTA' : 'Customer VTA',
    enabled: true,
    transport: 'https',
    endpoint: 'http://127.0.0.1:8100',
    vta_did: 'did:key:z6MkVta',
    default_context_id: 'gateway',
    status: state === 'connected' ? 'connected' : 'unpaired',
    pairing: { state, granted_role: 'initiator', granted_contexts: ['gateway'] },
    keys: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }) as unknown as VtaConnection;

const renderList = (connections: VtaConnection[]) =>
  render(
    <VtaConnectionsList
      connections={connections}
      busyId={null}
      canEdit
      canDelete
      onOpen={() => {}}
      onVerify={() => {}}
      onRevoke={() => {}}
    />
  );

describe('VtaConnectionsList', () => {
  it('shows the bundled agent as connected, not as waiting to be paired', () => {
    renderList([connection('vta-bootstrap', 'connected')]);
    expect(screen.getByText('Connected')).toBeInTheDocument();
    expect(screen.queryByText(/Not paired/)).not.toBeInTheDocument();
  });

  it('offers no Revoke on the bootstrap connection, which the server refuses to revoke', () => {
    renderList([connection('vta-bootstrap', 'connected')]);
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify' })).toBeInTheDocument();
  });

  it('still offers Revoke on a connection the operator paired', () => {
    renderList([connection('customer-1', 'connected')]);
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
  });
});
