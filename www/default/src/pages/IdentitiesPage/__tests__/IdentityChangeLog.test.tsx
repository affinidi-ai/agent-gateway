import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IdentityChangeLog } from '../IdentityChangeLog';
import { groupIdentities, GroupableIdentity } from '../identityGrouping';

const members: GroupableIdentity[] = [
  {
    did: 'did:key:first',
    group_key: 'surface:s1',
    created_at: '2026-01-01T00:00:00Z',
    identity_hash: 'hash-1',
    credential_principal: { kind: 'certificate', id: 'cert-1', name: 'NITROGEN' },
    agent_identity: { team: 'billing' },
  },
  {
    did: 'did:key:second',
    group_key: 'surface:s1',
    created_at: '2026-02-01T00:00:00Z',
    identity_hash: 'hash-2',
    credential_principal: { kind: 'api_key', id: 'key-1', name: 'OXYGEN' },
    agent_identity: { team: 'billing' },
  },
  {
    did: 'did:key:third',
    group_key: 'surface:s1',
    created_at: '2026-03-01T00:00:00Z',
    identity_hash: 'hash-2',
    credential_principal: { kind: 'api_key', id: 'key-1', name: 'OXYGEN' },
    agent_identity: { team: 'payments' },
  },
];

describe('IdentityChangeLog', () => {
  it('lists changes newest first with DID, credential and claim details', () => {
    const [group] = groupIdentities(members);
    render(<IdentityChangeLog changes={group.changes} />);

    const entries = screen.getAllByTestId('identities-change-log-entry');
    expect(entries).toHaveLength(2);

    expect(entries[0]).toHaveTextContent('Claims changed:team');
    expect(within(entries[0]).getByTitle('did:key:second')).toBeInTheDocument();
    expect(within(entries[0]).getByTitle('did:key:third')).toBeInTheDocument();
    expect(entries[0]).not.toHaveTextContent('Credential:');

    expect(entries[1]).toHaveTextContent('Credential:NITROGEN');
    expect(entries[1]).toHaveTextContent('OXYGEN');
    expect(entries[1]).not.toHaveTextContent('Claims changed');
  });

  it('shows an empty message when nothing changed', () => {
    render(<IdentityChangeLog changes={[]} />);

    expect(screen.getByText(/No identity changes recorded/)).toBeInTheDocument();
    expect(screen.queryByTestId('identities-change-log')).not.toBeInTheDocument();
  });
});
