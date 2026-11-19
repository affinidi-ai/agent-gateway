import React from 'react';
import { render, screen } from '@testing-library/react';
import MediatorAccessStep from '../MediatorAccessStep';

const renderStep = (mediatorName: string) =>
  render(
    <MediatorAccessStep
      dids={[
        { role: 'connection_point', label: 'Connection Point DID', did: 'did:peer:2.example' },
      ]}
      mediatorName={mediatorName}
      continuing={false}
      onContinue={jest.fn()}
      onLater={jest.fn()}
    />
  );

describe('MediatorAccessStep', () => {
  it('names the mediator followed by "Mediator"', () => {
    renderStep('Shared');

    expect(screen.getByTestId('mediator-access-explanation')).toHaveTextContent(
      'This Shared Mediator most probably uses Explicit Allow, so it only accepts connections from DIDs on its ACL.'
    );
  });

  it('does not say "Mediator" twice when the name already ends in it', () => {
    renderStep('Explicit Allow Affinidi Mediator');

    expect(screen.getByTestId('mediator-access-explanation')).toHaveTextContent(
      'This Explicit Allow Affinidi Mediator most probably uses Explicit Allow,'
    );
    expect(screen.getByTestId('mediator-access-explanation')).not.toHaveTextContent(
      'Mediator Mediator'
    );
  });

  it('lists the DIDs per mediator, each with its own bundle, when they sit on two', () => {
    render(
      <MediatorAccessStep
        dids={[
          {
            role: 'temporary',
            label: 'Temporary DID for the handshake',
            did: 'did:peer:2.handshake',
            mediatorDid: 'did:web:inviter-mediator',
            mediatorName: 'Inviter Mediator',
          },
          {
            role: 'permanent',
            label: 'Permanent DID for this pairing',
            did: 'did:peer:2.permanent',
            mediatorDid: 'did:web:own-mediator',
            mediatorName: 'Own Mediator',
          },
        ]}
        mediatorName="Inviter Mediator"
        refusal={{ label: 'Permanent DID for this pairing', did: 'did:peer:2.permanent' }}
        continuing={false}
        onContinue={jest.fn()}
        onLater={jest.fn()}
      />
    );

    expect(screen.getByTestId('mediator-access-explanation')).toHaveTextContent(
      'Add each DID to the DIDComm Mediator it is listed under.'
    );
    expect(screen.getByTestId('mediator-access-group-0')).toHaveTextContent(
      'On DIDComm Mediator Inviter Mediator'
    );
    expect(screen.getByTestId('mediator-access-group-1')).toHaveTextContent(
      'On DIDComm Mediator Own Mediator'
    );
    expect(screen.getByTestId('mediator-access-copy-all-0')).toBeInTheDocument();
    expect(screen.getByTestId('mediator-access-copy-all-1')).toBeInTheDocument();
    expect(screen.queryByTestId('mediator-access-copy-all')).not.toBeInTheDocument();
    expect(screen.getByTestId('mediator-access-refused')).toHaveTextContent(
      'DIDComm Mediator Own Mediator still refuses the Permanent DID for this pairing'
    );
  });

  it('keeps one bundle when every DID is on the same mediator', () => {
    render(
      <MediatorAccessStep
        dids={[
          {
            role: 'connection_point',
            label: 'Connection Point DID',
            did: 'did:peer:2.cp',
            mediatorDid: 'did:web:m',
          },
          {
            role: 'permanent',
            label: 'Permanent DID',
            did: 'did:peer:2.perm',
            mediatorDid: 'did:web:m',
          },
        ]}
        mediatorName="Shared"
        continuing={false}
        onContinue={jest.fn()}
        onLater={jest.fn()}
      />
    );

    expect(screen.getByTestId('mediator-access-copy-all')).toBeInTheDocument();
    expect(screen.queryByTestId('mediator-access-group-0')).not.toBeInTheDocument();
  });
});
