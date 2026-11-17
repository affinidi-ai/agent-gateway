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
});
