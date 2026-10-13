import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import A2aProxyEndpointFields from '../managed-agent/A2aProxyEndpointFields';

const renderFields = (selectedProxyId?: string, acceptedVersions?: string[]) =>
  render(
    <MemoryRouter>
      <A2aProxyEndpointFields
        selectedProxyId={selectedProxyId}
        a2aProxies={[{ id: 'p1', name: 'Copilot', status: 'active' }]}
        updateFields={jest.fn()}
        acceptedVersions={acceptedVersions}
      />
    </MemoryRouter>
  );

describe('Managed Agent A2A proxy fields', () => {
  it('states that a new A2A proxy surface accepts A2A 1.0 only', () => {
    renderFields('p1');

    const hint = screen.getByTestId('managed-agent-a2a-proxy-protocol-hint');
    expect(screen.getByTestId('managed-agent-a2a-proxy-versions')).toHaveTextContent(
      'Accepts A2A 1.0 only'
    );
    expect(hint).toHaveTextContent('Callers must send A2A-Version: 1.0.');
    expect(hint).toHaveTextContent(
      'SendMessage gets an A2A 1.0 reply, message/send an A2A 0.3 reply'
    );
    expect(hint).toHaveTextContent('Only the JSON-RPC envelope is checked');
    expect(hint).toHaveTextContent('These versions are fixed.');
    expect(screen.queryByTestId('managed-agent-a2a-proxy-0-3-reason')).not.toBeInTheDocument();
  });

  it('states that an existing A2A proxy surface also accepts A2A 0.3', () => {
    renderFields('p1', ['0.3', '1.0']);

    const hint = screen.getByTestId('managed-agent-a2a-proxy-protocol-hint');
    expect(screen.getByTestId('managed-agent-a2a-proxy-versions')).toHaveTextContent(
      'Accepts A2A 0.3 and 1.0'
    );
    expect(hint).toHaveTextContent('or no header (read as 0.3)');
    expect(screen.getByTestId('managed-agent-a2a-proxy-0-3-reason')).toHaveTextContent(
      'This surface was created as an A2A 0.3 proxy, so it keeps accepting 0.3 for its existing callers. New surfaces with an A2A proxy accept A2A 1.0 only.'
    );
    expect(hint).not.toHaveTextContent('Callers must send');
  });

  it('states it before a proxy is selected', () => {
    renderFields();

    expect(screen.getByTestId('managed-agent-a2a-proxy-protocol-hint')).toBeInTheDocument();
  });
});
