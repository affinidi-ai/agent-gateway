import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import A2aProxyEndpointFields from '../managed-agent/A2aProxyEndpointFields';

const renderFields = (selectedProxyId?: string) =>
  render(
    <MemoryRouter>
      <A2aProxyEndpointFields
        selectedProxyId={selectedProxyId}
        a2aProxies={[{ id: 'p1', name: 'Copilot', status: 'active' }]}
        updateFields={jest.fn()}
      />
    </MemoryRouter>
  );

describe('Managed Agent A2A proxy fields', () => {
  it('states that an A2A proxy serves A2A 1.0 without message validation', () => {
    renderFields('p1');

    const hint = screen.getByTestId('managed-agent-a2a-proxy-protocol-hint');
    expect(hint).toHaveTextContent('A2A 1.0 only, without message validation.');
    expect(hint).toHaveTextContent('callers must send the A2A-Version: 1.0 header');
    expect(hint).toHaveTextContent("The Access Point's A2A Protocol settings are locked");
  });

  it('states it before a proxy is selected', () => {
    renderFields();

    expect(screen.getByTestId('managed-agent-a2a-proxy-protocol-hint')).toBeInTheDocument();
  });
});
