import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AgentCardTab from '../AgentCardTab';
import type { A2aProxyFormData } from '../types';

const FORM = {
  backend: { kind: 'rest' },
  agent_card_name: '',
  agent_card_description: '',
} as unknown as A2aProxyFormData;

const renderTab = () => {
  render(<AgentCardTab formData={FORM} onChange={jest.fn()} />);
  fireEvent.click(screen.getByTestId('a2a-proxy-agent-card-intro-context-toggle'));
};

describe('AgentCardTab A2A version note', () => {
  it('says the card follows the surface versions and which reply each send method gets', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).toHaveTextContent('lists the A2A versions accepted by the Agent Surface');
    expect(note).toHaveTextContent('A2A 1.0 for a new surface');
    expect(note).toHaveTextContent('Callers using message/send get A2A 0.3 replies');
    expect(note).toHaveTextContent('those using SendMessage get A2A 1.0 replies');
  });

  it('says the exposing surface has locked A2A settings', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-locked');
    expect(note).toHaveTextContent('its versions are fixed');
    expect(note).toHaveTextContent('only the JSON-RPC envelope is checked');
    expect(note).toHaveTextContent('callers must send A2A-Version: 1.0');
    expect(note).toHaveTextContent('A surface created as an A2A 0.3 proxy keeps accepting 0.3');
  });
});
