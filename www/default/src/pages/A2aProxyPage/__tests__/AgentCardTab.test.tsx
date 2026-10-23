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
  it('says the card lists the exposing surface versions shown on its Access Point', () => {
    renderTab();

    expect(screen.getByTestId('a2a-proxy-agent-card-version')).toHaveTextContent(
      'The card lists the A2A versions accepted by the Agent Surface that exposes this proxy, as shown on its Access Point.'
    );
  });

  it('limits the A2A 1.0 header requirement to a new surface', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).toHaveTextContent(
      'A new surface whose Target is this proxy accepts only A2A 1.0, so its callers must send the A2A-Version: 1.0 header'
    );
    expect(note).toHaveTextContent('should use A2A 1.0 methods such as SendMessage');
    expect(note).not.toHaveTextContent('By default');
    expect(note).not.toHaveTextContent('locked');
  });

  it('says requests are checked only for the JSON-RPC envelope', () => {
    renderTab();

    expect(screen.getByTestId('a2a-proxy-agent-card-version')).toHaveTextContent(
      'Requests to this proxy are checked only for a valid JSON-RPC envelope.'
    );
  });
});
