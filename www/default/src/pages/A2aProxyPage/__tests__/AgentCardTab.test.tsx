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
  it('says the card lists A2A 1.0 by default and the surface settings are locked', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).toHaveTextContent('By default, the card lists A2A 1.0');
    expect(note).toHaveTextContent('Callers must send the A2A-Version: 1.0 header');
    expect(note).toHaveTextContent('should use A2A 1.0 methods such as SendMessage');
    expect(note).toHaveTextContent("That surface's A2A settings are locked");
    expect(note).toHaveTextContent('only the JSON-RPC envelope is checked');
  });

  it('does not describe A2A 0.3 surfaces or replies', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).not.toHaveTextContent('created as an A2A 0.3 proxy');
    expect(note).not.toHaveTextContent('0.3');
    expect(note).not.toHaveTextContent('message/send');
    expect(screen.queryByTestId('a2a-proxy-agent-card-locked')).not.toBeInTheDocument();
  });
});
