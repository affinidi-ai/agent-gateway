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
  it('says the card is A2A 1.0 only and the surface accepts 1.0 callers only', () => {
    renderTab();

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).toHaveTextContent('A2A version 1.0 only');
    expect(note).toHaveTextContent('accepts A2A 1.0 callers only');
    expect(note).not.toHaveTextContent('0.3');
  });
});
