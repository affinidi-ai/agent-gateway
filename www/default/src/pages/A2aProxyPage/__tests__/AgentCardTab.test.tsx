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

const renderTab = (legacyCompatibility: boolean) => {
  render(
    <AgentCardTab formData={FORM} onChange={jest.fn()} legacyCompatibility={legacyCompatibility} />
  );
  fireEvent.click(screen.getByTestId('a2a-proxy-agent-card-intro-context-toggle'));
};

describe('AgentCardTab A2A version note', () => {
  it('says the card also carries the 0.3 fields while legacy compatibility is on', () => {
    renderTab(true);

    expect(screen.getByTestId('a2a-proxy-agent-card-version')).toHaveTextContent(
      'also carries the version 0.3 fields'
    );
  });

  it('says the card is 1.0 only when legacy compatibility is off', () => {
    renderTab(false);

    const note = screen.getByTestId('a2a-proxy-agent-card-version');
    expect(note).toHaveTextContent('version 1.0 only');
    expect(note).not.toHaveTextContent('0.3 fields');
  });
});
