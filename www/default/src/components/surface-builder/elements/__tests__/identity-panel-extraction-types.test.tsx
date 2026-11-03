import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import IdentityPanel from '../identity/IdentityPanel';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockedApi = apiClient as unknown as { fetch: jest.Mock };

function showPanel(slotId: string, config: Record<string, unknown> = {}) {
  render(
    <IdentityPanel
      {...({
        node: { id: 'identity', type: 'identity', slotId, label: '', configured: true, config },
        config,
        updateField: jest.fn(),
        updateFields: jest.fn(),
        protocol: 'mcp',
        allNodes: [],
      } as any)}
    />
  );
}

const apiKeyOption = () =>
  within(screen.getByLabelText('Identity Extraction Type')).getByRole('option', {
    name: 'From API Key',
  });

describe('IdentityPanel From API Key placement', () => {
  beforeEach(() => {
    mockedApi.fetch.mockResolvedValue({
      ok: true,
      json: async () => [
        { key_id: 'key-1', agent_id: 'agent-1', client_id: 'client-1', status: 'active' },
      ],
    });
  });

  it('disables From API Key on the Managed Agent response identity', () => {
    showPanel('response:identity-protected');

    expect(apiKeyOption()).toBeDisabled();
  });

  it.each(['request:identity-inbound', 'response:identity-external'])(
    'still offers From API Key on %s',
    slotId => {
      showPanel(slotId);

      expect(apiKeyOption()).toBeEnabled();
    }
  );

  it('keeps the key selector for a protected identity already set to From API Key', async () => {
    showPanel('response:identity-protected', { type: 'from_api_key', api_key_id: 'key-1' });

    expect(await screen.findByRole('option', { name: 'client-1 — agent-1' })).toBeInTheDocument();
  });
});
