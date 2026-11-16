import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import IdentityPanel from '../identity/IdentityPanel';
import { identityConfigToWire, identityDefinition } from '../identity/definition';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockedApi = apiClient as unknown as { fetch: jest.Mock };

function showPanel(slotId: string, config: Record<string, unknown> = {}, nodeId = 'identity') {
  const updateField = jest.fn();
  render(
    <IdentityPanel
      {...({
        node: { id: nodeId, type: 'identity', slotId, label: '', configured: true, config },
        config,
        updateField,
        updateFields: jest.fn(),
        protocol: 'mcp',
        allNodes: [],
      } as any)}
    />
  );
  return { updateField };
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

  it('disables From API Key on a legacy identity-protected node', () => {
    showPanel('response:identity', {}, 'identity-protected');

    expect(apiKeyOption()).toBeDisabled();
  });

  it('ignores a change to From API Key on the Managed Agent response identity', () => {
    const { updateField } = showPanel('response:identity-protected');

    fireEvent.change(screen.getByLabelText('Identity Extraction Type'), {
      target: { value: 'from_api_key' },
    });

    expect(updateField).not.toHaveBeenCalled();
  });

  it.each(['request:identity-inbound', 'response:identity-external'])(
    'still offers From API Key on %s',
    slotId => {
      showPanel(slotId);

      expect(apiKeyOption()).toBeEnabled();
    }
  );

  it('keeps the key selector for a protected identity already set to From API Key', () => {
    showPanel('response:identity-protected', { type: 'from_api_key', api_key_id: 'key-1' });

    expect(screen.getByTestId('identity-panel-api-key-select')).toBeInTheDocument();
  });

  it('keeps the key id of a stored protected From API Key identity on the wire', () => {
    const stored = { type: 'from_api_key', api_key_id: 'key-1' };
    const config = identityDefinition.configFromPayload?.(stored);

    expect(identityConfigToWire(config)).toEqual(stored);
  });
});
