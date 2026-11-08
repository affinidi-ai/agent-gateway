import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import IdentityPanel from '../IdentityPanel';
import type { CanvasNode } from '../../types';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const fetchMock = apiClient.fetch as jest.Mock;

const renderPanel = (placement: Pick<CanvasNode, 'id' | 'slotId'>) => {
  const config = { type: 'from_api_key' };
  const node: CanvasNode = { ...placement, type: 'identity', label: '', configured: true, config };
  return render(
    <MemoryRouter>
      <IdentityPanel
        node={node}
        config={config}
        updateField={jest.fn()}
        updateFields={jest.fn()}
        protocol="a2a"
        allNodes={[node]}
      />
    </MemoryRouter>
  );
};

describe('IdentityPanel From API Key', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => [
        { key_id: 'atgk_agent', agent_id: 'agent-1', client_id: 'client-1', status: 'active' },
      ],
    });
  });

  it('shows the per-caller line and no key picker on the inbound node', () => {
    renderPanel({ id: 'identity-inbound', slotId: 'request:identity-inbound' });
    expect(screen.getByTestId('identity-panel-inbound-api-key-note')).toHaveTextContent(
      'Each caller is identified by the API key it presents.'
    );
    expect(screen.queryByTestId('identity-panel-api-key-select')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps the key picker on the protected node', async () => {
    renderPanel({ id: 'identity-protected', slotId: 'response:identity-protected' });
    expect(screen.getByTestId('identity-panel-api-key-select')).toBeInTheDocument();
    expect(screen.queryByTestId('identity-panel-inbound-api-key-note')).toBeNull();
    expect(await screen.findByText('client-1 — agent-1')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/api-keys');
  });
});
