import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import { apiClient } from '../../../../api';
import { failedBody, previewBody } from '../../../../utils/agentCardTestFixtures';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

const mockFetch = apiClient.fetch as jest.Mock;
const mockGet = apiClient.get as jest.Mock;

const props = {
  node: { id: 'target', type: 'target', label: '', configured: true, config: {} } as CanvasNode,
  config: {},
  updateField: jest.fn(),
  updateFields: jest.fn(),
  protocol: 'a2a',
  allNodes: [],
} as unknown as ConfigPanelProps;

const answerCard = (body: unknown) =>
  mockFetch.mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      status: 200,
      json: async () => (url.endsWith('/agent-card') ? body : []),
    })
  );

const renderPanel = (meta: Partial<SurfaceMetaValue> = {}) => {
  const onOpenAgentCard = jest.fn();
  render(
    <SurfaceMetaProvider
      value={{ isCreate: false, surfaceId: 's-123', onOpenAgentCard, ...meta } as SurfaceMetaValue}
    >
      <ManagedAgentPanel {...props} />
    </SurfaceMetaProvider>
  );
  return { onOpenAgentCard };
};

beforeEach(() => {
  jest.resetAllMocks();
  mockGet.mockResolvedValue({ data: [] });
  answerCard(previewBody());
});

describe('Managed Agent panel card fetch line', () => {
  it('shows the card fetch status with a link to the Agent Cards tab', async () => {
    const { onOpenAgentCard } = renderPanel();
    await waitFor(() =>
      expect(screen.getByTestId('managed-agent-card-fetch-status')).toHaveTextContent(
        'Card fetch: OK'
      )
    );
    fireEvent.click(screen.getByTestId('managed-agent-card-fetch-link'));
    expect(onOpenAgentCard).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/surfaces/s-123/agent-card', undefined);
  });

  it('shows a failing card fetch with its cause', async () => {
    answerCard(failedBody('forbidden', 403));
    renderPanel();
    await waitFor(() =>
      expect(screen.getByTestId('managed-agent-card-fetch-status')).toHaveTextContent(
        'Card fetch: failing (Refused — HTTP 403)'
      )
    );
  });

  it('keeps the Target Authentication controls beside the line', async () => {
    renderPanel();
    await screen.findByTestId('managed-agent-card-fetch');
    expect(screen.getByTestId('managed-agent-auth-type')).toBeInTheDocument();
  });

  it('shows no line for a surface that is not saved', () => {
    renderPanel({ isCreate: true, surfaceId: undefined });
    expect(screen.queryByTestId('managed-agent-card-fetch')).not.toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('shows no line on a protocol without the Agent Cards tab', () => {
    renderPanel({ onOpenAgentCard: undefined });
    expect(screen.queryByTestId('managed-agent-card-fetch')).not.toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
