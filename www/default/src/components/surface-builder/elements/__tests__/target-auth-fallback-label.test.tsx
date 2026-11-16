import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentAuthFullscreen from '../managed-agent/ManagedAgentAuthFullscreen';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        available_listen_addresses: [],
        available_outbound_listen_addresses: [],
        channel_path_prefix: [],
      }),
  });
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
});

function panelProps(type: string, config: Record<string, unknown>): ConfigPanelProps {
  return {
    node: { id: `${type}-1`, type, label: '', configured: true, config } as CanvasNode,
    config: { id: 'node-1', ...config },
    updateField: jest.fn(),
    updateFields: jest.fn(),
    replaceCommit: jest.fn(),
    protocol: 'a2a',
    allNodes: [],
  } as unknown as ConfigPanelProps;
}

describe('Target authentication fallback', () => {
  it('names no status for reject on the Managed Agent', () => {
    render(
      <ManagedAgentAuthFullscreen
        {...panelProps('managed-agent', {
          target_auth_enabled: true,
          target_auth_fallback: 'reject',
        })}
      />
    );
    expect(screen.getByRole('option', { name: 'Reject request' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /502/ })).not.toBeInTheDocument();
  });

  it('names no status for reject on a Transit Point', () => {
    render(
      <TransitPointPanel
        {...panelProps('transit-point-a2a', {
          target_endpoint: 'https://partner.example.com/a2a',
          auth_type: 'bearer',
          auth_fallback: 'reject',
        })}
      />
    );
    expect(screen.getByRole('option', { name: 'Reject request' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /502/ })).not.toBeInTheDocument();
  });
});
