import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
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

function a2aTransitPointProps(config: Record<string, unknown>): ConfigPanelProps {
  return {
    node: {
      id: 'transit-point-a2a-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config,
    } as CanvasNode,
    config: { id: 'tp-1', ...config },
    updateField: jest.fn(),
    updateFields: jest.fn(),
    replaceCommit: jest.fn(),
    protocol: 'a2a',
    allNodes: [],
  } as unknown as ConfigPanelProps;
}

describe('Transit Point agent card location', () => {
  it('is offered for a URL destination', () => {
    render(
      <TransitPointPanel
        {...a2aTransitPointProps({ target_endpoint: 'https://partner.example.com/a2a' })}
      />
    );
    expect(screen.getByLabelText('Override Agent Card Location')).toBeInTheDocument();
  });

  it('is not offered for a gateway destination, which reads the card over Fabric', () => {
    render(
      <TransitPointPanel
        {...a2aTransitPointProps({
          target_endpoint: 'fabric://gw-2/surface-2',
          agent_card_path: '/custom/card.json',
        })}
      />
    );
    expect(screen.queryByLabelText('Override Agent Card Location')).not.toBeInTheDocument();
  });

  it('is not offered for a fabric:// address entered as a URL', () => {
    render(
      <TransitPointPanel
        {...a2aTransitPointProps({
          endpoint_type: 'url',
          target_endpoint: 'fabric://gw-2/surface-2',
        })}
      />
    );
    expect(screen.queryByLabelText('Override Agent Card Location')).not.toBeInTheDocument();
  });
});
