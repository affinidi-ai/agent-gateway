import React, { useState } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import { registry } from '../index';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

const mockGet = apiClient.get as jest.Mock;

const GATEWAYS = [
  { id: 'gw-a', name: 'Gateway A', gateway_type: 'remote', status: 'active' },
  { id: 'gw-b', name: 'Gateway B', gateway_type: 'remote', status: 'active' },
  { id: 'gw-pending', name: 'Pending', gateway_type: 'remote', status: 'pending' },
];

const SURFACES: Record<string, unknown[]> = {
  'gw-a': [
    { config_id: 'a-mcp', name: 'A tools', protocol: 'mcp' },
    { config_id: 'a-a2a', name: 'A agent', protocol: 'a2a' },
    { config_id: 'a-any', name: 'A legacy' },
  ],
  'gw-b': [{ config_id: 'b-mcp', name: 'B tools', protocol: 'mcp' }],
  'gw-c': [{ config_id: 'c-a2a', name: 'C agent', protocol: 'a2a' }],
};

function mockGateways(gateways: unknown[] = GATEWAYS) {
  mockGet.mockImplementation((url: string) => {
    if (url === '/gateways') return Promise.resolve({ data: gateways });
    const id = decodeURIComponent(url.split('/')[2] ?? '');
    return Promise.resolve({ data: SURFACES[id] ?? [] });
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        available_listen_addresses: [],
        available_outbound_listen_addresses: [],
        channel_path_prefix: [],
      }),
  });
  mockGateways();
});

let lastConfig: Record<string, any> = {};

const TransitPointHarness: React.FC<{ initial: Record<string, any> }> = ({ initial }) => {
  const [config, setConfig] = useState<Record<string, any>>({ id: 'tp-1', ...initial });
  lastConfig = config;
  const apply = (fields: Record<string, unknown>) => setConfig(c => ({ ...c, ...fields }));
  const props = {
    node: { id: 'transit-point-mcp-1', type: 'transit-point-mcp', label: '', configured: true },
    config,
    updateField: (field: string, value: unknown) => apply({ [field]: value }),
    updateFields: apply,
    replaceCommit: jest.fn(),
    protocol: 'mcp',
    allNodes: [] as CanvasNode[],
  } as unknown as ConfigPanelProps;
  return <TransitPointPanel {...props} />;
};

const ManagedAgentHarness: React.FC<{ initial: Record<string, any> }> = ({ initial }) => {
  const [config, setConfig] = useState<Record<string, any>>(initial);
  lastConfig = config;
  const apply = (fields: Record<string, unknown>) => setConfig(c => ({ ...c, ...fields }));
  const props = {
    node: { id: 'target', type: 'target', label: 'Managed Agent', configured: true },
    config,
    updateField: (field: string, value: unknown) => apply({ [field]: value }),
    updateFields: apply,
    protocol: 'mcp',
    allNodes: [] as CanvasNode[],
  } as unknown as ConfigPanelProps;
  return <ManagedAgentPanel {...props} />;
};

const options = (select: HTMLElement) =>
  within(select)
    .getAllByRole('option')
    .map(o => o.textContent);

describe('Transit Point gateway picker', () => {
  it('lists only active remote gateways', async () => {
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway' }} />);

    const select = await screen.findByTestId('transit-point-gateway-select');
    await waitFor(() => expect(options(select)).toContain('Gateway A'));
    expect(options(select)).toEqual(['Select a gateway…', 'Gateway A', 'Gateway B']);
    expect(screen.queryByTestId('transit-point-no-gateway')).not.toBeInTheDocument();
  });

  it('offers Add Gateway in a new tab when no gateway is connected', async () => {
    mockGateways([]);
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway' }} />);

    expect(await screen.findByTestId('transit-point-no-gateway')).toHaveTextContent(
      'No connected gateway'
    );
    const link = screen.getByTestId('transit-point-add-gateway-link');
    expect(link).toHaveAttribute('href', '/gateways/connect');
    expect(link).toHaveAttribute('target', '_blank');
    expect(screen.queryByTestId('transit-point-gateway-select')).not.toBeInTheDocument();
  });

  it('says the gateway list failed rather than showing it as empty', async () => {
    mockGet.mockRejectedValueOnce(new Error('boom'));
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway' }} />);

    expect(await screen.findByTestId('transit-point-gateway-error')).toHaveTextContent(
      'Could not load the connected gateways.'
    );
    expect(screen.queryByTestId('transit-point-no-gateway')).not.toBeInTheDocument();
  });

  it('routes to the chosen surface and names the chain after it', async () => {
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway' }} />);
    const gatewaySelect = await screen.findByTestId('transit-point-gateway-select');
    await waitFor(() => expect(options(gatewaySelect)).toContain('Gateway A'));

    fireEvent.change(gatewaySelect, { target: { value: 'gw-a' } });
    const surfaceSelect = await screen.findByTestId('transit-point-surface-select');
    await waitFor(() => expect(options(surfaceSelect)).toContain('A tools (a-mcp)'));
    fireEvent.change(surfaceSelect, { target: { value: 'a-mcp' } });

    expect(lastConfig).toMatchObject({
      gateway_id: 'gw-a',
      gateway_channel: 'a-mcp',
      target_endpoint: 'fabric://gw-a/a-mcp',
      fabric_remote_gateway_name: 'Gateway A',
      fabric_remote_channel_name: 'A tools',
    });
  });

  it('drops the previous route and its names when another gateway is chosen', async () => {
    render(
      <TransitPointHarness
        initial={{
          endpoint_type: 'gateway',
          gateway_id: 'gw-a',
          gateway_channel: 'a-mcp',
          target_endpoint: 'fabric://gw-a/a-mcp',
          fabric_remote_gateway_name: 'Gateway A',
          fabric_remote_channel_name: 'A tools',
        }}
      />
    );
    const gatewaySelect = await screen.findByTestId('transit-point-gateway-select');
    await waitFor(() => expect(options(gatewaySelect)).toContain('Gateway B'));

    fireEvent.change(gatewaySelect, { target: { value: 'gw-b' } });

    expect(lastConfig).toMatchObject({
      gateway_id: 'gw-b',
      gateway_channel: '',
      target_endpoint: '',
    });
    expect(lastConfig.fabric_remote_gateway_name).toBeUndefined();
    expect(lastConfig.fabric_remote_channel_name).toBeUndefined();
    expect(
      registry.getIncompleteReason('transit-point-mcp', { ...lastConfig, listen_address: 'x' })
    ).toBe('Select an Agent Surface on the gateway');
  });

  it('restores a route saved without picker fields from its fabric URL', async () => {
    render(<TransitPointHarness initial={{ target_endpoint: 'fabric://gw-a/a-mcp' }} />);

    const gatewaySelect = await screen.findByTestId('transit-point-gateway-select');
    await waitFor(() => expect(gatewaySelect).toHaveValue('gw-a'));
    const surfaceSelect = await screen.findByTestId('transit-point-surface-select');
    await waitFor(() => expect(surfaceSelect).toHaveValue('a-mcp'));
    expect(screen.getByTestId('transit-point-endpoint-type-select')).toHaveValue('gateway');
  });

  it('keeps matching and unlabelled surfaces', async () => {
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway', gateway_id: 'gw-a' }} />);

    const surfaceSelect = await screen.findByTestId('transit-point-surface-select');
    await waitFor(() => expect(options(surfaceSelect)).toContain('A tools (a-mcp)'));
    expect(options(surfaceSelect)).toEqual([
      'Select an Agent Surface…',
      'A tools (a-mcp)',
      'A legacy (a-any)',
    ]);
  });

  it('counts the surfaces hidden for speaking another protocol', async () => {
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway', gateway_id: 'gw-c' }} />);

    expect(await screen.findByTestId('transit-point-surface-empty')).toHaveTextContent(
      'No MCP Agent Surfaces on this gateway (1 of other protocols hidden).'
    );
    expect(screen.getByTestId('transit-point-surface-select')).toBeDisabled();
  });

  it('says an unconnected gateway cannot be listed instead of reporting no surfaces', async () => {
    mockGet.mockImplementation((url: string) =>
      url === '/gateways'
        ? Promise.resolve({ data: GATEWAYS })
        : Promise.reject(Object.assign(new Error('Service Unavailable'), { status: 503 }))
    );
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway', gateway_id: 'gw-a' }} />);

    expect(await screen.findByTestId('transit-point-surface-error')).toHaveTextContent(
      'Gateway is not connected'
    );
    expect(screen.queryByTestId('transit-point-surface-empty')).not.toBeInTheDocument();
  });

  it('keeps a saved surface the gateway no longer lists', async () => {
    render(
      <TransitPointHarness
        initial={{ target_endpoint: 'fabric://gw-a/removed-surface', endpoint_type: 'gateway' }}
      />
    );

    const surfaceSelect = await screen.findByTestId('transit-point-surface-select');
    await waitFor(() =>
      expect(options(surfaceSelect)).toContain('removed-surface (not currently exposed)')
    );
    expect(surfaceSelect).toHaveValue('removed-surface');
  });

  it('never lists an earlier gateway surfaces under a later gateway', async () => {
    let resolveA: (value: unknown) => void = () => {};
    mockGet.mockImplementation((url: string) => {
      if (url === '/gateways') return Promise.resolve({ data: GATEWAYS });
      if (url.startsWith('/gateways/gw-a/')) return new Promise(resolve => (resolveA = resolve));
      return Promise.resolve({ data: SURFACES['gw-b'] });
    });
    render(<TransitPointHarness initial={{ endpoint_type: 'gateway', gateway_id: 'gw-a' }} />);
    const gatewaySelect = await screen.findByTestId('transit-point-gateway-select');
    await waitFor(() => expect(options(gatewaySelect)).toContain('Gateway B'));

    fireEvent.change(gatewaySelect, { target: { value: 'gw-b' } });
    const surfaceSelect = screen.getByTestId('transit-point-surface-select');
    await waitFor(() => expect(options(surfaceSelect)).toContain('B tools (b-mcp)'));
    await act(async () => resolveA({ data: SURFACES['gw-a'] }));

    expect(options(surfaceSelect)).not.toContain('A tools (a-mcp)');
  });

  it('names the missing step on the node', () => {
    const base = { listen_address: 'http://0.0.0.0:9000' };
    expect(
      registry.getIncompleteReason('transit-point-mcp', { ...base, endpoint_type: 'gateway' })
    ).toBe('Select a gateway');
    expect(registry.getIncompleteReason('transit-point-mcp', base)).toBe(
      'Target endpoint URL is required'
    );
    expect(
      registry.getIncompleteReason('transit-point-mcp', {
        ...base,
        target_endpoint: 'fabric://gw-a/a-mcp',
      })
    ).toBeNull();
  });
});

describe('Managed Agent gateway picker', () => {
  it('drops the previous route and its names when another gateway is chosen', async () => {
    render(
      <ManagedAgentHarness
        initial={{
          endpoint_type: 'gateway',
          gateway_id: 'gw-a',
          gateway_channel: 'a-mcp',
          endpoint: 'fabric://gw-a/a-mcp',
          fabric_remote_gateway_name: 'Gateway A',
          fabric_remote_channel_name: 'A tools',
        }}
      />
    );
    const gatewaySelect = await screen.findByTestId('managed-agent-gateway-select');
    await waitFor(() => expect(options(gatewaySelect)).toContain('Gateway B'));

    fireEvent.change(gatewaySelect, { target: { value: 'gw-b' } });
    expect(lastConfig).toMatchObject({
      gateway_id: 'gw-b',
      gateway_channel: '',
      endpoint: '',
      fabric_remote_gateway_name: '',
      fabric_remote_channel_name: '',
    });

    const surfaceSelect = await screen.findByTestId('managed-agent-surface-select');
    await waitFor(() => expect(options(surfaceSelect)).toContain('B tools (b-mcp)'));
    fireEvent.change(surfaceSelect, { target: { value: 'b-mcp' } });
    expect(lastConfig).toMatchObject({
      endpoint: 'fabric://gw-b/b-mcp',
      fabric_remote_gateway_name: 'Gateway B',
      fabric_remote_channel_name: 'B tools',
    });
  });

  it('refreshes the surface list from the gateway', async () => {
    render(<ManagedAgentHarness initial={{ endpoint_type: 'gateway', gateway_id: 'gw-a' }} />);
    const refresh = await screen.findByTestId('managed-agent-surface-refresh-button');
    await waitFor(() => expect(refresh).toBeEnabled());

    fireEvent.click(refresh);

    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith('/gateways/gw-a/surfaces?force_refresh=true')
    );
  });
});
