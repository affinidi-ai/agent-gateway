import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';
import {
  fabricPeerGatewayId,
  hasOutboundCredentialBindings,
} from '../_shared/FabricDelegatedCredentialsSection';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve(
          url === '/api/v1/config/surface-routing'
            ? {
                available_listen_addresses: [],
                available_outbound_listen_addresses: [],
                channel_path_prefix: [],
              }
            : []
        ),
    })
  );
  (apiClient.get as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === '/gateways'
          ? [{ id: 'gw-2', name: 'Partner Gateway', gateway_type: 'remote', status: 'active' }]
          : [],
    })
  );
});

function delegationNodeWith(rows: Array<{ credential_provider_id?: string }>): CanvasNode {
  return {
    id: 'credential-delegation',
    type: 'credential-delegation',
    label: 'Credential Delegation',
    configured: true,
    config: { outbound_credentials_form: rows },
  } as CanvasNode;
}

const delegationNode = delegationNodeWith([{ credential_provider_id: 'github' }]);

function managedAgentProps(
  config: Record<string, unknown>,
  allNodes: CanvasNode[]
): ConfigPanelProps & { updateField: jest.Mock } {
  return {
    node: {
      id: 'target',
      type: 'target',
      label: 'Managed Agent',
      configured: true,
      config,
    } as CanvasNode,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'mcp',
    allNodes,
  } as unknown as ConfigPanelProps & { updateField: jest.Mock };
}

function transitPointProps(
  config: Record<string, unknown>,
  allNodes: CanvasNode[]
): ConfigPanelProps & { updateField: jest.Mock } {
  return {
    node: {
      id: 'transit-point-mcp-1',
      type: 'transit-point-mcp',
      label: '',
      configured: true,
      config,
    } as CanvasNode,
    config: { id: 'tp-1', ...config },
    updateField: jest.fn(),
    updateFields: jest.fn(),
    replaceCommit: jest.fn(),
    protocol: 'mcp',
    allNodes,
  } as unknown as ConfigPanelProps & { updateField: jest.Mock };
}

const fabricTarget = {
  endpoint: 'fabric://gw-2/surface-2',
  endpoint_type: 'gateway',
  gateway_id: 'gw-2',
  gateway_channel: 'surface-2',
};

describe('Managed Agent fabric delegated-credentials toggle', () => {
  it('is hidden without credential delegation bindings', () => {
    render(<ManagedAgentPanel {...managedAgentProps(fabricTarget, [])} />);
    expect(
      screen.queryByTestId('managed-agent-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('is hidden on a non-fabric target even with bindings', () => {
    render(
      <ManagedAgentPanel
        {...managedAgentProps({ endpoint: 'https://upstream.example.com' }, [delegationNode])}
      />
    );
    expect(
      screen.queryByTestId('managed-agent-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('defaults to off with no warning on a fabric target with bindings', () => {
    render(<ManagedAgentPanel {...managedAgentProps(fabricTarget, [delegationNode])} />);
    const toggle = screen.getByTestId('managed-agent-fabric-delegated-credentials-switch');
    expect(toggle).not.toBeChecked();
    expect(
      screen.queryByTestId('managed-agent-fabric-delegated-credentials-warning')
    ).not.toBeInTheDocument();
  });

  it('writes the opt-in when switched on', () => {
    const props = managedAgentProps(fabricTarget, [delegationNode]);
    render(<ManagedAgentPanel {...props} />);
    fireEvent.click(screen.getByTestId('managed-agent-fabric-delegated-credentials-switch'));
    expect(props.updateField).toHaveBeenCalledWith('fabric_delegated_credentials', true);
  });

  it('warns and names the peer gateway when on', async () => {
    render(
      <ManagedAgentPanel
        {...managedAgentProps({ ...fabricTarget, fabric_delegated_credentials: true }, [
          delegationNode,
        ])}
      />
    );
    expect(screen.getByTestId('managed-agent-fabric-delegated-credentials-switch')).toBeChecked();
    expect(await screen.findByText(/access token is sent to Partner Gateway/)).toBeInTheDocument();
  });
});

describe('Transit Point fabric delegated-credentials toggle', () => {
  const fabricTransitPoint = { target_endpoint: 'fabric://gw-2/surface-2' };

  it('is hidden without any credential binding', () => {
    render(<TransitPointPanel {...transitPointProps(fabricTransitPoint, [])} />);
    expect(
      screen.queryByTestId('transit-point-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('is hidden on a non-fabric destination even with bindings', () => {
    render(
      <TransitPointPanel
        {...transitPointProps({ target_endpoint: 'https://partner.example/mcp' }, [delegationNode])}
      />
    );
    expect(
      screen.queryByTestId('transit-point-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('shows for a fabric destination with surface bindings and writes the opt-in', () => {
    const props = transitPointProps(fabricTransitPoint, [delegationNode]);
    render(<TransitPointPanel {...props} />);
    const toggle = screen.getByTestId('transit-point-fabric-delegated-credentials-switch');
    expect(toggle).not.toBeChecked();
    fireEvent.click(toggle);
    expect(props.updateField).toHaveBeenCalledWith('fabric_delegated_credentials', true);
  });

  it('is hidden when its own transit credentials name no provider', () => {
    render(
      <TransitPointPanel
        {...transitPointProps(
          {
            ...fabricTransitPoint,
            transit_credentials: {
              credential_provider_id: '',
              scopes: '',
              consent_mode: 'on_demand',
              inject_as_type: 'bearer_header',
            },
          },
          []
        )}
      />
    );
    expect(
      screen.queryByTestId('transit-point-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('shows for a fabric destination with its own transit credentials and warns when on', async () => {
    render(
      <TransitPointPanel
        {...transitPointProps(
          {
            ...fabricTransitPoint,
            fabric_delegated_credentials: true,
            transit_credentials: {
              credential_provider_id: 'github',
              scopes: ['read:user'],
              consent_mode: 'on_demand',
              inject_as: { type: 'bearer_header' },
            },
          },
          []
        )}
      />
    );
    expect(screen.getByTestId('transit-point-fabric-delegated-credentials-switch')).toBeChecked();
    expect(await screen.findByText(/access token is sent to Partner Gateway/)).toBeInTheDocument();
  });
});

describe('fabric delegated-credentials helpers', () => {
  it('counts only binding rows that name a credential provider', () => {
    expect(hasOutboundCredentialBindings([delegationNodeWith([{}])])).toBe(false);
    expect(hasOutboundCredentialBindings([delegationNodeWith([])])).toBe(false);
    expect(hasOutboundCredentialBindings(undefined)).toBe(false);
    expect(hasOutboundCredentialBindings([delegationNode])).toBe(true);
  });

  it('takes the peer gateway from the fabric route before the picker', () => {
    expect(fabricPeerGatewayId('fabric://gw-2/surface-2', 'gw-3')).toBe('gw-2');
    expect(fabricPeerGatewayId('fabric:///surface-2', 'gw-3')).toBe('gw-3');
    expect(fabricPeerGatewayId('https://upstream.example.com', 'gw-3')).toBe('gw-3');
    expect(fabricPeerGatewayId(undefined, '')).toBeUndefined();
  });

  it('hides the Managed Agent switch for a blank binding row', () => {
    render(<ManagedAgentPanel {...managedAgentProps(fabricTarget, [delegationNodeWith([{}])])} />);
    expect(
      screen.queryByTestId('managed-agent-fabric-delegated-credentials-switch')
    ).not.toBeInTheDocument();
  });

  it('names the peer from the route when the picker has no gateway', async () => {
    render(
      <ManagedAgentPanel
        {...managedAgentProps(
          {
            endpoint: 'fabric://gw-2/surface-2',
            endpoint_type: 'gateway',
            fabric_delegated_credentials: true,
          },
          [delegationNode]
        )}
      />
    );
    expect(await screen.findByText(/access token is sent to Partner Gateway/)).toBeInTheDocument();
  });
});
