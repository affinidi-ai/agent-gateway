import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import { isHttpTarget } from '../managed-agent/PartnerGrantReleaseSection';
import { apiClient } from '../../../../api';
import { registry } from '../index';
import { computeOverridesFromPayload, resolveVariant } from '../../variants/resolve';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps, SurfaceContext } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
});

const SWITCH = 'managed-agent-partner-grants-switch';
const WARNING = 'managed-agent-partner-grants-warning';

const delegationNode = {
  id: 'credential-delegation',
  type: 'credential-delegation',
  label: 'Credential Delegation',
  configured: true,
  config: { outbound_credentials_form: [{ credential_provider_id: 'github' }] },
} as CanvasNode;

function panelProps(
  config: Record<string, unknown>,
  allNodes: CanvasNode[]
): ConfigPanelProps & { updateField: jest.Mock } {
  return {
    node: { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config },
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'a2a',
    allNodes,
  } as unknown as ConfigPanelProps & { updateField: jest.Mock };
}

const httpTarget = { endpoint: 'https://agent.example/a2a', endpoint_type: 'url' };

describe('Managed Agent partner grant switch', () => {
  it('is hidden without credential delegation bindings', () => {
    render(<ManagedAgentPanel {...panelProps(httpTarget, [])} />);
    expect(screen.queryByTestId(SWITCH)).not.toBeInTheDocument();
  });

  it('is hidden on a fabric, MCP Proxy or A2A Proxy Target even with bindings', () => {
    for (const endpoint of ['fabric://gw-2/surface-2', 'proxy://tools', 'a2a-proxy://worker']) {
      const { unmount } = render(
        <ManagedAgentPanel {...panelProps({ endpoint }, [delegationNode])} />
      );
      expect(screen.queryByTestId(SWITCH)).not.toBeInTheDocument();
      unmount();
    }
  });

  it('defaults to off, with no warning, on an HTTP Target with bindings', () => {
    render(<ManagedAgentPanel {...panelProps(httpTarget, [delegationNode])} />);
    expect(screen.getByTestId(SWITCH)).not.toBeChecked();
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

  it('writes the switch when turned on', () => {
    const props = panelProps(httpTarget, [delegationNode]);
    render(<ManagedAgentPanel {...props} />);
    fireEvent.click(screen.getByTestId(SWITCH));
    expect(props.updateField).toHaveBeenCalledWith(
      'delegated_credentials_for_fabric_callers',
      true
    );
  });

  it('warns while on and writes off when turned off', () => {
    const props = panelProps({ ...httpTarget, delegated_credentials_for_fabric_callers: true }, [
      delegationNode,
    ]);
    render(<ManagedAgentPanel {...props} />);
    expect(screen.getByTestId(SWITCH)).toBeChecked();
    expect(screen.getByTestId(WARNING)).toHaveTextContent(/gets that person's grant/);
    fireEvent.click(screen.getByTestId(SWITCH));
    expect(props.updateField).toHaveBeenCalledWith(
      'delegated_credentials_for_fabric_callers',
      false
    );
  });

  it('takes only HTTP and HTTPS endpoints, exactly as the gateway reads them, for HTTP Targets', () => {
    expect(isHttpTarget('https://agent.example')).toBe(true);
    expect(isHttpTarget('http://agent.example')).toBe(true);
    for (const endpoint of [
      'HTTP://agent.example',
      'HTTPS://agent.example',
      ' https://agent.example',
      'fabric://gw/s',
      'proxy://p',
      'a2a-proxy://a',
      '',
      undefined,
    ]) {
      expect(isHttpTarget(endpoint)).toBe(false);
    }
  });
});

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'partner-grants', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function targetSavedAgain(target: Record<string, unknown>) {
  const nodes = registry.nodesFromPayload({
    access_point: { route: '/a2a', protocol: 'a2a' },
    target,
  });
  return registry.buildPayload(makeCtx(nodes)).target;
}

describe('target.delegated_credentials_for_fabric_callers', () => {
  it('keeps a Target that releases grants to Fabric callers opted in across a dashboard save', () => {
    const target = targetSavedAgain({
      endpoint: 'https://agent.example/a2a',
      delegated_credentials_for_fabric_callers: true,
    });
    expect(target.delegated_credentials_for_fabric_callers).toBe(true);
  });

  it('leaves a Target without the switch opted out', () => {
    expect(targetSavedAgain({ endpoint: 'https://agent.example/a2a' })).not.toHaveProperty(
      'delegated_credentials_for_fabric_callers'
    );
  });

  it.each([
    'fabric://peer/surface',
    'proxy://tools',
    'a2a-proxy://worker',
    'HTTPS://agent.example/a2a',
  ])(
    'drops the switch when the Target is %s, not an HTTP URL as the gateway reads it',
    endpoint => {
      const target = targetSavedAgain({
        endpoint,
        delegated_credentials_for_fabric_callers: true,
      });
      expect(target).not.toHaveProperty('delegated_credentials_for_fabric_callers');
    }
  );

  it('round-trips a variant override, and a variant snapshot without it turns it off', () => {
    const base = {
      access_point: { route: '/a2a', protocol: 'a2a' },
      target: { endpoint: 'https://agent.example/a2a' },
    };
    const on = computeOverridesFromPayload({
      ...base,
      target: { ...base.target, delegated_credentials_for_fabric_callers: true },
    });
    expect(on.target).toMatchObject({ delegated_credentials_for_fabric_callers: true });
    expect(resolveVariant(base, on).target.delegated_credentials_for_fabric_callers).toBe(true);

    const optedIn = {
      ...base,
      target: { ...base.target, delegated_credentials_for_fabric_callers: true },
    };
    const off = computeOverridesFromPayload(base);
    expect(off.complete).toBe(true);
    expect(off.target).not.toHaveProperty('delegated_credentials_for_fabric_callers');
    expect(resolveVariant(optedIn, off).target).not.toHaveProperty(
      'delegated_credentials_for_fabric_callers'
    );
  });
});
