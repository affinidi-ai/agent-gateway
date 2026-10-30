import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { registry } from '../index';
import type { PayloadContext } from '../types';
import AccessPointPanel from '../access-point/AccessPointPanel';
import { nodesFromSurface } from '../../nodesFromSurface';
import { showSurfaceSaveWarnings } from '../saveWarnings';
import { showToast } from '../../../../utils/toaster';
import type { AgentSurface } from '../../../../api';

jest.mock('../_shared/RouteListenerSection', () => () => null);
jest.mock('../../../../utils/toaster', () => ({
  ...jest.requireActual('../../../../utils/toaster'),
  showToast: jest.fn(),
}));

const toast = showToast as jest.Mock;

const PUBLIC_WARNING =
  'Warning: This Access Point is public. Anyone who can reach it can call your agent without credentials.';
const NO_CALLER_CONTEXT_WARNING =
  'Warning: This Access Point has no Caller Context. Anyone who can reach it can call your agent without credentials.';

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'mcp',
    surfaceMeta: { name: 'orders', tags: [], status: 'active', surface_id: 'srf-1' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function storedSurface(
  accessPoint: Record<string, unknown>,
  canvasApConfig?: object
): AgentSurface {
  return {
    surface_id: 'srf-1',
    name: 'orders',
    description: '',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gw.example',
      route: '/agents/orders',
      protocol: 'mcp',
      ...accessPoint,
    },
    target: { endpoint: 'https://agent.example' },
    ...(canvasApConfig
      ? {
          canvas: {
            nodes: [{ id: 'access-point', type: 'access-point', config: canvasApConfig }],
          },
        }
      : {}),
  } as unknown as AgentSurface;
}

const roundTrip = (surface: AgentSurface): any =>
  (registry.buildPayload(makeCtx(nodesFromSurface(surface))) as any).access_point;

const API_KEY_AUTH = {
  methods: [
    {
      type: 'api_key',
      extraction: { source: 'http_header', field: 'X-Api-Key' },
      secret_id: 'sec-1',
    },
  ],
};

describe('Access Point public access and caller auth on_failure round trip', () => {
  it('keeps public and on_failure on a surface created closed', () => {
    const ap = roundTrip(
      storedSurface({
        public: false,
        caller_authentication: { ...API_KEY_AUTH, on_failure: 'reject' },
      })
    );
    expect(ap.public).toBe(false);
    expect(ap.caller_authentication).toEqual({ ...API_KEY_AUTH, on_failure: 'reject' });
  });

  it('keeps public: true', () => {
    expect(roundTrip(storedSurface({ public: true })).public).toBe(true);
  });

  it('adds neither field to a surface stored without them, even with a stale canvas copy', () => {
    const ap = roundTrip(
      storedSurface(
        { caller_authentication: API_KEY_AUTH },
        { route: '/agents/orders', public: true }
      )
    );
    expect(ap).not.toHaveProperty('public');
    expect(ap.caller_authentication).toEqual(API_KEY_AUTH);
  });
});

describe('AccessPointPanel Public access switch', () => {
  const props = (config: Record<string, unknown>, updateField = jest.fn()) =>
    ({
      node: {
        id: 'access-point',
        type: 'access-point',
        label: 'Access Point',
        configured: true,
        config,
      },
      config,
      updateField,
      updateFields: jest.fn(),
      protocol: 'mcp',
      allNodes: [],
    }) as any;

  it('is off by default and writes access_point.public', () => {
    const updateField = jest.fn();
    render(<AccessPointPanel {...props({}, updateField)} />);

    const sw = screen.getByTestId('access-point-public-switch');
    expect(sw).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: /^Public access/ })).toBe(sw);
    expect(screen.queryByTestId('access-point-public-warning')).not.toBeInTheDocument();

    fireEvent.click(sw);
    expect(updateField).toHaveBeenCalledWith('public', true);
  });

  it('shows the warning while on and can be turned off', () => {
    const updateField = jest.fn();
    render(<AccessPointPanel {...props({ public: true }, updateField)} />);

    expect(screen.getByTestId('access-point-public-warning')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('access-point-public-switch'));
    expect(updateField).toHaveBeenCalledWith('public', false);
  });

  it('writes the field into the payload once set', () => {
    const nodes = [
      { id: 'access-point', type: 'access-point', config: { route: '/a', public: true } },
    ];
    expect((registry.buildPayload(makeCtx(nodes)) as any).access_point.public).toBe(true);
  });
});

describe('showSurfaceSaveWarnings', () => {
  beforeEach(() => toast.mockReset());

  it('warns on every save of a public surface', () => {
    const saved = storedSurface({ public: true, caller_authentication: API_KEY_AUTH });
    showSurfaceSaveWarnings(saved);
    showSurfaceSaveWarnings(saved);

    expect(toast.mock.calls.filter(c => c[1] === PUBLIC_WARNING)).toHaveLength(2);
    expect(toast.mock.calls.every(c => c[0] === 'warning')).toBe(true);
  });

  it('warns about a stored surface with no Caller Context', () => {
    showSurfaceSaveWarnings(storedSurface({}));
    expect(toast).toHaveBeenCalledWith('warning', NO_CALLER_CONTEXT_WARNING, expect.anything());
  });

  it('stays quiet for a closed surface with a Caller Context', () => {
    showSurfaceSaveWarnings(storedSurface({ public: false, caller_authentication: API_KEY_AUTH }), {
      isNew: true,
    });
    expect(toast).not.toHaveBeenCalled();
  });
});
