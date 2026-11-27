import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import TransitPointPanel from '../TransitPointPanel';
import { transitPointTargetAuth } from '../targetAuth';
import { storedTargetAuth } from '../../_shared/providerTargetAuth';
import { fetchRoutingConfig } from '../../access-point/defaults';
import { apiClient } from '../../../../../api';
import type { CanvasNode } from '../../../SurfaceCanvas';
import type { ConfigPanelProps } from '../../types';

jest.mock('../../../../../api', () => {
  class MockApiError extends Error {
    readonly status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  }
  return { apiClient: { get: jest.fn(), fetch: jest.fn() }, ApiError: MockApiError };
});

jest.mock('../../access-point/defaults', () => ({
  ...jest.requireActual('../../access-point/defaults'),
  fetchRoutingConfig: jest.fn(),
}));

const OUTBOUND = 'https://outbound.example.com';

const STATIC_SECRET = {
  method: {
    static_secret: {
      secret_id: 'partner-key',
      header_name: 'X-Partner-Key',
      header_format: '{value}',
    },
  },
  fallback: 'reject',
};

const PROVIDER = {
  method: {
    credential_provider: {
      provider_id: 'prov-1',
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
      scopes: ['read', 'write'],
    },
  },
  fallback: 'reject',
};

beforeEach(() => {
  (fetchRoutingConfig as jest.Mock).mockResolvedValue({
    available_listen_addresses: [],
    available_outbound_listen_addresses: [OUTBOUND],
    channel_path_prefix: [{ id: 'agents', name: 'agents', prefix: '/agents' }],
  });
  (apiClient.get as jest.Mock).mockImplementation((path: string) =>
    Promise.resolve({
      data:
        path === '/secrets/'
          ? [{ id: '1', name: 'Partner key', secret_id: 'partner-key', secret_type: 'api_key' }]
          : [],
    })
  );
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve([
        { id: 'prov-1', name: 'Partner provider', provider_type: 'oauth2_client_credentials' },
      ]),
  });
});

type Config = Record<string, unknown>;

/** A Transit Point as the builder loads it from the stored surface. */
function loaded(targetAuth: Config): Config {
  return {
    id: 'tp-1',
    alias: 'partner',
    target_endpoint: 'https://partner.example.com',
    require_transit_token: true,
    target_auth: targetAuth,
    _stored_target_auth: storedTargetAuth(targetAuth),
  };
}

/**
 * Opens the panel the way the builder does: each write is the whole config of the render that
 * made it, with the written fields over it, and the builder keeps the last write as the node's
 * config. Writes are held until `land` applies the last one, so a write made from the loaded
 * config replaces one made before it, which is the order the browser gives when the routing
 * config arrives before the builder applies the panel's first write.
 */
function openTransitPoint(config: Config) {
  const writes: Config[] = [];
  const props = (current: Config): ConfigPanelProps =>
    ({
      node: {
        id: 'transit-point-a2a-1',
        type: 'transit-point-a2a',
        label: '',
        configured: true,
        config: current,
      } as CanvasNode,
      config: current,
      updateField: (field: string, value: unknown) => writes.push({ ...current, [field]: value }),
      updateFields: (fields: Config) => writes.push({ ...current, ...fields }),
      replaceCommit: jest.fn(),
      protocol: 'a2a',
      allNodes: [],
    }) as unknown as ConfigPanelProps;
  const view = render(<TransitPointPanel {...props(config)} />);
  const land = (): Config => {
    const last = writes[writes.length - 1] ?? config;
    view.rerender(<TransitPointPanel {...props(last)} />);
    return last;
  };
  const listenerSeeded = () =>
    waitFor(() => expect(writes.some(write => 'route_suffix' in write)).toBe(true));
  return { writes, land, listenerSeeded };
}

const authType = () => screen.getByTestId('transit-point-target-auth-type');

describe('a Transit Point opened with a stored Target authentication', () => {
  it('shows its stored static secret when the listener seed lands last', async () => {
    const { land, listenerSeeded } = openTransitPoint(loaded(STATIC_SECRET));
    await listenerSeeded();
    land();

    expect(authType()).toHaveValue('custom_header');
    await waitFor(() =>
      expect(screen.getByTestId('transit-point-target-auth-secret')).toHaveValue('partner-key')
    );
    expect(screen.getByPlaceholderText('X-Auth')).toHaveValue('X-Partner-Key');
    expect(screen.getByPlaceholderText('{value}')).toHaveValue('{value}');
  });

  it('shows its stored credential provider when the listener seed lands last', async () => {
    const { land, listenerSeeded } = openTransitPoint(loaded(PROVIDER));
    await listenerSeeded();
    land();

    expect(authType()).toHaveValue('credential_provider');
    await waitFor(() =>
      expect(screen.getByTestId('transit-point-target-auth-provider')).toHaveValue('prov-1')
    );
    expect(screen.getByTestId('transit-point-target-auth-provider-scopes')).toHaveValue(
      'read write'
    );
  });

  it('writes no Target authentication until the operator edits it', async () => {
    const { writes, land, listenerSeeded } = openTransitPoint(loaded(STATIC_SECRET));
    await listenerSeeded();

    expect(writes.filter(write => 'auth_type' in write)).toEqual([]);
    expect(transitPointTargetAuth(land())).toEqual(STATIC_SECRET);
  });

  it('writes the stored setting with the first edit', async () => {
    const { writes, land, listenerSeeded } = openTransitPoint(loaded(STATIC_SECRET));
    await listenerSeeded();
    land();

    fireEvent.change(screen.getByDisplayValue('Reject request'), {
      target: { value: 'passthrough' },
    });

    const edited = writes[writes.length - 1];
    expect(edited).toMatchObject({
      auth_type: 'custom_header',
      auth_secret: 'partner-key',
      auth_header_name: 'X-Partner-Key',
      auth_header_format: '{value}',
      auth_fallback: 'passthrough',
    });
    expect(transitPointTargetAuth(edited)).toEqual({ ...STATIC_SECRET, fallback: 'passthrough' });
  });

  it('shows None for a stored method the panel cannot show and keeps it', async () => {
    const stored = { method: { credential_lookup: { target_identifier: 'partner' } } };
    const { land, listenerSeeded } = openTransitPoint(loaded(stored));
    await listenerSeeded();
    const config = land();

    expect(authType()).toHaveValue('none');
    expect(transitPointTargetAuth(config)).toEqual(stored);
  });
});
