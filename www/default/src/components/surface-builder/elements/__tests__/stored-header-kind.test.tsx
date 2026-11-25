import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { registry } from '../index';
import { storedHeaderKind } from '../_shared/providerTargetAuth';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';
import { roundTrip, staticSecret } from '../testing/targetAuthFixtures';

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

describe('the kind of a stored Target header', () => {
  it.each([
    ['Authorization', 'Bearer {value}', 'bearer'],
    ['authorization', 'Bearer {value}', 'bearer'],
    ['AUTHORIZATION', 'bearer {value}', 'bearer'],
    ['Authorization', 'BEARER {value}', 'bearer'],
    ['Authorization', 'Bearer x-{value}', 'bearer'],
    ['Authorization', 'Basic {value}', 'basic'],
    ['authorization', 'basic {value}', 'basic'],
    ['X-API-Key', '{value}', 'api_key'],
    ['x-api-key', '{value}', 'api_key'],
    ['X_API_KEY', '{value}', 'api_key'],
    ['X-API-Key', 'Token {value}', 'api_key'],
    ['X-API-Key', 'Bearer {value}', 'api_key'],
    ['X-Partner', 'Bearer {value}', 'custom'],
    ['X-Auth', 'Basic {value}', 'custom'],
    ['X-Partner-Api-Key', '{value}', 'custom'],
    ['Authorization', '{value}', 'custom'],
    ['Authorization', 'Bearer{value}', 'custom'],
    ['Authorization', ' Bearer {value}', 'custom'],
    [' Authorization', 'Bearer {value}', 'custom'],
    ['Authorization ', 'Bearer {value}', 'custom'],
    ['X-Auth', 'Token {value}', 'custom'],
    ['', '', 'custom'],
  ])('reads %p with format %p as %s', (headerName, headerFormat, kind) => {
    expect(storedHeaderKind(headerName, headerFormat)).toBe(kind);
  });
});

const PAIRS_THE_EDITORS_DISAGREED_ON: Array<[string, string, string, string]> = [
  ['authorization', 'Bearer {value}', 'bearer', 'bearer'],
  ['X-Partner', 'Bearer {value}', 'custom', 'custom_header'],
  ['X-API-Key', 'Bearer {value}', 'api_key', 'api_key'],
  ['x-api-key', '{value}', 'api_key', 'api_key'],
  ['X-Partner-Api-Key', '{value}', 'custom', 'custom_header'],
];

const baseSurface = {
  name: 'stored-header',
  protocol: 'a2a',
  access_point: { route: '/stored', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
};

describe('the Managed Agent editor', () => {
  it.each(PAIRS_THE_EDITORS_DISAGREED_ON)(
    'shows a stored %p header with format %p as %s and saves it unchanged',
    (headerName, headerFormat, managedAgentType) => {
      const stored = staticSecret(headerName, headerFormat);
      const surface = {
        ...baseSurface,
        target: { endpoint: 'https://agent.example.com', auth: stored },
      };
      const config = registry.nodesFromPayload(surface).find(n => n.type === 'target')?.config;
      expect(config?.target_auth_type).toBe(managedAgentType);
      expect(roundTrip(surface).target.auth).toEqual(stored);
    }
  );
});

function transitPointPanelProps(node: CanvasNode, updateFields: jest.Mock): ConfigPanelProps {
  return {
    node,
    config: node.config,
    updateField: jest.fn(),
    updateFields,
    replaceCommit: jest.fn(),
    protocol: 'a2a',
    allNodes: [node],
  } as unknown as ConfigPanelProps;
}

describe('the Transit Point editor', () => {
  it.each(PAIRS_THE_EDITORS_DISAGREED_ON)(
    'shows a stored %p header with format %p as the %s kind (%s) and saves it unchanged',
    (headerName, headerFormat, _kind, transitPointType) => {
      const stored = staticSecret(headerName, headerFormat);
      const surface = {
        ...baseSurface,
        target: { endpoint: 'https://agent.example.com' },
        transit: {
          points: [
            {
              id: 'tp-1',
              alias: 'partner',
              protocol: 'a2a',
              target_endpoint: 'https://partner.example.com',
              require_transit_token: true,
              target_auth: stored,
            },
          ],
        },
      };
      const updateFields = jest.fn();
      const saved = roundTrip(surface, nodes => {
        const node = nodes.find(n => n.type === 'transit-point-a2a');
        render(<TransitPointPanel {...transitPointPanelProps(node, updateFields)} />);
        Object.assign(node.config, ...updateFields.mock.calls.map(([fields]) => fields));
      });
      expect(screen.getByTestId('transit-point-target-auth-type')).toHaveValue(transitPointType);
      expect(updateFields.mock.calls.filter(([fields]) => 'auth_type' in fields)).toEqual([]);
      expect(saved.transit.points[0].target_auth).toEqual(stored);
    }
  );
});
