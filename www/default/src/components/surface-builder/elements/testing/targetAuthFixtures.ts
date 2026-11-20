import { registry } from '../index';
import type { SurfaceContext } from '../types';
import { targetAuthBreaches } from '../targetAuthRules';

export const breachMessages = (surface: unknown, stored: unknown) =>
  targetAuthBreaches(surface, stored).map(breach => breach.message);

export function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'guards', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

export const staticSecret = (headerName: string, headerFormat: string) => ({
  method: {
    static_secret: { secret_id: 's', header_name: headerName, header_format: headerFormat },
  },
  fallback: 'reject',
});

export const providerAuth = {
  method: {
    credential_provider: {
      provider_id: 'prov-1',
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
      scopes: ['read', 'write'],
    },
  },
  auth_type: 'bearer',
  target_identifier: null,
  fallback: 'passthrough',
  future_field: { keep: true },
};

export const maConfig = (over: Record<string, unknown> = {}) => ({
  endpoint: 'https://agent.example.com',
  target_auth_enabled: true,
  target_auth_source: 'secret',
  target_auth_secret_id: 's',
  target_auth_type: 'custom',
  target_auth_header_name: 'X-Api-Key',
  target_auth_header_format: '{value}',
  ...over,
});

/** Loads `surface` into canvas nodes, lets `edit` change them, and builds the payload a save sends. */
export const roundTrip = (surface: any, edit?: (nodes: any[]) => void) => {
  const nodes = registry.nodesFromPayload(surface);
  edit?.(nodes);
  return registry.buildPayload(makeCtx(nodes)) as any;
};

/** A stored method the editors have no form for. */
export const unknownMethodAuth = {
  method: { credential_lookup: { target_identifier: 'partner' } },
  fallback: 'reject',
};
