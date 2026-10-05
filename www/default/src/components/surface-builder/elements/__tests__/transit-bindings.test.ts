import { registry } from '../index';
import type { SurfaceContext } from '../types';
import {
  transitCredentialsApiToForm,
  transitCredentialsFormToApi,
  type TransitCredentialsForm,
} from '../_shared/TransitCredentialBindingSection';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'tp-bindings', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function readPath(obj: any, path: string): any {
  return path.split('.').reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

const baseNodes = [
  {
    id: 'ap',
    type: 'access-point',
    label: 'AP',
    configured: true,
    config: { route: '/api' },
  },
  {
    id: 'tg',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'http://example.com' },
  },
];

describe('transit-point transit_credentials', () => {
  it('writes form-shape credentials as the runtime API shape under transit.points[].transit_credentials', () => {
    const form: TransitCredentialsForm = {
      credential_provider_id: 'prov-1',
      scopes: 'repo, read:user',
      consent_mode: 'pre_authorize',
      inject_as_type: 'custom_header',
      inject_as_custom_name: 'X-GitHub-Token',
      inject_as_custom_format: 'token {value}',
    };
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: {
        target_endpoint: 'https://upstream.example.com',
        transit_credentials: form,
      },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.transit_credentials).toEqual({
      credential_provider_id: 'prov-1',
      scopes: ['repo', 'read:user'],
      consent_mode: 'pre_authorize',
      inject_as: { type: 'custom_header', name: 'X-GitHub-Token', format: 'token {value}' },
    });
  });

  it('omits transit_credentials when the binding is disabled or has no provider', () => {
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://upstream.example.com' },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.transit_credentials).toBeUndefined();
  });

  it('round-trips API↔form for a bearer-header binding', () => {
    const api = {
      credential_provider_id: 'prov-x',
      scopes: ['email'],
      consent_mode: 'on_demand',
      inject_as: { type: 'bearer_header' },
    };
    const form = transitCredentialsApiToForm(api)!;
    expect(form.credential_provider_id).toBe('prov-x');
    expect(form.scopes).toBe('email');
    expect(form.consent_mode).toBe('on_demand');
    expect(form.inject_as_type).toBe('bearer_header');
    expect(transitCredentialsFormToApi(form)).toEqual(api);
  });

  it('round-trips API↔form for a meta binding', () => {
    const api = {
      credential_provider_id: 'prov-y',
      scopes: [],
      consent_mode: 'pre_authorize',
      inject_as: { type: 'meta', field: 'oauth_token' },
    };
    const form = transitCredentialsApiToForm(api)!;
    expect(form.inject_as_type).toBe('meta');
    expect(form.inject_as_meta_field).toBe('oauth_token');
    expect(transitCredentialsFormToApi(form)).toEqual(api);
  });
});
