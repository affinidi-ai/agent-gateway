import { buildCanvasBlob, registry } from '../index';
import type { SurfaceContext } from '../types';
import { nodesFromSurface } from '../../nodesFromSurface';
import {
  transitCredentialsApiToForm,
  transitCredentialsFormToApi,
  transitCredentialsToApi,
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

describe('transitCredentialsToApi', () => {
  const api = {
    credential_provider_id: 'prov-1',
    scopes: ['repo', 'read:user'],
    consent_mode: 'pre_authorize',
    inject_as: { type: 'meta', field: 'oauth_token' },
  };

  it('converts form-state to the runtime shape', () => {
    expect(transitCredentialsToApi(transitCredentialsApiToForm(api))).toEqual(api);
  });

  it('returns credentials already in the runtime shape unchanged', () => {
    expect(transitCredentialsToApi(api)).toEqual(api);
  });

  it('keeps the stored elicitation timeout and fallback in either shape', () => {
    const elicit = {
      ...api,
      consent_mode: 'elicit',
      elicit_timeout_secs: 45,
      elicit_fallback: 'fail',
    };
    expect(transitCredentialsToApi(elicit)).toEqual(elicit);
    expect(transitCredentialsToApi(transitCredentialsApiToForm(elicit))).toEqual(elicit);
  });

  it('returns undefined for missing, non-object or provider-less values', () => {
    expect(transitCredentialsToApi(undefined)).toBeUndefined();
    expect(transitCredentialsToApi(null)).toBeUndefined();
    expect(transitCredentialsToApi('prov-1')).toBeUndefined();
    expect(transitCredentialsToApi({ ...api, credential_provider_id: '' })).toBeUndefined();
    expect(
      transitCredentialsToApi({ ...transitCredentialsApiToForm(api), credential_provider_id: '' })
    ).toBeUndefined();
  });
});

describe('saving a reloaded surface with a Transit Point', () => {
  const api = {
    credential_provider_id: 'prov-1',
    scopes: ['repo', 'read:user'],
    consent_mode: 'pre_authorize',
    inject_as: { type: 'custom_header', name: 'X-GitHub-Token', format: 'token {value}' },
  };

  function savedSurface(tpConfig: Record<string, any>): any {
    const nodes = [
      ...baseNodes,
      {
        id: 'target-variant',
        type: 'target-variant',
        label: 'Variants',
        configured: true,
        config: { variants: [] },
      },
      {
        id: 'transit-point-a2a-1',
        type: 'transit-point-a2a',
        label: 'Upstream',
        configured: true,
        config: { name: 'Upstream', target_endpoint: 'https://upstream.example.com', ...tpConfig },
        parentId: 'ap',
      },
    ];
    const payload = registry.buildPayload(makeCtx(nodes));
    payload.canvas = buildCanvasBlob(nodes as any);
    return payload;
  }

  function saveAfterEditingTarget(saved: any): any {
    const nodes = nodesFromSurface(saved).map(n =>
      n.type === 'target'
        ? { ...n, config: { ...n.config, endpoint: 'https://edited.example.com' } }
        : n
    );
    return registry.buildPayload(makeCtx(nodes));
  }

  it('keeps a Transit Point with credentials when another element is edited after reload', () => {
    const saved = savedSurface({ transit_credentials: transitCredentialsApiToForm(api) });
    expect(saved.transit.points[0].transit_credentials).toEqual(api);

    const resaved = saveAfterEditingTarget(saved);

    expect(resaved.target.endpoint).toBe('https://edited.example.com');
    expect(resaved.transit.points).toHaveLength(1);
    expect(resaved.transit.points[0]).toMatchObject({
      name: 'Upstream',
      target_endpoint: 'https://upstream.example.com',
      transit_credentials: api,
    });
  });

  it('keeps the stored elicitation settings when another element is edited after reload', () => {
    const elicit = {
      ...api,
      consent_mode: 'elicit',
      elicit_timeout_secs: 45,
      elicit_fallback: 'fail',
    };
    const saved = savedSurface({ transit_credentials: transitCredentialsApiToForm(elicit) });
    expect(saved.transit.points[0].transit_credentials).toEqual(elicit);

    const resaved = saveAfterEditingTarget(saved);

    expect(resaved.transit.points[0].transit_credentials).toEqual(elicit);
  });

  it('keeps a Transit Point without credentials when another element is edited after reload', () => {
    const resaved = saveAfterEditingTarget(savedSurface({}));

    expect(resaved.transit.points).toHaveLength(1);
    expect(resaved.transit.points[0].target_endpoint).toBe('https://upstream.example.com');
    expect(resaved.transit.points[0].transit_credentials).toBeUndefined();
  });
});

describe('Transit Points changed through the API after a dashboard save', () => {
  const cred = {
    credential_provider_id: 'prov-1',
    scopes: ['repo'],
    consent_mode: 'on_demand',
    inject_as: { type: 'bearer_header' },
  };

  const tp = (n: number, config: Record<string, any> = {}) => ({
    id: `transit-point-a2a-${n}`,
    type: 'transit-point-a2a',
    label: '',
    configured: true,
    config: {
      id: `tp-${n}`,
      name: `tp-${n}`,
      target_endpoint: `https://tp${n}.example`,
      ...config,
    },
    parentId: 'ap',
    position: { x: 100 * n, y: 50 },
  });

  /** Save from the dashboard, apply an API change, then reload and save again. */
  function resaveAfter(nodes: any[], change: (stored: any) => void): any {
    const stored = registry.buildPayload(makeCtx(nodes));
    stored.canvas = buildCanvasBlob(nodes as any);
    change(stored);
    return registry.buildPayload(makeCtx(nodesFromSurface(stored)));
  }

  const points = (payload: any) =>
    (payload.transit?.points ?? []).map((p: any) => [
      p.id,
      p.target_endpoint,
      p.transit_credentials?.credential_provider_id ?? null,
    ]);

  const shapes = [
    ['form-state', transitCredentialsApiToForm(cred)],
    ['stored', cred],
  ] as const;

  for (const [shape, value] of shapes) {
    it(`does not give a removed Transit Point's credential to another one (${shape} shape)`, () => {
      const resaved = resaveAfter(
        [...baseNodes, tp(1, { transit_credentials: value }), tp(2)],
        stored => stored.transit.points.splice(0, 1)
      );

      expect(points(resaved)).toEqual([['tp-2', 'https://tp2.example', null]]);
    });

    it(`does not restore a credential removed through the API (${shape} shape)`, () => {
      const resaved = resaveAfter([...baseNodes, tp(1, { transit_credentials: value })], stored => {
        delete stored.transit.points[0].transit_credentials;
      });

      expect(points(resaved)).toEqual([['tp-1', 'https://tp1.example', null]]);
    });
  }

  it("does not give a removed Transit Point's settings to one added through the API", () => {
    const resaved = resaveAfter([...baseNodes, tp(1, { transit_credentials: cred })], stored => {
      stored.transit.points = [
        { id: 'tp-3', name: 'tp-3', target_endpoint: 'https://tp3.example', protocol: 'a2a' },
      ];
    });

    expect(points(resaved)).toEqual([['tp-3', 'https://tp3.example', null]]);
  });

  it("does not attach a removed Transit Point's elements to another one", () => {
    const rateLimit = {
      id: 'rate-limit-transit-point-a2a-1',
      type: 'rate-limit',
      label: '',
      configured: true,
      config: { requests: '5', window_secs: '60' },
      parentId: 'transit-point-a2a-1',
    };
    const resaved = resaveAfter([...baseNodes, tp(1), rateLimit, tp(2)], stored => {
      expect(stored.transit.points[0].rate_limit).toEqual({ requests: 5, window_secs: 60 });
      stored.transit.points.splice(0, 1);
    });

    expect(points(resaved)).toEqual([['tp-2', 'https://tp2.example', null]]);
    expect(resaved.transit.points[0].rate_limit).toBeUndefined();
    expect(resaved.access_point?.rate_limit).toBeUndefined();
  });

  it('does not turn the Fabric credential switch back on after the API turned it off', () => {
    const fabric = 'fabric://peer-gateway/upstream';
    const resaved = resaveAfter(
      [
        ...baseNodes,
        tp(1, {
          target_endpoint: fabric,
          transit_credentials: cred,
          fabric_delegated_credentials: true,
        }),
      ],
      stored => {
        expect(stored.transit.points[0].fabric_delegated_credentials).toBe(true);
        delete stored.transit.points[0].fabric_delegated_credentials;
      }
    );

    expect(resaved.transit.points[0].target_endpoint).toBe(fabric);
    expect(resaved.transit.points[0].fabric_delegated_credentials).toBeUndefined();
  });

  it('keeps the remaining Transit Point on its own node and layout', () => {
    const nodes = [...baseNodes, tp(1), tp(2)];
    const stored = registry.buildPayload(makeCtx(nodes));
    stored.canvas = buildCanvasBlob(nodes as any);
    stored.transit.points.splice(0, 1);

    const reloaded = registry.nodesFromPayload(stored);
    const tps = reloaded.filter(n => registry.isTransitPointType(n.type));

    expect(tps.map(n => [n.id, n.config?.id, n.position])).toEqual([
      ['transit-point-a2a-2', 'tp-2', { x: 200, y: 50 }],
    ]);
  });
});
