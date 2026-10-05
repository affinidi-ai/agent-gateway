import {
  applyFullSurfaceTemplate,
  autoApplyFullSurfaceTemplate,
  buildAutoPlaceholderContext,
  previewFullTemplate,
} from '../applyFullTemplate';
import type { SurfaceTemplate } from '../types';

const mtlsFullTpl: SurfaceTemplate = {
  id: 'tpl-full-mtls',
  name: 'mTLS A2A',
  kind: 'full',
  surface: {
    name: '$NAME',
    access_point: {
      listen_address: '$HOST',
      route: '$ROUTE',
      protocol: 'a2a',
    },
    target: { endpoint: '$TARGET_ENDPOINT' },
    canvas: {
      variants: [{ alias: '$SLUG-v1' }, { alias: 'static-v2' }],
    },
  },
};

describe('previewFullTemplate', () => {
  it('returns the sorted set of placeholder tokens present in the snapshot', () => {
    expect(previewFullTemplate(mtlsFullTpl).tokens).toEqual([
      '$HOST',
      '$NAME',
      '$ROUTE',
      '$SLUG',
      '$TARGET_ENDPOINT',
    ]);
  });

  it('throws if called on a partial template', () => {
    const partial: SurfaceTemplate = { id: 'p', name: 'P', items: [] };
    expect(() => previewFullTemplate(partial)).toThrow(/kind='partial'/);
  });

  it('throws if a full template has no surface snapshot', () => {
    const broken: SurfaceTemplate = { id: 'b', name: 'B', kind: 'full' };
    expect(() => previewFullTemplate(broken)).toThrow(/no surface snapshot/);
  });
});

describe('applyFullSurfaceTemplate', () => {
  it('substitutes all bound placeholders and reports none missing', () => {
    const { surface, missing } = applyFullSurfaceTemplate(mtlsFullTpl, {
      host: '127.0.0.1:8443',
      route: '/agent',
      name: 'mtls-demo',
      slug: 'demo',
      targetEndpoint: 'http://backend:9000',
    });
    expect(missing).toEqual([]);
    expect(surface).toEqual({
      name: 'mtls-demo',
      access_point: {
        listen_address: '127.0.0.1:8443',
        route: '/agent',
        protocol: 'a2a',
      },
      target: { endpoint: 'http://backend:9000' },
      canvas: {
        variants: [{ alias: 'demo-v1' }, { alias: 'static-v2' }],
      },
    });
  });

  it('leaves unresolved tokens literal and lists them in missing', () => {
    const { surface, missing } = applyFullSurfaceTemplate(mtlsFullTpl, {
      host: 'h',
      route: '/r',
    });
    expect(missing.sort()).toEqual(['$NAME', '$SLUG', '$TARGET_ENDPOINT']);
    expect(surface.access_point.listen_address).toBe('h');
    expect(surface.name).toBe('$NAME');
    expect(surface.target.endpoint).toBe('$TARGET_ENDPOINT');
  });

  it('does not mutate the input template', () => {
    const before = JSON.parse(JSON.stringify(mtlsFullTpl));
    applyFullSurfaceTemplate(mtlsFullTpl, { host: 'h' });
    expect(mtlsFullTpl).toEqual(before);
  });

  it('throws on non-full templates', () => {
    const partial: SurfaceTemplate = { id: 'p', name: 'P', items: [] };
    expect(() => applyFullSurfaceTemplate(partial, {})).toThrow(/kind='partial'/);
  });

  it('throws if a full template has no surface snapshot', () => {
    const broken: SurfaceTemplate = { id: 'b', name: 'B', kind: 'full' };
    expect(() => applyFullSurfaceTemplate(broken, {})).toThrow(/no surface snapshot/);
  });
});

describe('buildAutoPlaceholderContext', () => {
  it('binds $HOST / $ROUTE from the first listen address and channel prefix', () => {
    const ctx = buildAutoPlaceholderContext({
      available_listen_addresses: ['127.0.0.1:8443', '127.0.0.1:9000'],
      channel_path_prefix: [{ id: 'p1', name: 'P1', prefix: '/v1' }],
    });
    expect(ctx.host).toBe('127.0.0.1:8443');
    expect(ctx.route).toMatch(/^\/v1\/.+/);
    // $NAME / $TARGET_ENDPOINT intentionally left unset.
    expect(ctx.name).toBeUndefined();
    expect(ctx.targetEndpoint).toBeUndefined();
  });
});

describe('autoApplyFullSurfaceTemplate', () => {
  it('fills $HOST/$ROUTE from routing and blanks the rest so the form validator catches them', () => {
    const { surface } = autoApplyFullSurfaceTemplate(mtlsFullTpl, {
      available_listen_addresses: ['127.0.0.1:8443'],
      channel_path_prefix: [{ id: 'p1', name: 'P1', prefix: '/v1' }],
    });
    expect(surface.access_point.listen_address).toBe('127.0.0.1:8443');
    expect(surface.access_point.route).toMatch(/^\/v1\/.+/);
    // `name` is stripped entirely — the user always fills it in.
    expect('name' in surface).toBe(false);
    expect(surface.target.endpoint).toBe('');
    // Unknown / `$SLUG` portions inside larger strings are blanked too.
    expect(surface.canvas.variants[0].alias).toBe('-v1');
    expect(surface.canvas.variants[1].alias).toBe('static-v2');
  });

  it('handles a null routing config by blanking every token', () => {
    const { surface } = autoApplyFullSurfaceTemplate(mtlsFullTpl, null);
    expect(surface.access_point.listen_address).toBe('');
    expect(surface.access_point.route).toBe('');
    expect('name' in surface).toBe(false);
    expect(surface.target.endpoint).toBe('');
  });
});
