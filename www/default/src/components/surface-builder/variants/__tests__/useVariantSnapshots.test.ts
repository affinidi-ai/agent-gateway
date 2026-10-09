import { registry } from '../../elements';
import { act, renderHook } from '@testing-library/react';
import {
  BASE_VARIANT_ID,
  patchAccessPointCanvasNode,
  syncAccessPointIdentifiers,
  useVariantSnapshots,
} from '../useVariantSnapshots';

const samplePayload = {
  access_point: { rate_limit: { rpm: 1 }, primary_extension: 'base' },
  target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
  variants: [
    { id: 'v1', alias: 'def', name: 'Default' },
    {
      id: 'v2',
      alias: 'fast',
      name: 'Fast',
      overrides: {
        access_point: { rate_limit: { rpm: 99 } },
        target: { endpoint: 'https://fast/y' },
      },
    },
  ],
  default_variant_id: 'v1',
};

describe('useVariantSnapshots', () => {
  it('starts empty', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    expect(result.current.variants).toEqual([]);
    expect(result.current.activeVariantId).toBeNull();
    expect(result.current.defaultVariantId).toBeNull();
    expect(result.current.hasVariants).toBe(false);
  });

  it('hydrates from a payload — variants metadata, default + active set, snapshots resolved', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    let activePayload: any;
    let activeId: string | null = null;
    act(() => {
      const r = result.current.hydrateFromPayload(samplePayload);
      activePayload = r.activePayload;
      activeId = r.activeId;
    });
    expect(activeId).toBe('v1');
    expect(result.current.activeVariantId).toBe('v1');
    expect(result.current.defaultVariantId).toBe('v1');
    expect(result.current.variants.map(v => v.id)).toEqual(['v1', 'v2']);
    expect(result.current.hasVariants).toBe(true);
    // Default variant resolves to the base shape, sans variants/default_variant_id.
    expect(activePayload.access_point.rate_limit).toEqual({ rpm: 1 });
    expect(activePayload.variants).toBeUndefined();
    expect(activePayload.default_variant_id).toBeUndefined();
  });

  it('switchVariant snapshots the previous canvas state and returns the next variant payload', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // User edits the default variant on the canvas: bump rpm to 7.
    const editedDefault = {
      access_point: { rate_limit: { rpm: 7 }, primary_extension: 'base' },
      target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
    };
    let nextPayload: any;
    act(() => {
      nextPayload = result.current.switchVariant('v2', editedDefault);
    });
    expect(result.current.activeVariantId).toBe('v2');
    // Returned payload is v2's resolved snapshot (overrides applied on the original base).
    expect(nextPayload.access_point.rate_limit).toEqual({ rpm: 99 });
    expect(nextPayload.target.endpoint).toEqual('https://fast/y');
    // Switching back returns the previously snapshotted edited default (rpm: 7).
    let backPayload: any;
    act(() => {
      backPayload = result.current.switchVariant('v1', nextPayload);
    });
    expect(backPayload.access_point.rate_limit).toEqual({ rpm: 7 });
  });

  it('switchVariant to the same id is a no-op that returns the existing snapshot', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    const sameAgain: any = result.current.switchVariant('v1', { junk: true });
    // Same-id branch returns the stored snapshot without mutating it.
    expect(sameAgain.junk).toBeUndefined();
    expect(sameAgain.access_point.rate_limit).toEqual({ rpm: 1 });
  });

  it('switchVariant to a brand-new variant shows BASE, not the previously-active variant', () => {
    // Repro for "a second variant inherits from the variant I was on
    // (its alias), not base". Switch to the configured v2 (rpm 99),
    // register a new snapshot-less v3, then switch to v3: it must show
    // base (rpm 1), never v2's edited canvas.
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    let v2Payload: any;
    act(() => {
      v2Payload = result.current.switchVariant('v2', {
        access_point: { rate_limit: { rpm: 1 }, primary_extension: 'base' },
        target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
      });
    });
    // v2 is configured: rpm 99.
    expect(v2Payload.access_point.rate_limit).toEqual({ rpm: 99 });
    act(() => {
      result.current.setCatalog({
        variants: [
          { id: 'v1', alias: 'def', name: 'Default' },
          { id: 'v2', alias: 'fast', name: 'Fast' },
          { id: 'v3', alias: 'new', name: 'New' },
        ],
        defaultVariantId: 'v1',
      });
    });
    let v3Payload: any;
    act(() => {
      // currentPayload is v2's live canvas (rpm 99) — the variant we
      // are switching AWAY from. v3 has no snapshot, so it must fall
      // back to BASE (rpm 1), not adopt v2's config.
      v3Payload = result.current.switchVariant('v3', v2Payload);
    });
    expect(result.current.activeVariantId).toBe('v3');
    expect(v3Payload.access_point.rate_limit).toEqual({ rpm: 1 });
    expect(v3Payload.target.endpoint).toEqual('https://base/x');
  });

  it('setCatalog rewrites the target-variant canvas mirror in every snapshot to the current catalog', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Base snapshot carries a canvas whose target-variant mirror is
    // STALE — it still shows the pre-rename alias `slow` for v2.
    act(() => {
      result.current.setSnapshot(BASE_VARIANT_ID, {
        access_point: { rate_limit: { rpm: 1 }, primary_extension: 'base' },
        target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
        canvas: {
          nodes: [
            { id: 'target', type: 'target' },
            {
              id: 'target-variant',
              type: 'target-variant',
              config: {
                variants: [
                  { id: 'v1', alias: 'def', name: 'Default', enabled: true },
                  { id: 'v2', alias: 'slow', name: 'Slow', enabled: true },
                ],
                default_variant_id: 'v1',
              },
            },
          ],
        },
      });
    });
    // Catalog renames v2 -> `fast` and flips the default to v2.
    act(() => {
      result.current.setCatalog({
        variants: [
          { id: 'v1', alias: 'def', name: 'Default' },
          { id: 'v2', alias: 'fast', name: 'Fast' },
        ],
        defaultVariantId: 'v2',
      });
    });
    const base = result.current.getSnapshot(BASE_VARIANT_ID);
    const tv = base.canvas.nodes.find((n: any) => n.id === 'target-variant');
    // The base snapshot's mirror now reflects the real catalog — no
    // stale `slow` alias, and the new default is recorded.
    expect(tv.config.variants).toEqual([
      { id: 'v1', alias: 'def', name: 'Default', enabled: true },
      { id: 'v2', alias: 'fast', name: 'Fast', enabled: true },
    ]);
    expect(tv.config.default_variant_id).toBe('v2');
    // Non-mirror nodes are untouched.
    expect(base.canvas.nodes.find((n: any) => n.id === 'target')).toEqual({
      id: 'target',
      type: 'target',
    });
  });

  it('setCatalog drops snapshots for removed variants and resets active to default if missing', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Switch to v2 so it's active, then remove it from the catalog.
    act(() => {
      result.current.switchVariant('v2', samplePayload);
    });
    expect(result.current.activeVariantId).toBe('v2');
    act(() => {
      result.current.setCatalog({
        variants: [{ id: 'v1', alias: 'def', name: 'Default' }],
        defaultVariantId: 'v1',
      });
    });
    expect(result.current.variants.map(v => v.id)).toEqual(['v1']);
    expect(result.current.activeVariantId).toBe('v1');
  });

  it('buildVariantsWireSlice projects every named variant as a full overrides delta against the base', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Switch to v2 then re-edit it on the "canvas" (rpm bumped to 123).
    act(() => {
      result.current.switchVariant('v2', samplePayload);
    });
    const liveV2 = {
      access_point: { rate_limit: { rpm: 123 } },
      target: { endpoint: 'https://fast/y', auth: { kind: 'none' } },
    };
    const wire = result.current.buildVariantsWireSlice(liveV2);
    // v1 is the named default — it now carries its full snapshot as
    // overrides (the base lives separately under wire.basePayload and
    // is the un-overridden surface).
    expect(wire.defaultVariantId).toBe('v1');
    const v1Wire = wire.variants.find(v => v.id === 'v1')!;
    const v2Wire = wire.variants.find(v => v.id === 'v2')!;
    expect(v1Wire.overrides?.access_point).toEqual({
      rate_limit: { rpm: 1 },
      primary_extension: 'base',
    });
    expect(v2Wire.overrides?.access_point).toEqual({ rate_limit: { rpm: 123 } });
    expect(v2Wire.overrides?.target).toEqual({
      endpoint: 'https://fast/y',
      auth: { kind: 'none' },
    });
    // basePayload is the always-present base snapshot — the unmodified surface.
    expect(wire.basePayload.access_point.rate_limit).toEqual({ rpm: 1 });
  });

  it('buildVariantsWireSlice freezes a never-visited variant from the base snapshot instead of emitting empty overrides', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Operator adds a brand-new variant, marks it default, and never
    // switches the canvas to it — so it has no snapshot of its own.
    act(() => {
      result.current.setCatalog({
        variants: [
          { id: 'v1', alias: 'def', name: 'Default' },
          { id: 'v2', alias: 'fast', name: 'Fast' },
          { id: 'v3', alias: 'new', name: 'New' },
        ],
        defaultVariantId: 'v3',
      });
    });
    const wire = result.current.buildVariantsWireSlice(samplePayload);
    const v3Wire = wire.variants.find(v => v.id === 'v3')!;
    // The never-visited variant is frozen from base — not an empty
    // override that would silently inherit later base edits.
    expect(v3Wire.overrides).not.toEqual({});
    expect(v3Wire.overrides?.complete).toBe(true);
    expect(v3Wire.overrides?.access_point).toEqual({
      rate_limit: { rpm: 1 },
      primary_extension: 'base',
    });
    expect(v3Wire.overrides?.target).toEqual({
      endpoint: 'https://base/x',
      auth: { kind: 'none' },
    });
  });

  it('returns the base snapshot when there are no variants', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    let activePayload: any;
    let activeId: string | null = null;
    act(() => {
      const r = result.current.hydrateFromPayload({ access_point: { rate_limit: { rpm: 1 } } });
      activePayload = r.activePayload;
      activeId = r.activeId;
    });
    // No named variants — base is the implicit default and the active
    // selection. The hook reports `BASE_VARIANT_ID` as the active id.
    expect(activeId).toBe(BASE_VARIANT_ID);
    expect(activePayload).toEqual({ access_point: { rate_limit: { rpm: 1 } } });
    expect(result.current.hasVariants).toBe(false);
    expect(result.current.defaultVariantId).toBeNull();
  });

  describe('access point URL is surface-level (shared across base + variants)', () => {
    const urlPayload = {
      access_point: {
        listen_address: '0.0.0.0:8443',
        route: '/old',
        protocol: 'a2a',
        rate_limit: { rpm: 1 },
      },
      target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
      variants: [
        { id: 'v1', alias: 'def', name: 'Default' },
        {
          id: 'v2',
          alias: 'fast',
          name: 'Fast',
          overrides: { access_point: { rate_limit: { rpm: 99 } } },
        },
      ],
      default_variant_id: 'v1',
    };

    it('propagates an access point URL edited on one variant to the others on switch', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      act(() => {
        result.current.hydrateFromPayload(urlPayload);
      });
      // Active is v1. Operator edits the surface URL on the canvas.
      const editedV1 = {
        access_point: {
          listen_address: '0.0.0.0:9000',
          route: '/new',
          protocol: 'a2a',
          rate_limit: { rpm: 1 },
        },
        target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
      };
      let v2Payload: any;
      act(() => {
        v2Payload = result.current.switchVariant('v2', editedV1);
      });
      // v2 must reflect the new URL — identifiers can't diverge from base.
      expect(v2Payload.access_point.listen_address).toBe('0.0.0.0:9000');
      expect(v2Payload.access_point.route).toBe('/new');
      // v2's own overridable field is untouched by the identifier sync.
      expect(v2Payload.access_point.rate_limit).toEqual({ rpm: 99 });
    });

    it('keeps a URL edited on a named variant on the wire base payload (not lost on save)', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      act(() => {
        result.current.hydrateFromPayload(urlPayload);
      });
      // Switch to the named (non-base) variant, then edit the URL there.
      act(() => {
        result.current.switchVariant('v2', urlPayload);
      });
      const liveV2 = {
        access_point: {
          listen_address: '0.0.0.0:9000',
          route: '/new',
          protocol: 'a2a',
          rate_limit: { rpm: 99 },
        },
        target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
      };
      const wire = result.current.buildVariantsWireSlice(liveV2);
      // Identifiers are stripped from per-variant overrides, so the base
      // payload is the only place the URL survives — it must carry the edit.
      expect(wire.basePayload.access_point.listen_address).toBe('0.0.0.0:9000');
      expect(wire.basePayload.access_point.route).toBe('/new');
      // And the URL is never leaked into the variant overrides.
      const v2Wire = wire.variants.find(v => v.id === 'v2')!;
      expect((v2Wire.overrides?.access_point as any)?.listen_address).toBeUndefined();
      expect((v2Wire.overrides?.access_point as any)?.route).toBeUndefined();
    });

    it('keeps the base A2A settings when saving while viewing an A2A proxy variant', () => {
      const ctx = (endpoint: string) => {
        const nodes = [
          {
            id: 'access-point',
            type: 'access-point',
            config: {
              route: '/a',
              listen_address: '0.0.0.0:8443',
              a2a_accepted_versions: ['0.3'],
              a2a_validation: 'full',
            },
          },
          { id: 'target', type: 'target', config: { endpoint } },
        ] as any[];
        return {
          protocol: 'a2a' as const,
          surfaceMeta: { name: 's', tags: [], status: 'active' as const },
          allNodes: nodes,
          nodesOfType: (t: string) => nodes.filter(n => n.type === t),
          firstNodeOfType: (t: string) => nodes.find(n => n.type === t),
        };
      };
      const base = registry.buildPayload(ctx('https://agent.example')) as any;
      expect(base.access_point.a2a).toEqual({ accepted_versions: ['0.3'], validation: 'full' });

      const { result } = renderHook(() => useVariantSnapshots());
      act(() => {
        result.current.hydrateFromPayload({
          ...base,
          variants: [
            {
              id: 'v2',
              alias: 'p',
              name: 'p',
              overrides: { target: { endpoint: 'a2a-proxy://w' } },
            },
          ],
        });
      });
      act(() => {
        result.current.switchVariant('v2', base);
      });
      const live = registry.buildPayload(ctx('a2a-proxy://w')) as any;
      expect(live.access_point).not.toHaveProperty('a2a');

      const wire = result.current.buildVariantsWireSlice(live);
      expect(wire.basePayload.access_point.a2a).toEqual({
        accepted_versions: ['0.3'],
        validation: 'full',
      });
    });

    it('shares the A2A settings across variants and keeps them on the base payload', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      act(() => {
        result.current.hydrateFromPayload(urlPayload);
      });
      const a2a = { accepted_versions: ['1.0'], validation: 'full' };
      const editedV1 = {
        access_point: { ...urlPayload.access_point, a2a },
        target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
      };
      let v2Payload: any;
      act(() => {
        v2Payload = result.current.switchVariant('v2', editedV1);
      });
      expect(v2Payload.access_point.a2a).toEqual(a2a);
      expect(v2Payload.access_point.rate_limit).toEqual({ rpm: 99 });

      const wire = result.current.buildVariantsWireSlice(v2Payload);
      expect(wire.basePayload.access_point.a2a).toEqual(a2a);
      const v2Wire = wire.variants.find(v => v.id === 'v2')!;
      expect((v2Wire.overrides?.access_point as any)?.a2a).toBeUndefined();
    });

    it('syncs the A2A settings inside every variant canvas blob', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      const apCanvasConfig = (versions: string[], validate: boolean) => ({
        listen_address: '0.0.0.0:8443',
        route: '/agents/a',
        protocol: 'a2a',
        a2a_accepted_versions: versions,
        a2a_validation: validate ? 'full' : 'envelope',
      });
      const canvasBlob = (versions: string[], validate: boolean) => ({
        version: 1,
        nodes: [
          { id: 'access-point', type: 'access-point', config: apCanvasConfig(versions, validate) },
        ],
      });
      act(() => {
        result.current.hydrateFromPayload({
          access_point: { listen_address: '0.0.0.0:8443', route: '/agents/a', protocol: 'a2a' },
          canvas: canvasBlob(['0.3', '1.0'], false),
          variants: [
            {
              id: 'v2',
              alias: 'fast',
              name: 'Fast',
              overrides: { complete: true, canvas: canvasBlob(['0.3', '1.0'], false) },
            },
          ],
          default_variant_id: 'v2',
        });
      });
      act(() => {
        result.current.switchVariant(BASE_VARIANT_ID, {
          access_point: { listen_address: '0.0.0.0:8443', route: '/agents/a', protocol: 'a2a' },
          canvas: canvasBlob(['1.0'], true),
        });
      });
      const baseAp = result.current
        .getSnapshot(BASE_VARIANT_ID)
        .canvas.nodes.find((n: any) => n.id === 'access-point');
      expect(baseAp.config.a2a_accepted_versions).toEqual(['1.0']);
      expect(baseAp.config.a2a_validation).toBe('full');
    });

    it('syncs the access-point config inside every variant canvas blob (incl. route_prefix/suffix)', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      // Base + one variant, each carrying its own canvas blob with an
      // access-point node whose config holds the URL + the UI-only
      // route-composition fields (as saved surfaces do).
      const apCanvasConfig = {
        listen_address: '0.0.0.0:8443',
        route: '/agents/old',
        protocol: 'a2a',
        route_prefix: '/agents',
        route_suffix: 'old',
        publish_to_did_document: false,
      };
      const canvasBlob = () => ({
        version: 1,
        nodes: [{ id: 'access-point', type: 'access-point', config: { ...apCanvasConfig } }],
      });
      const payload = {
        access_point: { listen_address: '0.0.0.0:8443', route: '/agents/old', protocol: 'a2a' },
        canvas: canvasBlob(),
        variants: [
          {
            id: 'v2',
            alias: 'fast',
            name: 'Fast',
            overrides: {
              complete: true,
              access_point: { publish_to_did_document: true },
              canvas: canvasBlob(),
            },
          },
        ],
        default_variant_id: 'v2',
      };
      act(() => {
        result.current.hydrateFromPayload(payload);
      });
      // Active is v2 (the default). Edit the URL on the canvas — the live
      // payload carries a fresh canvas blob with recomposed route fields.
      const liveV2 = {
        access_point: { listen_address: '0.0.0.0:9000', route: '/agents/new', protocol: 'a2a' },
        canvas: {
          version: 1,
          nodes: [
            {
              id: 'access-point',
              type: 'access-point',
              config: {
                listen_address: '0.0.0.0:9000',
                route: '/agents/new',
                protocol: 'a2a',
                route_prefix: '/agents',
                route_suffix: 'new',
                publish_to_did_document: true,
              },
            },
          ],
        },
      };
      act(() => {
        result.current.switchVariant(BASE_VARIANT_ID, liveV2);
      });
      // Base snapshot's canvas access-point node must reflect the new URL
      // and the recomposed route_suffix — not the stale frozen copy.
      const baseSnap = result.current.getSnapshot(BASE_VARIANT_ID);
      const baseAp = baseSnap.canvas.nodes.find((n: any) => n.id === 'access-point');
      expect(baseAp.config.route).toBe('/agents/new');
      expect(baseAp.config.listen_address).toBe('0.0.0.0:9000');
      expect(baseAp.config.route_suffix).toBe('new');
      // The variant-overridable field on the blob is left untouched.
      expect(baseAp.config.publish_to_did_document).toBe(false);
    });

    it('refreshes a stale variant canvas prefix/suffix from base on hydrate', () => {
      const { result } = renderHook(() => useVariantSnapshots());
      // A previously-saved surface whose base route was changed to
      // `/agents/new`, but whose variant override still carries a canvas
      // blob frozen at the old `/agents/old` (with the old
      // route_prefix/route_suffix). The wire base slice is current; only
      // the variant's canvas blob is stale.
      const staleVariantCanvas = {
        version: 1,
        nodes: [
          {
            id: 'access-point',
            type: 'access-point',
            config: {
              listen_address: '0.0.0.0:8443',
              route: '/agents/old',
              protocol: 'a2a',
              route_prefix: '/agents',
              route_suffix: 'old',
              publish_to_did_document: true,
            },
          },
        ],
      };
      const payload = {
        access_point: { listen_address: '0.0.0.0:8443', route: '/agents/new', protocol: 'a2a' },
        canvas: {
          version: 1,
          nodes: [
            {
              id: 'access-point',
              type: 'access-point',
              config: {
                listen_address: '0.0.0.0:8443',
                route: '/agents/new',
                protocol: 'a2a',
                route_prefix: '/agents',
                route_suffix: 'new',
                publish_to_did_document: false,
              },
            },
          ],
        },
        variants: [
          {
            id: 'v2',
            alias: 'fast',
            name: 'Fast',
            overrides: {
              complete: true,
              access_point: { publish_to_did_document: true },
              canvas: staleVariantCanvas,
            },
          },
        ],
        default_variant_id: 'v2',
      };
      act(() => {
        result.current.hydrateFromPayload(payload);
      });
      // The variant's canvas access-point node must be refreshed from
      // base's identifiers (route + route_suffix) on load — not left at
      // the stale `/agents/old` copy that the route editor would render.
      const v2Snap = result.current.getSnapshot('v2');
      const v2Ap = v2Snap.canvas.nodes.find((n: any) => n.id === 'access-point');
      expect(v2Ap.config.route).toBe('/agents/new');
      expect(v2Ap.config.route_suffix).toBe('new');
      // The variant's own overridable field stays as the variant set it.
      expect(v2Ap.config.publish_to_did_document).toBe(true);
    });
  });
});

describe('patchAccessPointCanvasNode', () => {
  const ids = { route: '/agents/new', route_suffix: 'new' };
  const canvasBlob = (...nodes: any[]) => ({ version: 1, nodes });

  it('merges identifiers into the AP config, leaving everything else intact', () => {
    const canvas = canvasBlob(
      { id: 'target', config: { endpoint: 'x' } },
      {
        id: 'access-point',
        type: 'access-point',
        position: { x: 10, y: 20 },
        config: { route: '/agents/old', route_suffix: 'old', publish_to_did_document: true },
      }
    );
    const out = patchAccessPointCanvasNode(canvas, ids);
    const ap = out.nodes.find((n: any) => n.id === 'access-point');

    // New blob, identifiers applied, non-identifier + layout fields kept.
    expect(out).not.toBe(canvas);
    expect(ap.config).toMatchObject({
      route: '/agents/new',
      route_suffix: 'new',
      publish_to_did_document: true,
    });
    expect(ap.type).toBe('access-point');
    expect(ap.position).toEqual({ x: 10, y: 20 });
    // Siblings and the original canvas are untouched.
    expect(out.nodes[0].config.endpoint).toBe('x');
    expect(canvas.nodes[1].config.route).toBe('/agents/old');
  });
});

describe('syncAccessPointIdentifiers', () => {
  it('returns the same snapshots reference when the source has no identifiers or canvas', () => {
    const snapshots = { __base__: { access_point: { route: '/keep' } } };
    // Source carries neither access_point nor a canvas access-point node.
    expect(syncAccessPointIdentifiers(snapshots, { target: { endpoint: 'x' } })).toBe(snapshots);
  });

  it('copies the wire identifier fields from source into every snapshot access_point', () => {
    const source = {
      access_point: { listen_address: '0.0.0.0:9000', route: '/new', protocol: 'a2a', name: 'n' },
    };
    const snapshots = {
      __base__: {
        access_point: { listen_address: '0.0.0.0:1', route: '/old', rate_limit: { rpm: 1 } },
      },
      v2: { access_point: { listen_address: '0.0.0.0:1', route: '/old', rate_limit: { rpm: 9 } } },
    };
    const out = syncAccessPointIdentifiers(snapshots, source);
    // Identifiers overwritten from source on both snapshots.
    expect(out.__base__.access_point.listen_address).toBe('0.0.0.0:9000');
    expect(out.__base__.access_point.route).toBe('/new');
    expect(out.__base__.access_point.protocol).toBe('a2a');
    expect(out.__base__.access_point.name).toBe('n');
    expect(out.v2.access_point.route).toBe('/new');
    // Per-variant overridable fields are left alone.
    expect(out.__base__.access_point.rate_limit).toEqual({ rpm: 1 });
    expect(out.v2.access_point.rate_limit).toEqual({ rpm: 9 });
  });

  it('does not write identifier keys that are undefined on the source', () => {
    // Source omits protocol → it must not be stamped as `undefined`.
    const source = { access_point: { route: '/new' } };
    const snapshots = { __base__: { access_point: { route: '/old', protocol: 'a2a' } } };
    const out = syncAccessPointIdentifiers(snapshots, source);
    expect(out.__base__.access_point.route).toBe('/new');
    // Pre-existing protocol survives because source didn't carry one.
    expect(out.__base__.access_point.protocol).toBe('a2a');
    expect('protocol' in out.__base__.access_point).toBe(true);
  });

  it('syncs the canvas identifier fields (incl. route_prefix/route_suffix) into every snapshot blob', () => {
    const canvasNode = (route: string, suffix: string) => ({
      version: 1,
      nodes: [
        {
          id: 'access-point',
          config: {
            route,
            route_prefix: '/agents',
            route_suffix: suffix,
            publish_to_did_document: true,
          },
        },
      ],
    });
    const source = {
      access_point: { route: '/agents/new' },
      canvas: canvasNode('/agents/new', 'new'),
    };
    const snapshots = {
      __base__: {
        access_point: { route: '/agents/old' },
        canvas: canvasNode('/agents/old', 'old'),
      },
      v2: { access_point: { route: '/agents/old' }, canvas: canvasNode('/agents/old', 'old') },
    };
    const out = syncAccessPointIdentifiers(snapshots, source);
    for (const id of ['__base__', 'v2']) {
      const ap = out[id].canvas.nodes.find((n: any) => n.id === 'access-point');
      expect(ap.config.route).toBe('/agents/new');
      expect(ap.config.route_suffix).toBe('new');
      expect(ap.config.route_prefix).toBe('/agents');
      expect(ap.config.publish_to_did_document).toBe(true);
    }
  });

  it('passes through non-object snapshot entries and snapshots without an access_point', () => {
    const source = { access_point: { route: '/new' } };
    const snapshots = {
      __base__: null,
      noAp: { target: { endpoint: 'x' } },
    };
    const out = syncAccessPointIdentifiers(snapshots, source);
    // Null entry preserved as-is.
    expect(out.__base__).toBeNull();
    // Snapshot without access_point is untouched (no access_point injected).
    expect(out.noAp).toEqual({ target: { endpoint: 'x' } });
    expect(out.noAp.access_point).toBeUndefined();
  });
});
