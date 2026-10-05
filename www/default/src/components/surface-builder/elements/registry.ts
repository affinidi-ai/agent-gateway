import type { SurfaceNodeType } from '../nodeTypes';
import type {
  NodeDefinition,
  PayloadContext,
  PayloadSlice,
  Protocol,
  SurfaceContext,
} from './types';
import { getArchetype, ANY_EDGE_MW } from './edges/archetypes';
import { transitConfigConfigFromPayload } from './transit-config/definition';
import { workloadBindingApiToForm } from './workload-binding/config';

export interface DependencyWarning {
  severity: 'error' | 'warning';
  message: string;
}

class ElementRegistry {
  private definitions = new Map<SurfaceNodeType, NodeDefinition>();

  register(def: NodeDefinition): void {
    if (this.definitions.has(def.type)) {
      // Allow re-registration in HMR; warn in dev only.
      if (process.env.NODE_ENV !== 'production') {
        // eslint-disable-next-line no-console
        console.warn(`[ElementRegistry] Re-registering element type "${def.type}"`);
      }
    }
    this.definitions.set(def.type, def);
  }

  get(type: SurfaceNodeType | string): NodeDefinition | undefined {
    return this.definitions.get(type as SurfaceNodeType);
  }

  has(type: SurfaceNodeType | string): boolean {
    return this.definitions.has(type as SurfaceNodeType);
  }

  all(): NodeDefinition[] {
    return Array.from(this.definitions.values());
  }

  /** Type names of every element flagged `isTransitPoint`. */
  transitPointTypes(): SurfaceNodeType[] {
    return this.all()
      .filter(d => d.isTransitPoint)
      .map(d => d.type);
  }

  /** True when `type` resolves to a definition flagged `isTransitPoint`. */
  isTransitPointType(type: SurfaceNodeType | string | undefined | null): boolean {
    if (!type) return false;
    return !!this.get(type)?.isTransitPoint;
  }

  /** Protocol bound to this element, if any. */
  getProtocolForType(type: SurfaceNodeType | string | undefined | null): Protocol | undefined {
    if (!type) return undefined;
    return this.get(type)?.getProtocol?.();
  }

  /**
   * Elements available in the palette for a given protocol.
   * Excludes core elements (auto-created) and protocol-locked items
   * that don't match the current protocol.
   */
  paletteItems(protocol: Protocol): NodeDefinition[] {
    return this.all()
      .filter(d => !d.hiddenFromPalette)
      .filter(d => !d.protocols || d.protocols.includes(protocol))
      .sort((a, b) => {
        if (a.paletteCategory !== b.paletteCategory) {
          return a.paletteCategory.localeCompare(b.paletteCategory);
        }
        return a.paletteOrder - b.paletteOrder;
      });
  }

  /** Group palette items by category. */
  paletteByCategory(
    protocol: Protocol
  ): Partial<Record<import('./types').PaletteCategory, NodeDefinition[]>> {
    const out: Partial<Record<import('./types').PaletteCategory, NodeDefinition[]>> = {};
    for (const def of this.paletteItems(protocol)) {
      const list = out[def.paletteCategory] ?? [];
      list.push(def);
      out[def.paletteCategory] = list;
    }
    return out;
  }

  /**
   * Can an element of `elementType` be dropped on the edge between
   * a node of `sourceType` and a node of `targetType`?
   *
   * Returns true when every capability in `element.requires.dropOnEdge`
   * is provided by either the source or the target node.
   */
  canDropOnEdge(
    elementType: SurfaceNodeType | string,
    sourceType: SurfaceNodeType | string,
    targetType: SurfaceNodeType | string
  ): boolean {
    const element = this.get(elementType);
    const source = this.get(sourceType);
    const target = this.get(targetType);
    if (!element || !source || !target) return false;

    const required = element.requires.dropOnEdge;
    if (!required || required.length === 0) return false;

    const available = new Set([...source.provides, ...target.provides]);
    return required.every(cap => available.has(cap));
  }

  /**
   * Can this element be dropped directly on a specific node
   * (as a node-modifier rather than as an edge node)?
   */
  canDropOnNode(
    elementType: SurfaceNodeType | string,
    nodeType: SurfaceNodeType | string
  ): boolean {
    const element = this.get(elementType);
    const node = this.get(nodeType);
    if (!element || !node) return false;

    const required = element.requires.dropOnNode;
    if (!required || required.length === 0) return false;

    return required.every(cap => node.provides.includes(cap));
  }

  /**
   * Is the node configured? Derived from both `incompleteReason` (required
   * fields present) AND `validate` (present fields are well-formed). A
   * node with an invalid URL is reported the same as a missing one so the
   * canvas mirrors the sidebar's fault state.
   */
  isConfigured(type: SurfaceNodeType | string, config: any): boolean {
    if (this.getIncompleteReason(type, config) !== null) return false;
    return this.getValidationErrors(type, config).length === 0;
  }

  /**
   * Returns a human-readable reason why a node is incomplete, or null if it
   * is fully configured. Delegates to the element's `incompleteReason` (a
   * mandatory contract member); returns null for unknown types.
   */
  getIncompleteReason(type: SurfaceNodeType | string, config: any): string | null {
    const def = this.get(type);
    if (!def) return null;
    return def.incompleteReason(config ?? {});
  }

  /**
   * Run the element's format validators (regex / range / etc.). Returns
   * an empty array when the element has none. Validation errors are
   * separate from `incompleteReason` and from cross-element dependency
   * warnings — they catch malformed values in already-filled fields.
   */
  getValidationErrors(
    type: SurfaceNodeType | string,
    config: any
  ): Array<{ field?: string; message: string }> {
    const def = this.get(type);
    if (!def?.validate) return [];
    try {
      return def.validate(config ?? {}) ?? [];
    } catch {
      return [];
    }
  }

  /**
   * Single fault reason suitable for canvas chrome (ring tooltip + label
   * text under the node). Prefers `incompleteReason` (missing required
   * fields) and falls back to the first validation error so a malformed
   * URL surfaces on the canvas the same way the sidebar shows it.
   */
  getFaultReason(type: SurfaceNodeType | string, config: any): string | null {
    const incomplete = this.getIncompleteReason(type, config);
    if (incomplete) return incomplete;
    const errs = this.getValidationErrors(type, config);
    return errs.length > 0 ? errs[0].message : null;
  }

  /** Evaluate feature dependencies for a node in the surface context. */
  getDependencyWarnings(
    type: SurfaceNodeType | string,
    config: any,
    context: SurfaceContext
  ): DependencyWarning[] {
    const def = this.get(type);
    if (!def?.featureDependencies) return [];
    const cfg = config ?? {};
    return def.featureDependencies
      .filter(dep => {
        try {
          return dep.condition(cfg, context);
        } catch {
          return false;
        }
      })
      .filter(dep => {
        try {
          return !dep.check(cfg, context);
        } catch {
          return true;
        }
      })
      .map(dep => ({ severity: dep.severity, message: dep.message }));
  }

  /**
   * Build the full surface payload from registered elements.
   *
   * Single-pass execution: every element's `buildPayload(ctx)` is invoked
   * and the returned slices are deep-merged into the payload at their
   * declared path. Slices are sorted by path depth ascending (parents
   * before children) and then by `paletteOrder` so deterministic ordering
   * is preserved across renders.
   *
   * Slice merging never replaces existing leaf objects wholesale — it
   * deep-merges so siblings written by other elements coexist (e.g.
   * `target.endpoint` from `target` and `target.policy` from `policy`).
   */
  buildPayload(ctx: PayloadContext): any {
    const payload: any = {
      ...(ctx.surfaceMeta.surface_id ? { surface_id: ctx.surfaceMeta.surface_id } : {}),
      name: ctx.surfaceMeta.name,
      ...(ctx.surfaceMeta.description ? { description: ctx.surfaceMeta.description } : {}),
      status: ctx.surfaceMeta.status ?? 'active',
      tags: ctx.surfaceMeta.tags,
      ...(ctx.surfaceMeta.issuer_id ? { issuer_id: ctx.surfaceMeta.issuer_id } : {}),
    };

    interface Pending {
      def: NodeDefinition;
      slice: PayloadSlice;
    }
    const pending: Pending[] = [];
    for (const def of this.all()) {
      if (!def.buildPayload) continue;
      let slices: PayloadSlice[] | undefined;
      try {
        slices = def.buildPayload(ctx);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[ElementRegistry] buildPayload failed for ${def.type}:`, err);
        continue;
      }
      if (!slices || slices.length === 0) continue;
      for (const slice of slices) {
        if (!slice || typeof slice.path !== 'string' || slice.path.length === 0) continue;
        if (slice.value === undefined || slice.value === null) continue;
        pending.push({ def, slice });
      }
    }

    pending.sort((a, b) => {
      const ad = a.slice.path.split('.').length;
      const bd = b.slice.path.split('.').length;
      if (ad !== bd) return ad - bd;
      return a.def.paletteOrder - b.def.paletteOrder;
    });

    for (const { slice } of pending) {
      deepMergePath(payload, slice.path, slice.value);
    }

    return payload;
  }

  /**
   * Reverse of {@link buildPayload}: reconstruct a list of canvas nodes from
   * a saved surface payload. Used by the detail page to render the canvas in
   * read-only / re-edit mode without forcing each element to ship a bespoke
   * deserializer.
   *
   * Reconstruction rules:
   * - Always emit `access-point` and `target` nodes, with `target` parented
   *   to the access-point so the primary chain renders.
   * - For every registered element with a `payloadPath`, look up the slice in
   *   the payload. When present (and non-empty for objects), emit a node with
   *   the slice as its config. Parenting is inferred from the path prefix
   *   (`target.*` → child of target, `access_point.*` → child of access-point,
   *   surface-wide elements → no parent).
   * - Each transit point in `transit.points` becomes its own `transit-point`
   *   node parented to the access-point.
   *
   * Element-specific slice → config conventions (e.g. transforming a
   * persisted shape back to wizard form fields) are out of scope here; the
   * panels read whatever shape they receive and degrade gracefully.
   */
  nodesFromPayload(payload: any): Array<{
    id: string;
    type: SurfaceNodeType;
    label: string;
    configured: boolean;
    config: any;
    parentId?: string;
    position?: { x: number; y: number };
    radius?: number;
    direction?: 'request' | 'response';
    slotId?: string;
  }> {
    type N = {
      id: string;
      type: SurfaceNodeType;
      label: string;
      configured: boolean;
      config: any;
      parentId?: string;
      position?: { x: number; y: number };
      radius?: number;
      direction?: 'request' | 'response';
      slotId?: string;
    };
    const nodes: N[] = [];

    // IDs are deterministic everywhere: singletons use their bare type
    // name (`access-point`, `target`, …), transit points use a 1-based
    // counter (`transit-point-1`, …). The canvas blob layered on top
    // uses the same scheme, so a node and its layout always merge into
    // a single record.
    const apConfig = payload?.access_point ?? {};
    const targetConfig = payload?.target ?? {};

    const apDef = this.get('access-point');
    const apPanelConfig = apDef?.configFromPayload
      ? apDef.configFromPayload(apConfig, payload)
      : apConfig;

    nodes.push({
      id: 'access-point',
      type: 'access-point',
      label: apDef?.label ?? 'Access Point',
      configured: this.isConfigured('access-point', apPanelConfig),
      config: apPanelConfig,
    });

    const targetDef = this.get('target');
    const targetPanelConfig = targetDef?.configFromPayload
      ? targetDef.configFromPayload(targetConfig, payload)
      : targetConfig;

    nodes.push({
      id: 'target',
      type: 'target',
      label: targetDef?.label ?? 'Target',
      configured: this.isConfigured('target', targetPanelConfig),
      config: targetPanelConfig,
      parentId: 'access-point',
    });

    /**
     * Materialise a node from a single slice path. Returns null when the
     * slice is missing or empty. Direction defaults to 'request'; pass
     * 'response' for the response-direction slice.
     */
    const emitFromSlice = (
      def: NodeDefinition,
      path: string,
      direction: 'request' | 'response',
      idSuffix?: string
    ): N | null => {
      const slice = readPath(payload, path);
      if (slice === undefined || slice === null) return null;
      if (typeof slice === 'object' && !Array.isArray(slice) && Object.keys(slice).length === 0) {
        return null;
      }
      if (Array.isArray(slice) && slice.length === 0) return null;
      if (
        typeof slice === 'object' &&
        !Array.isArray(slice) &&
        slice.enabled === false &&
        Object.keys(slice).every(k => k === 'enabled' || slice[k] === false || slice[k] == null)
      ) {
        return null;
      }

      const parentId = def.surfaceWide
        ? undefined
        : path.startsWith('target.')
          ? 'target'
          : path.startsWith('access_point.')
            ? 'access-point'
            : undefined;

      const panelConfig = def.configFromPayload ? def.configFromPayload(slice, payload) : slice;
      // Append id suffixes so multiple slices for the same element type
      // don't collide. Default request slice keeps the bare type name.
      const id = idSuffix ? `${def.type}-${idSuffix}` : def.type;
      // Middleware nodes (and other multi-instance elements) don't get
      // an auto-generated user-facing label — leaving label empty here
      // means the canvas renders no caption beneath the icon unless the
      // user explicitly sets one. Only the singleton anchor nodes
      // (target, access-point, surface) above auto-name themselves.
      return {
        id,
        type: def.type as SurfaceNodeType,
        label: '',
        configured: this.isConfigured(def.type, panelConfig),
        config: panelConfig,
        parentId,
        ...(direction === 'response' ? { direction: 'response' as const } : {}),
      };
    };

    // Non-edge-drop elements (mode: 'node' / 'canvas' / surface-wide)
    // still consult their own `payloadPath`/`responsePayloadPath`
    // declarations: they're anchored to nodes (credential-binding) or
    // live free on the surface (identity, transit-config).
    // The slot model only governs edge-drop routing today;
    // node-anchored hydration is unchanged.
    for (const def of this.all()) {
      if (def.type === 'access-point' || def.type === 'target') continue;
      if (def.isTransitPoint) continue;
      if (def.dropMode === 'edge') continue; // handled by slot walk above
      if (!def.payloadPath) continue;
      const reqNode = emitFromSlice(def, def.payloadPath, 'request');
      if (reqNode) nodes.push(reqNode);
      if (def.responsePayloadPath) {
        const respNode = emitFromSlice(def, def.responsePayloadPath, 'response', 'response');
        if (respNode) nodes.push(respNode);
      }
    }
    const apMaArchetype = getArchetype('ap-ma');
    const maExternalArchetype = getArchetype('ma-external');
    // Map archetype id → owner node ids. Per-endpoint slots resolve
    // their `parentId`/`{owner}` against this lookup so each
    // archetype's source/target endpoints point to the correct
    // singleton anchor (ap-ma: access-point↔target,
    // ma-external: target↔external — only `source` is meaningful for
    // hydration since the external endpoint is not a persisted node).
    const archetypeOwners: Record<string, { source: string; target: string }> = {
      'ap-ma': { source: 'access-point', target: 'target' },
      'ma-external': { source: 'target', target: 'target' },
    };
    // Tracks payload paths already hydrated by an earlier archetype
    // so paths exposed on multiple archetypes (UX-aliased drop zones)
    // don't emit duplicate nodes. The archetype iteration order below
    // (ap-ma → ma-external) determines which slot wins.
    const consumedPayloadPaths = new Set<string>();
    // Trust-recorder is a Vec of N entries — generic slot walk emits
    // one node per slot, so we hydrate via the custom block below and
    // tell the walk to skip the path.
    consumedPayloadPaths.add('access_point.trust_recorder');
    // Trust-check is a Vec of N elements per leg — generic slot walk
    // emits one node per slot, so we hydrate it via the custom block
    // below and tell the walk to skip both leg paths.
    consumedPayloadPaths.add('access_point.trust_check_list');
    consumedPayloadPaths.add('target.trust_check_list');
    for (const archetype of [apMaArchetype, maExternalArchetype]) {
      if (!archetype) continue;
      const owners = archetypeOwners[archetype.id];
      for (const slot of archetype.slots) {
        if (!slot.payloadPathTemplate) continue; // catch-all: no path
        if (slot.accepts === ANY_EDGE_MW) continue;
        // Some archetypes alias the same payload path on more than one
        // edge (e.g. `access_point.rate_limit` is exposed both on
        // ap↔ma and on ma↔external as a UX convenience for drag-drop).
        // Only the first archetype that owns the path should hydrate
        // it — otherwise we emit duplicate nodes (the second one
        // appears in the canvas as an orphan element pointing at the
        // wrong endpoint).
        if (consumedPayloadPaths.has(slot.payloadPathTemplate)) continue;
        const elementType = slot.accepts[0] as SurfaceNodeType;
        const def = this.get(elementType);
        if (!def) continue;
        const path = slot.payloadPathTemplate; // archetype slots never use {owner}
        const slice = readPath(payload, path);
        if (slice === undefined || slice === null) continue;
        if (typeof slice === 'object' && !Array.isArray(slice) && Object.keys(slice).length === 0) {
          continue;
        }
        if (Array.isArray(slice) && slice.length === 0) continue;
        if (
          typeof slice === 'object' &&
          !Array.isArray(slice) &&
          slice.enabled === false &&
          Object.keys(slice).every(k => k === 'enabled' || slice[k] === false || slice[k] == null)
        ) {
          continue;
        }

        consumedPayloadPaths.add(path);
        const panelConfig = def.configFromPayload ? def.configFromPayload(slice, payload) : slice;
        // Id format mirrors `useSurfaceBuilder.handleDrop`:
        //  - per-endpoint slot → `${type}-${owner}` (with `-response`
        //    suffix on response direction)
        //  - non-endpoint slot → bare type for request, `${type}-response`
        //    for response.
        let id: string;
        if (slot.ownedBy) {
          const owner = slot.ownedBy === 'source' ? owners.source : owners.target;
          id =
            slot.direction === 'response'
              ? `${elementType}-${owner}-response`
              : `${elementType}-${owner}`;
        } else {
          id = slot.direction === 'response' ? `${elementType}-response` : elementType;
        }
        // Backwards-compat id mapping for the inbound policy slot,
        // which keeps the legacy `policy-inbound` id so saved surfaces
        // round-trip through the same node id.
        if (slot.id === 'request:policy-inbound') {
          id = 'policy-inbound';
        }
        // Identity slots share the same `type='identity'` across three
        // distinct edges; derive a stable id from the payload path so
        // protected (AP→MA response) and external (MA→External response)
        // don't collide on `identity-target-response`.
        if (elementType === 'identity') {
          if (path === 'identity_slots.inbound') id = 'identity-inbound';
          else if (path === 'identity_slots.protected') id = 'identity-protected';
          else if (path === 'identity_slots.external') id = 'identity-external';
        }

        const parentId = slot.ownedBy
          ? slot.ownedBy === 'source'
            ? owners.source
            : owners.target
          : path.startsWith('access_point.')
            ? 'access-point'
            : path.startsWith('target.')
              ? 'target'
              : undefined;

        nodes.push({
          id,
          type: elementType,
          label: '',
          configured: this.isConfigured(elementType, panelConfig),
          config: panelConfig,
          parentId,
          slotId: slot.id,
          ...(slot.direction === 'response' ? { direction: 'response' as const } : {}),
        });
      }
    }

    // Credential Delegation owns the `outbound_credentials` (root) slice,
    // hydrated above via the ma-external slot walk. Workload Binding is
    // now a separate Transit-Point-scoped element and is hydrated per-TP
    // below.

    // Trust-recorder: custom hydration for the AP↔MA response leg. The
    // wire slice is `access_point.trust_recorder = { entries: [...] }`;
    // we emit a single canvas node holding all entries so the panel's
    // "+ Add Trust Registry" button appends to `config.entries` and
    // `buildPayload` re-flattens back to the wire array.
    {
      const trRec = readPath(payload, 'access_point.trust_recorder');
      if (trRec && typeof trRec === 'object' && Array.isArray(trRec.entries)) {
        const trDef = this.get('trust-recorder');
        if (trDef && trRec.entries.length > 0) {
          const panelConfig = trDef.configFromPayload
            ? trDef.configFromPayload(trRec, payload)
            : trRec;
          nodes.push({
            id: 'trust-recorder-target-response',
            type: 'trust-recorder',
            label: '',
            configured: this.isConfigured('trust-recorder', panelConfig),
            config: panelConfig,
            parentId: 'target',
            slotId: 'response:trust-recorder',
            direction: 'response' as const,
          });
        }
      }
    }

    // Trust-check: per-leg Vec<TrustCheckElement>. Emit one canvas
    // node per leg holding all of that leg's queries on
    // `config.queries`; the panel's "+ Add Another Query" button
    // appends entries and `buildPayload` fans each back out into the
    // wire `trust_check_list` array.
    {
      const tcDef = this.get('trust-check');
      if (tcDef) {
        const hydrateLeg = (
          path: string,
          edge: 'ap-ma' | 'ma-tp',
          parentId: string,
          slotId: string
        ) => {
          const raw = readPath(payload, path);
          if (!Array.isArray(raw) || raw.length === 0) return;
          const queries = raw
            .filter((e: any) => e && typeof e === 'object')
            .map((e: any) => ({
              id: typeof e.id === 'string' ? e.id : undefined,
              trust_registry_id: typeof e.trust_registry_id === 'string' ? e.trust_registry_id : '',
              query_type: e.query_type === 'recognition' ? 'recognition' : 'authorization',
              name: typeof e.name === 'string' ? e.name : undefined,
              query: e.query || {},
            }));
          if (queries.length === 0) return;
          const id = `trust-check-${edge === 'ap-ma' ? 'caller' : 'target'}`;
          const config = { _edge: edge, queries };
          nodes.push({
            id,
            type: 'trust-check',
            label: '',
            configured: this.isConfigured('trust-check', config),
            config,
            parentId,
            slotId,
          });
        };
        hydrateLeg(
          'access_point.trust_check_list',
          'ap-ma',
          'access-point',
          'request:trust-check-access_point_trust_check_list'
        );
        hydrateLeg(
          'target.trust_check_list',
          'ma-tp',
          'target',
          'request:trust-check-target_trust_check_list'
        );
      }
    }

    // Variants — always emit a surface-wide `target-variant` node,
    // even when the surface has no variants yet. The dedicated
    // top-left widget is the only entry point to the editor; the node
    // is hidden from the canvas (filtered in SurfaceBuilder) but its
    // config still carries `variants[]` and `default_variant_id` for
    // round-trip persistence. Prefer the north-star top-level
    // `variants` shape (`AgentSurface.variants`); fall back to the
    // legacy `target.variants` for surfaces saved before the migration.
    const useTopLevel = Array.isArray(payload?.variants) && payload.variants.length > 0;
    const variants: any[] = useTopLevel
      ? payload.variants
      : Array.isArray(payload?.target?.variants)
        ? payload.target.variants
        : [];
    const defaultVariantId = useTopLevel
      ? payload?.default_variant_id
      : payload?.target?.default_variant_id;
    const variantList = variants.map((v, idx) => {
      const id = v?.id || `target-variant-${idx + 1}`;
      // Identity-only shape for the panel. Legacy override fields
      // (endpoint, policy_definition_id, mpp_*, agent_card_*,
      // extensions, …) are no longer surfaced here — they live on
      // `surface.variants[].overrides` and are produced by the
      // (forthcoming) per-element `VariantEditingContext`.
      return {
        id,
        alias: typeof v?.alias === 'string' ? v.alias : '',
        name: typeof v?.name === 'string' ? v.name : '',
        enabled: v?.enabled !== false,
        ...(typeof v?.description === 'string' && v.description
          ? { description: v.description }
          : {}),
      };
    });
    nodes.push({
      id: 'target-variant',
      type: 'target-variant',
      label: 'Variants',
      configured: variantList.length === 0 || variantList.every(v => !!v.alias && !!v.name),
      config: {
        variants: variantList,
        ...(typeof defaultVariantId === 'string' ? { default_variant_id: defaultVariantId } : {}),
      },
    });

    const transitPoints: any[] = payload?.transit?.points ?? [];
    // Auto-hydrate transit-config (`transit.shared.*`) when meaningful
    // fields are present on the payload (e.g. surface authored via the
    // JSON tab, an import, or another tool). The transit-config
    // helper deliberately ignores the harmless `sign_requests` /
    // `transit_token_mode` defaults that the TP factory writes
    // unconditionally — otherwise every surface with a TP would
    // sprout a "Transit Settings" node on its canvas. The canvas blob
    // layer below still wins for round-trips that previously saved a
    // transit-config node (preserving its layout and any UI-only
    // fields).
    const transitConfigPanelCfg = transitConfigConfigFromPayload(payload);
    if (transitConfigPanelCfg) {
      nodes.push({
        id: 'transit-config',
        type: 'transit-config' as SurfaceNodeType,
        label: '',
        configured: this.isConfigured('transit-config' as SurfaceNodeType, transitConfigPanelCfg),
        config: transitConfigPanelCfg,
      });
    }

    // Map saved `protocol` back to the matching TP variant type. Falls
    // back to the first registered TP type so legacy payloads (no
    // `protocol` field) still hydrate.
    const tpDefs = this.all().filter(d => d.isTransitPoint);
    const fallbackTpType = (tpDefs[0]?.type ?? 'transit-point-a2a') as SurfaceNodeType;
    const perTypeCounter = new Map<SurfaceNodeType, number>();
    transitPoints.forEach((tp, idx) => {
      const protocol = tp?.protocol;
      const def = tpDefs.find(d => d.getProtocol?.() === protocol) ?? tpDefs[0];
      const effectiveProtocol = protocol ?? def?.getProtocol?.();
      const tpType = (def?.type ?? fallbackTpType) as SurfaceNodeType;
      const next = (perTypeCounter.get(tpType) ?? 0) + 1;
      perTypeCounter.set(tpType, next);
      const tpId = `${tpType}-${next}`;
      const tpConfig = tp && typeof tp === 'object' ? { ...tp } : tp;
      if (tpConfig && typeof tpConfig === 'object') {
        delete tpConfig.header_metadata_mapping;
      }
      nodes.push({
        id: tpId,
        type: tpType,
        // Mirror the runtime contract: TP `name` is optional and the
        // label is purely cosmetic. Leave it empty when the user
        // didn't set one rather than fabricating "Transit N", which
        // would surprise users by appearing on the canvas after save.
        label: tp?.name || '',
        configured: !!tp?.target_endpoint,
        config: tpConfig,
        parentId: 'access-point',
      });
      // Per-TP request policy (`transit.points[i].policy`) → policy node
      // parented to this TP. Mirrors the slot id produced by
      // `canonicalEdgeMiddlewareId('policy', tpId, 'request')` so a
      // freshly-dropped policy reloads as the same node.
      const reqPol = tp?.policy?.policy_definition_id;
      if (reqPol) {
        nodes.push({
          id: `policy-${tpId}`,
          type: 'policy' as SurfaceNodeType,
          label: '',
          configured: true,
          config: {
            policy_definition_id: reqPol,
            ...(tp.policy.require_agent_context ? { require_agent_context: true } : {}),
          },
          parentId: tpId,
        });
      }
      // Per-TP response policy (`transit.points[i].response_policy`).
      const respPol = tp?.response_policy?.policy_definition_id;
      if (respPol) {
        nodes.push({
          id: `policy-${tpId}-response`,
          type: 'policy' as SurfaceNodeType,
          label: '',
          configured: true,
          config: {
            policy_definition_id: respPol,
          },
          parentId: tpId,
          direction: 'response' as const,
        });
      }
      // Per-TP networking (`transit.points[i].networking`). Hydrate via
      // the networking element's `configFromPayload` so the panel sees
      // the same flat shape it produces. Falls through to a verbatim
      // copy when no transformer is registered.
      const tpNetworking = tp?.networking;
      if (tpNetworking && typeof tpNetworking === 'object') {
        const netDef = this.get('networking');
        const panelConfig = netDef?.configFromPayload
          ? netDef.configFromPayload(tpNetworking, payload)
          : tpNetworking;
        nodes.push({
          id: `networking-${tpId}`,
          type: 'networking' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('networking', panelConfig),
          config: panelConfig,
          parentId: tpId,
        });
      }
      // Per-TP rate limit (`transit.points[i].rate_limit`). The panel
      // uses string-typed numeric inputs so coerce wire numbers back to
      // strings on hydration.
      const tpRl = tp?.rate_limit;
      if (tpRl && typeof tpRl === 'object' && tpRl.requests != null) {
        const rlDef = this.get('rate-limit');
        const panelConfig = rlDef?.configFromPayload
          ? rlDef.configFromPayload(tpRl, payload)
          : {
              requests: String(tpRl.requests),
              window_secs: String(tpRl.window_secs ?? 60),
              ...(tpRl.burst != null ? { burst: String(tpRl.burst) } : {}),
            };
        nodes.push({
          id: `rate-limit-${tpId}`,
          type: 'rate-limit' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('rate-limit', panelConfig),
          config: panelConfig,
          parentId: tpId,
        });
      }
      const tpHeaderMetadataMapping = tp?.header_metadata_mapping;
      if (
        (effectiveProtocol === 'a2a' || effectiveProtocol === 'ap2') &&
        tpHeaderMetadataMapping &&
        typeof tpHeaderMetadataMapping === 'object' &&
        Object.keys(tpHeaderMetadataMapping).length > 0
      ) {
        const config = { header_metadata_mapping: tpHeaderMetadataMapping };
        nodes.push({
          id: `metadata-extraction-${tpId}`,
          type: 'metadata-extraction' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('metadata-extraction' as SurfaceNodeType, config),
          config,
          parentId: tpId,
          slotId: 'request:metadata-extraction',
        });
      }
      // Per-TP managed identity (`transit.points[i].managed_identity`).
      // Mirrors the request-slot id produced by the identity element
      // when freshly dropped on the MA→TP edge so it round-trips
      // through the same node id.
      const tpIdentity = tp?.managed_identity;
      if (tpIdentity && typeof tpIdentity === 'object' && Object.keys(tpIdentity).length > 0) {
        const idDef = this.get('identity');
        const panelConfig = idDef?.configFromPayload
          ? idDef.configFromPayload(tpIdentity, payload)
          : tpIdentity;
        nodes.push({
          id: `identity-${tpId}-request`,
          type: 'identity' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('identity', panelConfig),
          config: panelConfig,
          parentId: tpId,
          direction: 'request' as const,
          slotId: 'request:identity-managed_identity',
        });
      }
      // Per-TP workload binding (`transit.points[i].workload_binding`).
      // Mirrors the request-slot id produced by the workload-binding
      // element on the MA→TP edge so it round-trips through the same node
      // id. The TP factory owns the slice on the way out.
      const tpWorkloadBinding = tp?.workload_binding;
      if (
        tpWorkloadBinding &&
        typeof tpWorkloadBinding === 'object' &&
        !Array.isArray(tpWorkloadBinding)
      ) {
        const wbDef = this.get('workload-binding');
        const panelConfig = wbDef?.configFromPayload
          ? wbDef.configFromPayload(tpWorkloadBinding, payload)
          : workloadBindingApiToForm(tpWorkloadBinding);
        nodes.push({
          id: `workload-binding-${tpId}`,
          type: 'workload-binding' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('workload-binding', panelConfig),
          config: panelConfig,
          parentId: tpId,
          slotId: 'request:workload-binding',
        });
      }
      // Per-TP MCP Tool Gating (`transit.points[i].mcp_tool_gating`).
      // A per-endpoint response slot owned by the TP; the TP factory owns
      // the slice on the way out. Mirrors the response-slot id the
      // gating element carries on the MA→TP edge so it round-trips.
      const tpMcpToolGating = tp?.mcp_tool_gating;
      if (
        tpMcpToolGating &&
        typeof tpMcpToolGating === 'object' &&
        Array.isArray(tpMcpToolGating.gates) &&
        tpMcpToolGating.gates.length > 0
      ) {
        const gatingDef = this.get('mcp-tool-gating');
        const panelConfig = gatingDef?.configFromPayload
          ? gatingDef.configFromPayload(tpMcpToolGating, payload)
          : tpMcpToolGating;
        nodes.push({
          id: `mcp-tool-gating-${tpId}`,
          type: 'mcp-tool-gating' as SurfaceNodeType,
          label: '',
          configured: this.isConfigured('mcp-tool-gating' as SurfaceNodeType, panelConfig),
          config: panelConfig,
          parentId: tpId,
          direction: 'response' as const,
          slotId: 'response:mcp-tool-gating',
        });
      }
      void idx;
    });

    const normalizeApMaRequestChain = () => {
      if (!apMaArchetype) return;
      let requestParentId = 'access-point';
      const requestSlots = [...apMaArchetype.slots]
        .filter(slot => slot.direction === 'request' && !slot.ownedBy)
        .sort((a, b) => a.order - b.order);
      for (const slot of requestSlots) {
        const occupants = nodes.filter(
          node =>
            node.slotId === slot.id &&
            (node.direction ?? 'request') === 'request' &&
            !nodes.some(
              parent => parent.id === node.parentId && this.isTransitPointType(parent.type)
            )
        );
        for (const occupant of occupants) {
          occupant.parentId = requestParentId;
          requestParentId = occupant.id;
        }
      }
      const target = nodes.find(node => node.id === 'target');
      if (target) target.parentId = requestParentId;
    };

    // Runtime-only payloads have no canvas blob to preserve the
    // drop-time request chain. Rebuild the AP→MA chain in canonical
    // slot order so request middleware remains edge-bound after
    // hydration. Per-endpoint slots keep their endpoint parentage.
    normalizeApMaRequestChain();

    // Layer the persisted canvas blob over the registry-derived nodes:
    // (a) restore canvas-only nodes that don't appear in the runtime
    // config (NPCs, human, caller); (b) apply layout hints (position,
    // radius, parentId overrides) to every matching node.
    const blob = readCanvasBlob(payload?.canvas);
    if (blob) {
      const byId = new Map(nodes.map(n => [n.id, n] as const));
      const claimedIds = new Set<string>();
      // Tracks blob-id → adoptee-id remappings introduced by slot-id
      // adoption (which preserves the hydrated canonical id and drops
      // the drifted blob id). Applied at the end of the overlay pass
      // to rewrite any parentId reference — on other blob nodes or on
      // hydrated nodes — that still points at the discarded blob id,
      // otherwise `validateSurface` fires a "references missing parent"
      // warning for legacy blobs where a chain-spliced node was
      // parented on the drifted id.
      const renameMap = new Map<string, string>();
      for (const bn of blob.nodes) {
        let target = byId.get(bn.id);
        if (target) claimedIds.add(target.id);
        if (!target && bn.type) {
          // Adopt an unclaimed synthesized node of the same type when
          // the blob's id derives from a different archetype slot for
          // the same payload path. Example: `target.networking` is
          // exposed both on ap-ma (id `networking`) and on ma-external
          // with `ownedBy: 'source'` (id `networking-target`).
          // Hydration emits the ap-ma variant first; if the user
          // actually dropped on ma-external the blob carries
          // `networking-target`. Without adoption we'd render both.
          const candidates = nodes.filter(
            n =>
              n.type === bn.type &&
              !claimedIds.has(n.id) &&
              !byId.has(bn.id) &&
              !blob.nodes.some(b => b.id === n.id)
          );
          // Prefer slotId-based adoption when the blob carries one and
          // exactly one hydrated candidate owns the same slot. Keeps
          // the hydrated (canonical) id so legacy blobs whose drop-
          // time ids drifted from the canonical scheme converge on
          // the canonical form on the next save, instead of dragging
          // the old id forward forever.
          if (bn.slotId) {
            const bySlot = candidates.filter(c => c.slotId === bn.slotId);
            if (bySlot.length === 1) {
              target = bySlot[0];
              claimedIds.add(target.id);
              if (bn.id !== target.id) renameMap.set(bn.id, target.id);
            }
          }
          if (!target && candidates.length === 1) {
            const adoptee = candidates[0];
            byId.delete(adoptee.id);
            adoptee.id = bn.id;
            byId.set(bn.id, adoptee);
            target = adoptee;
            claimedIds.add(bn.id);
          }
        }
        if (!target) {
          if (!bn.type) continue;
          // Compute `configured` from the blob's config rather than
          // hard-coding `true`. Otherwise an element that the user
          // dropped but never finished configuring (no payload slice
          // emitted because required fields were missing) reloads as
          // "configured" on the canvas while every other surface (the
          // panel banner, the elements list) computes the opposite from
          // `incompleteReason`. The canvas badge then disagrees with
          // the panel — exactly the "shows invalid on canvas, ok in
          // panel" symptom users report.
          const blobCfg = bn.config ?? {};
          target = {
            id: bn.id,
            type: bn.type as SurfaceNodeType,
            label: bn.label || bn.id,
            configured: this.isConfigured(bn.type as SurfaceNodeType, blobCfg),
            config: blobCfg,
            parentId: bn.parentId ?? undefined,
            ...(bn.slotId ? { slotId: bn.slotId } : {}),
          };
          nodes.push(target);
          byId.set(bn.id, target);
        }
        // Restore slotId from the blob if the slot-walker didn't set it
        // (e.g. the runtime payload slice was missing or the node was
        // canvas-only).
        if (target && !target.slotId && bn.slotId) {
          target.slotId = bn.slotId;
        }
        const blobConfig = bn.config;
        if (target && blobConfig && typeof blobConfig === 'object') {
          // Backend-truth fields (set by `nodesFromPayload`) win on key
          // collision; canvas-blob fields fill in UI-only keys (e.g.
          // `endpoint_type`, `route_prefix`, `route_suffix`,
          // `gateway_id`, `auth_type`) so the panel doesn't "reset"
          // after save. Without this, every save round-trip strips
          // those fields and the panel re-derives them on next mount.
          target.config = { ...blobConfig, ...(target.config ?? {}) };
          // Recompute `configured` after the merge — UI-only fields
          // pulled from the blob can flip validity (e.g. an element
          // whose `incompleteReason` looks at a field that isn't part
          // of the persisted payload slice).
          target.configured = this.isConfigured(target.type, target.config);
        }
        const overlay = readLayoutOverlay(bn);
        if (overlay.position) target.position = overlay.position;
        if (overlay.radius !== undefined) target.radius = overlay.radius;
        // The canvas blob is authoritative for layout-time parenting:
        // it captures middleware insertions (e.g. a TP re-parented from
        // the access-point onto the managed agent or onto a freshly
        // dropped middleware node). Always honour an explicit overlay
        // parentId so reloads don't snap edges back to defaults.
        if (overlay.parentId !== undefined) {
          target.parentId = overlay.parentId || undefined;
        }
      }
      // Rewrite any parentId that still points at a discarded blob id
      // (an id that slot-id adoption merged into a canonical hydrated
      // node). Runs once after the overlay loop so it catches both
      // hydrated nodes and blob-only nodes regardless of iteration
      // order.
      if (renameMap.size > 0) {
        for (const n of nodes) {
          if (typeof n.parentId === 'string' && renameMap.has(n.parentId)) {
            n.parentId = renameMap.get(n.parentId);
          }
        }
      }
    }

    // Semantic slot identity is authoritative for the request path.
    // A canvas blob authored outside the dashboard may omit or carry
    // stale parent links, so normalize once more after applying its
    // layout-only overlay.
    normalizeApMaRequestChain();

    return nodes;
  }
}

/**
 * Layout-only fields persisted alongside each node in the canvas blob.
 * Kept separate from the runtime config so the wizard can reason about
 * "where does this go on screen" independently of "what does this do".
 */
interface LayoutOverlay {
  position?: { x: number; y: number };
  radius?: number;
  /**
   * `string` → set this parent on the target node.
   * `null`   → explicitly clear the parent (the runtime had no
   *            parentId and the registry default should be ignored).
   * `undefined` → no opinion; keep whatever default `nodesFromPayload`
   *            already picked.
   */
  parentId?: string | null;
}

function readLayoutOverlay(bn: CanvasBlob['nodes'][number]): LayoutOverlay {
  const out: LayoutOverlay = {};
  if (bn.position && typeof bn.position.x === 'number' && typeof bn.position.y === 'number') {
    out.position = { x: bn.position.x, y: bn.position.y };
  }
  if (typeof bn.radius === 'number') out.radius = bn.radius;
  if (bn.parentId !== undefined) out.parentId = bn.parentId;
  return out;
}

/**
 * Shape persisted under `payload.canvas` — opaque to the backend, owned by
 * the management dashboard. Bumping `version` is the migration hook.
 */
export interface CanvasBlob {
  version: number;
  /** Persisted surface rectangle dimensions so resizes round-trip. */
  surface?: { width: number; height: number };
  /**
   * Persisted d3 zoom transform (pan + scale) so the canvas resumes
   * the same view on reload. Identity (`{x:0,y:0,k:1}`) is omitted at
   * write time. Cleared by the recentre button.
   */
  view?: { x: number; y: number; k: number };
  nodes: Array<{
    id: string;
    type?: string;
    label?: string;
    /**
     * `null` means "no parent" (explicit). `undefined` means the field
     * was not persisted. `string` is a normal parent id.
     */
    parentId?: string | null;
    position?: { x: number; y: number };
    radius?: number;
    /** Only persisted for canvas-only node types (NPCs, human, caller). */
    config?: any;
    /**
     * Slot identity (e.g. `'request:policy-inbound'`). Persisted so a
     * round-trip preserves which payload path this node owns even when
     * the runtime payload alone is ambiguous (e.g. policy at
     * `target.policy` vs `access_point.inbound_policy`).
     */
    slotId?: string;
  }>;
}

const CANVAS_BLOB_VERSION = 1;

/**
 * Build the `canvas` blob from the live wizard nodes. Always emits layout
 * hints; emits config only for canvas-only node types so we don't duplicate
 * data that already lives in the runtime payload.
 */
export function buildCanvasBlob(
  nodes: Array<{
    id: string;
    type: string;
    label?: string;
    parentId?: string;
    position?: { x: number; y: number };
    radius?: number;
    config?: any;
    slotId?: string;
  }>,
  meta?: {
    surfaceSize?: { width: number; height: number };
    view?: { x: number; y: number; k: number } | null;
  }
): CanvasBlob {
  const view = meta?.view;
  const viewIsIdentity = !view || (view.x === 0 && view.y === 0 && view.k === 1);
  return {
    version: CANVAS_BLOB_VERSION,
    ...(meta?.surfaceSize ? { surface: meta.surfaceSize } : {}),
    ...(view && !viewIsIdentity ? { view: { x: view.x, y: view.y, k: view.k } } : {}),
    nodes: nodes.map(n => {
      const def = registry.get(n.type);
      const canvasOnly = !!def?.canvasOnly;
      const persistPosition = !!n.position;
      // `parentId` is persisted explicitly: a runtime value of
      // `undefined` means "no parent" and must round-trip to "no
      // parent" rather than fall back to whichever default
      // `nodesFromPayload` would otherwise pick (e.g. TPs default to
      // `access-point`). Serialise as `null` so JSON keeps the key.
      const parentId = n.parentId == null ? null : n.parentId;
      // Persist config for canvas-only nodes (the only place those
      // configs live) AND for configurable runtime nodes whose panels
      // depend on UI-only fields not present in the backend payload
      // (TPs and APs especially — endpoint_type, route_prefix,
      // route_suffix, gateway_id, auth_type, etc.). Without this the
      // panel "resets" after save because reconstruction sees only
      // backend-known keys.
      const persistConfig = canvasOnly || !!def?.ConfigPanel;
      // `trust_check_list` only belongs on `trust-check` canvas nodes;
      // strip it from every other node's persisted config so a stale
      // field left on the singleton target / access-point config from a
      // pre-canvas-split schema doesn't ride the blob forward forever
      // (removing the trust-check node from the canvas must remove the
      // config).
      let configToPersist = persistConfig ? (n.config ?? {}) : undefined;
      if (
        configToPersist &&
        n.type !== 'trust-check' &&
        Object.prototype.hasOwnProperty.call(configToPersist, 'trust_check_list')
      ) {
        const { trust_check_list: _stripped, ...rest } = configToPersist as Record<string, unknown>;
        void _stripped;
        configToPersist = rest;
      }
      return {
        id: n.id,
        type: n.type,
        label: n.label,
        parentId,
        ...(persistPosition ? { position: { x: n.position!.x, y: n.position!.y } } : {}),
        ...(typeof n.radius === 'number' ? { radius: n.radius } : {}),
        ...(persistConfig ? { config: configToPersist } : {}),
        ...(n.slotId ? { slotId: n.slotId } : {}),
      };
    }),
  };
}

function readCanvasBlob(raw: any): CanvasBlob | null {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.nodes)) return null;
  return raw as CanvasBlob;
}

/** Read the persisted surface rectangle from `payload.canvas.surface`, if any. */
export function readCanvasSurfaceSize(payload: any): { width: number; height: number } | null {
  const blob = readCanvasBlob(payload?.canvas);
  const s = blob?.surface;
  if (!s || typeof s.width !== 'number' || typeof s.height !== 'number') return null;
  return { width: s.width, height: s.height };
}

/** Read the persisted zoom/pan transform from `payload.canvas.view`, if any. */
export function readCanvasView(payload: any): { x: number; y: number; k: number } | null {
  const blob = readCanvasBlob(payload?.canvas);
  const v = blob?.view;
  if (!v || typeof v.x !== 'number' || typeof v.y !== 'number' || typeof v.k !== 'number') {
    return null;
  }
  return { x: v.x, y: v.y, k: v.k };
}

function readPath(obj: any, path: string): any {
  if (!obj || !path) return undefined;
  return path.split('.').reduce((cur, key) => (cur == null ? cur : cur[key]), obj);
}

/**
 * Deep-merge `value` into `obj` at the dot-notation `path`.
 * - Intermediate objects are created on demand.
 * - Plain objects are merged shallowly at the leaf (existing keys preserved
 *   when `value` doesn't override them).
 * - Arrays and primitives replace any existing value at the leaf.
 */
function deepMergePath(obj: any, path: string, value: any): void {
  if (value === undefined || value === null) return;
  const parts = path.split('.').filter(p => p.length > 0);
  if (parts.length === 0) return;
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    const nextKey = parts[i + 1];
    const nextIsNumeric = /^\d+$/.test(nextKey);
    // Decide what container to materialise at `key` if it's missing.
    // - If the next key is numeric, the container should be an array.
    // - Otherwise, an object.
    if (Array.isArray(cur)) {
      const idx = /^\d+$/.test(key) ? parseInt(key, 10) : NaN;
      if (Number.isNaN(idx)) return; // can't merge into a non-numeric key on an array
      if (cur[idx] === undefined || cur[idx] === null) {
        cur[idx] = nextIsNumeric ? [] : {};
      }
      cur = cur[idx];
    } else {
      if (cur[key] === undefined || cur[key] === null) {
        cur[key] = nextIsNumeric ? [] : {};
      } else if (nextIsNumeric && !Array.isArray(cur[key])) {
        // Need an array but found something else — leave it alone to avoid data loss.
        return;
      } else if (!nextIsNumeric && Array.isArray(cur[key])) {
        // Need an object but found an array — bail out for the same reason.
        return;
      }
      cur = cur[key];
    }
  }
  const leaf = parts[parts.length - 1];
  if (Array.isArray(cur)) {
    const idx = /^\d+$/.test(leaf) ? parseInt(leaf, 10) : NaN;
    if (Number.isNaN(idx)) return;
    const existing = cur[idx];
    if (
      existing &&
      typeof existing === 'object' &&
      !Array.isArray(existing) &&
      typeof value === 'object' &&
      !Array.isArray(value)
    ) {
      cur[idx] = { ...existing, ...value };
    } else {
      cur[idx] = value;
    }
    return;
  }
  const existing = cur[leaf];
  if (
    existing &&
    typeof existing === 'object' &&
    !Array.isArray(existing) &&
    typeof value === 'object' &&
    !Array.isArray(value)
  ) {
    cur[leaf] = { ...existing, ...value };
  } else {
    cur[leaf] = value;
  }
}

export const registry = new ElementRegistry();
