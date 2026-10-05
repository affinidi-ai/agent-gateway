import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { useHistory } from './useHistory';
import { registry, buildCanvasBlob, buildSurfaceContext } from '../elements';
import type { CanvasNode, DropContext } from '../SurfaceCanvas';
import type { SurfaceNodeType } from '../nodeTypes';
import { showToast } from '../../../utils/toaster';
import { deriveEdges } from '../elements/edges/deriveEdges';
import { synthesizeFabricCanvasNodes } from '../elements/synthesizeFabric';
import {
  findEdgeForHit,
  getArchetype,
  getSlot,
  makeSurfaceSlotFilter,
  tryDrop,
} from '../elements/edges/archetypes';
import { computeAutoLayout } from '../autoLayout';

/**
 * Generic builder state contract. Any caller can extend this with extra
 * fields (e.g. wizard-only `name`, `protocol`, `tags`) — the hook only
 * touches `nodes` and `selectedNodeId`.
 */
export interface SurfaceBuilderState {
  nodes: CanvasNode[];
  selectedNodeId: string | null;
  /**
   * Resizable surface rectangle dimensions in canvas units. Lives in
   * state (not just a ref) so that surface-resize edits participate in
   * the undo/redo history alongside the AP/TP position changes they
   * cascade. `undefined` means "use the canvas default".
   */
  surfaceSize?: { w: number; h: number };
}

function isCascadeRoot(type: SurfaceNodeType): boolean {
  // Removing a canvas-only node that is the leaf of a transit-point chain
  // should cascade-delete the chain. We treat any canvasOnly element as a
  // potential leaf for this purpose.
  return !!registry.get(type)?.canvasOnly;
}

function isNodeConfigured(type: SurfaceNodeType, config: any): boolean {
  return registry.isConfigured(type, config);
}

function getNodeLabel(_type: SurfaceNodeType, config: any): string {
  return config.npc_name || config.name || '';
}

function getNodeDescription(config: any, fallback: string | undefined): string | undefined {
  if ('npc_description' in config) return config.npc_description;
  if ('description' in config) return config.description;
  return fallback;
}

function defaultConfigFor(type: SurfaceNodeType): any {
  const def = registry.get(type);
  return def?.defaultConfig ? def.defaultConfig() : {};
}

/**
 * Mint a stable, human-readable node ID.
 *
 * Singletons get a bare type name (`access-point`, `target`) so reload
 * round-trips to the exact same ID. Multi-instance types get the lowest
 * unused `${type}-N` suffix (1-based) — predictable and free of
 * timestamps.
 */
function mintNodeId(type: SurfaceNodeType, multi: boolean, existing: CanvasNode[]): string {
  if (!multi) return type;
  const taken = new Set(existing.filter(n => n.type === type).map(n => n.id));
  for (let i = 1; ; i++) {
    const candidate = `${type}-${i}`;
    if (!taken.has(candidate)) return candidate;
  }
}

/** Deep merge where right wins for non-object leaves. */
function deepMergePreferringRight(left: any, right: any): any {
  if (right === undefined || right === null) return left;
  if (typeof right !== 'object' || Array.isArray(right)) return right;
  if (typeof left !== 'object' || Array.isArray(left) || left === null) {
    return right;
  }
  const out: Record<string, unknown> = { ...left };
  for (const k of Object.keys(right)) {
    out[k] = deepMergePreferringRight(left[k], right[k]);
  }
  return out;
}

/**
 * Pure topology computation for an edge-targeted drop. Resolves the
 * edge, slot and parentage decisions from the supplied `nodes` array
 * and returns the next nodes plus the created id. No side effects.
 *
 * Extracted from `handleDrop` so the same logic can run inside a
 * single `setState` callback when applying multiple template edge
 * drops in one transaction (each iteration sees the previous drop's
 * mutations via `prev.nodes`, not a stale `stateRef`).
 */
type EdgeDropAttempt =
  | {
      ok: true;
      nextNodes: CanvasNode[];
      createdId: string;
    }
  | {
      ok: false;
      reason: string;
      /** Existing node the user should be redirected to (already-in-use slot). */
      conflictingNodeId?: string;
    };

function attemptEdgeDrop(
  nodes: CanvasNode[],
  type: SurfaceNodeType,
  ctx: {
    edgeSourceId: string;
    edgeTargetId: string;
    edgeDirection: 'request' | 'response';
    position?: { x: number; y: number };
  }
): EdgeDropAttempt {
  const def = registry.get(type);
  const direction = ctx.edgeDirection === 'response' ? 'response' : 'request';
  // Resolve the edge against the SAME synthesised view the canvas
  // renders. For a fabric:// (G2G) target the drop lands on the
  // synthesised `local-gateway-hop` arrow, whose node id exists only in
  // the view — not in the persisted `nodes`. Deriving edges from the raw
  // nodes would leave the hop id unresolvable ("Could not resolve the
  // edge under the drop."). The view is used for edge/slot resolution
  // only; the new node is still created against the real `nodes` (every
  // ma-external slot is `ownedBy: 'source'`, so it parents on the real
  // Managed Agent, never on the synthesised hop).
  const viewNodes = synthesizeFabricCanvasNodes(nodes);
  const edges = deriveEdges(viewNodes);
  const edge = findEdgeForHit(edges, ctx.edgeSourceId, ctx.edgeTargetId);
  if (!edge) {
    return { ok: false, reason: 'Could not resolve the edge under the drop.' };
  }
  const srcType = viewNodes.find(n => n.id === edge.endpoints.source)?.type;
  const tgtType = viewNodes.find(n => n.id === edge.endpoints.target)?.type;
  if (
    srcType &&
    tgtType &&
    !registry.canDropOnEdge(type, srcType, tgtType) &&
    !registry.canDropOnEdge(type, tgtType, srcType)
  ) {
    return { ok: false, reason: `${def?.label ?? type} cannot be dropped on this edge.` };
  }
  const result = tryDrop(
    edge,
    type,
    direction,
    id => {
      const n = viewNodes.find(x => x.id === id);
      return n?.type;
    },
    makeSurfaceSlotFilter(
      viewNodes.find(n => n.type === 'target')?.config?.endpoint,
      viewNodes.some(n => registry.isTransitPointType(n.type)),
      viewNodes
    )
  );
  if (!result.ok) {
    return { ok: false, reason: result.reason, conflictingNodeId: result.conflictingNodeId };
  }
  const slot = getSlot(edge.archetype, result.slotId)!;
  const isResponse = slot.direction === 'response';
  const isPerEndpointSlot = !!slot.ownedBy;

  // Compute parentId / chainTgtId (see handleDrop for the long-form
  // commentary; this is a verbatim extraction of that logic).
  let parentId: string | undefined;
  let chainTgtId: string | undefined;
  if (isPerEndpointSlot) {
    parentId = slot.ownedBy === 'source' ? edge.endpoints.source : edge.endpoints.target;
  } else if (isResponse) {
    parentId = edge.endpoints.target;
  } else {
    const archetype = getArchetype(edge.archetype);
    const orderedOccupants: Array<{ id: string; order: number }> = [];
    if (archetype) {
      for (const s of archetype.slots) {
        if (s.direction !== 'request') continue;
        if (s.ownedBy) continue;
        const occs = edge.slots.get(s.id) ?? [];
        for (const id of occs) {
          orderedOccupants.push({ id, order: s.order });
        }
      }
    }
    orderedOccupants.sort((a, b) => a.order - b.order);
    const myOrder = slot.order;
    let predecessor: string | undefined;
    let successor: string | undefined;
    for (const o of orderedOccupants) {
      if (o.order <= myOrder) predecessor = o.id;
      else if (successor === undefined) successor = o.id;
    }
    parentId =
      predecessor ?? (edge.endpoints.source === '__surface__' ? undefined : edge.endpoints.source);
    chainTgtId = successor ?? edge.endpoints.target;
  }

  // Canonical id resolution for `cardinality: 'one'` slots so reload
  // round-trips produce the same id.
  let canonicalId: string | undefined;
  if (slot.cardinality === 'one') {
    if (slot.ownedBy) {
      const owner = slot.ownedBy === 'source' ? edge.endpoints.source : edge.endpoints.target;
      canonicalId =
        slot.direction === 'response' ? `${type}-${owner}-response` : `${type}-${owner}`;
    } else {
      canonicalId = slot.direction === 'response' ? `${type}-response` : type;
    }
  }
  // Identity nodes derive their id from the slot's payload path so the
  // inbound / protected / external slots get distinct ids.
  if (type === 'identity' && slot.payloadPathTemplate) {
    if (slot.payloadPathTemplate === 'identity_slots.inbound') canonicalId = 'identity-inbound';
    else if (slot.payloadPathTemplate === 'identity_slots.protected')
      canonicalId = 'identity-protected';
    else if (slot.payloadPathTemplate === 'identity_slots.external')
      canonicalId = 'identity-external';
  }
  // Trust Check ids mirror `hydrateLeg` so drop-time and reload-time
  // ids match — otherwise the canvas-blob overlay can't reconcile
  // hydrated `trust-check-caller`/`trust-check-target` against a
  // drop-minted id, and duplicates get pushed as extras on every save.
  if (type === 'trust-check' && slot.payloadPathTemplate) {
    if (slot.payloadPathTemplate === 'access_point.trust_check_list')
      canonicalId = 'trust-check-caller';
    else if (slot.payloadPathTemplate === 'target.trust_check_list')
      canonicalId = 'trust-check-target';
  }
  if (canonicalId && nodes.some(n => n.id === canonicalId)) {
    return {
      ok: false,
      reason: `${slot.label} already in use; remove it first.`,
      conflictingNodeId: canonicalId,
    };
  }
  const id = canonicalId ?? mintNodeId(type, def?.cardinality === 'multi', nodes);

  let nodeConfig = defaultConfigFor(type);
  if (type === 'identity' && canonicalId === 'identity-protected') {
    nodeConfig = {
      ...nodeConfig,
      meta_field: 'serverIdentity',
      json_schema: {
        type: 'object',
        required: [],
        properties: {
          serverIdentity: { type: 'object', required: [], properties: {} },
        },
      },
    };
  }
  if (type === 'trust-recorder') {
    nodeConfig = { ...nodeConfig, entries: (nodeConfig as any)?.entries ?? [] };
  }

  const newNode: CanvasNode = {
    id,
    type,
    label: '',
    configured: isNodeConfigured(type, nodeConfig),
    config: nodeConfig,
    parentId,
    slotId: result.slotId,
    ...(isResponse ? { direction: 'response' as const } : {}),
    ...(ctx.position ? { position: ctx.position } : {}),
  };
  const skipChainInsertion = isResponse || isPerEndpointSlot;
  const nextNodes = skipChainInsertion
    ? [...nodes, newNode]
    : [...nodes.map(n => (n.id === chainTgtId ? { ...n, parentId: id } : n)), newNode];
  return { ok: true, nextNodes, createdId: id };
}

export function useSurfaceBuilder<T extends SurfaceBuilderState>(
  initial: T,
  options?: {
    /**
     * Returns the live surface rectangle dimensions so `buildPayload`
     * can persist them in the canvas blob. Read at save time, not
     * subscribed to, so resize-during-edit is captured correctly.
     */
    getSurfaceSize?: () => { width: number; height: number } | null | undefined;
    /**
     * Returns the live d3 zoom transform (pan + scale) so `buildPayload`
     * can persist it in the canvas blob. Read at save time, not
     * subscribed to, so the latest pan/zoom is captured.
     */
    getCanvasView?: () => { x: number; y: number; k: number } | null | undefined;
    /**
     * Fires after `commit()` runs. Used by the page to schedule a
     * full-surface snapshot into its external history ring buffer.
     * The page-level history is the source of truth for undo/redo;
     * the inner `useHistory` past/future stacks are bypassed when
     * `undoOverride`/`redoOverride` are also supplied.
     */
    onCommit?: () => void;
    /**
     * Fires after `replaceCommit()` runs. Same purpose as `onCommit`
     * but for in-place baseline replacement.
     */
    onReplaceCommit?: () => void;
    /**
     * Substitutes the inner `undo` action for the Cmd/Ctrl+Z keyboard
     * shortcut. When provided, the inner history's past/future stacks
     * are no longer surfaced to the user; the page owns the walk.
     */
    undoOverride?: () => void;
    /** Counterpart of `undoOverride` for redo (Cmd/Ctrl+Shift+Z / Y). */
    redoOverride?: () => void;
    /**
     * Overrides the inner history's `canUndo` flag — used by pages
     * that supply an `undoOverride`, so the toolbar's enabled state
     * reflects the page-owned ring buffer rather than the bypassed
     * inner stack (which would be permanently empty).
     */
    canUndoOverride?: boolean;
    /** Counterpart of `canUndoOverride`. */
    canRedoOverride?: boolean;
    /**
     * Returns the current surface protocol (a2a, ap2, mcp, ...) so
     * context-aware dependency checks (e.g. payment.mcp_payment_triggers)
     * can be evaluated against the right protocol without waiting
     * until the page-level save handler assembles the payload.
     */
    getProtocol?: () => string | undefined;
  }
) {
  const {
    state,
    set: setState,
    commit: innerCommit,
    replaceCommit: innerReplaceCommit,
    undo,
    redo,
    canUndo,
    canRedo,
    externalRevision,
    bumpExternalRevision,
  } = useHistory<T>(initial);
  // Independent counter the canvas watches to fit the complete actor
  // graph after auto-layout. The handled revision lives outside the
  // canvas so a request survives a canvas mount or variant remount.
  const [resetViewRev, bumpResetView] = useReducer((x: number) => x + 1, 0);
  const handledResetViewRevRef = useRef(0);
  // Toolbar-callable wrappers that respect the page-level
  // `undoOverride` / `redoOverride` the same way the Cmd+Z keyboard
  // handler does — so the toolbar buttons and the shortcut always run
  // through the same code path.
  const handleUndo = useCallback(() => {
    if (undoOverrideRef.current) undoOverrideRef.current();
    else undo();
  }, [undo]);
  const handleRedo = useCallback(() => {
    if (redoOverrideRef.current) redoOverrideRef.current();
    else redo();
  }, [redo]);
  // Keep callback options in refs so the wrapped commit/replaceCommit
  // and the keyboard handler always invoke the freshest closure even
  // when callers pass unstable lambdas.
  const onCommitRef = useRef(options?.onCommit);
  onCommitRef.current = options?.onCommit;
  const onReplaceCommitRef = useRef(options?.onReplaceCommit);
  onReplaceCommitRef.current = options?.onReplaceCommit;
  const undoOverrideRef = useRef(options?.undoOverride);
  undoOverrideRef.current = options?.undoOverride;
  const redoOverrideRef = useRef(options?.redoOverride);
  redoOverrideRef.current = options?.redoOverride;
  const commit = useCallback(() => {
    innerCommit();
    onCommitRef.current?.();
  }, [innerCommit]);
  const replaceCommit = useCallback(() => {
    innerReplaceCommit();
    onReplaceCommitRef.current?.();
  }, [innerReplaceCommit]);

  // Keep mutable refs for state and handleNodeMove so the keyboard handler
  // (registered once with [undo, redo] deps) can read the latest selection
  // and dispatch a move without rebinding.
  const stateRef = useRef<T>(state);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);
  const handleNodeMoveRef = useRef<((nodeId: string, x: number, y: number) => void) | null>(null);
  const handleNodeRemoveRef = useRef<((nodeId: string) => void) | null>(null);
  const handleAutoLayoutRef = useRef<(() => void) | null>(null);

  // Multi-selection (lasso + shift-click). Kept in BOTH a ref and a state
  // mirror: the ref is read synchronously by the canvas keyboard / d3
  // handlers (no re-render), while the state mirror is what the right
  // panel uses to decide between single-node config and the multi-select
  // template-authoring panel.
  const multiSelectedIdsRef = useRef<Set<string>>(new Set());
  const [multiSelectedIds, setMultiSelectedIdsState] = useState<string[]>([]);
  const setMultiSelection = useCallback((ids: string[]) => {
    multiSelectedIdsRef.current = new Set(ids);
    setMultiSelectedIdsState(prev => {
      // Avoid noisy re-renders when the set is unchanged (d3 fires the
      // callback on every drag tick within a lasso).
      if (prev.length === ids.length && prev.every(id => multiSelectedIdsRef.current.has(id))) {
        return prev;
      }
      return ids.slice();
    });
  }, []);

  const handleDrop = useCallback(
    (type: SurfaceNodeType, context?: DropContext) => {
      const def = registry.get(type);
      const dropTarget = def?.dropMode ?? 'canvas';
      const defaultConfig = defaultConfigFor(type);

      // Edge-drop dispatch via the derived edge/slot model.
      //
      // The topology computation (slot resolution, parentId / chain
      // re-parenting, canonical id minting) lives in the pure
      // `attemptEdgeDrop` helper so it can also run inside a single
      // `setState` callback when applying multiple template edge
      // drops in one transaction. See `handleTemplateEdgeDrops`.
      if (dropTarget === 'edge' && context?.edgeSourceId && context?.edgeTargetId) {
        const attempt = attemptEdgeDrop(stateRef.current.nodes, type, {
          edgeSourceId: context.edgeSourceId,
          edgeTargetId: context.edgeTargetId,
          edgeDirection: context.edgeDirection === 'response' ? 'response' : 'request',
          position: context.position,
        });
        if (!attempt.ok) {
          showToast('error', attempt.reason);
          if (attempt.conflictingNodeId) {
            const conflictId = attempt.conflictingNodeId;
            setState(prev => ({ ...prev, selectedNodeId: conflictId }));
          }
          return;
        }
        setState(prev => ({
          ...prev,
          // Re-run the attempt against `prev.nodes` so concurrent
          // edits in the same render batch don't get clobbered.
          nodes: attempt.nextNodes,
          selectedNodeId: attempt.createdId,
        }));
        commit();
        context?.onCreated?.(attempt.createdId);
        return;
      }

      const id = mintNodeId(type, def?.cardinality === 'multi', stateRef.current.nodes);

      if (dropTarget === 'node' && context?.targetNodeId) {
        // Multi-cardinality elements dropped on a node create a child of
        // that node (e.g. target-variant on target, transit-payment on a
        // transit-point). Singleton + 'node' dropMode just selects the
        // existing target so the user can edit it in place.
        if (def?.cardinality === 'multi') {
          const newNode: CanvasNode = {
            id,
            type,
            label: '',
            configured: isNodeConfigured(type, defaultConfig),
            config: defaultConfig,
            parentId: context.targetNodeId,
          };
          setState(prev => ({
            ...prev,
            nodes: [...prev.nodes, newNode],
            selectedNodeId: id,
          }));
          commit();
          context?.onCreated?.(id);
        } else {
          setState(prev => ({ ...prev, selectedNodeId: context.targetNodeId! }));
        }
      } else {
        const newNode: CanvasNode = {
          id,
          type,
          label: '',
          configured: isNodeConfigured(type, defaultConfig),
          config: defaultConfig,
          parentId: undefined,
          // Persist the drop position when the canvas supplied one
          // (currently only edge-constrained types). Without this, a
          // freshly-dropped TP/AP has no `position` and the canvas
          // re-derives a default location after save/reload.
          ...(context?.position ? { position: context.position } : {}),
        };
        if (registry.isTransitPointType(type)) {
          const npcId = mintNodeId('npc-endpoint', true, [...stateRef.current.nodes, newNode]);
          const npcNode: CanvasNode = {
            id: npcId,
            type: 'npc-endpoint',
            label: 'External Target',
            configured: true,
            config: {
              npc_name: 'External Target',
              npc_description: 'Destination service',
              connection_direction: 'outbound',
              connected_to: id,
            },
            parentId: id,
            connectionDirection: 'outbound',
            description: 'Destination service',
          };
          setState(prev => ({
            ...prev,
            nodes: [...prev.nodes, newNode, npcNode],
            selectedNodeId: id,
          }));
        } else {
          setState(prev => ({
            ...prev,
            nodes: [...prev.nodes, newNode],
            selectedNodeId: id,
          }));
        }
        commit();
        context?.onCreated?.(id);
      }
    },
    [setState, commit]
  );

  const handleNodeClick = useCallback(
    (nodeId: string) => {
      setState(prev => ({ ...prev, selectedNodeId: nodeId }));
    },
    [setState]
  );

  // Live config edits — no history snapshot per keystroke. Callers should
  // wrap their config UI in a container with onBlur={commit} so that a
  // multi-keystroke edit becomes a single undo step.
  const handleNodeUpdate = useCallback(
    (nodeId: string, config: any) => {
      setState(prev => ({
        ...prev,
        nodes: prev.nodes.map(n => {
          if (n.id !== nodeId) return n;
          const prevConnectedTo = n.config?.connected_to;
          const newConnectedTo = config.connected_to;
          const connectedToChanged =
            newConnectedTo !== undefined && newConnectedTo !== prevConnectedTo;
          return {
            ...n,
            config,
            configured: isNodeConfigured(n.type, config),
            label: getNodeLabel(n.type, config) || registry.get(n.type)?.label || n.type,
            description: getNodeDescription(config, n.description),
            connectionDirection: config.connection_direction || n.connectionDirection,
            parentId: connectedToChanged ? newConnectedTo || undefined : n.parentId,
          };
        }),
      }));
    },
    [setState]
  );

  /**
   * Template-driven edge drop. Delegates the topology work to
   * `handleDrop` (so the new node lands with the correct
   * `parentId` / slot id / direction), then merges any
   * template-supplied config onto whatever the drop seeded.
   *
   * Returns the new node's id on success, or `null` if the drop
   * was rejected (e.g. slot already occupied — `handleDrop`
   * surfaces its own toast in that case).
   */
  const handleEdgeTemplateDrop = useCallback(
    (
      type: SurfaceNodeType,
      ctx: { edgeSourceId: string; edgeTargetId: string; edgeDirection: 'request' | 'response' },
      configOverrides: Record<string, unknown>
    ): string | null => {
      let createdId: string | null = null;
      handleDrop(type, {
        edgeSourceId: ctx.edgeSourceId,
        edgeTargetId: ctx.edgeTargetId,
        edgeDirection: ctx.edgeDirection,
        onCreated: id => {
          createdId = id;
        },
      });
      if (createdId && configOverrides && Object.keys(configOverrides).length > 0) {
        // Defer the merge so it lands in a follow-up render — by then
        // setState from handleDrop has flushed and the new node is
        // visible in state.
        setState(prev => {
          const node = prev.nodes.find(n => n.id === createdId);
          if (!node) return prev;
          const merged = deepMergePreferringRight(node.config ?? {}, configOverrides);
          return {
            ...prev,
            nodes: prev.nodes.map(n =>
              n.id === createdId
                ? { ...n, config: merged, configured: isNodeConfigured(n.type, merged) }
                : n
            ),
          };
        });
      }
      return createdId;
    },
    [handleDrop, setState]
  );

  /**
   * Batched variant of {@link handleEdgeTemplateDrop} for applying a
   * whole template's worth of edge items in one transaction. Each
   * iteration computes its topology against the running `prev.nodes`
   * from the previous iteration's result, so chain-insertion
   * re-parenting accumulates correctly across drops. The synchronous
   * forEach + `stateRef` pattern would otherwise let each drop
   * recompute against the same pre-drop state and overwrite earlier
   * re-parents.
   *
   * Returns the ids of successfully created nodes in input order.
   * Errors are reported via the standard toaster after the state
   * update commits.
   */
  const handleTemplateEdgeDrops = useCallback(
    (
      drops: Array<{
        type: SurfaceNodeType;
        ctx: { edgeSourceId: string; edgeTargetId: string; edgeDirection: 'request' | 'response' };
        configOverrides: Record<string, unknown>;
      }>
    ): string[] => {
      if (drops.length === 0) return [];
      const createdIds: string[] = [];
      const errors: string[] = [];
      setState(prev => {
        let nodes = prev.nodes;
        let lastSelected: string | null = prev.selectedNodeId;
        for (const d of drops) {
          const attempt = attemptEdgeDrop(nodes, d.type, {
            edgeSourceId: d.ctx.edgeSourceId,
            edgeTargetId: d.ctx.edgeTargetId,
            edgeDirection: d.ctx.edgeDirection,
          });
          if (!attempt.ok) {
            errors.push(attempt.reason);
            continue;
          }
          nodes = attempt.nextNodes;
          // Apply config overrides on the freshly-created node.
          if (d.configOverrides && Object.keys(d.configOverrides).length > 0) {
            nodes = nodes.map(n => {
              if (n.id !== attempt.createdId) return n;
              const merged = deepMergePreferringRight(n.config ?? {}, d.configOverrides);
              return { ...n, config: merged, configured: isNodeConfigured(n.type, merged) };
            });
          }
          createdIds.push(attempt.createdId);
          lastSelected = attempt.createdId;
        }
        return { ...prev, nodes, selectedNodeId: lastSelected };
      });
      commit();
      // Toasts after commit so we don't fire side effects from inside
      // the (potentially double-invoked under StrictMode) reducer.
      for (const reason of errors) showToast('error', reason);
      return createdIds;
    },
    [setState, commit]
  );

  const handleNodeRemove = useCallback(
    (nodeId: string) => {
      setState(prev => {
        const removedNode = prev.nodes.find(n => n.id === nodeId);
        if (!removedNode) return prev;

        // Removing a transit point cascade-deletes everything attached
        // to it (NPC endpoints, downstream chain segments, etc.).
        if (registry.isTransitPointType(removedNode.type)) {
          const chainIds = new Set<string>([nodeId]);
          let expanded = true;
          while (expanded) {
            expanded = false;
            for (const n of prev.nodes) {
              if (!chainIds.has(n.id) && n.parentId && chainIds.has(n.parentId)) {
                chainIds.add(n.id);
                expanded = true;
              }
            }
          }
          return {
            ...prev,
            nodes: prev.nodes.filter(n => !chainIds.has(n.id)),
            selectedNodeId: chainIds.has(prev.selectedNodeId || '') ? null : prev.selectedNodeId,
          };
        }

        // Canvas-only leaf of a TP chain — cascade-delete entire chain.
        if (isCascadeRoot(removedNode.type) && removedNode.parentId) {
          const chainIds = new Set<string>([nodeId]);
          let current: CanvasNode | undefined = removedNode;
          while (current?.parentId) {
            const parentId: string = current.parentId;
            const parent: CanvasNode | undefined = prev.nodes.find(n => n.id === parentId);
            if (!parent) break;
            chainIds.add(parent.id);
            if (registry.isTransitPointType(parent.type)) break;
            current = parent;
          }
          const hasTP = prev.nodes.some(
            n => chainIds.has(n.id) && registry.isTransitPointType(n.type)
          );
          if (hasTP) {
            let expanded = true;
            while (expanded) {
              expanded = false;
              for (const n of prev.nodes) {
                if (!chainIds.has(n.id) && n.parentId && chainIds.has(n.parentId)) {
                  chainIds.add(n.id);
                  expanded = true;
                }
              }
            }
            return {
              ...prev,
              nodes: prev.nodes.filter(n => !chainIds.has(n.id)),
              selectedNodeId: chainIds.has(prev.selectedNodeId || '') ? null : prev.selectedNodeId,
            };
          }
        }

        // Default: re-link children to the removed node's parent.
        const updatedNodes = prev.nodes
          .filter(n => n.id !== nodeId)
          .map(n => (n.parentId === nodeId ? { ...n, parentId: removedNode.parentId } : n));

        return {
          ...prev,
          nodes: updatedNodes,
          selectedNodeId: prev.selectedNodeId === nodeId ? null : prev.selectedNodeId,
        };
      });
      commit();
    },
    [setState, commit]
  );

  const handleCloseConfig = useCallback(() => {
    setState(prev => ({ ...prev, selectedNodeId: null }));
  }, [setState]);

  // SurfaceCanvas only fires onNodeMove on d3 drag-end (not during the
  // drag), and arrow-nudge fires once per keypress, so each call is a
  // discrete edit and warrants a commit.
  const handleNodeMove = useCallback(
    (nodeId: string, x: number, y: number) => {
      setState(prev => ({
        ...prev,
        nodes: prev.nodes.map(n => (n.id === nodeId ? { ...n, position: { x, y } } : n)),
      }));
      commit();
    },
    [setState, commit]
  );

  // System-driven position write: used for canvas-internal reflows
  // (surface-wide auto-placement, edge-middleware projection re-sync).
  // Updates state so the canvas stays the source of truth for slot
  // positions, but does NOT commit \u2014 these are not user actions and
  // must not occupy their own undo step.
  const handleSystemNodeMove = useCallback(
    (nodeId: string, x: number, y: number) => {
      setState(prev => ({
        ...prev,
        nodes: prev.nodes.map(n => (n.id === nodeId ? { ...n, position: { x, y } } : n)),
      }));
    },
    [setState]
  );

  // Apply a relative (dx, dy) translation to many nodes at once,
  // recording a single history snapshot for the whole group.
  const handleNodesNudge = useCallback(
    (ids: string[], dx: number, dy: number) => {
      if (ids.length === 0) return;
      const idSet = new Set(ids);
      setState(prev => ({
        ...prev,
        nodes: prev.nodes.map(n => {
          if (!idSet.has(n.id)) return n;
          const cur = n.position ?? { x: 0, y: 0 };
          return { ...n, position: { x: cur.x + dx, y: cur.y + dy } };
        }),
      }));
      commit();
    },
    [setState, commit]
  );

  useEffect(() => {
    handleNodeMoveRef.current = handleNodeMove;
  }, [handleNodeMove]);

  useEffect(() => {
    handleNodeRemoveRef.current = handleNodeRemove;
  }, [handleNodeRemove]);
  const handleNodeResize = useCallback(
    (nodeId: string, radius: number) => {
      setState(prev => ({
        ...prev,
        nodes: prev.nodes.map(n => (n.id === nodeId ? { ...n, radius } : n)),
      }));
      commit();
    },
    [setState, commit]
  );

  /**
   * Atomic surface-resize commit. Updates `state.surfaceSize` together
   * with every cascading node-position change in a single `setState`
   * + `commit()` so undo reverts the whole gesture as one snapshot.
   * Without this, the size lived in a ref and only the node moves were
   * undoable — leaving the layout broken on undo (positions reverted
   * to a small surface, but the surface stayed large).
   */
  const handleSurfaceResize = useCallback(
    (
      size: { w: number; h: number },
      moves: ReadonlyArray<{ id: string; x: number; y: number }>
    ) => {
      const moveMap = new Map(moves.map(m => [m.id, m] as const));
      setState(prev => ({
        ...prev,
        surfaceSize: { w: size.w, h: size.h },
        nodes: prev.nodes.map(n => {
          const m = moveMap.get(n.id);
          return m ? { ...n, position: { x: m.x, y: m.y } } : n;
        }),
      }));
      commit();
    },
    [setState, commit]
  );

  /**
   * Auto-layout: snap every node to a canonical position and resize
   * the surface to fit. All position writes + the size update land in
   * a single setState + commit so the entire reflow occupies one
   * undo step. Per-tick canvas reprojection (system-driven moves)
   * never commits, so subsequent middleware re-anchoring is not
   * pushed onto the undo stack.
   */
  const handleAutoLayout = useCallback(() => {
    const result = computeAutoLayout(stateRef.current.nodes);
    const moveMap = new Map(result.positions.map(p => [p.id, p] as const));
    setState(prev => ({
      ...prev,
      surfaceSize: result.surfaceSize,
      nodes: prev.nodes.map(n => {
        const m = moveMap.get(n.id);
        return m ? { ...n, position: { x: m.x, y: m.y } } : n;
      }),
    }));
    commit();
    // The canvas keeps its own `positionsRef` cache that wins over
    // `CanvasNode.position` on every tick — bumping externalRevision
    // forces the existing undo/redo re-sync effect to push our new
    // positions into d3 fx/fy and the cache.
    bumpExternalRevision();
    // Recentre the user's view onto the freshly laid-out surface so
    // the result is visible even if the user had panned/zoomed away.
    bumpResetView();
  }, [setState, commit, bumpExternalRevision]);

  useEffect(() => {
    handleAutoLayoutRef.current = handleAutoLayout;
  }, [handleAutoLayout]);

  // Global keyboard shortcuts: undo/redo + arrow-key nudge. Cmd+S is
  // owned by the page (see useSaveShortcut) — it has no business living
  // inside the builder hook because the save action is page-specific.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isMeta = e.metaKey || e.ctrlKey;
      if (isMeta && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        if (undoOverrideRef.current) undoOverrideRef.current();
        else undo();
        return;
      } else if (isMeta && e.key === 'z' && e.shiftKey) {
        e.preventDefault();
        if (redoOverrideRef.current) redoOverrideRef.current();
        else redo();
        return;
      } else if (isMeta && e.key === 'y') {
        e.preventDefault();
        if (redoOverrideRef.current) redoOverrideRef.current();
        else redo();
        return;
      } else if (isMeta && (e.key === 'l' || e.key === 'L')) {
        // Cmd/Ctrl+L: auto-layout the surface.
        const t = e.target as HTMLElement | null;
        const tg = t?.tagName;
        if (tg === 'INPUT' || tg === 'TEXTAREA' || tg === 'SELECT' || t?.isContentEditable) {
          return;
        }
        e.preventDefault();
        handleAutoLayoutRef.current?.();
        return;
      }

      // Escape closes the properties panel when the user is on the
      // canvas (not typing in a field). Mirrors the behaviour of
      // clicking the panel's close button or empty canvas.
      if (e.key === 'Escape') {
        const t = e.target as HTMLElement | null;
        const tg = t?.tagName;
        if (tg === 'INPUT' || tg === 'TEXTAREA' || tg === 'SELECT' || t?.isContentEditable) {
          return;
        }
        if (stateRef.current.selectedNodeId) {
          setState(prev => ({ ...prev, selectedNodeId: null }));
        }
        return;
      }

      // Delete / Backspace removes the lasso/shift-selected nodes (or
      // the single sidebar-selected node if no multi-selection). Skip
      // when typing in a field, and skip non-deletable elements
      // (e.g. surface root, fixed endpoints).
      if (e.key === 'Delete' || e.key === 'Backspace') {
        const t = e.target as HTMLElement | null;
        const tg = t?.tagName;
        if (tg === 'INPUT' || tg === 'TEXTAREA' || tg === 'SELECT' || t?.isContentEditable) {
          return;
        }
        const multi = Array.from(multiSelectedIdsRef.current);
        const ids =
          multi.length > 0
            ? multi
            : stateRef.current.selectedNodeId
              ? [stateRef.current.selectedNodeId]
              : [];
        if (ids.length === 0) return;
        const nodesById = new Map(stateRef.current.nodes.map(n => [n.id, n] as const));
        const deletable = ids.filter(id => {
          // Reserved auto-injected ids (surface, human, caller, the
          // managed-agent NPC) all start with `__`. They have d3 link
          // dependencies the simulation will choke on if they
          // disappear, so they're hard-blocked here regardless of
          // any per-element `deletable` flag.
          if (id.startsWith('__')) return false;
          const node = nodesById.get(id);
          if (!node) return false;
          const def = registry.get(node.type);
          return def?.deletable !== false;
        });
        if (deletable.length === 0) return;
        e.preventDefault();
        multiSelectedIdsRef.current = new Set();
        for (const id of deletable) {
          handleNodeRemoveRef.current?.(id);
        }
        return;
      }

      const isArrow =
        e.key === 'ArrowLeft' ||
        e.key === 'ArrowRight' ||
        e.key === 'ArrowUp' ||
        e.key === 'ArrowDown';
      if (!isArrow) return;
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable) {
        return;
      }
      const step = e.shiftKey ? 10 : 1;
      let dx = 0;
      let dy = 0;
      if (e.key === 'ArrowLeft') dx = -step;
      else if (e.key === 'ArrowRight') dx = step;
      else if (e.key === 'ArrowUp') dy = -step;
      else if (e.key === 'ArrowDown') dy = step;

      // Prefer multi-selection (lasso + shift-click) when present;
      // fall back to the single sidebar-selected node otherwise.
      const multi = Array.from(multiSelectedIdsRef.current);
      if (multi.length > 0) {
        e.preventDefault();
        const idSet = new Set(multi);
        setState(prev => ({
          ...prev,
          nodes: prev.nodes.map(n => {
            if (!idSet.has(n.id)) return n;
            const cur = n.position ?? { x: 0, y: 0 };
            return { ...n, position: { x: cur.x + dx, y: cur.y + dy } };
          }),
        }));
        commit();
        return;
      }
      const sel = stateRef.current.selectedNodeId;
      if (!sel) return;
      const node = stateRef.current.nodes.find(n => n.id === sel);
      if (!node) return;
      const pos = node.position ?? { x: 0, y: 0 };
      e.preventDefault();
      handleNodeMoveRef.current?.(sel, pos.x + dx, pos.y + dy);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [undo, redo]);

  // The surface itself (`__surface__`) is not a real entry in `state.nodes`
  // — it's an auto-injected D3 node. When selected, synthesize a minimal
  // CanvasNode so NodeConfigPanel can render the surface element's
  // ConfigPanel like any other element.
  const selectedNode =
    state.selectedNodeId === '__surface__'
      ? ({
          id: '__surface__',
          type: 'surface' as any,
          label: 'Agent Surface',
          configured: true,
          config: {},
        } as any)
      : state.nodes.find(n => n.id === state.selectedNodeId) || null;

  /**
   * True iff any node has at least one format-validation error from
   * `def.validate`. Use to gate the Create/Save button.
   */
  const hasValidationErrors = state.nodes.some(
    n => registry.getValidationErrors(n.type, n.config).length > 0
  );

  /**
   * True iff at least one node on the canvas is still flagged as
   * unconfigured (e.g. a freshly-dropped target with no endpoint, or an
   * access-point with no route). Use alongside `hasValidationErrors` to
   * gate the Create/Save button — saving an unconfigured node always
   * fails server-side with a 400.
   */
  const hasIncompleteNodes = state.nodes.some(n => !n.configured);

  /**
   * Nodes with at least one unmet error-severity feature dependency
   * (e.g. credential-delegation without source auth on the surface).
   * Returned as an array of `{ nodeId, message }` so the page layer
   * can surface a "Show me" toast and the canvas can highlight them
   * with the marching-ants ring. Use to gate the Create/Save button —
   * saving with unmet dependencies produces a surface the runtime
   * will reject (or silently mis-route) at the first request.
   */
  const dependencyErrors: Array<{ nodeId: string; nodeType: string; message: string }> = (() => {
    const ctx = buildSurfaceContext(options?.getProtocol?.(), state.nodes);
    const out: Array<{ nodeId: string; nodeType: string; message: string }> = [];
    for (const n of state.nodes) {
      if (n.type === 'surface') continue;
      const ws = registry.getDependencyWarnings(n.type, n.config, ctx);
      for (const w of ws) {
        if (w.severity === 'error') {
          out.push({ nodeId: n.id, nodeType: n.type, message: w.message });
        }
      }
    }
    return out;
  })();
  const hasDependencyErrors = dependencyErrors.length > 0;

  /**
   * Build the full surface payload from current nodes. Caller supplies
   * surface-level metadata (name / description / tags / issuer /
   * protocol / status) — the hook handles the rest by delegating to the
   * registry and persisting layout via the canvas blob.
   */
  const buildPayload = useCallback(
    (meta: {
      surface_id?: string;
      name: string;
      description?: string;
      tags: string[];
      issuer_id?: string;
      protocol: string;
      status?: string;
    }): any => {
      const payload = registry.buildPayload({
        protocol: meta.protocol,
        surfaceMeta: {
          ...(meta.surface_id ? { surface_id: meta.surface_id } : {}),
          name: meta.name,
          ...(meta.description ? { description: meta.description } : {}),
          tags: meta.tags,
          ...(meta.issuer_id ? { issuer_id: meta.issuer_id } : {}),
          status: meta.status ?? 'active',
        },
        allNodes: state.nodes,
        nodesOfType: type => state.nodes.filter(n => n.type === type),
        firstNodeOfType: type => state.nodes.find(n => n.type === type),
      });
      payload.canvas = buildCanvasBlob(state.nodes, {
        // Prefer the history-tracked size on state so undo/redo and a
        // post-undo save persist the reverted dimensions. Falls back to
        // the live-write ref (`getSurfaceSize`) for the legacy path
        // where size lives only in a ref.
        surfaceSize: state.surfaceSize
          ? { width: state.surfaceSize.w, height: state.surfaceSize.h }
          : (options?.getSurfaceSize?.() ?? undefined),
        view: options?.getCanvasView?.() ?? undefined,
      });
      return payload;
    },
    [state.nodes, state.surfaceSize, options]
  );

  return {
    state,
    setState,
    commit,
    replaceCommit,
    undo,
    redo,
    handleUndo,
    handleRedo,
    canUndo: options?.canUndoOverride ?? canUndo,
    canRedo: options?.canRedoOverride ?? canRedo,
    selectedNode,
    handleDrop,
    handleEdgeTemplateDrop,
    handleTemplateEdgeDrops,
    handleNodeClick,
    handleNodeUpdate,
    handleNodeRemove,
    handleNodeMove,
    handleSystemNodeMove,
    handleNodesNudge,
    handleNodeResize,
    handleSurfaceResize,
    handleAutoLayout,
    handleCloseConfig,
    buildPayload,
    externalRevision,
    bumpExternalRevision,
    resetViewRev,
    handledResetViewRevRef,
    bumpResetView,
    hasValidationErrors,
    hasIncompleteNodes,
    hasDependencyErrors,
    dependencyErrors,
    setMultiSelection,
    multiSelectedIds,
  };
}

export type UseSurfaceBuilderReturn<T extends SurfaceBuilderState> = ReturnType<
  typeof useSurfaceBuilder<T>
>;
