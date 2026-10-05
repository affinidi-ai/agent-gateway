import React, { useEffect, useState, useCallback, useRef, useReducer } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AgentSurface, apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { usePermissions } from '../context/PermissionsContext';
import { usePageTitle } from '../context/PageTitleContext';
import { useApp } from '../context/AppContext';
import { CanvasNode, getIncompleteReason } from '../components/surface-builder/SurfaceCanvas';
import {
  registry,
  validateSurfacePayload,
  buildCanvasBlob,
} from '../components/surface-builder/elements';
import type { Protocol } from '../components/surface-builder/elements/types';
import { useSurfaceBuilder } from '../components/surface-builder/hooks/useSurfaceBuilder';
import { useSurfaceHistory } from '../components/surface-builder/hooks/useSurfaceHistory';
import { useSaveShortcut } from '../components/surface-builder/hooks/useSaveShortcut';
import { useDiscardWithUndo } from '../components/surface-builder/hooks/useDiscardWithUndo';
import SurfaceFormShell from '../components/surface-builder/SurfaceFormShell';
import { useSurfacePolicyDefinitions } from '../components/surface-builder/hooks/useSurfacePolicyDefinitions';
import { surfacePolicyBlockingReason } from '../components/surface-builder/elements/policy/status';
import {
  DEFAULT_DIDWEBVH_CONFIG,
  type DidwebvhConfig,
} from '../components/surface-builder/SurfaceMetaContext';
import {
  useVariantSnapshots,
  BASE_VARIANT_ID,
} from '../components/surface-builder/variants/useVariantSnapshots';
import { DeleteButton } from '../components/shared/DeleteButton';
import {
  hydrateSurfaceCanvas,
  nodesFromSurface,
} from '../components/surface-builder/nodesFromSurface';
import { findDuplicateListenerRoutes } from '../components/surface-builder/templates/scrubVolatile';
import './SurfaceBuilder.css';

interface DetailBuilderState {
  nodes: CanvasNode[];
  selectedNodeId: string | null;
}

interface DirtyInputs {
  /**
   * Variants snapshot signature (from `variantSnapshots.signature`).
   * Already encodes every per-variant payload (nodes, positions,
   * canvas size + view), the catalog, and the default variant id.
   * Switching variants alone leaves this string untouched because
   * `signature()` deliberately excludes `activeVariantId`.
   */
  variantsSig: string;
  name: string;
  description: string;
  tagsCsv: string;
  status: AgentSurface['status'];
  protocol: Protocol;
  publishToDid: boolean;
  terminateTraceId: boolean;
  issuerId: string;
  didwebvh: DidwebvhConfig;
  jsonOverride: string | null;
}

/**
 * Stable serialisation of every user-visible piece of surface state so we
 * can detect unsaved edits by string comparison against a baseline. Node
 * order matters (the canvas preserves insertion order), so we don't sort.
 */
function serializeDirtySignature(inputs: DirtyInputs): string {
  return JSON.stringify(inputs);
}

function didwebvhFromAccessPoint(ap: any): DidwebvhConfig {
  const did = ap?.didwebvh_identity;
  if (!did || typeof did !== 'object') return DEFAULT_DIDWEBVH_CONFIG;
  return {
    enabled: true,
    auto_create: did.auto_create ?? true,
    identity_id: typeof did.identity_id === 'string' ? did.identity_id : '',
    did_path: typeof did.did_path === 'string' ? did.did_path : '',
    injection_mode: (did.injection_mode as DidwebvhConfig['injection_mode']) ?? 'header',
  };
}

function writeDidwebvhToAccessPoint(ap: any, cfg: DidwebvhConfig): void {
  if (!ap || !cfg.enabled) return;
  const did: Record<string, any> = {
    auto_create: cfg.auto_create,
    injection_mode: cfg.injection_mode,
  };
  if (cfg.identity_id.trim()) did.identity_id = cfg.identity_id.trim();
  if (cfg.did_path.trim()) did.did_path = cfg.did_path.trim();
  ap.didwebvh_identity = did;
}

const SurfaceDetailPage: React.FC = () => {
  const { surfaceId } = useParams<{ surfaceId: string }>();
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('surfaces.edit');
  const { getCurrentStats } = useApp();

  const [surface, setSurface] = useState<AgentSurface | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasAttemptedSave, setHasAttemptedSave] = useState(false);
  const surfacePolicyLoadState = useSurfacePolicyDefinitions();
  const surfacePolicyIds =
    surfacePolicyLoadState.status === 'loaded' ? surfacePolicyLoadState.ids : null;
  const [activeTab, setActiveTab] = useState<
    'surface' | 'elements' | 'monitoring' | 'config' | 'editor'
  >('surface');
  const [editorTabNodeId, setEditorTabNodeId] = useState<string | null>(null);

  const handleOpenFullscreenEditor = useCallback((nodeId: string) => {
    setEditorTabNodeId(nodeId);
    setActiveTab('editor');
  }, []);

  const handleCloseFullscreenEditor = useCallback(() => {
    setEditorTabNodeId(null);
    setActiveTab('surface');
  }, []);

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tagsCsv, setTagsCsv] = useState('');
  const [status, setStatus] = useState<AgentSurface['status']>('active');
  const [protocol, setProtocol] = useState<Protocol>('a2a');
  const [publishToDid, setPublishToDid] = useState(false);
  const [terminateTraceId, setTerminateTraceId] = useState(false);
  const [issuerId, setIssuerId] = useState('');
  const [didwebvh, setDidwebvh] = useState<DidwebvhConfig>(DEFAULT_DIDWEBVH_CONFIG);

  usePageTitle(`Edit Agent Surface - ${name || 'Untitled'}`);

  const [jsonOverride, setJsonOverride] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);

  const surfaceSizeRef = useRef<{ w: number; h: number } | null>(null);
  const canvasViewRef = useRef<{ x: number; y: number; k: number } | null>(null);
  /**
   * Snapshot of the last persisted (or freshly-loaded) state, serialised
   * to a single string. The page is considered dirty when the live form +
   * canvas signature differs from this baseline. Initialised to `null` so
   * we don't flag the surface as dirty before the first load completes.
   *
   * Captured asynchronously via `rebaselineDirty` (see effect below)
   * because `variantSnapshots.signature()` depends on React state that
   * `hydrateFromPayload` updates via `setState` — synchronous capture
   * inside `load()` / `handleSave()` would store a stale string and
   * flip the form dirty on the first post-load render.
   */
  const baselineRef = useRef<string | null>(null);
  /**
   * When true, the next render captures `currentSignature` into
   * `baselineRef` and clears the flag. Set by `load()` and `handleSave()`
   * after they finish writing state.
   */
  const [rebaselineDirty, setRebaselineDirty] = useState(0);
  /**
   * Tracks which variant the canvas is currently rendering. Updated by
   * every code path that writes to `state.nodes` from a snapshot
   * (initial hydrate, post-save re-hydrate, `handleSwitchVariant`).
   * The "active variant changed externally" effect compares
   * `variantSnapshots.activeVariantId` against this ref and
   * re-renders the canvas when they diverge — which happens when the
   * variants editor panel deletes the active variant and the snapshot
   * hook silently re-points `activeVariantId` to base.
   */
  const canvasActiveVariantRef = useRef<string | null>(null);
  /**
   * Snapshot of the variant ids the catalog-mirror effect last saw.
   * Used to detect a brand-new variant id appearing in the catalog
   * (typically because the user clicked "Add variant" inside the
   * `TargetVariantPanel` editor) and auto-switch the canvas to it.
   * `null` means "not yet seeded" — the first run after page load
   * does not auto-switch.
   */
  const knownVariantIdsRef = useRef<Set<string> | null>(null);
  // Forward-declared refs for the page-level full-surface history
  // ring buffer. The actual hook + handlers are constructed below
  // the builder (they need `setState` / `bumpExternalRevision` /
  // `buildPayload`), but the builder's `onCommit` / `undoOverride` /
  // `redoOverride` callbacks need to reach them — so the callbacks
  // dereference these refs at invocation time (always after first
  // render). Initial values are no-op stubs so a stray fire during
  // the first render is safe.
  const scheduleSnapRef = useRef<(mode: 'commit' | 'replace' | 'reset') => void>(() => {});
  const fullHistoryRef = useRef<ReturnType<typeof useSurfaceHistory> | null>(null);
  const applyRef = useRef<(snap: string) => void>(() => {});
  // `showBlockingToast` (declared near `computeBlockingReason`) needs
  // to drive a variant switch when the failing element lives on an
  // inactive variant, but `handleSwitchVariant` is declared further
  // down. Bridge them via this ref so neither has to be hoisted.
  const switchVariantRef = useRef<((variantId: string) => void) | null>(null);
  // Page-level full-surface undo/redo ring buffer is hoisted above
  // the builder so its `canUndo` / `canRedo` flags can drive the
  // builder's toolbar override flags in the same render. The
  // scheduleSnap / applySnapshot handlers are still constructed
  // below (they need `buildPayload` etc.) and reach back via the
  // forward refs above.
  const fullHistory = useSurfaceHistory();
  fullHistoryRef.current = fullHistory;
  const builder = useSurfaceBuilder<DetailBuilderState>(
    {
      nodes: [],
      selectedNodeId: null,
    },
    {
      getSurfaceSize: () =>
        surfaceSizeRef.current
          ? { width: surfaceSizeRef.current.w, height: surfaceSizeRef.current.h }
          : null,
      getCanvasView: () => canvasViewRef.current,
      getProtocol: () => protocol,
      // Page-level full-surface ring buffer drives undo/redo. The
      // inner `useHistory` past/future stacks are dead code in this
      // hook instance — the page captures a snapshot of the full
      // surface (payload + variants + active id + meta) after every
      // commit and walks that buffer via the keyboard overrides
      // below.
      onCommit: () => scheduleSnapRef.current('commit'),
      undoOverride: () => {
        const s = fullHistoryRef.current?.undo();
        if (s) applyRef.current(s);
      },
      redoOverride: () => {
        const s = fullHistoryRef.current?.redo();
        if (s) applyRef.current(s);
      },
      canUndoOverride: fullHistory.canUndo,
      canRedoOverride: fullHistory.canRedo,
    }
  );
  const {
    setState,
    buildPayload,
    hasValidationErrors,
    hasIncompleteNodes,
    hasDependencyErrors,
    dependencyErrors,
    replaceCommit,
    bumpExternalRevision,
    bumpResetView,
  } = builder;

  // Per-variant canvas snapshot manager. Hydrates from
  // `payload.variants[]` on load, swaps the canvas state when the
  // user picks a different variant in the widget dropdown, and
  // produces the `variants[]` wire slice on save.
  const variantSnapshots = useVariantSnapshots();
  // Pull stable callback references out so effects/useCallbacks can
  // depend on them without re-firing on every snapshot state change
  // (the hook's return object is fresh per render via useMemo).
  const {
    hydrateFromPayload: hydrateVariants,
    switchVariant: switchVariantFn,
    setCatalog,
    setSnapshot: setVariantSnapshot,
    buildVariantsWireSlice,
    getSnapshot: getVariantSnapshot,
  } = variantSnapshots;

  // ---- Page-level full-surface undo / redo ring buffer ----------------
  //
  // Captures a JSON-serialised snapshot of the FULL surface (wire
  // payload with all variants, the active variant id, and the
  // meta-form fields) at every meaningful boundary (canvas edit,
  // variant switch, variant add, save, etc). Undo / redo pop a
  // snapshot off the ring and apply it wholesale via `applySnapshot`
  // — which restores meta, re-hydrates per-variant snapshots,
  // re-points the active variant, and rebuilds the canvas nodes.
  //
  // The capture is deferred to a useEffect on `snapRev` so the
  // snapshot reads post-render state (refs and the live closure of
  // `buildPayload` / `variantSnapshots`). The builder's `onCommit`
  // and the page's load/save/variant-switch handlers all funnel
  // through `scheduleSnap(mode)` which bumps the reducer. The
  // `fullHistory` hook itself is constructed above the builder so
  // its `canUndo` / `canRedo` flags can drive the builder's toolbar.
  const [snapRev, bumpSnap] = useReducer((x: number) => x + 1, 0);
  const snapModeRef = useRef<'commit' | 'replace' | 'reset' | null>(null);
  const scheduleSnap = useCallback((mode: 'commit' | 'replace' | 'reset') => {
    snapModeRef.current = mode;
    bumpSnap();
  }, []);
  scheduleSnapRef.current = scheduleSnap;

  /**
   * Round-trip a stored snapshot through the same `buildPayload`
   * pipeline the live canvas uses. Without this, baseline snapshots
   * (server-shape JSON) disagree with subsequent live-spliced
   * payloads (buildPayload-shape) on fields the builder normalises
   * (e.g. identity_slots.*.type "payload_extraction" -> "from_payload",
   * default-valued booleans omitted, server-only fields stripped).
   * The mismatch flips dirty whenever a variant switch shifts which
   * slot is the "live" one. Normalising every stored snapshot at
   * hydrate time makes all entries share one canonical shape.
   */
  const normalizeSnapshot = useCallback((snap: any, surfaceMeta: AgentSurface): any => {
    const hydration = hydrateSurfaceCanvas(snap as AgentSurface);
    const nodes = hydration.nodes;
    const payload: any = registry.buildPayload({
      protocol: (surfaceMeta.access_point?.protocol as Protocol) || 'a2a',
      surfaceMeta: {
        ...(surfaceMeta.surface_id ? { surface_id: surfaceMeta.surface_id } : {}),
        name: surfaceMeta.name,
        ...(surfaceMeta.description ? { description: surfaceMeta.description } : {}),
        tags: surfaceMeta.tags || [],
        ...(surfaceMeta.issuer_id ? { issuer_id: surfaceMeta.issuer_id } : {}),
        status: surfaceMeta.status ?? 'active',
      },
      allNodes: nodes,
      nodesOfType: type => nodes.filter(n => n.type === type),
      firstNodeOfType: type => nodes.find(n => n.type === type),
    });
    const savedSize = hydration.surfaceSize;
    const savedView = hydration.view;
    payload.canvas = buildCanvasBlob(nodes, {
      surfaceSize: savedSize ?? undefined,
      view: savedView ?? undefined,
    });
    if (payload.access_point) {
      payload.access_point.publish_to_did_document =
        surfaceMeta.access_point?.publish_to_did_document ?? false;
      payload.access_point.terminate_trace_id =
        surfaceMeta.access_point?.terminate_trace_id ?? false;
      const did = (surfaceMeta as any).access_point?.didwebvh_identity;
      if (did && typeof did === 'object') {
        payload.access_point.didwebvh_identity = did;
      }
    }
    return payload;
  }, []);

  /**
   * Serialise the FULL surface (wire payload with all variants +
   * active variant id + page meta fields) into a single string for
   * the history ring buffer. Mirrors `handleSave`'s payload assembly
   * so an undo applies the exact shape a save would have persisted.
   */
  const captureSnapshot = useCallback((): string => {
    let wirePayload: Partial<AgentSurface>;
    try {
      const activePayload = buildPayload({
        surface_id: surfaceId,
        name,
        description,
        tags: tagsCsv
          .split(',')
          .map(t => t.trim())
          .filter(Boolean),
        protocol,
        status,
      }) as Partial<AgentSurface>;
      if (activePayload.access_point) {
        activePayload.access_point.publish_to_did_document = publishToDid;
        activePayload.access_point.terminate_trace_id = terminateTraceId;
        writeDidwebvhToAccessPoint(activePayload.access_point, didwebvh);
      }
      if (variantSnapshots.hasVariants) {
        const wire = buildVariantsWireSlice(activePayload);
        const base = wire.basePayload ?? activePayload;
        wirePayload = {
          ...base,
          variants: wire.variants,
          ...(wire.defaultVariantId ? { default_variant_id: wire.defaultVariantId } : {}),
        } as Partial<AgentSurface>;
      } else {
        wirePayload = activePayload;
      }
    } catch {
      // buildPayload should never throw during normal editing; if it
      // does, return empty so the scheduler skips the commit instead
      // of poisoning the history with a partial state.
      return '';
    }
    return JSON.stringify({
      payload: wirePayload,
      activeVariantId: variantSnapshots.activeVariantId ?? BASE_VARIANT_ID,
      meta: {
        name,
        description,
        tagsCsv,
        status,
        protocol,
        publishToDid,
        terminateTraceId,
        issuerId,
        didwebvh,
      },
    });
  }, [
    buildPayload,
    surfaceId,
    name,
    description,
    tagsCsv,
    protocol,
    status,
    publishToDid,
    terminateTraceId,
    issuerId,
    didwebvh,
    variantSnapshots,
    buildVariantsWireSlice,
  ]);
  const captureRef = useRef(captureSnapshot);
  captureRef.current = captureSnapshot;

  /**
   * Restore a snapshot string produced by `captureSnapshot`. Applies
   * page meta first, re-points `canvasActiveVariantRef` up-front so
   * the variant-watcher effect treats the imminent activeVariantId
   * change as in-progress, then rehydrates the per-variant snapshot
   * manager, splices the live target-variant catalog back in, and
   * pushes the resolved nodes + canvas dimensions into builder state.
   * Does NOT call `commit`/`replaceCommit` — `setState` updates the
   * canvas without re-entering the history pipeline, which preserves
   * the redo stack across an undo.
   */
  const applySnapshot = useCallback(
    (snapStr: string) => {
      let snap: any;
      try {
        snap = JSON.parse(snapStr);
      } catch {
        return;
      }
      const { payload, activeVariantId, meta } = snap;
      if (!payload || !meta) {
        return;
      }
      setName(meta.name);
      setDescription(meta.description);
      setTagsCsv(meta.tagsCsv);
      setStatus(meta.status);
      setProtocol(meta.protocol);
      setPublishToDid(meta.publishToDid);
      setTerminateTraceId(meta.terminateTraceId);
      setIssuerId(meta.issuerId);
      setDidwebvh(meta.didwebvh ?? DEFAULT_DIDWEBVH_CONFIG);
      // Mark the canvas as already showing the target variant BEFORE
      // we trigger any state change, so the activeVariantId-watcher
      // useEffect short-circuits on the redundant id.
      canvasActiveVariantRef.current = activeVariantId;
      const { activePayload } = hydrateVariants(payload as AgentSurface, {
        preserveActiveId: activeVariantId,
      });
      const sourcePayload = (activePayload ?? payload) as any;
      // Splice the un-resolved payload's `target-variant` config back
      // onto the resolved nodes — the resolved payload intentionally
      // strips the surface-level catalog so it can't resurrect
      // variants the user just deleted, but the canvas needs the
      // live catalog to render the variants widget.
      const catalogTv = nodesFromSurface(payload as AgentSurface).find(
        n => n.id === 'target-variant'
      );
      const hydration = hydrateSurfaceCanvas(sourcePayload as AgentSurface);
      const baseNodes = hydration.nodes;
      const finalNodes = catalogTv
        ? baseNodes.map(n => (n.id === 'target-variant' ? catalogTv : n))
        : baseNodes;
      const savedSize = hydration.surfaceSize;
      if (savedSize) {
        surfaceSizeRef.current = { w: savedSize.width, h: savedSize.height };
      }
      const savedView = hydration.view;
      canvasViewRef.current = savedView ?? null;
      setState(prev => ({
        ...prev,
        nodes: finalNodes,
        selectedNodeId: null,
        surfaceSize: savedSize ? { w: savedSize.width, h: savedSize.height } : prev.surfaceSize,
      }));
      bumpExternalRevision();
      if (hydration.didAutoLayout) bumpResetView();
    },
    [hydrateVariants, setState, bumpExternalRevision, bumpResetView]
  );
  applyRef.current = applySnapshot;

  /**
   * Live-apply a user-pasted/edited AgentSurface payload from the
   * Config tab to the canvas. Synthesises the snapshot shape that
   * `applySnapshot` expects so all the meta + variants + node
   * rebuilding paths are reused. Returns `null` on success or an error
   * string surfaced inline by the editor.
   */
  const applyJsonPayloadToCanvas = useCallback(
    (payload: any): string | null => {
      if (!payload || typeof payload !== 'object') return 'Payload must be a JSON object';
      if (!payload.access_point || typeof payload.access_point !== 'object') {
        return 'Payload is missing an access_point';
      }
      const dupErr = findDuplicateListenerRoutes(payload);
      if (dupErr) return dupErr;
      const tags = Array.isArray(payload.tags) ? payload.tags : [];
      // Only touch `name` when the payload actually carries the key.
      // Full-template apply deletes it so we preserve whatever the
      // user has already typed.
      const nextName =
        'name' in payload ? (typeof payload.name === 'string' ? payload.name : '') : name;
      const meta = {
        name: nextName,
        description: typeof payload.description === 'string' ? payload.description : '',
        tagsCsv: tags.join(', '),
        status: payload.status ?? status,
        protocol: (payload.access_point?.protocol as Protocol) || protocol,
        publishToDid: payload.access_point?.publish_to_did_document ?? false,
        terminateTraceId: payload.access_point?.terminate_trace_id ?? false,
        issuerId: typeof payload.issuer_id === 'string' ? payload.issuer_id : '',
        didwebvh: didwebvhFromAccessPoint(payload.access_point),
      };
      const activeVariantId =
        typeof payload.default_variant_id === 'string' && payload.default_variant_id
          ? payload.default_variant_id
          : BASE_VARIANT_ID;
      try {
        applySnapshot(JSON.stringify({ payload, activeVariantId, meta }));
      } catch (err: any) {
        return err?.message || 'Failed to apply payload';
      }
      return null;
    },
    [applySnapshot, status, protocol]
  );

  /**
   * Effect: dispatch a pending history snapshot operation after React
   * has flushed the state updates from the action that triggered it.
   * `scheduleSnap(mode)` sets `snapModeRef` + bumps `snapRev`; this
   * effect picks up the bump, calls `captureSnapshot()` against the
   * now-fresh state, and writes into the page-level history.
   */
  useEffect(() => {
    if (snapRev === 0 || !snapModeRef.current) return;
    const snap = captureRef.current();
    const mode = snapModeRef.current;
    snapModeRef.current = null;
    if (!snap) return;
    if (mode === 'commit') fullHistoryRef.current?.commit(snap);
    else if (mode === 'replace') fullHistoryRef.current?.replaceCommitted(snap);
    else if (mode === 'reset') fullHistoryRef.current?.reset(snap);
  }, [snapRev]);

  const load = useCallback(async () => {
    if (!surfaceId) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getSurface(surfaceId);
      setSurface(data);
      setName(data.name);
      setDescription(data.description || '');
      setTagsCsv((data.tags || []).join(', '));
      setStatus(data.status);
      setProtocol((data.access_point?.protocol as Protocol) || 'a2a');
      setPublishToDid(data.access_point?.publish_to_did_document ?? false);
      setTerminateTraceId(data.access_point?.terminate_trace_id ?? false);
      setIssuerId(data.issuer_id || '');
      setDidwebvh(didwebvhFromAccessPoint(data.access_point));
      setJsonOverride(null);
      setJsonError(null);
      // Hydrate the per-variant snapshot manager from the wire payload.
      // When the surface has variants we render the active variant's
      // resolved payload on the canvas; otherwise fall back to the
      // bare surface payload (single-variant / legacy surfaces).
      const { activePayload, activeId } = hydrateVariants(data);
      // Capture this before normalization serializes the generated
      // positions into the snapshot and makes later hydration appear
      // fully positioned. The fit request can safely fire before the
      // loading spinner releases the canvas because its handled cursor
      // lives in the builder hook and survives the canvas mount.
      const activeNeededAutoLayout = hydrateSurfaceCanvas(activePayload ?? data).didAutoLayout;
      // Normalise every stored snapshot to buildPayload shape so the
      // dirty signature stays symmetric across variant switches (see
      // normalizeSnapshot doc).
      const allIds = [
        BASE_VARIANT_ID,
        ...(Array.isArray((data as any).variants)
          ? (data as any).variants.map((v: any) => String(v.id))
          : []),
      ];
      for (const id of allIds) {
        const snap = getVariantSnapshot(id);
        if (snap) {
          // Two passes: the second iteration reaches a fixed point
          // for the canvas-blob node configs (the first pass leaves
          // node.config still in disk shape because nodes were
          // built from the raw snap; the second pass rebuilds nodes
          // from the already-normalized payload).
          const once = normalizeSnapshot(snap, data);
          setVariantSnapshot(id, normalizeSnapshot(once, data));
        }
      }
      const normalizedActive = getVariantSnapshot(activeId ?? BASE_VARIANT_ID);
      canvasActiveVariantRef.current = activeId;
      // Re-seed the known-ids tracker from the freshly loaded
      // catalog so the auto-switch-on-add effect doesn't fire for
      // variants that arrived via load (only for ones the user
      // genuinely just added).
      knownVariantIdsRef.current = new Set(
        Array.isArray(data.variants) ? data.variants.map((v: any) => String(v.id)) : []
      );
      const canvasSource = normalizedActive ?? activePayload ?? data;
      // Re-attach surface-level catalog fields (`variants` /
      // `default_variant_id`) onto the per-variant snapshot before
      // rebuilding nodes. `resolveVariant` strips them from snapshots
      // (they belong to the surface, not to a variant view), so
      // without this the `target-variant` node would rebuild with an
      // empty catalog and the sync-from-nodes effect would wipe the
      // snapshot manager's variants list — making every saved variant
      // disappear on reload.
      const nodesSource = {
        ...canvasSource,
        ...(Array.isArray((data as any).variants) && (data as any).variants.length > 0
          ? { variants: (data as any).variants }
          : {}),
        ...((data as any).default_variant_id
          ? { default_variant_id: (data as any).default_variant_id }
          : {}),
      };
      const hydration = hydrateSurfaceCanvas(nodesSource);
      const loadedNodes = hydration.nodes;
      // Read canvas dimensions + view from the resolved active-variant
      // payload (not from the bare surface) so per-variant overrides
      // win on initial load — otherwise reloading a surface always
      // shows the base variant's surface size / pan / zoom regardless
      // of which variant is active.
      const savedSize = hydration.surfaceSize;
      if (savedSize) {
        surfaceSizeRef.current = { w: savedSize.width, h: savedSize.height };
      }
      const savedView = hydration.view;
      canvasViewRef.current = savedView ?? null;
      setState(prev => ({
        ...prev,
        nodes: loadedNodes,
        selectedNodeId: null,
        surfaceSize: savedSize ? { w: savedSize.width, h: savedSize.height } : prev.surfaceSize,
      }));
      // Trigger an async rebaseline once React has flushed the
      // variantSnapshots state updates from `hydrateVariants` — see
      // `rebaselineDirty` effect below.
      setRebaselineDirty(n => n + 1);
      // Replace the baseline history snapshot in-place with the
      // freshly loaded state so the empty initial nodes never enter
      // the past stack — otherwise an immediate undo would pop the
      // empty placeholder and visually wipe the canvas.
      replaceCommit();
      // Reset the page-level full-surface ring buffer so undo cannot
      // walk past the freshly loaded baseline (load is a fresh
      // start; the user expects no history before the first edit).
      scheduleSnap('reset');
      // Force config panels with local useState to remount and
      // resync from the freshly loaded config props.
      bumpExternalRevision();
      if (activeNeededAutoLayout || hydration.didAutoLayout) bumpResetView();
    } catch (err: any) {
      setError(err.message || 'Failed to load surface');
    } finally {
      setLoading(false);
    }
  }, [
    surfaceId,
    setState,
    replaceCommit,
    bumpExternalRevision,
    bumpResetView,
    hydrateVariants,
    getVariantSnapshot,
    setVariantSnapshot,
    normalizeSnapshot,
    scheduleSnap,
  ]);

  useEffect(() => {
    load();
  }, [load]);

  // Sync the variant catalog (variants list + default) from the
  // target-variant node's config back into the snapshot manager
  // whenever the user edits the variants panel. The panel is the
  // single source of truth for variant identity (id/alias/name/
  // default flag); the snapshot manager owns the per-variant
  // canvas state. Both must agree on the catalog shape.
  //
  // IMPORTANT: depend on the stable `setCatalog` reference, NOT the
  // whole `variantSnapshots` object — the latter gets a fresh
  // identity on every render via its internal `useMemo`, which
  // would re-fire this effect → setCatalog → re-render → loop.
  useEffect(() => {
    const node = builder.state.nodes.find(n => n.type === 'target-variant');
    const cfg: any = node?.config ?? {};
    const list: any[] = Array.isArray(cfg.variants) ? cfg.variants : [];
    const variants = list.map(v => ({
      id: String(v.id),
      alias: String(v.alias ?? ''),
      name: String(v.name ?? ''),
      ...(v.description ? { description: String(v.description) } : {}),
      enabled: v.enabled !== false,
    }));
    const rawDefault =
      typeof cfg.default_variant_id === 'string' && cfg.default_variant_id.length > 0
        ? cfg.default_variant_id
        : (list.find(v => v.is_default)?.id ?? null);
    // Drop a stale default that no longer matches any variant in the
    // catalog (e.g. variant was deleted/replaced but the node config
    // still carries the old id). The backend rejects unmatched
    // default_variant_id with a 400.
    const defaultVariantId =
      rawDefault && variants.some(v => v.id === rawDefault) ? rawDefault : null;
    setCatalog({ variants, defaultVariantId });
  }, [builder.state.nodes, setCatalog]);

  /**
   * Re-render the canvas when `variantSnapshots.activeVariantId` is
   * reassigned by something other than `handleSwitchVariant` — most
   * commonly when the user deletes the active variant in the editor
   * panel and the snapshot hook silently re-points `activeVariantId`
   * to base. Without this, the variants widget jumps to "base" but
   * the canvas keeps showing the deleted variant's nodes.
   *
   * The `canvasActiveVariantRef` mirror is updated by every code path
   * that intentionally renders a variant (initial load, post-save
   * re-hydrate, `handleSwitchVariant`), so this effect is a no-op
   * for those flows and only fires on external reassignment.
   */
  useEffect(() => {
    const active = variantSnapshots.activeVariantId;
    if (active == null) return;
    if (canvasActiveVariantRef.current === active) return;
    const snapshot = getVariantSnapshot(active);
    if (!snapshot) return;
    canvasActiveVariantRef.current = active;
    const hydration = hydrateSurfaceCanvas(snapshot as AgentSurface);
    if (hydration.surfaceSize) {
      surfaceSizeRef.current = {
        w: hydration.surfaceSize.width,
        h: hydration.surfaceSize.height,
      };
    }
    canvasViewRef.current = hydration.view;
    setState(prev => {
      const nextNodes = hydration.nodes;
      // The snapshot intentionally strips the surface-level catalog
      // (`variants[]` / `default_variant_id`) so it can't resurrect
      // a variant the user just deleted. The live `target-variant`
      // node carries the authoritative catalog, so copy its config
      // back onto the rebuilt node.
      const liveTv = prev.nodes.find(n => n.id === 'target-variant');
      const finalNodes = liveTv
        ? nextNodes.map(n => (n.id === 'target-variant' ? { ...n, config: liveTv.config } : n))
        : nextNodes;
      return {
        ...prev,
        nodes: finalNodes,
        selectedNodeId: null,
        surfaceSize: hydration.surfaceSize
          ? { w: hydration.surfaceSize.width, h: hydration.surfaceSize.height }
          : prev.surfaceSize,
      };
    });
    replaceCommit();
    // External activeVariantId reassignment (e.g. user deleted the
    // active variant) is a meaningful state change — push it onto
    // the full-surface history so undo can walk back.
    scheduleSnap('commit');
    bumpExternalRevision();
    if (hydration.didAutoLayout) bumpResetView();
  }, [
    variantSnapshots.activeVariantId,
    getVariantSnapshot,
    setState,
    replaceCommit,
    bumpExternalRevision,
    bumpResetView,
    scheduleSnap,
  ]);

  /**
   * Build a single, user-facing reason explaining why the surface cannot
   * be saved right now. Returns `null` when ready to PUT. Surfaces the
   * first incomplete element's label + reason so the toast matches what
   * the user sees in the Elements tab.
   *
   * Validates EVERY variant snapshot — not just the currently active
   * one — so the user can't sidestep a broken variant by switching
   * away from it before clicking Save. When the offending variant is
   * inactive, the returned `variantId` lets the blocking toast offer
   * a one-click jump to that variant on the canvas.
   */
  const computeBlockingReason = (): {
    message: string;
    nodeId?: string;
    variantId?: string;
  } | null => {
    if (!canEdit) return { message: 'You do not have permission to edit this surface' };
    if (jsonError) {
      return { message: `Fix Config JSON errors before saving: ${jsonError}` };
    }
    const policyDefinitionsReason = surfacePolicyBlockingReason(
      builder.state.nodes,
      surfacePolicyLoadState
    );
    if (policyDefinitionsReason) return { message: policyDefinitionsReason };
    const firstIncomplete = builder.state.nodes.find(
      n => !n.configured || getIncompleteReason(n.type, n.config, surfacePolicyIds) !== null
    );
    if (firstIncomplete) {
      const def = registry.get(firstIncomplete.type);
      const reason =
        getIncompleteReason(firstIncomplete.type, firstIncomplete.config, surfacePolicyIds) ||
        'configuration is incomplete';
      return {
        message: `${def?.label ?? firstIncomplete.type}: ${reason}`,
        nodeId: firstIncomplete.id,
      };
    }
    // Unmet feature dependencies (e.g. credential-delegation without
    // source auth on the surface). Block save so the runtime never
    // sees a half-wired surface — the marching-ants ring on the
    // canvas points the user at the offending node.
    const firstDepErr = dependencyErrors[0];
    if (firstDepErr) {
      const def = registry.get(firstDepErr.nodeType);
      return {
        message: `${def?.label ?? firstDepErr.nodeType}: ${firstDepErr.message}`,
        nodeId: firstDepErr.nodeId,
      };
    }
    // Structural validation of the assembled payload — catches shape
    // problems that only surface once individual element slices are
    // stitched together (empty surface name, dangling parents, etc).
    // Error-severity issues block save; warnings are surfaced after a
    // successful save so they don't gate the user.
    try {
      const draftPayload = buildPayload({
        surface_id: surfaceId,
        name,
        description,
        tags: tagsCsv
          .split(',')
          .map(t => t.trim())
          .filter(Boolean),
        protocol,
        status,
      });
      const issues = validateSurfacePayload(draftPayload);
      const firstError = issues.find(i => i.severity === 'error');
      if (firstError) {
        return { message: firstError.message, nodeId: firstError.nodeId };
      }
      // Also validate every INACTIVE variant snapshot. Without this,
      // the user can park on a clean variant and save while one of
      // the others carries an error — the wire payload would then
      // round-trip the broken overrides untouched. `getVariantSnapshot`
      // returns the last resolved payload for each id; for the active
      // variant we already used the live `draftPayload` above.
      const activeId = variantSnapshots.activeVariantId ?? BASE_VARIANT_ID;
      const ids: string[] = [BASE_VARIANT_ID, ...variantSnapshots.variants.map(v => v.id)];
      for (const vid of ids) {
        if (vid === activeId) continue;
        const snap = getVariantSnapshot(vid);
        if (!snap) continue;
        const label =
          vid === BASE_VARIANT_ID
            ? 'base'
            : variantSnapshots.variants.find(v => v.id === vid)?.name ||
              variantSnapshots.variants.find(v => v.id === vid)?.alias ||
              vid;
        // Per-node incomplete check on the variant's canvas nodes —
        // mirrors what the Elements tab shows on the active variant
        // so a broken inactive variant can't sneak past save just
        // because it isn't currently rendered.
        try {
          const snapNodes = nodesFromSurface(snap as AgentSurface);
          const snapshotPolicyDefinitionsReason = surfacePolicyBlockingReason(
            snapNodes,
            surfacePolicyLoadState
          );
          if (snapshotPolicyDefinitionsReason) {
            return {
              message: `Variant "${label}" — ${snapshotPolicyDefinitionsReason}`,
              variantId: vid,
            };
          }
          const incomplete = snapNodes.find(
            n => getIncompleteReason(n.type, n.config, surfacePolicyIds) !== null
          );
          if (incomplete) {
            const def = registry.get(incomplete.type);
            const reason =
              getIncompleteReason(incomplete.type, incomplete.config, surfacePolicyIds) ||
              'configuration is incomplete';
            return {
              message: `Variant "${label}" — ${def?.label ?? incomplete.type}: ${reason}`,
              nodeId: incomplete.id,
              variantId: vid,
            };
          }
        } catch {
          // Falling through to the structural check below is fine —
          // a payload `nodesFromSurface` can't decode will trip the
          // structural validator anyway.
        }
        const variantIssues = validateSurfacePayload(snap);
        const variantErr = variantIssues.find(i => i.severity === 'error');
        if (variantErr) {
          return {
            message: `Variant "${label}": ${variantErr.message}`,
            nodeId: variantErr.nodeId,
            variantId: vid,
          };
        }
      }
    } catch {
      // buildPayload should not throw; if it ever does, surface it as
      // a structural error so the user isn't silently blocked.
      return { message: 'Could not assemble surface payload — check the canvas for errors.' };
    }
    return null;
  };

  const showBlockingToast = (blocking: {
    message: string;
    nodeId?: string;
    variantId?: string;
  }) => {
    // When the failing element lives on an inactive variant, the
    // "Show me" action first switches the canvas to that variant
    // (via the ref, since `handleSwitchVariant` is declared below)
    // and then selects the node so the user lands on the exact slot
    // with the error highlighted.
    const hasJump = !!blocking.nodeId || !!blocking.variantId;
    showToast('error', blocking.message, {
      autoRemove: true,
      duration: 8000,
      action: hasJump
        ? {
            label: 'Show me',
            onClick: () => {
              setActiveTab('surface');
              if (
                blocking.variantId &&
                blocking.variantId !== (variantSnapshots.activeVariantId ?? BASE_VARIANT_ID)
              ) {
                switchVariantRef.current?.(blocking.variantId);
              }
              if (blocking.nodeId) {
                builder.handleNodeClick(blocking.nodeId);
              }
            },
          }
        : undefined,
    });
  };

  /**
   * Switch the canvas to a different variant. Snapshots the current
   * canvas payload into the active variant slot, then resolves the
   * target variant's payload (default + overrides) and rebuilds the
   * canvas nodes from it.
   */
  const handleSwitchVariant = useCallback(
    (newVariantId: string) => {
      const currentPayload = buildPayload({
        surface_id: surfaceId,
        name,
        description,
        tags: tagsCsv
          .split(',')
          .map(t => t.trim())
          .filter(Boolean),
        protocol,
        status,
      }) as Partial<AgentSurface>;
      if (currentPayload.access_point) {
        currentPayload.access_point.publish_to_did_document = publishToDid;
        currentPayload.access_point.terminate_trace_id = terminateTraceId;
        writeDidwebvhToAccessPoint(currentPayload.access_point, didwebvh);
      }
      const nextPayload = switchVariantFn(newVariantId, currentPayload);
      const hydration = hydrateSurfaceCanvas(nextPayload as AgentSurface);
      const nextNodes = hydration.nodes;
      // Per-variant surface dimensions live in `canvas.surface` — pull
      // them out so switching variants restores the saved size of the
      // newly-active variant (positions/view already round-trip via
      // the canvas blob, but the size is also read separately by the
      // SurfaceCanvas size effect and must be propagated explicitly).
      const nextSize = hydration.surfaceSize;
      // Same for the pan/zoom view: `canvasViewRef` is read by
      // `buildPayload` (via `getCanvasView`) to populate the live
      // `canvas.view` on every render. If we leave it pointing at the
      // OUTGOING variant's view, the next signature() build emits a
      // canvas.view that doesn't match the new active variant's
      // stored snapshot — flipping dirty on a pure variant switch.
      const nextView = hydration.view;
      canvasViewRef.current = nextView ?? null;
      canvasActiveVariantRef.current = newVariantId;
      setState(prev => {
        // Preserve the live `target-variant` node config (the
        // authoritative variants catalog) across the swap — the
        // snapshot the new payload was rebuilt from intentionally
        // strips the catalog to avoid stale-list contamination.
        const liveTv = prev.nodes.find(n => n.id === 'target-variant');
        const finalNodes = liveTv
          ? nextNodes.map(n => (n.id === 'target-variant' ? { ...n, config: liveTv.config } : n))
          : nextNodes;
        return {
          ...prev,
          nodes: finalNodes,
          selectedNodeId: null,
          surfaceSize: nextSize ? { w: nextSize.width, h: nextSize.height } : prev.surfaceSize,
        };
      });
      if (nextSize) {
        surfaceSizeRef.current = { w: nextSize.width, h: nextSize.height };
      }
      replaceCommit();
      // Variant switch is undoable — push the post-switch state onto
      // the page-level ring buffer. The PRIOR `committed` (the
      // pre-switch active variant's state) gets promoted to `past`,
      // so undo restores it and `applySnapshot` will auto-switch the
      // canvas back to the original variant.
      scheduleSnap('commit');
      bumpExternalRevision();
      if (hydration.didAutoLayout) bumpResetView();
    },
    [
      buildPayload,
      surfaceId,
      name,
      description,
      tagsCsv,
      protocol,
      status,
      publishToDid,
      terminateTraceId,
      didwebvh,
      switchVariantFn,
      setState,
      replaceCommit,
      bumpExternalRevision,
      bumpResetView,
      scheduleSnap,
    ]
  );

  // Keep a ref to `handleSwitchVariant` so `showBlockingToast` (which
  // is declared above the callback to live next to `computeBlockingReason`)
  // can drive a variant switch from the blocking toast's "Show me"
  // action without a forward-declaration cycle.
  switchVariantRef.current = handleSwitchVariant;

  /**
   * Seed a new variant on the target-variant node and open the panel
   * so it lands ready for the user to rename. Wired to the variants
   * widget's zero-state "+" button (and to the dropdown's "Add" item
   * once that lands).
   */
  const handleAddVariant = useCallback(() => {
    let createdId: string | null = null;
    setState(prev => {
      const node = prev.nodes.find(n => n.id === 'target-variant');
      const cfg: any = node?.config ?? {};
      const list: any[] = Array.isArray(cfg.variants) ? cfg.variants : [];
      // Pre-fill alias as `alias1`, `alias2`, ... skipping any already
      // in use, mirroring TargetVariantPanel.handleAdd so the flow is
      // identical regardless of entry point.
      const used = new Set(list.map(v => String(v.alias ?? '').toLowerCase()));
      let n = list.length + 1;
      while (used.has(`alias${n}`)) n += 1;
      const id =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? crypto.randomUUID()
          : `v-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
      createdId = id;
      const newVariant = { id, name: `alias${n}`, alias: `alias${n}`, enabled: true };
      const nextList = [...list, newVariant];
      // Adding never changes the default — base remains the implicit
      // default until the user explicitly promotes a named variant
      // from the panel.
      const nextCfg = { ...cfg, variants: nextList };
      const nextNodes = node
        ? prev.nodes.map(no =>
            no.id === 'target-variant' ? { ...no, config: nextCfg, configured: true } : no
          )
        : prev.nodes;
      return { ...prev, nodes: nextNodes, selectedNodeId: 'target-variant' };
    });
    // Switch the canvas to the brand-new variant so the user can
    // immediately start editing its layout. The new variant inherits
    // the current (active) canvas as its starting state — exactly
    // what the user sees right now — and `handleSwitchVariant`
    // snapshots the outgoing variant under its old id before the
    // swap, so no in-flight edits are lost. Falls back gracefully
    // when `setState` somehow didn't assign a new id (defensive).
    if (createdId) {
      handleSwitchVariant(createdId);
      // `handleSwitchVariant` clears the selection — re-open the
      // variants editor panel so the user lands on a ready-to-edit
      // entry for the freshly created variant. Without this re-
      // selection the floating "+" affordance silently swaps the
      // canvas but never surfaces the panel for naming.
      setState(prev => ({ ...prev, selectedNodeId: 'target-variant' }));
    }
    replaceCommit();
    // Adding a variant is undoable — push the post-add state. The
    // prior `committed` (state without the new variant) becomes the
    // top of `past`, so undo cleanly removes the just-added variant.
    scheduleSnap('commit');
    bumpExternalRevision();
  }, [setState, replaceCommit, bumpExternalRevision, handleSwitchVariant, scheduleSnap]);

  /**
   * Auto-switch to a freshly-added variant when it shows up in the
   * catalog. Covers the in-panel "Add variant" button (which writes
   * straight through `updateFields` and never calls `handleAddVariant`)
   * — without this the user adds a variant in the editor panel but
   * the canvas stays on whatever was active, defeating the "added a
   * variant → see and edit it" expectation.
   *
   * The `knownVariantIdsRef` mirror is seeded by `load` so this
   * effect is silent for variants that arrived via initial hydration.
   */
  useEffect(() => {
    const known = knownVariantIdsRef.current;
    const currentIds = variantSnapshots.variants.map(v => v.id);
    if (known === null) {
      knownVariantIdsRef.current = new Set(currentIds);
      return;
    }
    const fresh = currentIds.filter(id => !known.has(id));
    knownVariantIdsRef.current = new Set(currentIds);
    // Switch only when exactly one new variant appeared (the typical
    // "user clicked Add" flow). Multi-add (e.g. paste-import) leaves
    // the active selection alone — there's no good single answer.
    if (fresh.length === 1) {
      handleSwitchVariant(fresh[0]);
      // Open the variants editor panel so the missing-name/alias
      // banner is visible and the user can finish the entry. The
      // in-panel "Add" path already has the panel open; the floating
      // widget's "+" path opens it via `handleAddVariant`. Setting
      // it again here is idempotent in both cases.
      setState(prev => ({ ...prev, selectedNodeId: 'target-variant' }));
    }
  }, [variantSnapshots.variants, handleSwitchVariant, setState]);

  const handleSave = async () => {
    if (!surfaceId || !surface) return;
    setHasAttemptedSave(true);
    const blocking = computeBlockingReason();
    if (blocking) {
      showBlockingToast(blocking);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      let payload: Partial<AgentSurface>;
      {
        const activePayload = buildPayload({
          surface_id: surfaceId,
          name,
          description,
          tags: tagsCsv
            .split(',')
            .map(t => t.trim())
            .filter(Boolean),
          protocol,
          status,
        }) as Partial<AgentSurface>;
        if (activePayload.access_point) {
          activePayload.access_point.publish_to_did_document = publishToDid;
          activePayload.access_point.terminate_trace_id = terminateTraceId;
          writeDidwebvhToAccessPoint(activePayload.access_point, didwebvh);
        }
        // When the surface has variants, the wire payload's base
        // AgentSurface fields come from the DEFAULT variant's snapshot
        // (not the active variant's). Each non-default variant gets
        // an `overrides` slice computed from its snapshot.
        if (variantSnapshots.hasVariants) {
          const wire = buildVariantsWireSlice(activePayload);
          const base = wire.basePayload ?? activePayload;
          // Top-level payload.canvas must come from the BASE snapshot
          // (not activePayload) — otherwise every variant's view
          // collapses onto the active variant's layout after save,
          // because the backend uses top-level canvas for base/null
          // variant resolution and overrides for named variants.
          // The active variant's fresh canvas is already captured
          // inside `wire.variants[active].overrides.canvas` by
          // `buildVariantsWireSlice` (it splices activePayload into
          // the snapshot map under activeVariantId before deriving
          // overrides).
          payload = {
            ...base,
            variants: wire.variants,
            ...(wire.defaultVariantId ? { default_variant_id: wire.defaultVariantId } : {}),
          } as Partial<AgentSurface>;
        } else {
          payload = activePayload;
        }
      }
      payload.surface_id = surfaceId;
      payload.name = name;
      payload.description = description;
      payload.tags = tagsCsv
        .split(',')
        .map(t => t.trim())
        .filter(Boolean);
      payload.status = status;
      payload.issuer_id = issuerId.trim() || undefined;
      const updated = await apiClient.updateSurface(surfaceId, payload);
      setSurface(updated);
      setJsonOverride(null);
      setJsonError(null);
      // Re-hydrate the variant snapshot manager from the saved
      // payload so it picks up any catalog changes (renamed/added/
      // removed variants) and so the canvas reflects the active
      // variant's resolved state. Pass the previously-active variant
      // id as `preserveActiveId` so a save doesn't snap the canvas
      // back to the default variant — the user stays on whatever
      // variant they were editing.
      const { activePayload: postSaveActive, activeId: postSaveActiveId } = hydrateVariants(
        updated,
        { preserveActiveId: variantSnapshots.activeVariantId }
      );
      // Re-normalise every snapshot after save — same reasoning as in
      // `load()`.
      const allIdsPostSave = [
        BASE_VARIANT_ID,
        ...(Array.isArray((updated as any).variants)
          ? (updated as any).variants.map((v: any) => String(v.id))
          : []),
      ];
      for (const id of allIdsPostSave) {
        const snap = getVariantSnapshot(id);
        if (snap) {
          const once = normalizeSnapshot(snap, updated);
          setVariantSnapshot(id, normalizeSnapshot(once, updated));
        }
      }
      const postSaveNormalizedActive = getVariantSnapshot(postSaveActiveId ?? BASE_VARIANT_ID);
      canvasActiveVariantRef.current = postSaveActiveId;
      const updatedSource = postSaveNormalizedActive ?? postSaveActive ?? updated;
      // Read canvas dimensions + view from the resolved active-variant
      // payload (not from the bare surface) so a save while editing a
      // non-base variant doesn't snap the canvas back to base's size /
      // pan / zoom.
      const hydration = hydrateSurfaceCanvas(updatedSource);
      const savedSize = hydration.surfaceSize;
      if (savedSize) {
        surfaceSizeRef.current = { w: savedSize.width, h: savedSize.height };
      }
      const savedView = hydration.view;
      // Note: don't overwrite a non-null ref with null after save —
      // the user may have panned/zoomed since the canvas blob was
      // built, and the live ref already holds the latest transform
      // written by the canvas zoom handler.
      if (savedView) {
        canvasViewRef.current = savedView;
      }
      const updatedNodesRaw = hydration.nodes;
      // `postSaveActive` is the resolved active-variant payload; it
      // intentionally drops the surface-level catalog (`variants[]`
      // / `default_variant_id`). Rebuilding nodes from it alone
      // produces an empty `target-variant` config and silently wipes
      // user-typed names/aliases. Splice the catalog back in from
      // the full server response.
      const catalogTv = nodesFromSurface(updated).find(n => n.id === 'target-variant');
      const updatedNodes = catalogTv
        ? updatedNodesRaw.map(n => (n.id === 'target-variant' ? catalogTv : n))
        : updatedNodesRaw;
      setState(prev => ({
        ...prev,
        nodes: updatedNodes,
        surfaceSize: savedSize ? { w: savedSize.width, h: savedSize.height } : prev.surfaceSize,
      }));
      // Re-baseline dirty tracking from the freshly persisted values so
      // the page stops prompting about "unsaved changes" immediately
      // after a successful save. Done async (see `rebaselineDirty`
      // effect) so React has time to flush the variantSnapshots state
      // updates from the post-save `hydrateVariants` call.
      setRebaselineDirty(n => n + 1);
      // Re-baseline history in-place so a post-save undo doesn't revert
      // past the freshly persisted state, and doesn't leave a stale
      // pre-save snapshot at the top of the past stack.
      replaceCommit();
      // Push the post-save state onto the page-level ring buffer.
      // Crucially this is `commit` (NOT `reset`) — the past stack is
      // preserved so the user can still undo edits made before the
      // save. Future is cleared, matching standard undo semantics.
      scheduleSnap('commit');
      // Force the open config panel (if any) to remount so its local
      // useState (e.g. endpointType, selectedGatewayId) resyncs from
      // the just-saved config — otherwise it visually "resets to
      // defaults" until the user re-clicks the node.
      bumpExternalRevision();
      if (hydration.didAutoLayout) bumpResetView();
      showToast('success', `Agent Surface "${updated.name}" saved`);
      // Surface non-blocking structural warnings AFTER save so the
      // user notices issues like empty target endpoints / unrouted
      // transit points without being prevented from saving. The toast
      // helper only knows success/error/loading, so warnings reuse the
      // error styling — they are real shape problems the user should
      // see, just not severe enough to block the save itself.
      const warnings = validateSurfacePayload(updated).filter(i => i.severity === 'warning');
      for (const w of warnings.slice(0, 3)) {
        showToast('error', `Warning: ${w.message}`, { autoRemove: true, duration: 8000 });
      }
    } catch (err: any) {
      setError(err.message || 'Failed to save surface');
    } finally {
      setSaving(false);
    }
  };

  useSaveShortcut(() => {
    if (saving || deleting || !canEdit) return;
    const blocking = computeBlockingReason();
    if (blocking) {
      showBlockingToast(blocking);
      return;
    }
    handleSave();
  }, builder.commit);

  const handleDelete = async () => {
    if (!surfaceId || !surface) return;
    setDeleting(true);
    setError(null);
    try {
      await apiClient.deleteSurface(surfaceId);
      showToast('success', `Surface "${surface.name}" deleted`);
      navigate('/surfaces');
    } catch (err: any) {
      setError(err.message || 'Failed to delete surface');
      setDeleting(false);
    }
  };

  // Compare the current form + canvas state against the last
  // load/save baseline. Skipped while loading or before the first
  // baseline is captured so we don't prompt on the initial mount.
  // NOTE: must run before any early `return` below to keep hook order
  // stable across renders (React error #310).
  //
  // The canvas/nodes portion of the signature lives inside
  // `variantSnapshots.signature(activeLivePayload)` — we splice the
  // live active variant's payload into the snapshot map so unsaved
  // edits register, while pure variant switches (which do NOT change
  // any snapshot) leave the string untouched.
  const activeLivePayload = buildPayload({
    surface_id: surfaceId,
    name,
    description,
    tags: tagsCsv
      .split(',')
      .map(t => t.trim())
      .filter(Boolean),
    protocol,
    status,
  }) as Partial<AgentSurface>;
  if (activeLivePayload.access_point) {
    activeLivePayload.access_point.publish_to_did_document = publishToDid;
    activeLivePayload.access_point.terminate_trace_id = terminateTraceId;
    writeDidwebvhToAccessPoint(activeLivePayload.access_point, didwebvh);
  }
  const currentSignature = serializeDirtySignature({
    variantsSig: variantSnapshots.signature(activeLivePayload),
    name,
    description,
    tagsCsv,
    status,
    protocol,
    publishToDid,
    terminateTraceId,
    issuerId,
    didwebvh,
    jsonOverride,
  });
  // Keep the latest currentSignature in a ref so the deferred
  // rebaseline (effect below) reads the freshest value rather than
  // the closure-captured one from the render that scheduled it.
  const currentSignatureRef = useRef(currentSignature);
  currentSignatureRef.current = currentSignature;
  // Capture the baseline asynchronously after load/save: by the time
  // this effect fires, React has flushed the variantSnapshots state
  // updates from `hydrateFromPayload`, so the freshest signature
  // (read from `currentSignatureRef`) reflects the persisted truth.
  useEffect(() => {
    if (rebaselineDirty === 0) return;
    baselineRef.current = currentSignatureRef.current;
  }, [rebaselineDirty]);
  // Apply any pending undo-restore AFTER the rebaseline effect above has
  // captured the API state as the clean baseline. React runs effects in
  // declaration order, so this fires after the rebaseline and ensures
  // the restored dirty state is measured against the correct baseline.
  useEffect(() => {
    if (loading) return;
    popPendingRestore();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading]);
  const isDirty =
    !loading &&
    !saving &&
    !deleting &&
    baselineRef.current !== null &&
    baselineRef.current !== currentSignature;
  const { discard, popPendingRestore } = useDiscardWithUndo({
    dirty: isDirty,
    navigateTo: '/surfaces',
    snapshot: {
      storageKey: `surface-draft:${surfaceId}`,
      save: () => captureSnapshot(),
      restore: saved => applyRef.current(saved),
    },
  });
  // One-shot diff logger for debugging spurious dirty flips. Disabled
  // by default — flip `DIRTY_DEBUG` to true to print the first 12 JSON
  // paths where baseline and current signatures disagree. The walker
  // recursively re-parses nested JSON strings (e.g. `variantsSig`) so
  // diffs are reported at the original semantic path.
  const DIRTY_DEBUG = false;
  const wasDirtyRef = useRef(false);
  useEffect(() => {
    if (!DIRTY_DEBUG) {
      wasDirtyRef.current = isDirty;
      return;
    }
    if (isDirty && !wasDirtyRef.current && baselineRef.current) {
      try {
        const a = JSON.parse(baselineRef.current);
        const b = JSON.parse(currentSignature);
        const diffs: string[] = [];
        const tryParse = (s: any): any => {
          if (typeof s !== 'string' || s.length < 2) return s;
          const c = s[0];
          if (c !== '{' && c !== '[') return s;
          try {
            return JSON.parse(s);
          } catch {
            return s;
          }
        };
        const walk = (x: any, y: any, path: string) => {
          if (diffs.length >= 12) return;
          const xp = tryParse(x);
          const yp = tryParse(y);
          if (xp !== x || yp !== y) {
            walk(xp, yp, path);
            return;
          }
          if (typeof x !== typeof y || (x === null) !== (y === null)) {
            diffs.push(`${path}: ${JSON.stringify(x)} -> ${JSON.stringify(y)}`);
            return;
          }
          if (x && typeof x === 'object') {
            if (Array.isArray(x) !== Array.isArray(y)) {
              diffs.push(`${path}: array<->object`);
              return;
            }
            if (Array.isArray(x)) {
              if (x.length !== y.length) {
                diffs.push(`${path}.length: ${x.length} -> ${y.length}`);
              }
              const n = Math.max(x.length, y.length);
              for (let i = 0; i < n; i++) walk(x[i], y[i], `${path}[${i}]`);
              return;
            }
            const keys = Array.from(new Set([...Object.keys(x), ...Object.keys(y)]));
            for (const k of keys) walk(x[k], y[k], `${path}.${k}`);
            return;
          }
          if (x !== y) diffs.push(`${path}: ${JSON.stringify(x)} -> ${JSON.stringify(y)}`);
        };
        walk(a, b, '');
        // eslint-disable-next-line no-console
        console.warn('[dirty-debug] first diffs:\n' + diffs.slice(0, 12).join('\n'));
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[dirty-debug] parse failed', e);
      }
    }
    wasDirtyRef.current = isDirty;
  }, [isDirty, currentSignature, DIRTY_DEBUG]);

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
        }}
      >
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  if (error && !surface) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-circle me-2" />
          {error}
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/surfaces')}>
          <i className="fas fa-arrow-left me-1" /> Back to Surfaces
        </button>
      </div>
    );
  }

  if (!surface) return null;

  const livePayload = (() => {
    try {
      return buildPayload({
        surface_id: surfaceId,
        name,
        description,
        tags: tagsCsv
          .split(',')
          .map(t => t.trim())
          .filter(Boolean),
        protocol,
        status,
      });
    } catch {
      return surface;
    }
  })();
  // Full save-payload shape for the Config tab: the active variant's
  // resolved AgentSurface fields PLUS the catalog of `variants[].overrides`
  // when the surface has variants. This is the single source of truth
  // shown in the editor — what you see is what would be POSTed (and
  // what import/export round-trips through). When there are no
  // variants, `livePayload` already is the wire shape, so nothing to
  // merge.
  const livePayloadWithVariants = (() => {
    if (!variantSnapshots.hasVariants) return livePayload;
    try {
      const wire = buildVariantsWireSlice(livePayload);
      const base = wire.basePayload ?? livePayload;
      return {
        ...base,
        variants: wire.variants,
        ...(wire.defaultVariantId ? { default_variant_id: wire.defaultVariantId } : {}),
      } as any;
    } catch {
      return livePayload;
    }
  })();
  const configEditorValue = jsonOverride ?? JSON.stringify(livePayloadWithVariants, null, 2);

  const policyDefinitionsSaveBlocker = surfacePolicyBlockingReason(
    builder.state.nodes,
    surfacePolicyLoadState
  );
  const saveDisabledReason = jsonError
    ? 'Fix Config JSON errors before saving'
    : policyDefinitionsSaveBlocker
      ? policyDefinitionsSaveBlocker
      : hasValidationErrors
        ? 'Fix element validation errors before saving'
        : hasIncompleteNodes
          ? 'Configure all canvas elements before saving'
          : hasDependencyErrors
            ? 'Resolve element dependency errors before saving'
            : undefined;

  return (
    <div className="container-fluid surface-page-fill">
      <SurfaceFormShell
        mode="edit"
        canEdit={canEdit}
        builder={builder}
        topBanner={
          error ? (
            <div className="alert alert-danger surface-page-alert mb-2" role="alert">
              <i className="fas fa-exclamation-circle me-2" />
              {error}
            </div>
          ) : null
        }
        meta={{
          name,
          description,
          tagsCsv,
          status,
          protocol,
          publishToDid,
          terminateTraceId,
          issuerId,
          didwebvh,
        }}
        setMeta={{
          setName,
          setDescription,
          setTagsCsv,
          setStatus,
          setProtocol,
          setPublishToDid,
          setTerminateTraceId,
          setIssuerId,
          setDidwebvh,
        }}
        jsonOverride={jsonOverride}
        setJsonOverride={setJsonOverride}
        jsonError={jsonError}
        setJsonError={setJsonError}
        configEditorValue={configEditorValue}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        editorTabNodeId={editorTabNodeId}
        onOpenFullscreenEditor={handleOpenFullscreenEditor}
        onCloseFullscreenEditor={handleCloseFullscreenEditor}
        onApplyJsonPayload={applyJsonPayloadToCanvas}
        surfacePolicyLoadState={surfacePolicyLoadState}
        hasAttemptedSave={hasAttemptedSave}
        surfaceId={surface?.surface_id}
        lastActivity={
          // Backend doesn't carry `last_activity` on the surface payload;
          // pull it from runtime channel_stats keyed by surface_id.
          surface?.last_activity ??
          getCurrentStats()?.metrics?.channel_stats?.find(
            cs => cs.channel_config_id === surface?.surface_id
          )?.last_activity ??
          null
        }
        activeVariantId={variantSnapshots.activeVariantId}
        onSwitchVariant={handleSwitchVariant}
        onAddVariant={handleAddVariant}
        manageActions={
          <div className="d-flex gap-2">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={discard}
              disabled={saving || deleting}
              title="Back to surfaces"
            >
              <i className="fas fa-arrow-left" />
            </button>
            {canEdit && (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={handleSave}
                disabled={saving || deleting}
                title={saveDisabledReason || (saving ? 'Saving…' : 'Save changes')}
              >
                {saving ? <i className="fas fa-spinner fa-spin" /> : <i className="fas fa-save" />}
              </button>
            )}
            {canEdit && (
              <DeleteButton
                onDelete={handleDelete}
                disabled={deleting || saving}
                size="sm"
                title="Delete this surface"
              />
            )}
          </div>
        }
        surfaceSizeRef={surfaceSizeRef}
        canvasViewRef={canvasViewRef}
      />
    </div>
  );
};

export default SurfaceDetailPage;
