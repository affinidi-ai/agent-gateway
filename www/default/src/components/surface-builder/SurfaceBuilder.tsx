import React, { useCallback, useMemo, useRef, useState } from 'react';
import SurfaceCanvas from './SurfaceCanvas';
import NodeConfigPanel from './NodeConfigPanel';
import MultiSelectionPanel from './MultiSelectionPanel';
import SurfaceVariantsWidget from './SurfaceVariantsWidget';
import { RouteListenerBanner } from './elements/_shared/RouteListenerSection';
import type { UseSurfaceBuilderReturn, SurfaceBuilderState } from './hooks/useSurfaceBuilder';
import {
  synthesizeFabricCanvasNodes,
  resolveSyntheticNameBinding,
} from './elements/synthesizeFabric';
import { registry } from './elements/registry';

interface SurfaceBuilderProps<T extends SurfaceBuilderState> {
  builder: UseSurfaceBuilderReturn<T>;
  surfaceName: string;
  protocol: string;
  surfacePolicyIds: Set<string> | null;
  /** When true, the panel doesn't render itself when no node is selected. */
  hidePaletteWhenNoSelection?: boolean;
  onOpenFullscreenEditor?: (nodeId: string) => void;
  /**
   * Shared mutable ref tracking the resizable surface rectangle
   * dimensions. When provided, the canvas hydrates from and writes back
   * to it so the page can persist the size in the canvas blob.
   */
  surfaceSizeRef?: React.MutableRefObject<{ w: number; h: number } | null>;
  /**
   * Shared mutable ref tracking the d3 zoom transform (pan + scale).
   * When provided, the canvas hydrates from and writes back to it so
   * the page can persist the view in the canvas blob.
   */
  canvasViewRef?: React.MutableRefObject<{ x: number; y: number; k: number } | null>;
  /**
   * Currently active variant id (when the page hosts a variant
   * snapshot manager). When omitted, the variants widget acts as a
   * plain "open editor" affordance.
   */
  activeVariantId?: string | null;
  /**
   * Switch active variant. The variants widget invokes this when the
   * user picks an entry from its dropdown; the page is responsible for
   * swapping the canvas state via the snapshot manager.
   */
  onSwitchVariant?: (variantId: string) => void;
  /**
   * Open the variants editor AND seed a new variant entry. The widget
   * invokes this from its zero-state "+" affordance and from the
   * dropdown's "Add variant…" item.
   */
  onAddVariant?: () => void;
  /**
   * Called when the user clicks "Create Template from Selection" in
   * the multi-selection panel. Receives the current selected node ids
   * so the shell can build a partial-template seed and switch to the
   * Templates view in create mode.
   */
  onCreateTemplateFromSelection?: (selectedIds: string[]) => void;
  /**
   * Forwarded to NodeConfigPanel. Set to true by the page on first save
   * attempt so panels start error-free and only show validation errors
   * after the user presses Create / Save.
   */
  hasAttemptedSave?: boolean;
}

/**
 * The shared "palette + canvas + sidebar" body used by both the create
 * wizard and the surface detail page. Layout and styling come from
 * `SurfaceBuilder.css`'s `.surface-builder` class — height is computed
 * relative to the viewport so it always fills the available area.
 */
export function SurfaceBuilder<T extends SurfaceBuilderState>({
  builder,
  surfaceName,
  protocol,
  surfacePolicyIds,
  onOpenFullscreenEditor,
  surfaceSizeRef,
  canvasViewRef,
  activeVariantId,
  onSwitchVariant,
  onAddVariant,
  onCreateTemplateFromSelection,
  hasAttemptedSave,
}: SurfaceBuilderProps<T>) {
  const {
    state,
    commit,
    replaceCommit,
    selectedNode,
    handleDrop,
    handleNodeClick,
    handleNodeUpdate,
    handleNodeRemove,
    handleNodeMove,
    handleSystemNodeMove,
    handleNodeResize,
    handleSurfaceResize,
    handleAutoLayout,
    handleUndo,
    handleRedo,
    canUndo,
    canRedo,
    handleCloseConfig,
    externalRevision,
    resetViewRev,
    handledResetViewRevRef,
    setMultiSelection,
    multiSelectedIds,
  } = builder;

  // Snap-to-grid mode toggle. When on, node drags quantise to a fixed
  // grid; the shift modifier inverts behavior (held = free movement).
  // When off, drags are free and shift forces quantisation.
  const [gridSnap, setGridSnap] = useState(false);

  // Inject the synthesised `local-gateway-hop → remote-gateway`
  // chain for every TP/Target whose endpoint is a fabric:// URL.
  // The transformation is purely view-side and never enters
  // `state.nodes`, so persistence and edit gestures are unaffected.
  // We also drop the singleton `target-variant` node — it is the
  // surface-wide variants config carrier and the dedicated top-left
  // widget is its only entry point.
  //
  // Project the user-entered `config.name` onto `node.label` so a
  // rename in the properties panel is reflected on the canvas. The
  // original element-type label is kept as a fallback when no name
  // has been entered. This is purely view-side; persistence still
  // reads `config.name` from the source node.
  const displayNodes = useMemo(
    () =>
      synthesizeFabricCanvasNodes(
        state.nodes.filter(n => n.type !== 'target-variant'),
        state.surfaceSize
      ).map(n => {
        const userName = typeof n.config?.name === 'string' ? (n.config.name as string).trim() : '';
        if (userName) return { ...n, label: userName };
        if (!n.label) return { ...n, label: registry.get(n.type)?.label ?? n.type };
        return n;
      }),
    [state.nodes, state.surfaceSize]
  );

  const accessPointUrl = useMemo(() => {
    const ap = state.nodes.find(n => n.type === 'access-point');
    const listen = ap?.config?.listen_address;
    const route = ap?.config?.route;
    return listen && route ? `${listen}${route}` : '';
  }, [state.nodes]);

  // Clicking a synthesised node (`local-gateway-hop`, `remote-gateway`,
  // `remote-channel`) opens the same right-hand properties panel as
  // every other element. The synth nodes themselves are not in
  // `state.nodes`, so we resolve the click against `displayNodes`
  // and pass the synthesised CanvasNode through to the panel below
  // (via `synthSelectedNode`). Writes to `config.name` are intercepted
  // and persisted on the underlying parent target/TP so the rename
  // survives across renders.
  const handleSynthAwareNodeClick = useCallback(
    (nodeId: string) => {
      handleNodeClick(nodeId);
    },
    [handleNodeClick]
  );

  // When the panel issues an update for a synth node, redirect the
  // write to the corresponding parent `config` field so the rename
  // persists in `state.nodes`. Non-synth updates fall through to the
  // standard handler unchanged. Used by the wired `NodeConfigPanel`
  // below in place of `handleNodeUpdate`.
  const handleSynthAwareNodeUpdate = useCallback(
    (nodeId: string, config: any) => {
      const binding = resolveSyntheticNameBinding(nodeId);
      if (!binding) {
        handleNodeUpdate(nodeId, config);
        return;
      }
      const parent = state.nodes.find(n => n.id === binding.parentId);
      if (!parent) return;
      const newName = typeof config?.name === 'string' ? config.name : '';
      const parentUpdate: Record<string, any> = {
        ...(parent.config ?? {}),
        [binding.field]: newName,
      };
      // Tunnel mcp_tool_policies writes from the hop panel back to the
      // parent Transit Point, which IS persisted in state.nodes.
      if (config?.mcp_tool_policies !== undefined) {
        parentUpdate.mcp_tool_policies = config.mcp_tool_policies;
      }
      handleNodeUpdate(binding.parentId, parentUpdate);
    },
    [handleNodeUpdate, state.nodes]
  );

  // Removal is disabled for synth nodes (`deletable: false` on each
  // definition hides the panel's delete affordance), but guard the
  // remove path anyway to be safe against keyboard/context-menu
  // gestures that might bypass the panel.
  const handleSynthAwareNodeRemove = useCallback(
    (nodeId: string) => {
      if (resolveSyntheticNameBinding(nodeId)) return;
      handleNodeRemove(nodeId);
    },
    [handleNodeRemove]
  );

  // Resolve the selected node, falling back to the synthesised list
  // so synth nodes can drive the properties panel like any other
  // element. The hook's own `selectedNode` only knows about
  // `state.nodes`, which by design excludes the synth chain.
  const effectiveSelectedNode = useMemo(() => {
    if (selectedNode) return selectedNode;
    const id = state.selectedNodeId;
    if (!id || !resolveSyntheticNameBinding(id)) return selectedNode;
    return displayNodes.find(n => n.id === id) ?? null;
  }, [selectedNode, state.selectedNodeId, displayNodes]);

  const exportPngRef = useRef<(() => void) | null>(null);
  const resetViewRef = useRef<(() => void) | null>(null);

  return (
    <div className="surface-builder">
      <SurfaceCanvas
        // Remount on variant switch so the internal positionsRef and
        // d3-zoom DOM transform reset and re-seed from the incoming
        // variant's saved positions / canvas.view. Without this the
        // prior variant's layout state persists and overwrites the
        // new variant's snapshot on first render, flipping dirty on
        // a pure variant switch (no user edits).
        key={activeVariantId ?? '__base__'}
        surfaceName={surfaceName}
        protocol={protocol}
        nodes={displayNodes}
        surfacePolicyIds={surfacePolicyIds}
        onNodeClick={handleSynthAwareNodeClick}
        onCanvasClick={handleCloseConfig}
        onDrop={handleDrop}
        onNodeMove={handleNodeMove}
        onSystemNodeMove={handleSystemNodeMove}
        onNodeResize={handleNodeResize}
        onMultiSelectionChange={setMultiSelection}
        multiSelectedIds={multiSelectedIds}
        selectedNodeId={state.selectedNodeId}
        externalRevision={externalRevision}
        resetViewRev={resetViewRev}
        handledResetViewRevRef={handledResetViewRevRef}
        surfaceSizeRef={surfaceSizeRef}
        surfaceSize={state.surfaceSize}
        onSurfaceResize={handleSurfaceResize}
        canvasViewRef={canvasViewRef}
        gridSnap={gridSnap}
        exportPngRef={exportPngRef}
        resetViewRef={resetViewRef}
      />
      <SurfaceVariantsWidget
        nodes={state.nodes}
        selected={state.selectedNodeId === 'target-variant'}
        onOpen={() => handleNodeClick('target-variant')}
        activeVariantId={activeVariantId}
        onSwitchVariant={onSwitchVariant}
        onAddVariant={onAddVariant}
      />
      {accessPointUrl && (
        <div className="surface-access-point-url-widget">
          <RouteListenerBanner label="Access Point" url={accessPointUrl} />
        </div>
      )}
      <div className="surface-toolbar-widget">
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleUndo}
          disabled={!canUndo}
          title="Undo (⌘Z / Ctrl+Z)"
          aria-label="Undo"
        >
          <i className="fas fa-undo" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleRedo}
          disabled={!canRedo}
          title="Redo (⇧⌘Z / Ctrl+Shift+Z / Ctrl+Y)"
          aria-label="Redo"
        >
          <i className="fas fa-redo" />
        </button>
        <button
          type="button"
          className={`surface-toolbar-btn${gridSnap ? ' active' : ''}`}
          onClick={() => setGridSnap(g => !g)}
          title={
            gridSnap
              ? 'Snap to grid: on (hold Shift to move freely)'
              : 'Snap to grid: off (hold Shift to snap)'
          }
          aria-label="Toggle snap to grid"
          aria-pressed={gridSnap}
        >
          <i className="fas fa-border-all" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={() => exportPngRef.current?.()}
          title="Download canvas as PNG"
          aria-label="Download canvas as PNG"
        >
          <i className="fas fa-camera" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleAutoLayout}
          title="Auto-layout (⌘L / Ctrl+L)"
          aria-label="Auto-layout"
        >
          <i className="fas fa-up-down-left-right" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={() => resetViewRef.current?.()}
          title="Reset pan & zoom"
          aria-label="Reset pan and zoom"
        >
          <i className="fas fa-crosshairs" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={() => handleNodeClick('__surface__')}
          title="Surface properties"
          aria-label="Surface properties"
        >
          <i className="fas fa-cog" />
        </button>
      </div>
      <div onBlur={commit}>
        {multiSelectedIds.length >= 2 ? (
          <MultiSelectionPanel
            selectedIds={multiSelectedIds}
            allNodes={displayNodes}
            setSelection={setMultiSelection}
            onCreateTemplate={onCreateTemplateFromSelection}
            onClose={() => setMultiSelection([])}
          />
        ) : (
          <NodeConfigPanel
            node={effectiveSelectedNode}
            onUpdate={handleSynthAwareNodeUpdate}
            onRemove={handleSynthAwareNodeRemove}
            onClose={handleCloseConfig}
            onOpenFullscreenEditor={onOpenFullscreenEditor}
            protocol={protocol}
            allNodes={state.nodes}
            externalRevision={externalRevision}
            replaceCommit={replaceCommit}
            hasAttemptedSave={hasAttemptedSave}
          />
        )}
      </div>
    </div>
  );
}

export default SurfaceBuilder;
