import React from 'react';
import { apiClient, type AgentSurface, type SurfaceTemplate } from '../../api';
import type { Protocol } from './elements/types';
import SurfaceBuilder from './SurfaceBuilder';
import ConfigEditorFullscreen from './ConfigEditorFullscreen';
import ElementsListTab from './ElementsListTab';
import ElementPalette from './ElementPalette';
import SurfaceMonitoringPanel from './SurfaceMonitoringPanel';
import TemplatesPanel from './templates/TemplatesPanel';
import TemplateConflictModal from './templates/TemplateConflictModal';
import { applyPlan, planTemplate } from './templates/placement';
import { autoApplyFullSurfaceTemplate } from './templates/applyFullTemplate';
import { nodeToTemplateItem } from './templates/serializeTemplate';
import { fetchRoutingConfig } from './elements/access-point/defaults';
import type { PlacementDecision, PlacementResult, TemplatePlan } from './templates/types';
import type { SurfaceNodeType } from './nodeTypes';
import { showToast } from '../../utils/toaster';
import { registry } from './elements';
import type { UseSurfaceBuilderReturn } from './hooks/useSurfaceBuilder';
import type { CanvasNode } from './SurfaceCanvas';
import type { SurfaceTemplateItem } from '../../api';
import { SurfaceMetaProvider, type DidwebvhConfig } from './SurfaceMetaContext';
import type { SurfacePolicyDefinitionLoadState } from './elements/policy/status';
import { hasPolicyDefinitionReference, policyDefinitionsWarning } from './elements/policy/status';

export type SurfaceFormMode = 'create' | 'edit';
export type SurfaceFormView =
  | 'surface'
  | 'templates'
  | 'elements'
  | 'monitoring'
  | 'config'
  | 'editor';

export interface SurfaceMetaState {
  name: string;
  description: string;
  tagsCsv: string;
  status: AgentSurface['status'];
  protocol: Protocol;
  publishToDid: boolean;
  terminateTraceId: boolean;
  issuerId: string;
  didwebvh: DidwebvhConfig;
}

export interface SurfaceMetaSetters {
  setName: (v: string) => void;
  setDescription: (v: string) => void;
  setTagsCsv: (v: string) => void;
  setStatus: (v: AgentSurface['status']) => void;
  setProtocol: (v: Protocol) => void;
  setPublishToDid: (v: boolean) => void;
  setTerminateTraceId: (v: boolean) => void;
  setIssuerId: (v: string) => void;
  setDidwebvh: (v: DidwebvhConfig) => void;
}

interface BuilderShape {
  nodes: CanvasNode[];
  selectedNodeId: string | null;
}

export interface SurfaceFormShellProps {
  mode: SurfaceFormMode;
  canEdit: boolean;
  builder: UseSurfaceBuilderReturn<BuilderShape>;
  meta: SurfaceMetaState;
  setMeta: SurfaceMetaSetters;
  jsonOverride: string | null;
  setJsonOverride: (v: string | null) => void;
  jsonError: string | null;
  setJsonError: (v: string | null) => void;
  configEditorValue: string;
  /**
   * Apply a parsed JSON payload to the canvas. Called by the Config
   * tab whenever the user's text parses successfully. When provided,
   * editing the JSON live-updates the canvas (instead of treating the
   * text as an opaque save-time override). Return a string to surface
   * a semantic error to the user (e.g. "missing access_point"); return
   * null on success.
   */
  onApplyJsonPayload?: (payload: any) => string | null;
  activeTab: SurfaceFormView;
  setActiveTab: (v: SurfaceFormView) => void;
  editorTabNodeId: string | null;
  onOpenFullscreenEditor: (nodeId: string) => void;
  onCloseFullscreenEditor: () => void;
  canvasOverlay?: React.ReactNode;
  surfaceId?: string;
  lastActivity?: string | null;
  /**
   * Page-specific Save / Delete / etc. buttons rendered as a 'Manage'
   * section in the left sidebar. Each child should be a full-width
   * button. Hidden when the sidebar is collapsed.
   */
  manageActions?: React.ReactNode;
  /**
   * Shared mutable ref tracking the resizable surface rectangle
   * dimensions. Forwarded to the canvas so saves can persist the size
   * in the canvas blob and reloads can re-hydrate it.
   */
  surfaceSizeRef?: React.MutableRefObject<{ w: number; h: number } | null>;
  /**
   * Shared mutable ref tracking the d3 zoom transform (pan + scale).
   * Forwarded to the canvas so saves can persist the view in the
   * canvas blob and reloads can re-hydrate it.
   */
  canvasViewRef?: React.MutableRefObject<{ x: number; y: number; k: number } | null>;
  /**
   * Currently active surface variant id. Forwarded to the variants
   * widget so its dropdown reflects the resolved selection.
   */
  activeVariantId?: string | null;
  /**
   * Switch the active variant. The page wires this to its variant
   * snapshot manager which swaps canvas state atomically.
   */
  onSwitchVariant?: (variantId: string) => void;
  /**
   * Open the variants editor AND seed a new variant. Wired to the
   * widget's zero-state "+" affordance.
   */
  onAddVariant?: () => void;
  /**
   * Optional banner rendered at the top of the main column (above the
   * canvas / other tab content). Used by pages to surface inline
   * alerts (e.g. save failures) so they remain visible even in
   * fullscreen mode, and so they only push the canvas down — not the
   * sidebar.
   */
  topBanner?: React.ReactNode;
  /**
   * Load state of the surface (`agent_surface`) policy-definition id set,
   * owned by the page via `useSurfacePolicyDefinitions`. Drives the canvas
   * "policy no longer configured" rings and the non-blocking load-error
   * warning.
   */
  surfacePolicyLoadState: SurfacePolicyDefinitionLoadState;
  /**
   * Forwarded to the canvas so panels gate their inline errors on it.
   * Set to true by the page on first Create / Save attempt.
   */
  hasAttemptedSave?: boolean;
}

/**
 * Returns true once the user has placed (or pre-loaded) any node beyond
 * the auto-injected Human + Caller actors. Used to permanently lock the
 * surface protocol — once elements exist they may depend on it.
 */
function hasUserAddedNodes(nodes: CanvasNode[]): boolean {
  return nodes.some(n => n.type !== 'human' && n.type !== 'caller');
}

async function prepareTemplatePolicyDefinitions(
  template: SurfaceTemplate
): Promise<SurfaceTemplate> {
  const policyItems = (template.items ?? []).filter(item => {
    const config = item.config as Record<string, unknown> | undefined;
    return item.kind === 'policy' && typeof config?.rego === 'string' && config.rego.trim() !== '';
  });
  if (policyItems.length === 0) return template;

  const response = await apiClient.fetch('/api/v1/policy-definitions?policy_type=agent_surface');
  if (!response.ok) {
    throw new Error(`Could not load Agent Surface policies (${response.status})`);
  }
  const definitions = (await response.json()) as Array<{ id: string; policy?: string }>;

  const preparedItems = await Promise.all(
    (template.items ?? []).map(async item => {
      const config = item.config as Record<string, unknown> | undefined;
      if (
        item.kind !== 'policy' ||
        typeof config?.rego !== 'string' ||
        config.rego.trim() === '' ||
        typeof config.policy_definition_id === 'string'
      ) {
        return item;
      }

      const rego = config.rego;
      const existing = definitions.find(definition => definition.policy === rego);
      const policyDefinitionId = existing?.id ?? crypto.randomUUID();
      if (!existing) {
        const createResponse = await apiClient.fetch('/api/v1/policy-definitions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: policyDefinitionId,
            name: `${template.name} Policy`,
            description: `Policy created from the ${template.name} surface template.`,
            policy_type: 'agent_surface',
            policy: rego,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
        if (!createResponse.ok) {
          const detail = await createResponse.text();
          throw new Error(
            detail || `Could not create Agent Surface policy (${createResponse.status})`
          );
        }
      }

      const { rego: _rego, ...policyConfig } = config;
      return {
        ...item,
        config: {
          ...policyConfig,
          policy_definition_id: policyDefinitionId,
        },
      };
    })
  );

  return { ...template, items: preparedItems };
}

const SIDEBAR_VIEWS: ReadonlyArray<{
  key: SurfaceFormView;
  label: string;
  icon: string;
  editOnly?: boolean;
}> = [
  { key: 'surface', label: 'Surface', icon: 'fa-project-diagram' },
  { key: 'templates', label: 'Templates', icon: 'fa-layer-group' },
  { key: 'elements', label: 'Elements', icon: 'fa-list' },
  { key: 'monitoring', label: 'Monitoring', icon: 'fa-chart-line', editOnly: true },
  { key: 'config', label: 'Config', icon: 'fa-code' },
];

const SurfaceFormShell: React.FC<SurfaceFormShellProps> = ({
  mode,
  canEdit,
  builder,
  meta,
  setMeta,
  jsonOverride,
  setJsonOverride,
  jsonError,
  setJsonError,
  configEditorValue,
  onApplyJsonPayload,
  activeTab,
  setActiveTab,
  editorTabNodeId,
  onOpenFullscreenEditor,
  onCloseFullscreenEditor,
  canvasOverlay,
  surfaceId,
  lastActivity,
  manageActions,
  surfaceSizeRef,
  canvasViewRef,
  activeVariantId,
  onSwitchVariant,
  onAddVariant,
  topBanner,
  surfacePolicyLoadState,
  hasAttemptedSave,
}) => {
  const surfacePolicyIds =
    surfacePolicyLoadState.status === 'loaded' ? surfacePolicyLoadState.ids : null;

  const surfacePolicyWarning = policyDefinitionsWarning(
    surfacePolicyLoadState,
    hasPolicyDefinitionReference(builder.state.nodes)
  );

  const editorNode = editorTabNodeId
    ? builder.state.nodes.find(n => n.id === editorTabNodeId) || null
    : null;
  const editorDef = editorNode ? registry.get(editorNode.type) : undefined;

  const [pendingTemplateEditorNodeId, setPendingTemplateEditorNodeId] = React.useState<
    string | null
  >(null);

  // Protocol locks permanently in edit mode, or as soon as the user
  // adds any non-default element to the canvas.
  const protocolLocked = mode === 'edit' || hasUserAddedNodes(builder.state.nodes);

  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false);
  const SIDEBAR_WIDTH_KEY = 'surface-builder-sidebar-width';
  const SIDEBAR_MIN = 220;
  const SIDEBAR_MAX = 480;
  const [sidebarWidth, setSidebarWidth] = React.useState<number>(() => {
    try {
      const stored = localStorage.getItem(SIDEBAR_WIDTH_KEY);
      if (stored) {
        const n = parseInt(stored, 10);
        if (Number.isFinite(n)) return Math.min(Math.max(n, SIDEBAR_MIN), SIDEBAR_MAX);
      }
    } catch {
      /* ignore */
    }
    return 260;
  });
  const sidebarWidthRef = React.useRef(sidebarWidth);
  React.useEffect(() => {
    sidebarWidthRef.current = sidebarWidth;
  }, [sidebarWidth]);
  const [isResizingSidebar, setIsResizingSidebar] = React.useState(false);
  const handleSidebarResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizingSidebar(true);
    const startX = e.clientX;
    const startWidth = sidebarWidthRef.current;
    const onMove = (ev: MouseEvent) => {
      const delta = ev.clientX - startX;
      const next = Math.min(Math.max(startWidth + delta, SIDEBAR_MIN), SIDEBAR_MAX);
      setSidebarWidth(next);
    };
    const onUp = () => {
      setIsResizingSidebar(false);
      try {
        localStorage.setItem(SIDEBAR_WIDTH_KEY, String(sidebarWidthRef.current));
      } catch {
        /* ignore */
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  // The properties panel stays hidden on initial canvas load; the user
  // opens it explicitly by clicking a node (or the surface itself).

  // Canvas is rendered ONCE and shown/hidden via CSS so its internal
  // layout state (positionsRef, surfaceSizeRef, d3 simulation) survives
  // tab switches. Unmounting on every switch loses the resolved node
  // positions and re-runs the auto-layout against a freshly-measured
  // container, which produces visibly broken positions for the AP /
  // target / chain middleware on the way back.
  //
  // `handleCreateTemplateFromSelection` is declared later in this
  // component (it needs state that hasn't been initialised yet at this
  // point), so route the call through a ref to avoid the temporal dead
  // zone while keeping the canvas eagerly constructed.
  const createTemplateFromSelectionRef = React.useRef<((ids: string[]) => void) | null>(null);
  const surfaceCanvas = (
    <div
      className="surface-form-canvas-wrap"
      style={activeTab === 'surface' ? undefined : { display: 'none' }}
    >
      <SurfaceBuilder
        builder={builder}
        surfaceName={meta.name || 'Agent Surface'}
        protocol={meta.protocol}
        surfacePolicyIds={surfacePolicyIds}
        onOpenFullscreenEditor={onOpenFullscreenEditor}
        surfaceSizeRef={surfaceSizeRef}
        canvasViewRef={canvasViewRef}
        activeVariantId={activeVariantId}
        onSwitchVariant={onSwitchVariant}
        onAddVariant={onAddVariant}
        onCreateTemplateFromSelection={
          canEdit ? ids => createTemplateFromSelectionRef.current?.(ids) : undefined
        }
        hasAttemptedSave={hasAttemptedSave}
      />
      {activeTab === 'surface' && canvasOverlay}
    </div>
  );

  const renderOtherTab = () => {
    switch (activeTab) {
      case 'surface':
        return null;
      case 'templates':
        return (
          <TemplatesPanel
            protocol={meta.protocol}
            onApplyTemplate={handleTemplateApply}
            nodes={builder.state.nodes}
            currentSurfaceJson={configEditorValue}
            createMode={templatesCreateMode}
            createPartialSeed={pendingPartialSeed}
            onExitCreateMode={() => {
              // If the create form was opened from a canvas
              // selection, return the user to the surface view so
              // they land back where they started. Otherwise stay on
              // the Templates list (entered via the [+] affordance).
              const wasPartialSelectionFlow = pendingPartialSeed !== null;
              setTemplatesCreateMode(false);
              setPendingPartialSeed(null);
              if (wasPartialSelectionFlow) setActiveTab('surface');
            }}
          />
        );
      case 'elements':
        return (
          <ElementsListTab
            nodes={builder.state.nodes}
            surfacePolicyIds={surfacePolicyIds}
            onSelectNode={id => {
              builder.handleNodeClick(id);
              setActiveTab('surface');
            }}
          />
        );
      case 'monitoring':
        if (mode !== 'edit' || !surfaceId) return null;
        return (
          <SurfaceMonitoringPanel
            surfaceId={surfaceId}
            surfaceName={meta.name || 'Agent Surface'}
          />
        );
      case 'config':
        return (
          <div className="card shadow-sm mb-0">
            <div className="card-header d-flex align-items-center justify-content-between">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-code me-2"></i> Surface Configuration
              </h6>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                title="Copy JSON to clipboard"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(configEditorValue);
                  } catch {
                    // Clipboard API can fail in non-secure contexts;
                    // ignore silently — the textarea is still selectable.
                  }
                }}
              >
                <i className="fas fa-copy me-1" /> Copy
              </button>
            </div>
            <div className="card-body">
              {jsonOverride === null ? (
                <p className="text-muted small mb-2">
                  Complete Agent Surface configuration payload. Edit directly, or paste a payload
                  here and the canvas will refresh to match.
                </p>
              ) : (
                <div className="alert alert-danger py-2 px-3 mb-2 d-flex align-items-start">
                  <i className="fas fa-times-circle me-2 mt-1" />
                  <div className="flex-grow-1">
                    <strong>Invalid JSON.</strong> Fix the error below — the canvas is showing the
                    last accepted payload.
                    {jsonError && <div className="small mt-1">{jsonError}</div>}
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary ms-2"
                    onClick={() => {
                      setJsonOverride(null);
                      setJsonError(null);
                    }}
                  >
                    Discard edits
                  </button>
                </div>
              )}
              <textarea
                className={`form-control ${jsonError ? 'is-invalid' : ''}`}
                spellCheck={false}
                style={{
                  fontFamily: 'Monaco, Menlo, monospace',
                  fontSize: '12px',
                  whiteSpace: 'pre',
                  overflow: 'auto',
                  height: 'calc(100vh - 360px)',
                  minHeight: 320,
                  margin: 0,
                }}
                value={configEditorValue}
                onChange={e => {
                  const v = e.target.value;
                  setJsonOverride(v);
                  let parsed: any;
                  try {
                    parsed = JSON.parse(v);
                  } catch (err: any) {
                    setJsonError(err?.message || 'Invalid JSON');
                    return;
                  }
                  // Hand off to the page so the canvas can re-hydrate
                  // from the parsed payload. A semantic-error string
                  // from the page (e.g. missing access_point) surfaces
                  // the same way as a parse error.
                  const semanticErr = onApplyJsonPayload ? onApplyJsonPayload(parsed) : null;
                  if (semanticErr) {
                    setJsonError(semanticErr);
                    return;
                  }
                  setJsonError(null);
                  // Drop the buffered text on a successful apply so the
                  // textarea re-syncs to the canonical pretty-printed
                  // payload built from the now-updated canvas.
                  setJsonOverride(null);
                }}
                disabled={!canEdit}
              />
            </div>
          </div>
        );
      case 'editor':
        if (!editorNode || !editorDef) {
          return null;
        }
        return (
          <div className="surface-builder-fullscreen">
            <ConfigEditorFullscreen
              node={editorNode}
              protocol={meta.protocol}
              allNodes={builder.state.nodes}
              onUpdate={builder.handleNodeUpdate}
              onCloseFullscreenEditor={onCloseFullscreenEditor}
              hasAttemptedSave={hasAttemptedSave}
            />
          </div>
        );
    }
  };

  // If the editor view is active but the editor node disappeared, bounce.
  React.useEffect(() => {
    if (activeTab === 'editor' && (!editorNode || !editorDef)) {
      setActiveTab('surface');
    }
  }, [activeTab, editorNode, editorDef, setActiveTab]);

  React.useEffect(() => {
    if (!pendingTemplateEditorNodeId) return;
    const node = builder.state.nodes.find(n => n.id === pendingTemplateEditorNodeId);
    if (!node) return;
    setPendingTemplateEditorNodeId(null);
    onOpenFullscreenEditor(pendingTemplateEditorNodeId);
  }, [builder.state.nodes, onOpenFullscreenEditor, pendingTemplateEditorNodeId]);

  // Pending template plan — non-null only while the conflict modal is open.
  const [pendingPlan, setPendingPlan] = React.useState<TemplatePlan | null>(null);

  // True while the Templates tab shows the create-template form (driven
  // by the [+] button on the Templates sidebar entry). Cleared whenever
  // the user navigates away from the Templates tab so revisiting always
  // returns to the list view.
  const [templatesCreateMode, setTemplatesCreateMode] = React.useState(false);
  // Optional partial-template seed populated when the user invokes
  // "Create Template from Selection" from the multi-selection panel.
  // Cleared alongside `templatesCreateMode`.
  const [pendingPartialSeed, setPendingPartialSeed] = React.useState<{
    items: SurfaceTemplateItem[];
    count: number;
  } | null>(null);
  React.useEffect(() => {
    if (activeTab !== 'templates' && templatesCreateMode) {
      setTemplatesCreateMode(false);
      setPendingPartialSeed(null);
    }
  }, [activeTab, templatesCreateMode]);

  const handleCreateTemplateFromSelection = React.useCallback(
    (selectedIds: string[]) => {
      if (!canEdit || selectedIds.length === 0) return;
      const allNodes = builder.state.nodes;
      const idSet = new Set(selectedIds);
      const items: SurfaceTemplateItem[] = [];
      let skipped = 0;
      for (const node of allNodes) {
        if (!idSet.has(node.id)) continue;
        const item = nodeToTemplateItem(node, allNodes);
        if (item) items.push(item);
        else skipped += 1;
      }
      if (items.length === 0) {
        showToast(
          'error',
          'None of the selected elements can be saved as a template (built-in actors and the access point / target are excluded).'
        );
        return;
      }
      if (skipped > 0) {
        showToast(
          'success',
          `Added ${items.length} item${items.length === 1 ? '' : 's'}; ${skipped} skipped (not templatable).`
        );
      }
      setPendingPartialSeed({ items, count: items.length });
      setActiveTab('templates');
      setTemplatesCreateMode(true);
    },
    [builder.state.nodes, canEdit, setActiveTab]
  );
  // Keep the forward-declared ref in sync so the canvas's lambda calls
  // the latest closure.
  createTemplateFromSelectionRef.current = handleCreateTemplateFromSelection;

  const finalizeTemplateApply = React.useCallback(
    (templateName: string, result: PlacementResult) => {
      // Pass 1: free-standing nodes (placement engine resolved these
      // synchronously into `nextNodes`).
      builder.setState(prev => ({ ...prev, nodes: result.nextNodes }));
      builder.commit();
      // Pass 2: edge-bound items. Apply them in a single state
      // transaction via `handleTemplateEdgeDrops` so every drop's
      // topology computation sees the running result of the previous
      // drop. A synchronous forEach of single-drop helpers would have
      // each drop recompute against the pre-batch `stateRef` and
      // overwrite earlier chain re-parents, collapsing later drops
      // onto the same anchor.
      let createdEdgeNodeIds: string[] = [];
      if (result.edgeDrops.length > 0) {
        createdEdgeNodeIds = builder.handleTemplateEdgeDrops(
          result.edgeDrops.map(drop => ({
            type: drop.kind as SurfaceNodeType,
            ctx: {
              edgeSourceId: drop.edgeSourceId,
              edgeTargetId: drop.edgeTargetId,
              edgeDirection: drop.edgeDirection,
            },
            configOverrides: drop.config,
          }))
        );
      }
      const placedN = result.placed.length;
      const skippedN = result.skipped.length;
      if (placedN > 0) {
        const skipNote =
          skippedN > 0 ? ` (${skippedN} item${skippedN === 1 ? '' : 's'} skipped)` : '';
        showToast(
          'success',
          `Added ${placedN} item${placedN === 1 ? '' : 's'} from "${templateName}"${skipNote}.`
        );
      } else {
        showToast('error', `No items from "${templateName}" could be placed.`);
      }
      setActiveTab('surface');

      const fullscreenNodeId = createdEdgeNodeIds
        .map((nodeId, index) => ({
          nodeId,
          definition: registry.get(result.edgeDrops[index]?.kind as SurfaceNodeType),
        }))
        .find(({ definition }) => definition?.FullscreenPanel)?.nodeId;
      if (fullscreenNodeId) setPendingTemplateEditorNodeId(fullscreenNodeId);
    },
    [builder, setActiveTab]
  );

  const handleTemplateApply = React.useCallback(
    async (tpl: SurfaceTemplate) => {
      if (tpl.kind === 'full') {
        if (!onApplyJsonPayload) {
          showToast('error', 'This page does not support loading a full template payload.');
          return;
        }
        // No modal: auto-fill what we can from the routing config
        // (same defaults the AddSurface wizard uses for `$HOST` /
        // `$ROUTE`), blank the rest, and let the form validator
        // surface any remaining required fields.
        void fetchRoutingConfig().then(routing => {
          const { surface } = autoApplyFullSurfaceTemplate(tpl, routing);
          const err = onApplyJsonPayload(surface);
          if (err) {
            showToast('error', `Template "${tpl.name}" rejected: ${err}`);
            return;
          }
          showToast(
            'success',
            `Replaced surface with "${tpl.name}". Fill in any highlighted fields and Save.`
          );
          setActiveTab('surface');
        });
        return;
      }
      let preparedTemplate: SurfaceTemplate;
      try {
        preparedTemplate = await prepareTemplatePolicyDefinitions(tpl);
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Could not prepare policy definitions';
        showToast('error', `Template "${tpl.name}" rejected: ${message}`);
        return;
      }

      const plan = planTemplate(preparedTemplate, builder.state.nodes);
      if (plan.conflicts.length === 0) {
        finalizeTemplateApply(tpl.name, applyPlan(plan, builder.state.nodes, {}));
        return;
      }
      setPendingPlan(plan);
    },
    [builder.state.nodes, finalizeTemplateApply, onApplyJsonPayload, setActiveTab]
  );

  const handleConflictConfirm = React.useCallback(
    (decisions: Record<number, PlacementDecision>) => {
      if (!pendingPlan) return;
      const result = applyPlan(pendingPlan, builder.state.nodes, decisions);
      finalizeTemplateApply(pendingPlan.template.name, result);
      setPendingPlan(null);
    },
    [pendingPlan, builder.state.nodes, finalizeTemplateApply]
  );

  return (
    <SurfaceMetaProvider
      value={{
        name: meta.name,
        description: meta.description,
        tagsCsv: meta.tagsCsv,
        status: meta.status,
        protocol: meta.protocol,
        publishToDid: meta.publishToDid,
        terminateTraceId: meta.terminateTraceId,
        issuerId: meta.issuerId,
        didwebvh: meta.didwebvh,
        readOnly: !canEdit,
        protocolLocked,
        isCreate: mode === 'create',
        lastActivity,
        surfaceId,
        setName: setMeta.setName,
        setDescription: setMeta.setDescription,
        setTagsCsv: setMeta.setTagsCsv,
        setStatus: setMeta.setStatus,
        setProtocol: setMeta.setProtocol,
        setPublishToDid: setMeta.setPublishToDid,
        setTerminateTraceId: setMeta.setTerminateTraceId,
        setIssuerId: setMeta.setIssuerId,
        setDidwebvh: setMeta.setDidwebvh,
        onSaveAsTemplate: canEdit
          ? () => {
              setActiveTab('templates');
              setTemplatesCreateMode(true);
            }
          : undefined,
      }}
    >
      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-body p-0">
          <div
            className={`surface-form-shell${sidebarCollapsed ? ' sidebar-collapsed' : ''}`}
            style={
              !sidebarCollapsed
                ? ({
                    gridTemplateColumns: `${sidebarWidth}px minmax(0, 1fr)`,
                  } as React.CSSProperties)
                : undefined
            }
          >
            <aside className="surface-form-sidebar">
              {!sidebarCollapsed && (
                <div
                  className={`surface-form-sidebar-resize${isResizingSidebar ? ' active' : ''}`}
                  onMouseDown={handleSidebarResizeStart}
                  title="Drag to resize"
                />
              )}
              <div className="surface-form-sidebar-toolbar">
                <button
                  type="button"
                  className="surface-form-sidebar-iconbtn"
                  onClick={() => setSidebarCollapsed(c => !c)}
                  title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                  <i className={`fas fa-chevron-${sidebarCollapsed ? 'right' : 'left'}`} />
                </button>
                {!sidebarCollapsed && (
                  <span className="surface-form-sidebar-title" title={meta.name || 'Agent Surface'}>
                    {meta.name || 'Agent Surface'}
                  </span>
                )}
              </div>
              {!sidebarCollapsed && (
                <>
                  <div className="surface-form-sidebar-scroll">
                    <div className="surface-form-sidebar-section">
                      <div className="surface-form-sidebar-heading">Views</div>
                      {SIDEBAR_VIEWS.filter(v => !v.editOnly || mode === 'edit').map(v => (
                        <div
                          key={v.key}
                          className={`surface-form-sidebar-item${activeTab === v.key ? ' active' : ''}`}
                          style={{ display: 'flex', alignItems: 'center' }}
                        >
                          <button
                            type="button"
                            className="surface-form-sidebar-item-main"
                            onClick={() => setActiveTab(v.key)}
                            style={{
                              flex: 1,
                              display: 'flex',
                              alignItems: 'center',
                              background: 'transparent',
                              border: 0,
                              padding: 0,
                              color: 'inherit',
                              minWidth: 0,
                            }}
                          >
                            <i className={`fas ${v.icon} me-2`} />
                            <span>{v.label}</span>
                            {v.key === 'elements' && (
                              <span className="badge text-bg-secondary ms-auto">
                                {builder.state.nodes.length}
                              </span>
                            )}
                            {v.key === 'config' && jsonError && (
                              <span className="ms-auto text-danger" title={jsonError}>
                                <i className="fas fa-times-circle" />
                              </span>
                            )}
                          </button>
                          {v.key === 'templates' && canEdit && (
                            <button
                              type="button"
                              className="surface-form-sidebar-inline-action"
                              title="Create template from canvas"
                              onClick={e => {
                                e.stopPropagation();
                                setActiveTab('templates');
                                setTemplatesCreateMode(true);
                              }}
                              style={{
                                background: 'transparent',
                                border: 0,
                                color: 'inherit',
                                opacity: 0.7,
                                padding: '0 4px',
                                marginLeft: 6,
                              }}
                            >
                              <i className="fas fa-plus" />
                            </button>
                          )}
                        </div>
                      ))}
                      {editorNode && editorDef && (
                        <button
                          type="button"
                          className={`surface-form-sidebar-item${activeTab === 'editor' ? ' active' : ''}`}
                          onClick={() => setActiveTab('editor')}
                          title={`Editing ${editorDef.label}`}
                        >
                          <i
                            className={`fas ${editorDef.paletteIcon ?? 'fa-pen-to-square'} me-2`}
                            style={{ color: editorDef.color }}
                          />
                          <span className="text-truncate">
                            {editorNode.config?.name || editorDef.label}
                          </span>
                          <span
                            className="ms-auto surface-form-sidebar-close"
                            role="button"
                            aria-label="Close editor"
                            onClick={e => {
                              e.stopPropagation();
                              onCloseFullscreenEditor();
                              if (activeTab === 'editor') setActiveTab('surface');
                            }}
                          >
                            <i className="fas fa-times" />
                          </span>
                        </button>
                      )}
                    </div>
                    {canEdit && (
                      <div className="surface-form-sidebar-section surface-form-sidebar-palette">
                        <div className="surface-form-sidebar-heading">Palette</div>
                        <ElementPalette
                          variant="inline"
                          existingNodes={builder.state.nodes}
                          protocol={meta.protocol}
                          onAnyDragStart={() => {
                            if (activeTab !== 'surface') setActiveTab('surface');
                          }}
                        />
                      </div>
                    )}
                  </div>
                  {manageActions && (
                    <div className="surface-form-sidebar-section surface-form-sidebar-manage">
                      <div className="surface-form-sidebar-heading">Manage</div>
                      {manageActions}
                    </div>
                  )}
                </>
              )}
            </aside>
            <div className="surface-form-main">
              {topBanner}
              {surfacePolicyWarning && (
                <div className="alert alert-warning py-2 px-3 mb-2 d-flex align-items-start">
                  <i className="fas fa-exclamation-triangle me-2 mt-1" />
                  <div className="flex-grow-1 small">{surfacePolicyWarning}</div>
                </div>
              )}
              {surfaceCanvas}
              {renderOtherTab()}
            </div>
          </div>
        </div>
      </div>
      {pendingPlan && (
        <TemplateConflictModal
          plan={pendingPlan}
          onCancel={() => setPendingPlan(null)}
          onConfirm={handleConflictConfirm}
        />
      )}
    </SurfaceMetaProvider>
  );
};

export default SurfaceFormShell;
