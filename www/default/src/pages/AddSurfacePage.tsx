import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AgentSurface, apiClient } from '../api';
import type { CanvasNode } from '../components/surface-builder/SurfaceCanvas';
import type { SurfaceNodeType } from '../components/surface-builder/nodeTypes';
import { getIncompleteReason } from '../components/surface-builder/SurfaceCanvas';
import type { Protocol } from '../components/surface-builder/elements/types';
import { ALL_PROTOCOLS } from '../components/surface-builder/protocols';
import { registry, validateSurfacePayload } from '../components/surface-builder/elements';
import { useSurfaceBuilder } from '../components/surface-builder/hooks/useSurfaceBuilder';
import { useSaveShortcut } from '../components/surface-builder/hooks/useSaveShortcut';
import { useDiscardWithUndo } from '../components/surface-builder/hooks/useDiscardWithUndo';
import SurfaceFormShell from '../components/surface-builder/SurfaceFormShell';
import { useSurfacePolicyDefinitions } from '../components/surface-builder/hooks/useSurfacePolicyDefinitions';
import { surfacePolicyBlockingReason } from '../components/surface-builder/elements/policy/status';
import { freezeEmptyVariantOverrides } from '../components/surface-builder/variants/resolve';
import {
  DEFAULT_DIDWEBVH_CONFIG,
  type DidwebvhConfig,
} from '../components/surface-builder/SurfaceMetaContext';
import { hydrateSurfaceCanvas } from '../components/surface-builder/nodesFromSurface';
import {
  fetchRoutingConfig,
  buildDefaultAccessPointConfig,
} from '../components/surface-builder/elements/access-point/defaults';
import { useSurfaceTemplates } from '../components/surface-builder/templates/useSurfaceTemplates';
import { autoApplyFullSurfaceTemplate } from '../components/surface-builder/templates/applyFullTemplate';
import { findDuplicateListenerRoutes } from '../components/surface-builder/templates/scrubVolatile';
import {
  sortTemplatesForDisplay,
  getTemplateProtocolBadge,
} from '../components/surface-builder/templates/templateSort';
import { showToast } from '../utils/toaster';
import './SurfaceBuilder.css';

const WELCOME_DISMISSED_KEY = 'surface-builder-welcome-dismissed';

interface CreateBuilderState {
  nodes: CanvasNode[];
  selectedNodeId: string | null;
  surfaceSize?: { w: number; h: number };
}

/**
 * Stable serialisation of every user-visible piece of surface state so we
 * can detect unsaved edits by string comparison against a baseline.
 */
function serializeDirtySignature(inputs: {
  nodes: CanvasNode[];
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
}): string {
  return JSON.stringify(inputs);
}

const AddSurfacePage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const initialProtocol: Protocol = (() => {
    const raw = searchParams.get('protocol');
    return ALL_PROTOCOLS.includes(raw as Protocol) ? (raw as Protocol) : 'a2a';
  })();
  // When the user lands here without a `?protocol=` query (e.g. the
  // single "Add Surface" button on the list page), block the canvas
  // with a protocol-picker overlay until they choose one. The default
  // is still 'a2a' so the canvas can pre-render meaningfully behind
  // the overlay.
  const protocolPrefilled = ALL_PROTOCOLS.includes(
    (searchParams.get('protocol') ?? '') as Protocol
  );
  const [protocolPickerShown, setProtocolPickerShown] = useState(!protocolPrefilled);

  // Surface picker: the modal lists every full `starter`-tagged
  // template; picking one auto-applies it and dismisses the picker.
  // No more hardcoded per-protocol "blank" surfaces — anything we
  // want to offer ships as a `.json` template with `tags: ["...", "starter"]`.
  const surfaceTemplates = useSurfaceTemplates();
  const starterTemplates = sortTemplatesForDisplay(
    surfaceTemplates.templates.filter(t => t.kind === 'full' && (t.tags ?? []).includes('starter'))
  );
  const [applyingStarterId, setApplyingStarterId] = useState<string | null>(null);
  // Row in the starter-picker that the user has tapped open. Mirrors
  // the templates panel’s expand-to-reveal-details interaction so the
  // long-form `details` field is reachable from the create wizard too.
  const [pickerExpandedId, setPickerExpandedId] = useState<string | null>(null);

  const [description, setDescription] = useState('');
  const [tagsCsv, setTagsCsv] = useState('');
  const [status, setStatus] = useState<AgentSurface['status']>('active');
  const [protocol, setProtocol] = useState<Protocol>(initialProtocol);
  const [surfaceId] = useState<string>(() => crypto.randomUUID());
  const [name, setName] = useState(
    () => `${initialProtocol.toUpperCase()} Surface #${surfaceId.slice(-4)}`
  );
  const [publishToDid, setPublishToDid] = useState(false);
  const [terminateTraceId, setTerminateTraceId] = useState(false);
  const [issuerId, setIssuerId] = useState('');
  const [didwebvh, setDidwebvh] = useState<DidwebvhConfig>(DEFAULT_DIDWEBVH_CONFIG);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasAttemptedSave, setHasAttemptedSave] = useState(false);
  const surfacePolicyLoadState = useSurfacePolicyDefinitions();
  const surfacePolicyIds =
    surfacePolicyLoadState.status === 'loaded' ? surfacePolicyLoadState.ids : null;

  const [activeTab, setActiveTab] = useState<
    'surface' | 'elements' | 'monitoring' | 'config' | 'editor'
  >('surface');

  const [editorTabNodeId, setEditorTabNodeId] = useState<string | null>(null);
  const [jsonOverride, setJsonOverride] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Welcome callout: shown on the canvas the first time the user reaches
  // it in create mode, unless they previously checked "do not show again".
  const [welcomeShown, setWelcomeShown] = useState(false);
  const [welcomeDontShow, setWelcomeDontShow] = useState(false);
  // Template the user picked from the starter list (if any). Drives
  // the welcome balloon title (template name) and body (starter_hint).
  const [chosenTemplate, setChosenTemplate] = useState<import('../api').SurfaceTemplate | null>(
    null
  );
  const welcomeSeenRef = React.useRef(false);
  useEffect(() => {
    if (activeTab !== 'surface' || welcomeSeenRef.current) return;
    if (protocolPickerShown) return;
    if (localStorage.getItem(WELCOME_DISMISSED_KEY) === 'true') return;
    welcomeSeenRef.current = true;
    setWelcomeShown(true);
  }, [activeTab, protocolPickerShown]);
  const handleCloseWelcome = () => {
    if (welcomeDontShow) localStorage.setItem(WELCOME_DISMISSED_KEY, 'true');
    setWelcomeShown(false);
  };

  // Track the target node's screen rect so the callout can float directly
  // above it. Polled via rAF since the d3 canvas mutates SVG transforms
  // outside React's render cycle (zoom, drag, force layout settle).
  const [calloutPos, setCalloutPos] = useState<{ x: number; y: number } | null>(null);
  useEffect(() => {
    if (!welcomeShown || activeTab !== 'surface') {
      setCalloutPos(null);
      return;
    }
    let raf = 0;
    const tick = () => {
      const el = document.querySelector('[data-node-id="target"]');
      if (el) {
        const r = (el as SVGGraphicsElement).getBoundingClientRect();
        setCalloutPos(prev => {
          const next = { x: r.left + r.width / 2, y: r.top };
          if (prev && Math.abs(prev.x - next.x) < 0.5 && Math.abs(prev.y - next.y) < 0.5) {
            return prev;
          }
          return next;
        });
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [welcomeShown, activeTab]);

  // Pre-seed the Access Point with sensible defaults at mount so it
  // reports as Configured before the user clicks it. Without this, the
  // AP shows Incomplete on first canvas visit even though the panel
  // would have auto-filled the same values on its first render.
  const apSeededRef = React.useRef(false);
  useEffect(() => {
    if (apSeededRef.current) return;
    let alive = true;
    fetchRoutingConfig().then(routing => {
      if (!alive || !routing || apSeededRef.current) return;
      apSeededRef.current = true;
      const apNode = builder.state.nodes.find(n => n.id === 'access-point');
      if (!apNode) return;
      if (apNode.config?.route) return;
      builder.handleNodeUpdate('access-point', {
        ...apNode.config,
        ...buildDefaultAccessPointConfig(routing),
      });
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const surfaceSizeRef = useRef<{ w: number; h: number } | null>(null);
  const canvasViewRef = useRef<{ x: number; y: number; k: number } | null>(null);
  /**
   * Snapshot of the empty-form state captured once the Access Point
   * defaults have been seeded. The page is dirty when the live signature
   * differs from this baseline. Suppressed until baseline is set so the
   * unsaved-changes prompt doesn't fire on the initial mount.
   */
  const baselineRef = useRef<string | null>(null);
  /**
   * Set to true the moment the user clicks Create successfully so the
   * post-create `navigate('/surfaces')` doesn't trigger the prompt.
   */
  const justCreatedRef = useRef(false);
  const builder = useSurfaceBuilder<CreateBuilderState>(
    {
      nodes: [
        {
          id: '__human__',
          type: 'human' as SurfaceNodeType,
          label: 'Human',
          configured: true,
          config: {},
        },
        {
          id: '__caller__',
          type: 'caller' as SurfaceNodeType,
          label: 'Caller',
          configured: true,
          config: {},
        },
        {
          id: 'access-point',
          type: 'access-point' as SurfaceNodeType,
          label: '',
          configured: false,
          config: {},
        },
        {
          id: 'target',
          type: 'target' as SurfaceNodeType,
          label: '',
          configured: false,
          config: {},
        },
        {
          id: '__managed-agent-npc__',
          type: 'npc-endpoint' as SurfaceNodeType,
          label: 'External Target',
          configured: true,
          config: {
            name: 'External Target',
            npc_description: 'External agent endpoint',
            connection_direction: 'outbound',
            connected_to: 'target',
          },
          parentId: 'target',
          connectionDirection: 'outbound',
          description: 'External agent endpoint',
        },
        {
          id: 'target-variant',
          type: 'target-variant' as SurfaceNodeType,
          label: 'Variants',
          configured: true,
          config: { variants: [] },
        },
      ],
      selectedNodeId: '__surface__',
    },
    {
      getSurfaceSize: () =>
        surfaceSizeRef.current
          ? { width: surfaceSizeRef.current.w, height: surfaceSizeRef.current.h }
          : null,
      getCanvasView: () => canvasViewRef.current,
      getProtocol: () => protocol,
    }
  );
  const {
    buildPayload,
    hasValidationErrors,
    hasIncompleteNodes,
    hasDependencyErrors,
    dependencyErrors,
  } = builder;

  // Once the AP node has a route replace the "{PROTOCOL} Surface #{xxxx}" placeholder
  // with"{PROTOCOL} Surface - {route}" so users see a meaningful default.
  // Only fires while the name still holds the initial #-id placeholder;
  // once the user has typed custom name the check fails and the name value
  // stay untouched.
  useEffect(() => {
    const route = builder.state.nodes.find(n => n.id === 'access-point')?.config?.route;
    if (!route) return;
    if (!name.startsWith(`${protocol.toUpperCase()} Surface #`)) return;
    setName(`${protocol.toUpperCase()} Surface - ${route}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [builder.state.nodes]);

  const buildSurfacePayload = useCallback((): Partial<AgentSurface> => {
    const payload = buildPayload({
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
    if (payload.access_point) {
      payload.access_point.publish_to_did_document = publishToDid;
      payload.access_point.terminate_trace_id = terminateTraceId;
      if (didwebvh.enabled) {
        const did: Record<string, any> = {
          auto_create: didwebvh.auto_create,
          injection_mode: didwebvh.injection_mode,
        };
        if (didwebvh.identity_id.trim()) did.identity_id = didwebvh.identity_id.trim();
        if (didwebvh.did_path.trim()) did.did_path = didwebvh.did_path.trim();
        payload.access_point.didwebvh_identity = did;
      }
    }
    if (issuerId.trim()) {
      payload.issuer_id = issuerId.trim();
    }
    // Snapshot each variant from base so it doesn't silently inherit
    // later base edits (see freezeEmptyVariantOverrides). Guard the
    // assignment so we never inject an empty `variants: []`.
    if (Array.isArray(payload.variants) && payload.variants.length > 0) {
      payload.variants = freezeEmptyVariantOverrides(payload);
    }
    return payload;
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
  ]);

  const handleOpenFullscreenEditor = useCallback((nodeId: string) => {
    setEditorTabNodeId(nodeId);
    setActiveTab('editor');
  }, []);
  const handleCloseFullscreenEditor = useCallback(() => {
    setEditorTabNodeId(null);
    setActiveTab('surface');
  }, []);

  /**
   * Build a single, user-facing reason explaining why the surface cannot
   * be saved right now. Returns `null` when the surface is ready to POST.
   * The first incomplete element's label + reason is surfaced so the toast
   * matches what the user sees in the Elements tab.
   */
  const computeBlockingReason = (): { message: string; nodeId?: string } | null => {
    if (!name.trim()) return { message: 'Name is required', nodeId: '__surface__' };
    if (!protocol) return { message: 'Protocol is required', nodeId: '__surface__' };
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
    // source auth on the surface). The runtime would either reject or
    // mis-route the surface, so block save here too — the marching-ants
    // ring on the canvas points the user at the offending node.
    const firstDepErr = dependencyErrors[0];
    if (firstDepErr) {
      const def = registry.get(firstDepErr.nodeType);
      return {
        message: `${def?.label ?? firstDepErr.nodeType}: ${firstDepErr.message}`,
        nodeId: firstDepErr.nodeId,
      };
    }
    // Structural validation of the assembled payload — see the matching
    // SurfaceDetailPage block for rationale. Errors block save; warnings
    // surface after a successful POST.
    try {
      const draft = buildSurfacePayload();
      const issues = validateSurfacePayload(draft);
      const firstError = issues.find(i => i.severity === 'error');
      if (firstError) {
        return { message: firstError.message, nodeId: firstError.nodeId };
      }
    } catch {
      return { message: 'Could not assemble surface payload — check the canvas for errors.' };
    }
    return null;
  };

  const showBlockingToast = (blocking: { message: string; nodeId?: string }) => {
    showToast('error', blocking.message, {
      autoRemove: true,
      duration: 8000,
      action: blocking.nodeId
        ? {
            label: 'Show me',
            onClick: () => {
              setActiveTab('surface');
              builder.handleNodeClick(blocking.nodeId!);
            },
          }
        : undefined,
    });
  };

  const handleCreate = async () => {
    setHasAttemptedSave(true);
    const blocking = computeBlockingReason();
    if (blocking) {
      showBlockingToast(blocking);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload: Partial<AgentSurface> = buildSurfacePayload();
      await apiClient.createSurface(payload);
      justCreatedRef.current = true;
      showToast('success', `Agent Surface "${name}" created`);
      // Surface non-blocking structural warnings AFTER create. See
      // SurfaceDetailPage for full rationale.
      const warnings = validateSurfacePayload(payload).filter(i => i.severity === 'warning');
      for (const w of warnings.slice(0, 3)) {
        showToast('error', `Warning: ${w.message}`, { autoRemove: true, duration: 8000 });
      }
      navigate('/surfaces');
    } catch (err: any) {
      setError(err.message || 'Failed to create surface');
    } finally {
      setSaving(false);
    }
  };

  const policyDefinitionsSaveBlocker = surfacePolicyBlockingReason(
    builder.state.nodes,
    surfacePolicyLoadState
  );
  const saveDisabledReason = !name.trim()
    ? 'Name is required'
    : !protocol
      ? 'Protocol is required'
      : jsonError
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

  // Compute the live dirty signature on every render. Cheap (a single
  // JSON.stringify of the canvas + meta state) and reused for both the
  // baseline-capture effect and the unsaved-changes prompt.
  const currentSignature = serializeDirtySignature({
    nodes: builder.state.nodes,
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

  // Capture the baseline once the Access Point has been seeded with its
  // default route. Without waiting for the seed, the async fetch would
  // mutate the AP node *after* baseline capture and the user would see
  // an unsaved-changes prompt without ever touching the form.
  useEffect(() => {
    if (baselineRef.current !== null) return;
    const apNode = builder.state.nodes.find(n => n.id === 'access-point');
    if (!apNode?.config?.route) return;
    baselineRef.current = currentSignature;
  }, [builder.state.nodes, currentSignature]);

  const isDirty =
    !saving &&
    !justCreatedRef.current &&
    baselineRef.current !== null &&
    baselineRef.current !== currentSignature;
  const { discard } = useDiscardWithUndo({ dirty: isDirty, navigateTo: '/surfaces' });

  useSaveShortcut(() => {
    if (saving) return;
    const blocking = computeBlockingReason();
    if (blocking) {
      showBlockingToast(blocking);
      return;
    }
    handleCreate();
  }, builder.commit);

  const configEditorValue = jsonOverride ?? JSON.stringify(buildSurfacePayload(), null, 2);

  /**
   * Live-apply a user-pasted/edited AgentSurface payload from the
   * Config tab to the wizard canvas. Returns `null` on success or an
   * error string surfaced inline by the editor.
   *
   * Mirrors SurfaceDetailPage's helper but uses the wizard's flat
   * (variant-less) state: rebuild nodes via `nodesFromSurface` then
   * replace canvas state and meta in one shot.
   */
  const applyJsonPayloadToCanvas = useCallback(
    (payload: any): string | null => {
      if (!payload || typeof payload !== 'object') return 'Payload must be a JSON object';
      if (!payload.access_point || typeof payload.access_point !== 'object') {
        return 'Payload is missing an access_point';
      }
      const dupErr = findDuplicateListenerRoutes(payload);
      if (dupErr) return dupErr;
      try {
        const hydration = hydrateSurfaceCanvas(payload as AgentSurface);
        const rebuilt = hydration.nodes;
        const savedSize = hydration.surfaceSize;
        const savedView = hydration.view;
        if (savedSize) {
          surfaceSizeRef.current = { w: savedSize.width, h: savedSize.height };
        }
        canvasViewRef.current = savedView ?? null;
        builder.setState(prev => ({
          ...prev,
          nodes: rebuilt,
          selectedNodeId: null,
          surfaceSize: savedSize ? { w: savedSize.width, h: savedSize.height } : prev.surfaceSize,
        }));
        builder.bumpExternalRevision();
        if (hydration.didAutoLayout) builder.bumpResetView();
        const tags = Array.isArray(payload.tags) ? payload.tags : [];
        // Only touch `name` when the payload actually carries the key.
        // Full-template apply deletes it so we preserve whatever the
        // user has already typed (or the empty default).
        if ('name' in payload) {
          setName(typeof payload.name === 'string' ? payload.name : '');
        }
        setDescription(typeof payload.description === 'string' ? payload.description : '');
        setTagsCsv(tags.join(', '));
        if (payload.status) setStatus(payload.status);
        if (payload.access_point?.protocol) setProtocol(payload.access_point.protocol as Protocol);
        setPublishToDid(payload.access_point?.publish_to_did_document ?? false);
        setTerminateTraceId(payload.access_point?.terminate_trace_id ?? false);
        setIssuerId(typeof payload.issuer_id === 'string' ? payload.issuer_id : '');
        const did = payload.access_point?.didwebvh_identity;
        if (did && typeof did === 'object') {
          setDidwebvh({
            enabled: true,
            auto_create: did.auto_create ?? true,
            identity_id: typeof did.identity_id === 'string' ? did.identity_id : '',
            did_path: typeof did.did_path === 'string' ? did.did_path : '',
            injection_mode: did.injection_mode ?? 'header',
          });
        } else {
          setDidwebvh(DEFAULT_DIDWEBVH_CONFIG);
        }
      } catch (err: any) {
        return err?.message || 'Failed to apply payload';
      }
      return null;
    },
    [builder]
  );

  const handleApplyStarterTemplate = useCallback(
    async (tpl: import('../api').SurfaceTemplate) => {
      setApplyingStarterId(tpl.id);
      try {
        const routing = await fetchRoutingConfig();
        const { surface } = autoApplyFullSurfaceTemplate(tpl, routing);
        const tplProtocol = surface?.access_point?.protocol as Protocol | undefined;
        if (tplProtocol && ALL_PROTOCOLS.includes(tplProtocol)) {
          setProtocol(tplProtocol);
          // Derive name from the template's access-point route when available;
          // fall back to the random-id placeholder if the route is absent.
          const tplRoute = surface?.access_point?.route;
          setName(
            tplRoute
              ? `${tplProtocol.toUpperCase()} Surface - ${tplRoute}`
              : `${tplProtocol.toUpperCase()} Surface #${surfaceId.slice(-4)}`
          );
        }
        const err = applyJsonPayloadToCanvas(surface);
        if (err) {
          showToast('error', `Template "${tpl.name}" rejected: ${err}`);
          return;
        }
        showToast(
          'success',
          `Started from "${tpl.name}". Fill in any highlighted fields and Save.`
        );
        setChosenTemplate(tpl);
        setProtocolPickerShown(false);
      } finally {
        setApplyingStarterId(null);
      }
    },
    [applyJsonPayloadToCanvas]
  );

  // When the picker is up we render *only* the picker as a full-page
  // modal-styled card. The surface builder (canvas, tabs, side panels)
  // is intentionally NOT mounted yet so the user can't see or touch any
  // default surface state behind the chooser. Builder state still
  // exists in memory via `useSurfaceBuilder`; once the user picks a
  // template, `handleApplyStarterTemplate` populates it from the
  // template snapshot and dismisses the picker, at which point the
  // builder renders.
  if (protocolPickerShown) {
    return (
      <div className="container-fluid surface-page-fill surface-page-fill--picker">
        <div className="surface-canvas-protocol-picker">
          <div
            className="card shadow channel-editor-card surface-picker-card"
            role="dialog"
            aria-modal="true"
            aria-label="Pick a starter template for this surface"
          >
            <div className="card-header py-3 d-flex align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-layer-group me-2"></i> Start a new surface
              </h6>
            </div>
            <div className="card-body-channel-editor surface-picker-card__body">
              <p className="text-muted small mb-3">
                Select a Surface Starter Template from the list below.
              </p>
              {surfaceTemplates.loading ? (
                <div className="text-muted small">
                  <span className="spinner-border spinner-border-sm me-2" />
                  Loading starter templates…
                </div>
              ) : surfaceTemplates.error ? (
                <div className="alert alert-danger py-2 px-3 small mb-0">
                  <i className="fas fa-times-circle me-1" />
                  {surfaceTemplates.error}
                </div>
              ) : starterTemplates.length === 0 ? (
                <div className="text-muted small">
                  No starter templates are installed. Ship one as a full-kind template with{' '}
                  <code>tags: ["starter"]</code>.
                </div>
              ) : (
                <ul className="list-unstyled mb-0">
                  {starterTemplates.map(tpl => {
                    const applying = applyingStarterId === tpl.id;
                    const icon = tpl.icon ? `fa-${tpl.icon}` : 'fa-layer-group';
                    const protoBadge = getTemplateProtocolBadge(tpl);
                    const hasDetails = !!tpl.details && tpl.details.trim().length > 0;
                    const expanded = pickerExpandedId === tpl.id;
                    const toggle = () => {
                      if (!hasDetails) return;
                      setPickerExpandedId(prev => (prev === tpl.id ? null : tpl.id));
                    };
                    return (
                      <li
                        key={tpl.id}
                        className="surface-template-row surface-template-row--static"
                      >
                        <div
                          className="surface-template-row__header surface-template-row__header--static"
                          role={hasDetails ? 'button' : undefined}
                          tabIndex={hasDetails ? 0 : undefined}
                          aria-expanded={hasDetails ? expanded : undefined}
                          style={{ cursor: hasDetails ? 'pointer' : 'default' }}
                          onClick={toggle}
                          onKeyDown={e => {
                            if (!hasDetails) return;
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              toggle();
                            }
                          }}
                        >
                          <i className={`fas ${icon} surface-template-row__icon`} />
                          <div className="flex-grow-1" style={{ minWidth: 0 }}>
                            <div className="surface-template-row__title">{tpl.name}</div>
                            {tpl.description && (
                              <div className="surface-template-row__description">
                                {tpl.description}
                              </div>
                            )}
                          </div>
                          {protoBadge && (
                            <span
                              className={`badge ${protoBadge.badgeClass} me-2`}
                              title={`Access-point protocol: ${protoBadge.label}`}
                            >
                              {protoBadge.label}
                            </span>
                          )}
                          <button
                            type="button"
                            className="btn btn-sm btn-primary surface-template-row__action"
                            disabled={applying}
                            aria-label={`Use template ${tpl.name}`}
                            title={`Use template ${tpl.name}`}
                            onClick={e => {
                              e.stopPropagation();
                              void handleApplyStarterTemplate(tpl);
                            }}
                          >
                            {applying ? (
                              <span className="spinner-border spinner-border-sm" />
                            ) : (
                              <i className="fas fa-arrow-right" />
                            )}
                          </button>
                          {hasDetails && (
                            <i
                              className={`fas fa-chevron-${expanded ? 'up' : 'down'} text-muted`}
                              style={{ fontSize: 11 }}
                            />
                          )}
                        </div>
                        {hasDetails && expanded && (
                          <div className="surface-template-row__body">
                            <div className="surface-template-row__details">{tpl.details}</div>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
            <div className="card-footer d-flex justify-content-end">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => navigate('/surfaces')}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid surface-page-fill">
      {error && (
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-circle me-2" />
          {error}
        </div>
      )}

      <SurfaceFormShell
        mode="create"
        canEdit={true}
        builder={builder}
        surfaceId={surfaceId}
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
        manageActions={
          <div className="d-flex gap-2">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={discard}
              disabled={saving}
              title="Back to surfaces"
            >
              <i className="fas fa-arrow-left" />
            </button>
            <button
              type="button"
              className="btn btn-success btn-sm"
              onClick={handleCreate}
              disabled={saving || !!saveDisabledReason}
              title={saveDisabledReason || (saving ? 'Creating…' : 'Create surface')}
            >
              {saving ? <i className="fas fa-spinner fa-spin" /> : <i className="fas fa-check" />}
            </button>
          </div>
        }
        surfaceSizeRef={surfaceSizeRef}
        canvasViewRef={canvasViewRef}
        canvasOverlay={
          welcomeShown && activeTab === 'surface' && calloutPos ? (
            <div
              className="surface-canvas-callout surface-canvas-callout--floating"
              style={{
                position: 'fixed',
                left: calloutPos.x,
                top: calloutPos.y - 16,
                transform: 'translate(-50%, -100%)',
              }}
            >
              <button
                type="button"
                className="surface-canvas-callout__close"
                aria-label="Dismiss"
                onClick={handleCloseWelcome}
              >
                <i className="fas fa-times" />
              </button>
              <div className="surface-canvas-callout__title">
                <i className="fas fa-info-circle me-2" />
                {chosenTemplate?.name ?? 'Configure your Managed Agent'}
              </div>
              {chosenTemplate?.starter_hint ? (
                <p className="surface-canvas-callout__body" style={{ whiteSpace: 'pre-wrap' }}>
                  {chosenTemplate.starter_hint}
                </p>
              ) : (
                <p className="surface-canvas-callout__body">
                  We have pre-configured an Access Point for this Agent Surface, and are ready for
                  you to provide the endpoint details for the{' '}
                  <strong>{protocol.toUpperCase()}</strong> agent managed by this Surface. You can
                  choose a direct URL that is reachable on the network, or you can use an Affinidi
                  Trust Fabric connected Gateway endpoint.
                </p>
              )}
              <div className="surface-canvas-callout__footer">
                <label className="surface-canvas-callout__dontshow">
                  <input
                    type="checkbox"
                    checked={welcomeDontShow}
                    onChange={e => setWelcomeDontShow(e.target.checked)}
                  />
                  Do not show this again
                </label>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={handleCloseWelcome}
                >
                  Got it
                </button>
              </div>
              <span className="surface-canvas-callout__tail" />
            </div>
          ) : undefined
        }
      />
    </div>
  );
};

export default AddSurfacePage;
