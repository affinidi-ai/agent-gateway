import React, { useState, useRef, useEffect } from 'react';
import { Form } from 'react-bootstrap';
import { AppButton } from '../shared/AppButton';
import { CanvasNode, getIncompleteReason } from './SurfaceCanvas';
import type { SurfaceNodeType } from './nodeTypes';
import { registry, buildSurfaceContext } from './elements';
import HelpBalloon from './HelpBalloon';
import { shouldShowDependencyWarnings } from './dependencyWarningVisibility';

const PANEL_WIDTH_KEY = 'surface-builder-panel-width';

interface NodeConfigPanelProps {
  node: CanvasNode | null;
  onUpdate: (nodeId: string, config: any) => void;
  onRemove: (nodeId: string) => void;
  onClose: () => void;
  /** Called when the panel wants to open this node's fullscreen editor in a new builder tab. */
  onOpenFullscreenEditor?: (nodeId: string) => void;
  protocol?: string;
  allNodes?: CanvasNode[];
  /**
   * Bumps when the parent applies an external mutation (undo / redo) so
   * inner Panels with uncontrolled local state remount and resync from
   * `node.config`.
   */
  externalRevision?: number;
  /**
   * Replace the most recent committed history snapshot with the current
   * state in-place. Forwarded to ConfigPanel implementations whose
   * mount-time seeding effects need to coalesce auto-seeded defaults
   * into the snapshot created by the drop, so that a single undo from
   * after-seed jumps straight back to before-drop.
   */
  replaceCommit?: () => void;
  /**
   * Set to true by the page on the first Create / Save attempt. Gates
   * the incomplete banner and per-field validation errors so panels start
   * clean on open.
   */
  hasAttemptedSave?: boolean;
}

const FALLBACK_LABEL = 'Element';
const FALLBACK_ICON = 'fa-cog';
const FALLBACK_COLOR = '#858796';

function defLabel(type: SurfaceNodeType): string {
  return registry.get(type)?.label ?? FALLBACK_LABEL;
}

function defNamePlaceholder(type: SurfaceNodeType): string {
  return registry.get(type)?.namePlaceholder ?? defLabel(type);
}

function defPaletteIcon(type: SurfaceNodeType): string {
  return registry.get(type)?.paletteIcon ?? FALLBACK_ICON;
}

function defColor(type: SurfaceNodeType): string {
  return registry.get(type)?.color ?? FALLBACK_COLOR;
}

const NodeConfigPanel: React.FC<NodeConfigPanelProps> = ({
  node,
  onUpdate,
  onRemove,
  onClose,
  onOpenFullscreenEditor,
  protocol,
  allNodes,
  externalRevision = 0,
  replaceCommit,
  hasAttemptedSave = false,
}) => {
  const [panelWidth, setPanelWidth] = useState(() => {
    try {
      const stored = localStorage.getItem(PANEL_WIDTH_KEY);
      if (stored) {
        const n = parseInt(stored, 10);
        if (Number.isFinite(n)) return Math.min(Math.max(n, 280), 900);
      }
    } catch {
      /* ignore */
    }
    return 420;
  });
  const [isResizing, setIsResizing] = useState(false);

  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
    const startX = e.clientX;
    const startWidth = panelWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = startX - moveEvent.clientX;
      const newWidth = Math.min(Math.max(startWidth + delta, 280), 900);
      setPanelWidth(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      try {
        localStorage.setItem(PANEL_WIDTH_KEY, String(panelWidthRef.current));
      } catch {
        /* ignore */
      }
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const panelWidthRef = useRef(panelWidth);
  useEffect(() => {
    panelWidthRef.current = panelWidth;
  }, [panelWidth]);

  // Reopens the same in-palette help balloon for the placed node, since
  // the palette itself is no longer visible/relevant once a node is on
  // the canvas and selected.
  const [helpAnchorRect, setHelpAnchorRect] = useState<DOMRect | null>(null);
  useEffect(() => {
    setHelpAnchorRect(null);
  }, [node?.id]);

  if (!node) {
    return <div className="surface-builder-config collapsed" />;
  }

  const updateField = (field: string, value: any) => {
    onUpdate(node.id, { ...node.config, [field]: value });
  };
  const updateFields = (fields: Record<string, any>) => {
    onUpdate(node.id, { ...node.config, ...fields });
  };

  const def = registry.get(node.type);
  const Panel = def?.ConfigPanel;
  const ctx = buildSurfaceContext(protocol, allNodes);
  const warnings = registry.getDependencyWarnings(node.type, node.config, ctx);
  const validationErrors = registry.getValidationErrors(node.type, node.config);
  const label = defLabel(node.type);
  const isFullscreenSurface = def?.configSurface === 'fullscreen';
  const hasFullscreenEditor = !!def?.FullscreenPanel || isFullscreenSurface;
  const canDelete = def?.deletable !== false;
  const requestFullscreen = () => hasFullscreenEditor && onOpenFullscreenEditor?.(node.id);

  return (
    <div className="surface-builder-config" style={{ width: panelWidth }}>
      <div
        className={`config-resize-handle ${isResizing ? 'active' : ''}`}
        onMouseDown={handleResizeStart}
      />
      <div className="config-panel-header">
        <h5>
          <i
            className={`fas ${defPaletteIcon(node.type)} me-2`}
            style={{ color: defColor(node.type) }}
          />
          {label}
        </h5>
        <div className="config-panel-header-actions">
          {def?.help && (
            <button
              type="button"
              className="help-btn"
              data-help-toggle="true"
              data-testid={`node-config-help-${node.type}`}
              onClick={e =>
                setHelpAnchorRect(prev =>
                  prev ? null : (e.currentTarget as HTMLElement).getBoundingClientRect()
                )
              }
              title={`About ${label}`}
              aria-label={`About ${label}`}
            >
              <i className="fas fa-question-circle" />
            </button>
          )}
          <button className="close-btn" onClick={onClose} title="Close">
            <i className="fas fa-times" />
          </button>
        </div>
      </div>

      {helpAnchorRect && def?.help && (
        <HelpBalloon
          anchorRect={helpAnchorRect}
          title={def.help.title ?? label}
          bodyHtml={def.help.bodyHtml}
          docLink={def.help.docLink}
          docLinkLabel={def.help.docLinkLabel}
          onClose={() => setHelpAnchorRect(null)}
        />
      )}

      {hasAttemptedSave &&
        !node.configured &&
        (() => {
          if (def?.suppressIncompleteBanner?.(node.config)) return null;
          const reason = getIncompleteReason(node.type, node.config);
          return reason ? (
            <div className="config-incomplete-banner">
              <i className="fas fa-exclamation-circle me-2" />
              {reason}
            </div>
          ) : null;
        })()}

      {warnings.length > 0 && shouldShowDependencyWarnings(node.type, hasAttemptedSave) && (
        <div className="config-section">
          {warnings.map((w, i) => (
            <div
              key={i}
              className={`alert alert-${w.severity === 'error' ? 'danger' : 'warning'} py-1 px-2 mb-1`}
              style={{ fontSize: '11px' }}
            >
              <i
                className={`fas fa-${w.severity === 'error' ? 'times-circle' : 'exclamation-triangle'} me-1`}
              />
              {w.message}
            </div>
          ))}
        </div>
      )}

      {node.type !== 'surface' && (
        <div className="config-section">
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">Name</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              placeholder={defNamePlaceholder(node.type)}
              value={node.config?.name || ''}
              onChange={e => updateField('name', e.target.value)}
            />
          </Form.Group>
          {node.type.startsWith('npc-') && (
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1">Description</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="What does this actor/system do?"
                value={node.config?.npc_description || ''}
                onChange={e => updateField('npc_description', e.target.value)}
              />
            </Form.Group>
          )}
          {(node.type === 'human' || node.type === 'caller') && (
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1">Description</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder={
                  node.type === 'human' ? 'Describe the human user' : 'Describe the calling system'
                }
                value={node.config?.description || ''}
                onChange={e => updateField('description', e.target.value)}
              />
            </Form.Group>
          )}
        </div>
      )}

      {Panel ? (
        isFullscreenSurface ? (
          <div className="config-section">
            <p className="text-muted small mb-2">
              {def?.description ?? 'This element has detailed configuration.'}
            </p>
            <button
              className="btn btn-outline-primary btn-sm w-100"
              onClick={requestFullscreen}
              disabled={!onOpenFullscreenEditor}
            >
              <i className="fas fa-pen-to-square me-1" /> Edit {label}…
            </button>
          </div>
        ) : (
          <Panel
            key={`${node.id}:${externalRevision}`}
            node={node}
            config={node.config || {}}
            updateField={updateField}
            updateFields={updateFields}
            protocol={protocol as any}
            allNodes={allNodes}
            openFullscreenEditor={hasFullscreenEditor ? requestFullscreen : undefined}
            replaceCommit={replaceCommit}
            errorByField={
              hasAttemptedSave
                ? Object.fromEntries(
                    validationErrors.filter(v => v.field).map(v => [v.field as string, v.message])
                  )
                : {}
            }
            hasAttemptedSave={hasAttemptedSave}
          />
        )
      ) : node.type === 'local-gateway-hop' ? (
        <p className="text-muted">
          {node.config?.kind === 'proxy'
            ? 'To change which MCP proxy this hop fronts, update the destination on the Managed Agent component.'
            : 'To change details of the remote Gateway, update the destination on the Managed Agent component.'}
        </p>
      ) : (
        <p className="text-muted">No configuration available.</p>
      )}

      {canDelete && (
        <div className="mt-4">
          <AppButton
            variant="outline-danger"
            size="sm"
            className="w-100"
            onClick={() => onRemove(node.id)}
            iconStart={<i className="fas fa-trash me-1" aria-hidden="true" />}
          >
            Remove {label}
          </AppButton>
        </div>
      )}
    </div>
  );
};

export default NodeConfigPanel;
