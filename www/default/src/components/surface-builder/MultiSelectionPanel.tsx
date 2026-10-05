import React, { useEffect, useRef, useState } from 'react';
import { CanvasNode } from './SurfaceCanvas';
import { registry } from './elements';
import { isSyntheticFabricNodeId } from './elements/synthesizeFabric';
import type { SurfaceNodeType } from './nodeTypes';

const PANEL_WIDTH_KEY = 'surface-builder-panel-width';

interface MultiSelectionPanelProps {
  selectedIds: string[];
  allNodes: CanvasNode[];
  /**
   * Replace the multi-selection with `nextIds`. Sourced from the same
   * `setMultiSelection` callback the canvas uses, so canvas highlights
   * stay in sync when the user toggles a checkbox here.
   */
  setSelection: (nextIds: string[]) => void;
  /**
   * Switch the sidebar to the Templates view in "create from selection"
   * mode. Phase-4 wiring; until then this is left optional and the
   * button is disabled when not provided.
   */
  onCreateTemplate?: (selectedIds: string[]) => void;
  onClose: () => void;
}

const FALLBACK_ICON = 'fa-cog';
const FALLBACK_COLOR = '#858796';

function defLabel(type: SurfaceNodeType): string {
  return registry.get(type)?.label ?? 'Element';
}
function defIcon(type: SurfaceNodeType): string {
  return registry.get(type)?.paletteIcon ?? FALLBACK_ICON;
}
function defColor(type: SurfaceNodeType): string {
  return registry.get(type)?.color ?? FALLBACK_COLOR;
}

const MultiSelectionPanel: React.FC<MultiSelectionPanelProps> = ({
  selectedIds,
  allNodes,
  setSelection,
  onCreateTemplate,
  onClose,
}) => {
  // Reuse the same width key as NodeConfigPanel so users get a
  // consistent panel size when toggling between the two.
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
  const panelWidthRef = useRef(panelWidth);
  useEffect(() => {
    panelWidthRef.current = panelWidth;
  }, [panelWidth]);

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

  // Resolve nodes in stable canvas order so the list doesn't reshuffle
  // as the user adds/removes ticks.
  const selectedSet = new Set(selectedIds);
  // Only "managed" items (configurable, persisted) can be bulk-edited
  // or templated. NPCs (palette category `npc`) and synthetic fabric
  // nodes (hop / remote-gateway / remote-channel) are context-only and
  // are excluded here so the panel reflects what the user can act on.
  const rows = allNodes
    .filter(n => selectedSet.has(n.id))
    .filter(n => {
      if (isSyntheticFabricNodeId(n.id)) return false;
      if (registry.get(n.type)?.paletteCategory === 'npc') return false;
      return true;
    })
    .map(n => ({
      id: n.id,
      type: n.type,
      label: (typeof n.config?.name === 'string' && n.config.name.trim()) || defLabel(n.type),
    }));

  const toggle = (id: string) => {
    if (selectedSet.has(id)) {
      setSelection(selectedIds.filter(x => x !== id));
    } else {
      setSelection([...selectedIds, id]);
    }
  };

  const clearAll = () => setSelection([]);

  const count = rows.length;
  const canCreateTemplate = count > 0 && !!onCreateTemplate;

  return (
    <div className="surface-builder-config" style={{ width: panelWidth }}>
      <div
        className={`config-resize-handle ${isResizing ? 'active' : ''}`}
        onMouseDown={handleResizeStart}
      />
      <div className="config-panel-header">
        <h5>
          <i className="fas fa-object-group me-2" style={{ color: '#4e73df' }} />
          {count === 0 ? 'No managed items selected' : `${count} selected`}
        </h5>
        <button className="close-btn" onClick={onClose} title="Clear selection">
          <i className="fas fa-times" />
        </button>
      </div>

      <div className="config-section">
        <p className="text-muted small mb-2">
          {count === 0
            ? 'The current selection only contains context nodes (NPCs or fabric hops) which cannot be bulk edited or templated.'
            : 'Tick the items to include. Unticking removes a node from the selection both here and on the canvas.'}
        </p>
        <ul className="list-unstyled mb-0">
          {rows.map(row => (
            <li
              key={row.id}
              className="d-flex align-items-center py-1 px-2 rounded"
              style={{ gap: 8 }}
            >
              <input
                type="checkbox"
                className="form-check-input m-0"
                checked
                onChange={() => toggle(row.id)}
                aria-label={`Deselect ${row.label}`}
              />
              <i
                className={`fas ${defIcon(row.type)}`}
                style={{ color: defColor(row.type), width: 16, textAlign: 'center' }}
              />
              <div className="flex-grow-1 text-truncate">
                <div className="small fw-semibold text-truncate" title={row.label}>
                  {row.label}
                </div>
                <div className="text-muted" style={{ fontSize: '11px' }}>
                  {defLabel(row.type)}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="config-section">
        <button
          type="button"
          className="btn btn-primary btn-sm w-100 mb-2"
          onClick={() => onCreateTemplate?.(selectedIds)}
          disabled={!canCreateTemplate}
          title={
            canCreateTemplate
              ? 'Open the Templates view in create mode with these items'
              : 'Templates view not available yet'
          }
        >
          <i className="fas fa-layer-group me-1" /> Create Template from Selection
        </button>
        <button type="button" className="btn btn-outline-secondary btn-sm w-100" onClick={clearAll}>
          <i className="fas fa-eraser me-1" /> Clear Selection
        </button>
      </div>
    </div>
  );
};

export default MultiSelectionPanel;
