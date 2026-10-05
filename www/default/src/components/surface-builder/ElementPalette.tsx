import React, { useCallback, useState, useMemo, useRef } from 'react';
import type { SurfaceNodeType } from './nodeTypes';
import { registry } from './elements';
import type { NodeDefinition, PaletteCategory } from './elements/types';
import HelpBalloon from './HelpBalloon';

interface ElementPaletteProps {
  existingNodes: { type: SurfaceNodeType }[];
  protocol?: string;
  /**
   * `overlay` (default): floating glass card pinned over the canvas with
   * its own hide toggle. `inline`: bare list intended for the form
   * shell's left sidebar — no positioning, no hide button.
   */
  variant?: 'overlay' | 'inline';
  /** Called once when the user starts dragging any item. Used by the
   *  shell to auto-switch to the Surface view so the drop target appears. */
  onAnyDragStart?: () => void;
}

const CATEGORY_ORDER: PaletteCategory[] = [
  'transitPoints',
  'policy',
  'enhancement',
  'npc',
  'actor',
];
const CATEGORY_LABELS: Record<PaletteCategory, string> = {
  transitPoints: 'Transit Points',
  policy: 'Security & Policy',
  enhancement: 'Enhancements',
  npc: 'NPCs (External Actors)',
  actor: 'Actors',
};

const ElementPalette: React.FC<ElementPaletteProps> = ({
  existingNodes,
  protocol,
  variant = 'overlay',
  onAnyDragStart,
}) => {
  const [hidden, setHidden] = useState(false);
  const [filter, setFilter] = useState('');
  const [showDescs, setShowDescs] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    transitPoints: false,
    policy: false,
    enhancement: false,
    npc: false,
    actor: false,
  });

  const toggleSection = (key: string) => setExpanded(prev => ({ ...prev, [key]: !prev[key] }));

  const itemsByCategory = useMemo(
    () => registry.paletteByCategory((protocol as any) || 'http'),
    [protocol]
  );

  const filterLower = filter.trim().toLowerCase();

  /** "tp" matches "Transit Point", "ap" matches "Access Point", etc. */
  function matchesFilter(label: string, description: string | undefined, query: string): boolean {
    const l = label.toLowerCase();
    if (l.includes(query)) return true;
    if (description && description.toLowerCase().includes(query)) return true;
    // Acronym match: first letter of each word
    const initials = l
      .split(/\s+/)
      .map(w => w[0] ?? '')
      .join('');
    return initials.startsWith(query);
  }

  const filteredByCategory = useMemo(() => {
    if (!filterLower) return itemsByCategory;
    const result: Record<string, NodeDefinition[]> = {};
    for (const [cat, items] of Object.entries(itemsByCategory)) {
      const matched = items.filter(d => matchesFilter(d.label, d.description, filterLower));
      if (matched.length > 0) result[cat] = matched;
    }
    return result;
  }, [itemsByCategory, filterLower]);

  const isDisabled = useCallback(
    (def: NodeDefinition) => {
      if (def.cardinality !== 'singleton') return false;
      return existingNodes.some(n => n.type === def.type);
    },
    [existingNodes]
  );

  const handleDragStart = useCallback(
    (e: React.DragEvent, def: NodeDefinition) => {
      e.dataTransfer.setData('application/surface-element', def.type);
      e.dataTransfer.setData(`application/surface-type-${def.type}`, '');
      e.dataTransfer.effectAllowed = 'copy';
      mouseDownRef.current = null;
      setHelp(null);
      onAnyDragStart?.();
    },
    [onAnyDragStart]
  );

  // ── Click-vs-drag detection for the help balloon ──
  // Browsers reliably suppress the synthetic `click` event when an HTML5
  // drag actually starts on a `draggable` element, so `onClick` already
  // fires only for true clicks. We still track the mousedown position so
  // (a) the balloon anchors at the item's bounding rect (captured before
  // any layout shift) and (b) tiny accidental moves while the button is
  // held don't fire — though in practice the browser handles that too.
  const [help, setHelp] = useState<{ type: SurfaceNodeType; rect: DOMRect } | null>(null);
  const mouseDownRef = useRef<{
    type: SurfaceNodeType;
    rect: DOMRect;
  } | null>(null);

  const handleMouseDown = useCallback((e: React.MouseEvent, def: NodeDefinition) => {
    if (e.button !== 0) return;
    mouseDownRef.current = {
      type: def.type,
      rect: (e.currentTarget as HTMLElement).getBoundingClientRect(),
    };
  }, []);

  const handleClick = useCallback((e: React.MouseEvent, def: NodeDefinition) => {
    const start = mouseDownRef.current;
    mouseDownRef.current = null;
    if (!def.help) return;
    const rect =
      start && start.type === def.type
        ? start.rect
        : (e.currentTarget as HTMLElement).getBoundingClientRect();
    e.stopPropagation();
    setHelp(prev => (prev?.type === def.type ? null : { type: def.type, rect }));
  }, []);

  const renderItem = (def: NodeDefinition) => {
    const disabled = isDisabled(def);
    const iconClass = def.paletteIcon || 'fa-square';
    return (
      <div
        key={def.type}
        className={`palette-item ${disabled ? 'disabled' : ''} ${
          help?.type === def.type ? 'palette-item--help-open' : ''
        }`}
        draggable={!disabled}
        onDragStart={e => handleDragStart(e, def)}
        onMouseDown={e => handleMouseDown(e, def)}
        onClick={e => handleClick(e, def)}
        title={disabled ? `${def.label} already added (singleton)` : def.description}
      >
        <div className={`palette-item-icon ${def.type}`} style={{ background: def.color }}>
          <i className={`fas ${iconClass}`} />
        </div>
        <div className="palette-item-text">
          <span className="palette-item-name">{def.label}</span>
          <span className="palette-item-desc">{def.description}</span>
        </div>
      </div>
    );
  };

  const sections = CATEGORY_ORDER.map(cat => {
    const items = filteredByCategory[cat] || [];
    if (items.length === 0) return null;
    const isExpanded = !!filterLower || expanded[cat];
    return (
      <React.Fragment key={cat}>
        <h6
          className="palette-section-header"
          onClick={() => toggleSection(cat)}
          style={{ cursor: 'pointer', userSelect: 'none' }}
        >
          <i
            className={`fas fa-chevron-${isExpanded ? 'down' : 'right'} me-1`}
            style={{ fontSize: '9px' }}
          />
          {CATEGORY_LABELS[cat]}
        </h6>
        {isExpanded && items.map(renderItem)}
      </React.Fragment>
    );
  });

  // Resolve the help def for the currently-open balloon (if any).
  const helpDef = help ? registry.get(help.type) : undefined;
  const helpNode =
    help && helpDef?.help ? (
      <HelpBalloon
        anchorRect={help.rect}
        title={helpDef.help.title ?? helpDef.label}
        bodyHtml={helpDef.help.bodyHtml}
        docLink={helpDef.help.docLink}
        docLinkLabel={helpDef.help.docLinkLabel}
        onClose={() => setHelp(null)}
      />
    ) : null;

  const descsVisible = showDescs;

  const filterInput = (
    <div className="palette-filter mb-2 d-flex align-items-center gap-1">
      <div className="position-relative flex-grow-1">
        <i
          className="fas fa-search position-absolute"
          style={{
            left: 8,
            top: '50%',
            transform: 'translateY(-50%)',
            fontSize: '10px',
            color: '#858796',
          }}
        />
        <input
          type="text"
          className="form-control form-control-sm"
          placeholder="Filter elements…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ paddingLeft: 26, fontSize: '11px' }}
        />
        {filter && (
          <button
            className="btn btn-link btn-sm position-absolute p-0"
            style={{
              right: 6,
              top: '50%',
              transform: 'translateY(-50%)',
              fontSize: '10px',
              color: '#858796',
            }}
            onClick={() => setFilter('')}
            title="Clear filter"
          >
            <i className="fas fa-times" />
          </button>
        )}
      </div>
      <button
        className={`btn btn-sm palette-desc-toggle ${descsVisible ? 'active' : ''}`}
        onClick={() => setShowDescs(p => !p)}
        title={showDescs ? 'Hide descriptions' : 'Show descriptions'}
        style={{
          fontSize: '10px',
          flexShrink: 0,
          padding: '2px 6px',
          borderRadius: '4px',
          border: `1px solid ${descsVisible ? '#4e73df' : '#d1d3e2'}`,
          background: descsVisible ? '#4e73df' : 'transparent',
          color: descsVisible ? '#fff' : '#858796',
          lineHeight: 1,
          userSelect: 'none',
          outline: 'none',
          boxShadow: 'none',
        }}
      >
        <i className="fas fa-align-left" />
      </button>
    </div>
  );

  if (variant === 'inline') {
    return (
      <div className={`surface-builder-palette-inline ${descsVisible ? 'palette-show-descs' : ''}`}>
        {filterInput}
        {sections}
        {helpNode}
      </div>
    );
  }

  return (
    <>
      {hidden && (
        <button
          className="palette-toggle-btn"
          onClick={() => setHidden(false)}
          title="Show elements"
        >
          <i className="fas fa-th-large" />
        </button>
      )}
      <div
        className={`surface-builder-palette ${hidden ? 'hidden' : ''} ${descsVisible ? 'palette-show-descs' : ''}`}
      >
        <div className="d-flex align-items-center gap-2 mb-2">
          <i className="fas fa-th-large text-muted" />
          <span style={{ fontSize: '13px', fontWeight: 700, color: '#3a3b45' }}>Elements</span>
          <button
            className="btn btn-link btn-sm ms-auto p-0"
            onClick={() => setHidden(true)}
            title="Hide elements panel"
            style={{ fontSize: '12px', color: '#858796' }}
          >
            <i className="fas fa-chevron-left" />
          </button>
        </div>
        {filterInput}
        {sections}
      </div>
      {helpNode}
    </>
  );
};

export default ElementPalette;
