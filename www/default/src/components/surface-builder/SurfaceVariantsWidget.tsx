import React, { useEffect, useRef, useState } from 'react';
import type { CanvasNode } from './SurfaceCanvas';
import type { VariantEntry } from './elements/target-variant/definition';
import { BASE_VARIANT_ID } from './variants/useVariantSnapshots';

interface SurfaceVariantsWidgetProps {
  /** All current builder nodes — we look up the singleton target-variant node. */
  nodes: CanvasNode[];
  /** Whether the variants editor (target-variant node) is the current selection. */
  selected: boolean;
  /** Open the variants editor by selecting the target-variant node. */
  onOpen: () => void;
  /**
   * Open the variants editor AND immediately seed a new variant row so
   * the user lands on a ready-to-edit entry. Used by the zero-state
   * "+" affordance and the dropdown's "Add variant…" item.
   */
  onAddVariant?: () => void;
  /** Currently active variant id (from the page-level snapshot manager). */
  activeVariantId?: string | null;
  /**
   * Switch the active variant. Only invoked when the user picks an
   * entry from the dropdown; the page is responsible for swapping the
   * canvas state via the snapshot manager.
   */
  onSwitchVariant?: (variantId: string) => void;
}

/**
 * Always-on overlay control pinned to the top-left of the surface
 * builder shell. Acts as a switcher when the surface has variants and
 * as an "open editor" affordance otherwise.
 *
 * The underlying `target-variant` node is hidden from the canvas and
 * the palette; this widget is the only entry point.
 */
const SurfaceVariantsWidget: React.FC<SurfaceVariantsWidgetProps> = ({
  nodes,
  selected,
  onOpen,
  onAddVariant,
  activeVariantId,
  onSwitchVariant,
}) => {
  const node = nodes.find(n => n.id === 'target-variant');
  const variants: VariantEntry[] = Array.isArray(node?.config?.variants)
    ? (node!.config.variants as VariantEntry[])
    : [];
  const defaultId: string | undefined =
    typeof node?.config?.default_variant_id === 'string' && node!.config.default_variant_id
      ? node!.config.default_variant_id
      : undefined;
  // Base is always-present — it represents the surface with no
  // variant overlay applied. When `defaultId` is undefined the base
  // is the implicit default (alias-less URLs resolve to the bare
  // surface).
  const baseIsDefault = !defaultId;
  const isBaseActive = activeVariantId === BASE_VARIANT_ID || activeVariantId == null;
  const count = variants.length;
  const active = variants.find(v => v.id === activeVariantId);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  // No variants yet — show the implicit "base" surface as the active
  // entry, with a right-justified "+" that opens the editor and seeds
  // a new variant. Clicking elsewhere on the row just opens the
  // editor (no creation), so the user can inspect the panel first.
  if (count === 0) {
    return (
      <div
        ref={rootRef}
        className={`surface-variants-widget surface-variants-widget--zero${selected ? ' is-selected' : ''}`}
      >
        <button
          type="button"
          className="surface-variants-widget-row"
          onClick={onOpen}
          title="Open variants editor"
        >
          <i className="fas fa-code-branch widget-icon" />
          <span className="widget-body">
            <span className="widget-title">Variant</span>
            <span className="widget-meta">
              <strong>base</strong>
            </span>
          </span>
        </button>
        <button
          type="button"
          className="surface-variants-widget-add"
          onClick={e => {
            // Don't let the click bubble into the row's open handler —
            // we want the "+" to open AND seed, not open twice.
            e.stopPropagation();
            if (onAddVariant) onAddVariant();
            else onOpen();
          }}
          title="Add a new variant"
          aria-label="Add a new variant"
        >
          <i className="fas fa-plus" />
        </button>
      </div>
    );
  }

  // Switcher mode — the surface has at least one named variant. The
  // dropdown always lists `base` as the first entry; `base` is the
  // implicit default when no named variant is marked as default.
  const displayLabel = isBaseActive ? 'base' : active?.name || active?.alias || '—';
  const displayAlias = isBaseActive ? null : active?.alias;

  return (
    <div ref={rootRef} className="surface-variants-widget-wrapper">
      <div
        role="button"
        tabIndex={0}
        className={`surface-variants-widget${selected ? ' is-selected' : ''}${open ? ' is-open' : ''}`}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen(o => !o);
          }
        }}
        title={`Active variant: ${displayLabel}`}
      >
        <i className="fas fa-code-branch widget-icon" />
        <span className="widget-body">
          <span className="widget-title">Variant</span>
          <span className="widget-meta">
            <strong>{displayLabel}</strong>
            {displayAlias && (
              <>
                {' '}
                <code
                  className="surface-variants-widget-alias-link"
                  role="button"
                  tabIndex={0}
                  title="Open variants properties"
                  onClick={e => {
                    e.stopPropagation();
                    setOpen(false);
                    onOpen();
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      e.stopPropagation();
                      setOpen(false);
                      onOpen();
                    }
                  }}
                >
                  ${displayAlias}
                </code>
              </>
            )}
          </span>
        </span>
        <i className={`fas fa-chevron-${open ? 'up' : 'down'} widget-caret`} />
      </div>
      {open && (
        <div className="surface-variants-widget-menu" role="menu">
          <button
            key={BASE_VARIANT_ID}
            type="button"
            role="menuitem"
            className={`surface-variants-widget-item${isBaseActive ? ' is-active' : ''}`}
            onClick={() => {
              setOpen(false);
              if (!isBaseActive && onSwitchVariant) onSwitchVariant(BASE_VARIANT_ID);
            }}
          >
            <span className="item-name">
              <strong>base</strong>
              {baseIsDefault && (
                <span className="badge bg-secondary ms-1" style={{ fontSize: '8px' }}>
                  default
                </span>
              )}
            </span>
          </button>
          {variants.map(v => {
            const isActive = v.id === activeVariantId;
            const isDefault = v.id === defaultId;
            return (
              <button
                key={v.id}
                type="button"
                role="menuitem"
                className={`surface-variants-widget-item${isActive ? ' is-active' : ''}`}
                onClick={() => {
                  setOpen(false);
                  if (!isActive && onSwitchVariant) onSwitchVariant(v.id);
                }}
              >
                <span className="item-name">
                  {v.name || <span className="text-muted">(unnamed)</span>}
                  {isDefault && (
                    <span className="badge bg-secondary ms-1" style={{ fontSize: '8px' }}>
                      default
                    </span>
                  )}
                  {v.enabled === false && (
                    <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '8px' }}>
                      disabled
                    </span>
                  )}
                </span>
                <code
                  className="item-alias surface-variants-widget-alias-link"
                  role="button"
                  tabIndex={0}
                  title="Open variants properties"
                  onClick={e => {
                    e.stopPropagation();
                    setOpen(false);
                    onOpen();
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      e.stopPropagation();
                      setOpen(false);
                      onOpen();
                    }
                  }}
                >
                  ${v.alias}
                </code>
              </button>
            );
          })}
          <div className="surface-variants-widget-divider" />
          <button
            type="button"
            role="menuitem"
            className="surface-variants-widget-item is-action"
            onClick={() => {
              setOpen(false);
              onOpen();
            }}
          >
            <i className="fas fa-cog me-1" />
            Manage variants…
          </button>
        </div>
      )}
    </div>
  );
};

export default SurfaceVariantsWidget;
