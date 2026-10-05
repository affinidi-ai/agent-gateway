/**
 * TemplatesPanel — the sidebar tab that lists surface templates,
 * applies them to the current canvas, and lets the user create / edit
 * / delete their own user-authored templates.
 *
 * Three internal modes:
 *  - `list`   — default; renders the searchable list with apply / edit
 *               / delete affordances per row.
 *  - `create` — entered via the `[+]` button next to the Templates
 *               tab in the shell (controlled via `createMode` prop).
 *               Shows {@link CreateTemplateForm} seeded with the
 *               current canvas nodes as the items picker.
 *  - `edit`   — entered locally when the user clicks the pencil on a
 *               user-authored row. Edits metadata; items are
 *               preserved as-is.
 */

import React, { useState } from 'react';
import type { CanvasNode } from '../SurfaceCanvas';
import type { Protocol } from '../elements/types';
import type { SurfaceTemplate, SurfaceTemplateItem } from '../../../api';
import { sortTemplatesForDisplay, templateMatchesProtocol } from './templateSort';
import { useSurfaceTemplates } from './useSurfaceTemplates';
import CreateTemplateForm from './CreateTemplateForm';
import { DeleteButton } from '../../shared/DeleteButton';

interface TemplatesPanelProps {
  /** Active surface protocol used to hide incompatible partial templates. */
  protocol: Protocol;
  /**
   * Called when the user confirms applying a template. Receives the
   * full template; the caller wires up `placement.applyTemplate` and
   * the builder's `setState` + `commit`.
   */
  onApplyTemplate: (template: SurfaceTemplate) => void;
  /** Current canvas nodes — seeds the items picker in create mode. */
  nodes: CanvasNode[];
  /**
   * Pretty-printed JSON of the current surface payload (same string
   * the Config tab shows). Used by the create form when the user
   * chooses `kind: full` to snapshot the whole surface. Optional so
   * pages that don't expose a Config tab can still mount the panel
   * (the Full kind option just becomes unavailable in that case).
   */
  currentSurfaceJson?: string;
  /**
   * Whether the panel is in create mode (controlled by the shell so
   * the `[+]` button next to the Templates tab can flip it on).
   */
  createMode: boolean;
  /**
   * When supplied, the create form opens in partial-template mode
   * seeded with these items (built by the shell from the canvas
   * multi-selection). Ignored unless `createMode` is true.
   */
  createPartialSeed?: { items: SurfaceTemplateItem[]; count: number } | null;
  /** Asks the shell to leave create mode (cancel / save). */
  onExitCreateMode: () => void;
}

const TemplatesPanel: React.FC<TemplatesPanelProps> = ({
  protocol,
  onApplyTemplate,
  nodes,
  currentSurfaceJson,
  createMode,
  createPartialSeed,
  onExitCreateMode,
}) => {
  const { templates, loading, error, refresh, create, update, remove, importTemplate } =
    useSurfaceTemplates();
  const [filter, setFilter] = useState('');
  const [kindTab, setKindTab] = useState<'full' | 'partial'>('partial');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<SurfaceTemplate | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refresh();
    } finally {
      setRefreshing(false);
    }
  };
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  // When create mode flips on we always cancel any in-flight edit so
  // the form doesn't render twice.
  React.useEffect(() => {
    if (createMode) setEditing(null);
  }, [createMode]);

  if (createMode) {
    // Parse the current surface JSON lazily and defensively — if the
    // Config-tab text is currently invalid, the Full kind option
    // simply stays disabled inside CreateTemplateForm.
    let currentSurface: Record<string, any> | undefined;
    if (currentSurfaceJson) {
      try {
        const parsed = JSON.parse(currentSurfaceJson);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          currentSurface = parsed;
        }
      } catch {
        // Invalid JSON — disable Full kind path; user can fix it in
        // the Config tab and reopen.
      }
    }
    return (
      <CreateTemplateForm
        mode="create"
        currentSurface={currentSurface}
        partialSeed={createPartialSeed ?? undefined}
        onCancel={onExitCreateMode}
        onSave={async payload => {
          await create(payload);
          onExitCreateMode();
        }}
      />
    );
  }

  if (editing) {
    return (
      <CreateTemplateForm
        mode="edit"
        template={editing}
        onCancel={() => setEditing(null)}
        onSave={async payload => {
          // PUT expects a complete SurfaceTemplate; the form only
          // returns the editable metadata fields, so merge it over
          // the existing template. The backend re-applies id /
          // builtin / created_at / updated_at server-side.
          await update(editing.id, { ...editing, ...payload });
          setEditing(null);
        }}
      />
    );
  }

  // Split by kind first so the two tabs each show their own count;
  // then apply the free-text filter to whichever tab is active.
  // Each tab is sorted by the optional `sort_priority` field (lower
  // first; ties on name) so authored builtins appear in a stable,
  // curated order regardless of API insertion order.
  const fullTemplates = sortTemplatesForDisplay(templates.filter(t => t.kind === 'full'));
  const partialTemplates = sortTemplatesForDisplay(
    templates.filter(t => t.kind !== 'full' && templateMatchesProtocol(t, protocol))
  );
  const visibleTemplates = kindTab === 'full' ? fullTemplates : partialTemplates;
  const lowered = filter.trim().toLowerCase();
  const filtered = lowered
    ? visibleTemplates.filter(
        t =>
          t.name.toLowerCase().includes(lowered) ||
          (t.description ?? '').toLowerCase().includes(lowered) ||
          (t.details ?? '').toLowerCase().includes(lowered) ||
          (t.tags ?? []).some(tag => tag.toLowerCase().includes(lowered))
      )
    : visibleTemplates;

  const handleDelete = async (tpl: SurfaceTemplate) => {
    setDeletingId(tpl.id);
    try {
      await remove(tpl.id);
      if (expandedId === tpl.id) setExpandedId(null);
    } finally {
      setDeletingId(null);
    }
  };

  const handleApply = (tpl: SurfaceTemplate) => {
    if (tpl.kind === 'full' && nodes.length > 0) {
      const confirmed = window.confirm(
        `Applying "${tpl.name}" will replace the current surface and discard your existing elements. Continue?`
      );
      if (!confirmed) return;
    }
    onApplyTemplate(tpl);
  };

  const handleImportClick = () => {
    setImportError(null);
    fileInputRef.current?.click();
  };

  const handleImportFile = async (file: File) => {
    setImporting(true);
    setImportError(null);
    try {
      const text = await file.text();
      let payload: unknown;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new Error('File is not valid JSON');
      }
      await importTemplate(payload);
    } catch (e: any) {
      setImportError(e?.message ?? 'Import failed');
    } finally {
      setImporting(false);
      // Reset so re-importing the same file fires `onChange` again.
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div className="card shadow-sm mb-0 surface-templates-panel">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-layer-group me-2" />
          Surface Templates
        </h6>
        <div className="d-flex gap-1">
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={handleImportClick}
            disabled={importing}
            title="Import a Surface Template JSON file"
          >
            {importing ? (
              <span className="spinner-border spinner-border-sm" />
            ) : (
              <i className="fas fa-file-import" />
            )}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => void handleRefresh()}
            disabled={refreshing}
            title="Reload templates"
          >
            <i className={`fas fa-rotate-right${refreshing ? ' fa-spin' : ''}`} />
          </button>
        </div>
      </div>
      <input
        ref={fileInputRef}
        type="file"
        accept="application/json,.json"
        style={{ display: 'none' }}
        onChange={e => {
          const f = e.target.files?.[0];
          if (f) void handleImportFile(f);
        }}
      />
      <div className="card-body surface-templates-panel__body">
        <ul className="nav nav-tabs surface-templates-panel__tabs mb-2" role="tablist">
          <li className="nav-item" role="presentation">
            <button
              type="button"
              className={`nav-link ${kindTab === 'partial' ? 'active' : ''}`}
              role="tab"
              aria-selected={kindTab === 'partial'}
              onClick={() => {
                setKindTab('partial');
                setExpandedId(null);
              }}
            >
              Partials
              <span className="badge text-bg-light ms-2">{partialTemplates.length}</span>
            </button>
          </li>
          <li className="nav-item" role="presentation">
            <button
              type="button"
              className={`nav-link ${kindTab === 'full' ? 'active' : ''}`}
              role="tab"
              aria-selected={kindTab === 'full'}
              onClick={() => {
                setKindTab('full');
                setExpandedId(null);
              }}
            >
              Full Surfaces
              <span className="badge text-bg-light ms-2">{fullTemplates.length}</span>
            </button>
          </li>
        </ul>
        <input
          type="search"
          className="form-control form-control-sm mb-3"
          placeholder="Search templates…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />

        {loading && !refreshing && (
          <div className="text-muted small d-flex align-items-center">
            <span className="spinner-border spinner-border-sm me-2" />
            Loading templates…
          </div>
        )}

        {error && (
          <div className="alert alert-danger py-2 px-3 small mb-2">
            <i className="fas fa-times-circle me-1" />
            {error}
          </div>
        )}

        {importError && (
          <div className="alert alert-danger py-2 px-3 small mb-2">
            <i className="fas fa-times-circle me-1" />
            Import failed: {importError}
          </div>
        )}

        {!loading && !error && filtered.length === 0 && (
          <div className="text-muted small">No templates match.</div>
        )}

        <ul className="list-unstyled mb-0">
          {filtered.map(tpl => (
            <TemplateRow
              key={tpl.id}
              template={tpl}
              expanded={expandedId === tpl.id}
              deleting={deletingId === tpl.id}
              onToggle={() => setExpandedId(prev => (prev === tpl.id ? null : tpl.id))}
              onApply={() => handleApply(tpl)}
              onEdit={() => setEditing(tpl)}
              onDelete={() => void handleDelete(tpl)}
            />
          ))}
        </ul>
      </div>
    </div>
  );
};

interface TemplateRowProps {
  template: SurfaceTemplate;
  expanded: boolean;
  deleting: boolean;
  onToggle: () => void;
  onApply: () => void;
  onEdit: () => void;
  onDelete: () => void;
}

const TemplateRow: React.FC<TemplateRowProps> = ({
  template,
  expanded,
  deleting,
  onToggle,
  onApply,
  onEdit,
  onDelete,
}) => {
  const icon = template.icon ? `fa-${template.icon}` : 'fa-layer-group';
  const editable = !template.builtin;
  const isFull = template.kind === 'full';
  return (
    <li className="surface-template-row">
      <div
        className="surface-template-row__header"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onToggle();
          }
        }}
      >
        <i className={`fas ${icon} surface-template-row__icon`} />
        <div className="flex-grow-1" style={{ minWidth: 0 }}>
          <div className="surface-template-row__title text-truncate">{template.name}</div>
          {template.description && (
            <div className="surface-template-row__description">{template.description}</div>
          )}
        </div>
        <div className="surface-template-row__meta">
          {template.builtin ? (
            <span className="badge text-bg-secondary" title="Shipped with the gateway">
              system
            </span>
          ) : (
            <span className="badge text-bg-info" title="User-authored template">
              custom
            </span>
          )}
          {editable && (
            <>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary surface-template-row__action"
                title="Edit template"
                aria-label="Edit template"
                disabled={deleting}
                onClick={e => {
                  e.stopPropagation();
                  onEdit();
                }}
              >
                <i className="fas fa-pen" />
              </button>
              <span onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
                <DeleteButton
                  onDelete={onDelete}
                  disabled={deleting}
                  variant="danger"
                  size="sm"
                  className="surface-template-row__action"
                  title="Delete template"
                />
              </span>
            </>
          )}
          <button
            type="button"
            className={`btn btn-sm ${isFull ? 'btn-warning' : 'btn-primary'} surface-template-row__action`}
            title={
              isFull
                ? 'Replace the current surface with this template'
                : 'Add this template’s items to the current surface'
            }
            aria-label={
              isFull ? 'Replace surface with this template' : 'Add this template to surface'
            }
            onClick={e => {
              e.stopPropagation();
              onApply();
            }}
          >
            <i className="fas fa-arrow-right" />
          </button>
          <i
            className={`fas fa-chevron-${expanded ? 'up' : 'down'} text-muted`}
            style={{ fontSize: 11 }}
          />
        </div>
      </div>

      {expanded && (
        <div className="surface-template-row__body">
          {template.details ? (
            <div className="surface-template-row__details">{template.details}</div>
          ) : (
            <div className="text-muted small fst-italic">No additional details.</div>
          )}
        </div>
      )}
    </li>
  );
};

export default TemplatesPanel;
