/**
 * CreateTemplateForm — used both for creating a brand-new template
 * (full snapshot of the current surface) and for editing an existing
 * user template's metadata.
 *
 * Create mode always saves a `kind: 'full'` template seeded from the
 * surface payload currently in the builder; AP-level tokens
 * (`$HOST` / `$ROUTE` / `$TARGET_ENDPOINT` / `$NAME`) and TP
 * listener scrubbing are applied unconditionally.
 *
 * Edit mode hides the snapshot/items derivation entirely and only
 * exposes the editable metadata fields.
 */

import React, { useMemo, useState } from 'react';
import type { SurfaceTemplate, SurfaceTemplateItem } from '../../../api';
import { tokenizeSnapshot } from './tokenizeSnapshot';

/**
 * Curated FontAwesome (solid) icons offered in the create/edit form.
 * Limited to a small, visually-distinct set so authors don't have to
 * memorise FA names. Values are bare icon ids (without the `fa-`).
 */
const ICON_CHOICES: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'layer-group', label: 'Layer group' },
  { value: 'rocket', label: 'Rocket' },
  { value: 'server', label: 'Server' },
  { value: 'bolt', label: 'Bolt' },
  { value: 'shield-halved', label: 'Shield' },
  { value: 'key', label: 'Key' },
  { value: 'robot', label: 'Robot' },
  { value: 'network-wired', label: 'Network' },
  { value: 'cube', label: 'Cube' },
  { value: 'cubes', label: 'Cubes' },
  { value: 'diagram-project', label: 'Diagram' },
  { value: 'code-branch', label: 'Branch' },
  { value: 'code', label: 'Code' },
  { value: 'handshake', label: 'Handshake' },
  { value: 'circle-nodes', label: 'Nodes' },
  { value: 'microchip', label: 'Microchip' },
  { value: 'gauge', label: 'Gauge' },
  { value: 'compass', label: 'Compass' },
  { value: 'map', label: 'Map' },
  { value: 'puzzle-piece', label: 'Puzzle' },
  { value: 'bullseye', label: 'Bullseye' },
  { value: 'flag', label: 'Flag' },
  { value: 'gear', label: 'Gear' },
  { value: 'briefcase', label: 'Briefcase' },
  { value: 'gem', label: 'Gem' },
];

export interface CreateTemplateFormProps {
  mode: 'create' | 'edit';
  /** Required in edit mode; ignored in create mode. */
  template?: SurfaceTemplate;
  /**
   * Current surface payload (same shape `onApplyJsonPayload` accepts).
   * Required in create mode for `kind: 'full'` — the entire surface is
   * snapshotted into the new template. Ignored in edit mode and when
   * `partialSeed` is supplied.
   */
  currentSurface?: Record<string, any>;
  /**
   * When set in create mode, the form saves a `kind: 'partial'`
   * template carrying these pre-built items (typically derived from
   * the user's current canvas multi-selection). Takes precedence over
   * `currentSurface` — the full-snapshot path is disabled.
   */
  partialSeed?: { items: SurfaceTemplateItem[]; count: number };
  onCancel: () => void;
  onSave: (payload: Partial<SurfaceTemplate>) => Promise<void>;
}

const CreateTemplateForm: React.FC<CreateTemplateFormProps> = ({
  mode,
  template,
  currentSurface,
  partialSeed,
  onCancel,
  onSave,
}) => {
  const isPartialCreate = mode === 'create' && !!partialSeed;
  const [name, setName] = useState(template?.name ?? '');
  const [description, setDescription] = useState(template?.description ?? '');
  const [details, setDetails] = useState(template?.details ?? '');
  const [starterHint, setStarterHint] = useState(template?.starter_hint ?? '');
  const [icon, setIcon] = useState(template?.icon ?? ICON_CHOICES[0].value);
  const [tagsCsv, setTagsCsv] = useState((template?.tags ?? []).join(', '));
  // In create mode, default to surfacing the template in the
  // "Create New Surface" starter picker. AddSurfacePage filters
  // starter templates by the literal `starter` tag. Partial
  // selection-based templates aren't starters by nature, so default
  // them off.
  const [showInStarter, setShowInStarter] = useState(!partialSeed);
  const [priority, setPriority] = useState<'high' | 'normal' | 'low'>(() => {
    const p = template?.sort_priority;
    if (p === undefined || p === null) return 'normal';
    if (p <= 2500) return 'high';
    if (p >= 3500) return 'low';
    return 'normal';
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Always tokenize on save — the user has no reason to keep the
  // current host / route / endpoint baked into a portable template.
  const fullPreview = useMemo(() => {
    if (mode !== 'create' || isPartialCreate || !currentSurface) return null;
    const { surface } = tokenizeSnapshot(currentSurface, { tokenizeNamedFields: true });
    return surface;
  }, [mode, isPartialCreate, currentSurface]);

  const canSave =
    name.trim().length > 0 && (mode === 'edit' || isPartialCreate || !!fullPreview) && !saving;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave) return;
    setError(null);
    setSaving(true);
    try {
      const payload: Partial<SurfaceTemplate> = {
        name: name.trim(),
        description: description.trim() || undefined,
        details: details.trim() || undefined,
        starter_hint: starterHint.trim() || undefined,
        icon: icon.trim() || undefined,
        tags: (() => {
          const list = tagsCsv
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
          if (mode === 'create' && !isPartialCreate && showInStarter && !list.includes('starter')) {
            list.push('starter');
          }
          return list;
        })(),
        sort_priority: priority === 'high' ? 2000 : priority === 'low' ? 4000 : 3000,
      };
      if (mode === 'create') {
        if (isPartialCreate) {
          payload.kind = 'partial';
          payload.items = partialSeed!.items;
        } else {
          if (!fullPreview) {
            setError('No current surface payload available to snapshot.');
            setSaving(false);
            return;
          }
          payload.kind = 'full';
          payload.surface = fullPreview;
        }
      }
      await onSave(payload);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to save template');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card shadow-sm mb-0 surface-templates-panel">
      <div className="card-header">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas fa-${mode === 'create' ? 'plus' : 'pen'} me-2`} />
          {mode === 'create'
            ? isPartialCreate
              ? 'Create Partial Surface Template'
              : 'Create Surface Template'
            : 'Edit Surface Template'}
        </h6>
      </div>
      <form
        onSubmit={handleSubmit}
        style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}
      >
        <div className="card-body" style={{ overflowY: 'auto', minHeight: 0, flex: 1 }}>
          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Name</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
              required
            />
            <small className="form-text text-muted">
              Short, descriptive label shown in the template list (e.g. “Trust Registry
              Verification”).
            </small>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Description</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <small className="form-text text-muted">
              One-line summary shown beneath the name in the template list.
            </small>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Details</label>
            <textarea
              className="form-control form-control-sm"
              rows={2}
              value={details}
              onChange={e => setDetails(e.target.value)}
            />
            <small className="form-text text-muted">
              Long-form explanation shown when the template row is expanded.
            </small>
          </div>
          {!isPartialCreate && (
            <div className="mb-3">
              <label className="form-label small text-muted mb-1">Starter Hint</label>
              <textarea
                className="form-control form-control-sm"
                rows={3}
                value={starterHint}
                onChange={e => setStarterHint(e.target.value)}
              />
              <small className="form-text text-muted">
                Body text for the welcome balloon shown on the canvas the first time a user creates
                a surface from this template. The title, dismiss button and “don’t show again”
                checkbox are added automatically — just write the hint itself. Leave blank to skip
                the balloon entirely.
              </small>
            </div>
          )}
          <div className="row g-2 mb-3">
            <div className="col-6">
              <label className="form-label small text-muted mb-1">Icon</label>
              <div className="input-group input-group-sm">
                <span className="input-group-text">
                  <i className={`fas fa-${icon || 'layer-group'}`} />
                </span>
                <select
                  className="form-select form-select-sm"
                  value={icon}
                  onChange={e => setIcon(e.target.value)}
                >
                  {ICON_CHOICES.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="col-6">
              <label className="form-label small text-muted mb-1">Sort priority</label>
              <select
                className="form-select form-select-sm"
                value={priority}
                onChange={e => setPriority(e.target.value as 'high' | 'normal' | 'low')}
              >
                <option value="high">High</option>
                <option value="normal">Normal</option>
                <option value="low">Low</option>
              </select>
              <small className="form-text text-muted">
                Controls where this template appears in the list — higher priority shows first.
              </small>
            </div>
          </div>

          {!isPartialCreate && (
            <div className="mb-3">
              <label className="form-label small text-muted mb-1">Tags</label>
              <input
                type="text"
                className="form-control form-control-sm"
                value={tagsCsv}
                onChange={e => setTagsCsv(e.target.value)}
              />
              <small className="form-text text-muted">
                Add tags to easily identify your Surface Templates — you can add multiple, separated
                by commas.
              </small>
            </div>
          )}

          {mode === 'create' && !isPartialCreate && (
            <div className="mb-3 form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="surface-template-show-in-starter"
                checked={showInStarter}
                onChange={e => setShowInStarter(e.target.checked)}
              />
              <label className="form-check-label small" htmlFor="surface-template-show-in-starter">
                Show in Create New Surface list
              </label>
              <small className="form-text text-muted d-block">
                Uncheck to hide this template from the starter picker on the Create New Surface
                page. You can still apply it to an existing surface from the template list view.
              </small>
            </div>
          )}

          {isPartialCreate && (
            <div className="alert alert-info py-2 px-3 small mb-3">
              <i className="fas fa-circle-info me-1" />
              Saving {partialSeed!.items.length} item
              {partialSeed!.items.length === 1 ? '' : 's'} from your selection as a partial
              template. Apply it later to drop these elements onto any surface.
            </div>
          )}

          {mode === 'create' && !isPartialCreate && !fullPreview && (
            <div className="alert alert-warning py-2 px-3 small mb-3">
              <i className="fas fa-triangle-exclamation me-1" />
              The current surface payload is not parseable — fix the Config tab first, then re-open
              this form.
            </div>
          )}

          {mode === 'edit' && (
            <div className="alert alert-info py-2 px-3 small mb-3">
              <i className="fas fa-circle-info me-1" />
              {template?.kind === 'full' ? (
                <>
                  Editing metadata only. The surface snapshot is preserved as-is. To change the
                  template body, apply it to a new surface, edit, and re-save as a new template.
                </>
              ) : (
                <>
                  Editing metadata only. The {template?.items?.length ?? 0} item
                  {(template?.items?.length ?? 0) === 1 ? '' : 's'} in this template are preserved.
                </>
              )}
            </div>
          )}

          {error && (
            <div className="alert alert-danger py-2 px-3 small mb-3">
              <i className="fas fa-times-circle me-1" />
              {error}
            </div>
          )}
        </div>
        <div className="card-footer d-flex justify-content-end gap-2" style={{ flexShrink: 0 }}>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={onCancel}
            disabled={saving}
          >
            Cancel
          </button>
          <button type="submit" className="btn btn-sm btn-primary" disabled={!canSave}>
            {saving ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" />
                Saving…
              </>
            ) : mode === 'create' ? (
              <>
                <i className="fas fa-plus me-1" /> Create
              </>
            ) : (
              <>
                <i className="fas fa-save me-1" /> Save
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default CreateTemplateForm;
