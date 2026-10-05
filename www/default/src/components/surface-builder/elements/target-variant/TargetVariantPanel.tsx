import React, { useState } from 'react';
import { Form, Row, Col, Button } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import type { VariantEntry } from './definition';

/**
 * Make a short, URL-safe random id. Variants are identified by this id
 * across the wire, so it must round-trip in JSON.
 */
function makeVariantId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `v-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
}

const TargetVariantPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateFields,
  allNodes,
  hasAttemptedSave,
}) => {
  const variants: VariantEntry[] = Array.isArray(config.variants) ? config.variants : [];
  const defaultId: string | undefined =
    typeof config.default_variant_id === 'string' ? config.default_variant_id : undefined;

  // Build the per-variant URL from the access-point node so users can
  // copy the exact path they'd hit. The alias is appended to the route
  // as a `$alias` segment (see `crate::state::proxy` — surface variant
  // routing parses `/route$alias/...`). Base variant has no suffix.
  const accessPoint = allNodes?.find(n => n.id === 'access-point');
  const listen: string =
    typeof accessPoint?.config?.listen_address === 'string'
      ? accessPoint.config.listen_address.replace(/\/+$/, '')
      : '';
  const route: string =
    typeof accessPoint?.config?.route === 'string' ? accessPoint.config.route : '';
  const buildVariantUrl = (alias: string | undefined | null): string => {
    if (!listen) return '';
    const base = `${listen}${route || ''}`;
    return alias ? `${base}$${alias}` : base;
  };
  const copyUrl = (url: string) => {
    if (!url) return;
    void navigator.clipboard?.writeText(url);
  };

  // Which row is expanded for inline editing. Default to the only row,
  // or none when several exist so the list reads as a tidy table.
  const [openId, setOpenId] = useState<string | null>(() =>
    variants.length === 1 ? variants[0].id : null
  );

  const writeList = (next: VariantEntry[], nextDefault?: string | null) => {
    const fields: Record<string, any> = { variants: next };
    if (nextDefault !== undefined) {
      fields.default_variant_id = nextDefault === null ? '' : nextDefault;
    }
    updateFields(fields);
  };

  const handleAdd = () => {
    const id = makeVariantId();
    // Pre-fill alias as `alias1`, `alias2`, ... skipping any already in
    // use so the user never sees an unhelpful empty-with-red-border
    // state on a fresh row. They can still rename it inline.
    const used = new Set(variants.map(v => (v.alias || '').toLowerCase()));
    let n = variants.length + 1;
    while (used.has(`alias${n}`)) n += 1;
    const alias = `alias${n}`;
    const next: VariantEntry = { id, name: alias, alias, enabled: true };
    const list = [...variants, next];
    // Adding a new variant never changes the default — base stays
    // the implicit default until the user explicitly promotes a
    // named variant.
    writeList(list);
    setOpenId(id);
  };

  const handleRemove = (id: string) => {
    const list = variants.filter(v => v.id !== id);
    let newDefault: string | null | undefined;
    if (defaultId === id) {
      // Removing the default falls back to base, never to a sibling.
      newDefault = null;
    }
    writeList(list, newDefault);
    if (openId === id) setOpenId(null);
  };

  const handleSetDefault = (id: string | null) => {
    writeList(variants, id);
  };

  const updateRow = (id: string, patch: Partial<VariantEntry>) => {
    const list = variants.map(v => (v.id === id ? { ...v, ...patch } : v));
    writeList(list);
  };

  return (
    <>
      <div className="config-section">
        <p className="text-muted small mb-0">
          Variants are full snapshots of this surface, addressed by a <code>$alias</code> path
          segment. Add one or more variants here; configure each variant's elements (Access Point,
          Target, transit points, policies, payment, identity, networking) by switching to it via
          the variants widget on the canvas. Leave <strong>base</strong> as default to route
          alias-less URLs to the unmodified surface, or promote a named variant.
        </p>
      </div>

      <div className="config-section">
        <div className="d-flex align-items-center justify-content-between mb-2">
          <strong className="small">Variants ({variants.length})</strong>
          <Button size="sm" variant="outline-primary" onClick={handleAdd}>
            <i className="fas fa-plus me-1" /> Add variant
          </Button>
        </div>

        {/* Always-present "base" row — the surface with no overlay
            applied. Locked: no rename, no alias, no enable/disable.
            The only control is "set as default", which routes
            alias-less URLs to the bare surface (default_variant_id =
            null on the wire). */}
        <div className="variant-row variant-row-base rounded mb-2">
          <div className="d-flex align-items-center px-2 py-1">
            <span style={{ width: 18 }} />
            <div className="flex-grow-1" style={{ minWidth: 0 }}>
              <div className="d-flex align-items-center gap-2">
                <strong className="small">base</strong>
                <span className="small text-muted fst-italic">(unmodified surface)</span>
                {!defaultId && (
                  <span className="badge bg-secondary" style={{ fontSize: '9px' }}>
                    default
                  </span>
                )}
              </div>
            </div>
            <Form.Check
              type="switch"
              id="tv-default-base"
              label="Default"
              checked={!defaultId}
              onChange={() => handleSetDefault(null)}
              className="me-2 small"
            />
          </div>
          <div className="px-2 pb-2">
            <div className="input-group input-group-sm">
              <span className="input-group-text small">URL</span>
              <Form.Control
                size="sm"
                type="text"
                readOnly
                value={buildVariantUrl(null) || '(access point not configured)'}
                style={{ fontFamily: 'monospace' }}
              />
              <Button
                size="sm"
                variant="outline-secondary"
                title="Copy to clipboard"
                disabled={!buildVariantUrl(null)}
                onClick={() => copyUrl(buildVariantUrl(null))}
              >
                <i className="fas fa-copy" />
              </Button>
            </div>
          </div>
        </div>

        {variants.length === 0 && (
          <div className="text-muted small fst-italic">
            No named variants yet. Click <em>Add variant</em> to create one.
          </div>
        )}

        {variants.map(v => {
          const isOpen = openId === v.id;
          const isDefault = defaultId === v.id;
          const aliasError =
            v.alias && !/^[a-z0-9-]{1,32}$/.test(v.alias)
              ? 'Alias must be 1-32 chars: lowercase letters, digits, hyphens'
              : null;
          return (
            <div key={v.id} className="variant-row rounded mb-2">
              <div className="d-flex align-items-center px-2 py-1">
                <button
                  type="button"
                  className="btn btn-link btn-sm text-decoration-none p-0 me-2"
                  onClick={() => setOpenId(isOpen ? null : v.id)}
                  title={isOpen ? 'Collapse' : 'Expand'}
                  style={{ width: 18 }}
                >
                  <i className={`fas fa-chevron-${isOpen ? 'down' : 'right'}`} />
                </button>
                <div className="flex-grow-1" style={{ minWidth: 0 }}>
                  <div className="d-flex align-items-center gap-2">
                    <strong className="small text-truncate">
                      {v.name || <span className="text-muted">(unnamed)</span>}
                    </strong>
                    <code className="small text-muted">{v.alias ? `$${v.alias}` : '$alias?'}</code>
                    {isDefault && (
                      <span className="badge bg-secondary" style={{ fontSize: '9px' }}>
                        default
                      </span>
                    )}
                    {v.enabled === false && (
                      <span className="badge bg-warning text-dark" style={{ fontSize: '9px' }}>
                        disabled
                      </span>
                    )}
                  </div>
                  {v.description && (
                    <div className="small text-muted text-truncate">{v.description}</div>
                  )}
                </div>
                {!isDefault && variants.length > 0 && (
                  <button
                    type="button"
                    className="btn btn-link btn-sm text-decoration-none p-1"
                    onClick={() => handleSetDefault(v.id)}
                    title="Make default"
                  >
                    <i className="fas fa-star text-muted" />
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-link btn-sm text-decoration-none p-1 text-danger"
                  onClick={() => handleRemove(v.id)}
                  title="Remove variant"
                >
                  <i className="fas fa-trash" />
                </button>
              </div>

              {isOpen && (
                <div className="variant-row-body p-2">
                  <div className="input-group input-group-sm mb-2">
                    <span className="input-group-text small">URL</span>
                    <Form.Control
                      size="sm"
                      type="text"
                      readOnly
                      value={buildVariantUrl(v.alias) || '(access point not configured)'}
                      style={{ fontFamily: 'monospace' }}
                    />
                    <Button
                      size="sm"
                      variant="outline-secondary"
                      title="Copy to clipboard"
                      disabled={!buildVariantUrl(v.alias)}
                      onClick={() => copyUrl(buildVariantUrl(v.alias))}
                    >
                      <i className="fas fa-copy" />
                    </Button>
                  </div>

                  <Row className="g-2">
                    <Col xs={6}>
                      <Form.Group>
                        <Form.Label className="small mb-1">Name</Form.Label>
                        <Form.Control
                          size="sm"
                          type="text"
                          value={v.name || ''}
                          onChange={e => updateRow(v.id, { name: e.target.value })}
                        />
                      </Form.Group>
                    </Col>
                    <Col xs={6}>
                      <Form.Group>
                        <Form.Label className="small mb-1">Alias</Form.Label>
                        <Form.Control
                          size="sm"
                          type="text"
                          value={v.alias || ''}
                          onChange={e =>
                            updateRow(v.id, {
                              alias: e.target.value.replace(/\s+/g, '-').toLowerCase(),
                            })
                          }
                          isInvalid={!!hasAttemptedSave && !!aliasError}
                        />
                        {!!hasAttemptedSave && aliasError && (
                          <Form.Control.Feedback type="invalid">{aliasError}</Form.Control.Feedback>
                        )}
                      </Form.Group>
                    </Col>
                  </Row>

                  <Form.Group className="mt-2">
                    <Form.Label className="small mb-1">Description</Form.Label>
                    <Form.Control
                      size="sm"
                      type="text"
                      value={v.description || ''}
                      onChange={e => updateRow(v.id, { description: e.target.value })}
                    />
                  </Form.Group>

                  <div className="d-flex gap-3 mt-2">
                    <Form.Check
                      type="switch"
                      id={`tv-enabled-${v.id}`}
                      label="Enabled"
                      checked={isDefault ? true : v.enabled !== false}
                      disabled={isDefault}
                      title={
                        isDefault
                          ? 'The default variant cannot be disabled. Promote another variant to default first.'
                          : undefined
                      }
                      onChange={e => updateRow(v.id, { enabled: e.target.checked })}
                    />
                    <Form.Check
                      type="switch"
                      id={`tv-default-${v.id}`}
                      label="Default"
                      checked={isDefault}
                      onChange={() => handleSetDefault(v.id)}
                    />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
};

export default TargetVariantPanel;
