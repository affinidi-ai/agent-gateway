import React, { useCallback, useMemo, useEffect, useRef } from 'react';
import type { ConfigPanelProps } from '../types';
import { consumeOnboard } from './onboardEntry';
import IdentityOnboardingView, { type SupportedProtocol } from './IdentityOnboardingView';
import {
  COPILOT_HEADER_METADATA_IDENTITY_FIELDS,
  copilotHeaderMetadataIdentitySchema,
} from '../access-point/headerMetadataMapping';
import { transitPointProtocol } from '../transit-point/TransitPointPanel';
/**
 * Identity payload editor — mirrors the "Identity Management" section of the
 * Channels editor (`EditChannelPage/tabs/InboundTab.tsx`). The user defines a
 * JSON schema describing the agent identity object expected on each request,
 * marks fields as `x-identity` to include them in the identity hash, and adds
 * validation rules. `buildPayload` derives the flat `fields` array (legacy
 * backend contract) from the x-identity markers in the schema.
 */

type ValidationRule = {
  type: string;
  value?: string;
  elementType?: string;
  values?: string;
  min?: string;
  max?: string;
};

type SchemaProperty = {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required: boolean;
  xIdentity: boolean;
  level: number;
  parent?: number;
  collapsed?: boolean;
  validationRule?: ValidationRule;
};

const PRIMITIVE_TYPES: Array<SchemaProperty['type']> = ['string', 'number', 'boolean'];
function isSupportedOnboardingProtocol(
  protocol: string | null | undefined
): protocol is SupportedProtocol {
  return protocol === 'a2a' || protocol === 'ap2' || protocol === 'mcp';
}

function toSupportedOnboardingProtocol(protocol: string | null | undefined): SupportedProtocol {
  return isSupportedOnboardingProtocol(protocol) ? protocol : 'a2a';
}

function isChildVisible(properties: SchemaProperty[], property: SchemaProperty): boolean {
  if (property.level === 0) return true;
  if (property.parent === undefined) return true;
  const parent = properties[property.parent];
  if (!parent) return true;
  if (parent.collapsed) return false;
  return isChildVisible(properties, parent);
}

/** Walk a JSON schema and return dot-paths of every property marked x-identity. */
function extractIdentityPaths(schema: any): string[] {
  if (!schema || typeof schema !== 'object') return [];
  const out: string[] = [];
  const walk = (node: any, path: string[]) => {
    if (!node || typeof node !== 'object') return;
    if (node['x-identity'] === true && path.length > 0) {
      out.push(path.join('.'));
    }
    if (node.properties && typeof node.properties === 'object') {
      for (const [name, sub] of Object.entries(node.properties)) {
        walk(sub, [...path, name]);
      }
    }
    if (node.items) walk(node.items, path);
  };
  walk(schema, []);
  return out;
}

/** Convert the flat property list to a nested JSON schema with x-identity markers. */
function buildJsonSchema(properties: SchemaProperty[]): any {
  // Helpers: nest properties by parent index.
  const childrenByParent = new Map<number | 'root', number[]>();
  properties.forEach((p, i) => {
    const key: number | 'root' = p.parent === undefined ? 'root' : p.parent;
    if (!childrenByParent.has(key)) childrenByParent.set(key, []);
    childrenByParent.get(key)!.push(i);
  });

  const buildNode = (parentKey: number | 'root'): any => {
    const indices = childrenByParent.get(parentKey) || [];
    const required: string[] = [];
    const props: Record<string, any> = {};
    for (const idx of indices) {
      const p = properties[idx];
      if (!p.name) continue;
      const node: any = { type: p.type };
      if (p.xIdentity && PRIMITIVE_TYPES.includes(p.type)) {
        node['x-identity'] = true;
        required.push(p.name);
      } else if (p.required) {
        required.push(p.name);
      }
      if (p.type === 'object') {
        const inner = buildNode(idx);
        if (inner.properties) node.properties = inner.properties;
        if (inner.required && inner.required.length) node.required = inner.required;
      }
      if (p.validationRule && p.validationRule.type) {
        applyValidationRule(node, p.validationRule);
      }
      props[p.name] = node;
    }
    const out: any = { type: 'object', properties: props };
    if (required.length) out.required = required;
    return out;
  };

  return buildNode('root');
}

function applyValidationRule(node: any, rule: ValidationRule): void {
  switch (rule.type) {
    case 'equals':
      if (rule.value) node.const = rule.value;
      break;
    case 'contains':
      if (rule.value) node.pattern = rule.value;
      break;
    case 'regex':
      if (rule.value) node.pattern = rule.value;
      break;
    case 'range': {
      const m = rule.value?.match(/^(-?\d+)?\s*-\s*(-?\d+)?$/);
      if (m) {
        if (m[1]) node.minimum = Number(m[1]);
        if (m[2]) node.maximum = Number(m[2]);
      }
      break;
    }
    case 'array-length':
      if (rule.min) node.minItems = Number(rule.min);
      if (rule.max) node.maxItems = Number(rule.max);
      break;
  }
}

/** Parse an existing JSON schema back into the flat editor list. */
function parseJsonSchema(schema: any): SchemaProperty[] {
  if (!schema || !schema.properties) return [];
  const out: SchemaProperty[] = [];
  const walk = (node: any, level: number, parent: number | undefined) => {
    if (!node || !node.properties) return;
    const requiredSet = new Set<string>(Array.isArray(node.required) ? node.required : []);
    for (const [name, sub] of Object.entries<any>(node.properties)) {
      const propIdx = out.length;
      const t = (sub.type as SchemaProperty['type']) || 'string';
      out.push({
        name,
        type: t,
        required: requiredSet.has(name),
        xIdentity: sub['x-identity'] === true,
        level,
        parent,
        collapsed: false,
      });
      if (t === 'object') walk(sub, level + 1, propIdx);
    }
  };
  walk(schema, 0, undefined);
  return out;
}

const IdentityPayloadFullscreenPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  protocol,
  updateField,
  updateFields,
  closeFullscreenEditor,
  allNodes,
}) => {
  const metaField = (config.meta_field as string) || 'agentIdentity';
  const schemaFromConfig = (config.json_schema as any) || null;

  // Onboarding sub-view: entered when the "Capture Identity Payload"
  // button requested it for this node id. We consume the flag exactly
  // once on mount, then offer a manual toggle while the panel is open
  // so the user can re-enter onboarding without leaving the fullscreen
  // tab.
  const [onboarding, setOnboarding] = React.useState<boolean>(() => consumeOnboard(node.id));

  // The flat property list is the source of truth in the editor; the JSON
  // schema is derived on every change and persisted to config.
  const [properties, setProperties] = React.useState<SchemaProperty[]>(() =>
    parseJsonSchema(schemaFromConfig)
  );

  // Sync external resets (e.g. config replaced from outside) into local state.
  const lastSerialized = useRef('');
  useEffect(() => {
    const ser = JSON.stringify(schemaFromConfig);
    if (ser !== lastSerialized.current) {
      lastSerialized.current = ser;
      setProperties(parseJsonSchema(schemaFromConfig));
    }
  }, [schemaFromConfig]);

  const persist = useCallback(
    (next: SchemaProperty[]) => {
      const schema = buildJsonSchema(next);
      lastSerialized.current = JSON.stringify(schema);
      // Write both fields atomically. updateField captures node.config in a
      // stale closure on the parent, so two sequential updateField calls
      // would clobber each other; updateFields applies the patch in one go.
      updateFields({ json_schema: schema, fields: extractIdentityPaths(schema) });
    },
    [updateFields]
  );

  const setAndPersist = useCallback(
    (updater: (prev: SchemaProperty[]) => SchemaProperty[]) => {
      setProperties(prev => {
        const next = updater(prev);
        persist(next);
        return next;
      });
    },
    [persist]
  );

  const updateMetaField = (val: string) => updateField('meta_field', val);

  const addRootProperty = () =>
    setAndPersist(prev => [
      ...prev,
      {
        name: '',
        type: 'string',
        required: false,
        xIdentity: false,
        level: 0,
        parent: undefined,
      },
    ]);

  const addChildProperty = (parentIdx: number) =>
    setAndPersist(prev => {
      const parent = prev[parentIdx];
      if (!parent || parent.type !== 'object') return prev;
      // Insert immediately after the last descendant of the parent.
      let insertAt = parentIdx + 1;
      for (let i = parentIdx + 1; i < prev.length; i++) {
        if (prev[i].level > parent.level) insertAt = i + 1;
        else break;
      }
      const next = [...prev];
      const newProp: SchemaProperty = {
        name: '',
        type: 'string',
        required: false,
        xIdentity: false,
        level: parent.level + 1,
        parent: parentIdx,
      };
      next.splice(insertAt, 0, newProp);
      // Reindex `parent` references for items shifted by the insert.
      return next.map((p, i) => {
        if (i <= insertAt) return p;
        if (p.parent !== undefined && p.parent >= insertAt) {
          return { ...p, parent: p.parent + 1 };
        }
        return p;
      });
    });

  const removeProperty = (idx: number) =>
    setAndPersist(prev => {
      const target = prev[idx];
      if (!target) return prev;
      // Drop the target plus its descendants.
      const dropIndices = new Set<number>([idx]);
      for (let i = idx + 1; i < prev.length; i++) {
        if (prev[i].level > target.level) dropIndices.add(i);
        else break;
      }
      const filtered = prev.filter((_, i) => !dropIndices.has(i));
      // Reindex `parent` pointers.
      return filtered.map(p => {
        if (p.parent === undefined) return p;
        const removedBefore = [...dropIndices].filter(d => d < p.parent!).length;
        const removedAtOrAfter = [...dropIndices].filter(d => d >= p.parent!).length;
        if (removedAtOrAfter > 0 && p.parent === idx) return { ...p, parent: undefined, level: 0 };
        return { ...p, parent: p.parent - removedBefore };
      });
    });

  const updateAt = (idx: number, patch: Partial<SchemaProperty>) =>
    setAndPersist(prev => prev.map((p, i) => (i === idx ? { ...p, ...patch } : p)));

  const updateValidation = (idx: number, patch: Partial<ValidationRule>) =>
    setAndPersist(prev =>
      prev.map((p, i) => {
        if (i !== idx) return p;
        const next = { ...(p.validationRule || { type: '' }), ...patch } as ValidationRule;
        return { ...p, validationRule: next };
      })
    );

  const setValidationType = (idx: number, type: string) =>
    setAndPersist(prev =>
      prev.map((p, i) => {
        if (i !== idx) return p;
        if (!type) return { ...p, validationRule: undefined };
        return { ...p, validationRule: { type } };
      })
    );

  const toggleCollapsed = (idx: number) =>
    setAndPersist(prev => prev.map((p, i) => (i === idx ? { ...p, collapsed: !p.collapsed } : p)));

  const expandAll = () => setAndPersist(prev => prev.map(p => ({ ...p, collapsed: false })));
  const collapseAll = () => setAndPersist(prev => prev.map(p => ({ ...p, collapsed: true })));

  const identityFieldCount = useMemo(
    () => properties.filter(p => p.xIdentity && PRIMITIVE_TYPES.includes(p.type)).length,
    [properties]
  );
  const parentTransitProtocol = transitPointProtocol(
    allNodes?.find(candidate => candidate.id === node.parentId)?.type
  );
  const identityProtocol = parentTransitProtocol ?? protocol;
  const onboardingProtocol = toSupportedOnboardingProtocol(identityProtocol);
  const isA2aLikeProtocol = identityProtocol === 'a2a' || identityProtocol === 'ap2';
  const isInboundA2aIdentity =
    node.slotId === 'request:identity-inbound' && (protocol === 'a2a' || protocol === 'ap2');
  const isTransitPointA2aIdentity =
    (node.slotId === 'request:identity-managed_identity' ||
      node.slotId === 'response:identity-managed_identity') &&
    (parentTransitProtocol === 'a2a' || parentTransitProtocol === 'ap2');
  const canUseCopilotIdentitySchema = isInboundA2aIdentity || isTransitPointA2aIdentity;

  // Raw JSON editor state. The visual editor is the source of truth; this
  // mirror string lets the user paste / hand-edit the JSON. Edits stay local
  // (rawDirty=true) until the user clicks "Sync Visual", at which point the
  // parsed schema replaces `properties` and is persisted back to config.
  const visualJson = useMemo(
    () => JSON.stringify(buildJsonSchema(properties), null, 2),
    [properties]
  );
  const [rawJson, setRawJson] = React.useState<string>(visualJson);
  const [rawDirty, setRawDirty] = React.useState(false);
  const [rawError, setRawError] = React.useState<string | null>(null);

  // When the visual editor changes (and the user isn't mid-edit in raw),
  // refresh the raw mirror so the two stay in sync.
  useEffect(() => {
    if (!rawDirty) {
      setRawJson(visualJson);
      setRawError(null);
    }
  }, [visualJson, rawDirty]);

  const handleRawJsonChange = (val: string) => {
    setRawJson(val);
    setRawDirty(true);
    try {
      JSON.parse(val);
      setRawError(null);
    } catch (e: any) {
      setRawError(e.message || 'Invalid JSON');
    }
  };

  const syncRawToVisual = () => {
    if (rawError) return;
    try {
      const parsed = JSON.parse(rawJson);
      const next = parseJsonSchema(parsed);
      // Persist the parsed schema directly so structures the visual editor
      // can't represent (e.g. `array.items`, custom keywords) survive the
      // round-trip until the user changes them in the visual editor.
      lastSerialized.current = JSON.stringify(parsed);
      updateFields({ json_schema: parsed, fields: extractIdentityPaths(parsed) });
      setProperties(next);
      setRawDirty(false);
    } catch (e: any) {
      setRawError(e.message || 'Invalid JSON');
    }
  };

  return (
    <div className="card shadow-sm mb-4">
      {onboarding ? (
        <>
          <div className="card-header bg-light">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-satellite-dish"></i> Capture Identity Payload
              </h6>
              <div className="d-flex align-items-center gap-2">
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={() => setOnboarding(false)}
                >
                  <i className="fas fa-arrow-left me-1" /> Back to schema editor
                </button>
                {closeFullscreenEditor && (
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={closeFullscreenEditor}
                  >
                    <i className="fas fa-times me-1" /> Close tab
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="card-body">
            <IdentityOnboardingView
              metaField={metaField}
              protocol={onboardingProtocol}
              onSchemaAdopted={schema => {
                lastSerialized.current = JSON.stringify(schema);
                updateFields({ json_schema: schema, fields: extractIdentityPaths(schema) });
                setProperties(parseJsonSchema(schema));
                setOnboarding(false);
              }}
              onCancel={() => setOnboarding(false)}
            />
          </div>
        </>
      ) : (
        <>
          <div className="card-header bg-light">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-fingerprint"></i> Identity Management
              </h6>
              <div className="d-flex align-items-center gap-2">
                <span className="badge text-bg-info">
                  {identityFieldCount}{' '}
                  {identityFieldCount === 1 ? 'identity field' : 'identity fields'}
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-success"
                  onClick={() => setOnboarding(true)}
                >
                  <i className="fas fa-satellite-dish me-1" /> Capture Identity Payload
                </button>
                {closeFullscreenEditor && (
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={closeFullscreenEditor}
                  >
                    <i className="fas fa-times me-1" /> Close tab
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="card-body">
            {!isA2aLikeProtocol ? (
              <div className="mb-4">
                <label htmlFor="identity-meta-field" className="form-label fw-bold">
                  Identity Meta Field Name
                </label>
                <input
                  type="text"
                  className="form-control"
                  id="identity-meta-field"
                  value={metaField}
                  onChange={e => updateMetaField(e.target.value)}
                  placeholder="agentIdentity"
                />
                <small className="form-text text-muted">
                  The field name within <code>_meta</code> that contains the agent identity object —
                  e.g. <code>_meta.{metaField || 'agentIdentity'}</code>.
                </small>
              </div>
            ) : (
              <div className="alert alert-info mb-4" data-testid="identity-a2a-extension-note">
                A2A identity is read from the configured identity extension payload. Configure the
                schema below against that payload.
              </div>
            )}

            <div className="mb-3">
              <label className="form-label fw-bold">Request JSON Schema Properties</label>
              <div className="d-flex justify-content-between align-items-center gap-2 mb-2">
                <div>
                  <button
                    style={{ marginRight: '10px' }}
                    type="button"
                    className="btn btn-sm btn-primary me-3"
                    onClick={expandAll}
                  >
                    Expand All
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary ms-3"
                    onClick={collapseAll}
                  >
                    Collapse All
                  </button>
                </div>
                {canUseCopilotIdentitySchema && (
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => {
                      const schema = copilotHeaderMetadataIdentitySchema();
                      lastSerialized.current = JSON.stringify(schema);
                      updateFields({
                        json_schema: schema,
                        fields: [...COPILOT_HEADER_METADATA_IDENTITY_FIELDS],
                      });
                      setProperties(parseJsonSchema(schema));
                      setRawDirty(false);
                    }}
                  >
                    <i className="fas fa-wand-magic-sparkles me-1" /> Use Copilot identity schema
                  </button>
                )}
              </div>
              <div id="schema-properties-list" className="mb-2">
                {properties.map((property, index) => {
                  if (property.level > 0 && !isChildVisible(properties, property)) return null;
                  return (
                    <div
                      key={`schema-prop-${index}`}
                      className="schema-property-card"
                      data-level={property.level}
                    >
                      <div className="card-body">
                        <div className="d-flex align-items-center gap-2 mb-2">
                          {property.type === 'object' && (
                            <button
                              type="button"
                              className="btn btn-sm btn-info"
                              onClick={() => toggleCollapsed(index)}
                              title={property.collapsed ? 'Expand children' : 'Collapse children'}
                            >
                              {property.collapsed ? '↓' : '↑'}
                            </button>
                          )}
                          <input
                            type="text"
                            className="form-control"
                            placeholder="Property name"
                            value={property.name}
                            onChange={e => updateAt(index, { name: e.target.value })}
                          />
                          <select
                            className="form-control property-type-select dropdown-styling"
                            value={property.type}
                            onChange={e =>
                              updateAt(index, {
                                type: e.target.value as SchemaProperty['type'],
                                // Drop xIdentity if moving away from a primitive.
                                xIdentity: PRIMITIVE_TYPES.includes(
                                  e.target.value as SchemaProperty['type']
                                )
                                  ? property.xIdentity
                                  : false,
                              })
                            }
                            title="Property type"
                          >
                            <option value="string">String</option>
                            <option value="number">Number</option>
                            <option value="boolean">Boolean</option>
                            <option value="object">Object</option>
                            <option value="array">Array</option>
                          </select>
                          {property.type === 'object' && (
                            <button
                              type="button"
                              className="btn btn-sm btn-success"
                              onClick={() => addChildProperty(index)}
                              title="Add child property"
                            >
                              <i className="fas fa-plus"></i>
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-sm btn-danger"
                            onClick={() => removeProperty(index)}
                            title="Remove property"
                          >
                            <i className="fas fa-trash"></i>
                          </button>
                        </div>

                        <div className="d-flex align-items-center gap-5">
                          {PRIMITIVE_TYPES.includes(property.type) && (
                            <>
                              <div
                                className="form-check me-4"
                                title="Include in identity hash computation"
                                style={{ marginRight: '10px' }}
                              >
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  id={`identity-${index}`}
                                  checked={property.xIdentity}
                                  onChange={e =>
                                    updateAt(index, {
                                      xIdentity: e.target.checked,
                                      // Identity fields are implicitly required.
                                      required: e.target.checked ? true : property.required,
                                    })
                                  }
                                />
                                <label className="form-check-label" htmlFor={`identity-${index}`}>
                                  Identity
                                </label>
                              </div>
                              <div
                                className="form-check"
                                title={
                                  property.xIdentity
                                    ? 'Identity fields are automatically required'
                                    : 'Property is required'
                                }
                              >
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  id={`required-${index}`}
                                  checked={property.required}
                                  disabled={property.xIdentity}
                                  onChange={e => updateAt(index, { required: e.target.checked })}
                                />
                                <label className="form-check-label" htmlFor={`required-${index}`}>
                                  Required
                                </label>
                              </div>
                            </>
                          )}
                        </div>

                        {(['string', 'number'].includes(property.type) ||
                          property.type === 'array') && (
                          <div className="mt-2">
                            <div className="row">
                              <div className="col-md-4">
                                <select
                                  className="form-control form-control-sm dropdown-styling"
                                  value={property.validationRule?.type || ''}
                                  onChange={e => setValidationType(index, e.target.value)}
                                  title="Validation rule type"
                                >
                                  <option value="">No validation</option>
                                  {property.type !== 'array' && (
                                    <>
                                      <option value="equals">Equals</option>
                                      <option value="contains">Contains</option>
                                      {property.type !== 'number' && (
                                        <option value="regex">Regex</option>
                                      )}
                                      {property.type === 'number' && (
                                        <option value="range">Range</option>
                                      )}
                                    </>
                                  )}
                                  {property.type === 'array' && (
                                    <>
                                      <option value="array-all">Array All Elements</option>
                                      <option value="array-any">Array Any Element</option>
                                      <option value="array-length">Array Length</option>
                                    </>
                                  )}
                                </select>
                              </div>
                              {property.validationRule && (
                                <div className="col-md-8">
                                  {!property.validationRule.type.startsWith('array-') ? (
                                    <>
                                      <input
                                        type="text"
                                        className={`form-control form-control-sm ${
                                          property.validationRule.type === 'regex' &&
                                          property.validationRule.value
                                            ? (() => {
                                                try {
                                                  new RegExp(property.validationRule.value);
                                                  return 'is-valid';
                                                } catch {
                                                  return 'is-invalid';
                                                }
                                              })()
                                            : ''
                                        }`}
                                        placeholder={
                                          property.validationRule.type === 'equals'
                                            ? 'Enter expected value...'
                                            : property.validationRule.type === 'contains'
                                              ? 'Enter text that must be contained...'
                                              : property.validationRule.type === 'regex'
                                                ? 'Enter regex pattern (e.g., ^[A-Z]+$)...'
                                                : property.validationRule.type === 'range'
                                                  ? 'Enter range as min-max (e.g., 1-100 or -100 or 1-)...'
                                                  : 'Validation value'
                                        }
                                        value={property.validationRule.value || ''}
                                        onChange={e =>
                                          updateValidation(index, { value: e.target.value })
                                        }
                                      />
                                      <div
                                        className="form-text text-muted"
                                        style={{ fontSize: '0.75rem', marginTop: '2px' }}
                                      >
                                        {property.validationRule.type === 'equals' &&
                                          'Field must exactly match this value'}
                                        {property.validationRule.type === 'contains' &&
                                          'Field must contain this text'}
                                        {property.validationRule.type === 'regex' &&
                                          (property.validationRule.value
                                            ? (() => {
                                                try {
                                                  new RegExp(property.validationRule.value);
                                                  return (
                                                    <span className="text-success">
                                                      <i className="fas fa-check"></i> Valid regex
                                                      pattern
                                                    </span>
                                                  );
                                                } catch {
                                                  return (
                                                    <span className="text-danger">
                                                      <i className="fas fa-times"></i> Invalid regex
                                                      pattern
                                                    </span>
                                                  );
                                                }
                                              })()
                                            : 'Enter a JavaScript-compatible regular expression')}
                                        {property.validationRule.type === 'range' &&
                                          'Format: min-max (leave min or max empty for unbounded, e.g., "-100" for max 100)'}
                                      </div>
                                    </>
                                  ) : (
                                    <>
                                      {(property.validationRule.type === 'array-all' ||
                                        property.validationRule.type === 'array-any') && (
                                        <div className="mb-2">
                                          <label className="form-label form-label-sm">
                                            Element Type
                                          </label>
                                          <select
                                            title="Validation type"
                                            className="form-control form-control-sm dropdown-styling"
                                            value={property.validationRule.elementType || 'string'}
                                            onChange={e =>
                                              updateValidation(index, {
                                                elementType: e.target.value,
                                              })
                                            }
                                          >
                                            <option value="string">String</option>
                                            <option value="number">Number</option>
                                            <option value="boolean">Boolean</option>
                                            <option value="object">Object</option>
                                            <option value="array">Array</option>
                                          </select>
                                        </div>
                                      )}
                                      {(property.validationRule.type === 'array-all' ||
                                        property.validationRule.type === 'array-any') && (
                                        <div className="mb-2">
                                          <label className="form-label form-label-sm">
                                            Allowed Values (optional)
                                          </label>
                                          <input
                                            type="text"
                                            className="form-control form-control-sm"
                                            placeholder="Comma-separated values (e.g., value1, value2, value3)"
                                            value={property.validationRule.values || ''}
                                            onChange={e =>
                                              updateValidation(index, { values: e.target.value })
                                            }
                                          />
                                        </div>
                                      )}
                                      {property.validationRule.type === 'array-length' && (
                                        <div className="row">
                                          <div className="col-6">
                                            <label className="form-label form-label-sm">
                                              Min Length
                                            </label>
                                            <input
                                              type="number"
                                              className="form-control form-control-sm"
                                              placeholder="Min"
                                              min="0"
                                              value={property.validationRule.min || ''}
                                              onChange={e =>
                                                updateValidation(index, { min: e.target.value })
                                              }
                                            />
                                          </div>
                                          <div className="col-6">
                                            <label className="form-label form-label-sm">
                                              Max Length
                                            </label>
                                            <input
                                              type="number"
                                              className="form-control form-control-sm"
                                              placeholder="Max"
                                              min="0"
                                              value={property.validationRule.max || ''}
                                              onChange={e =>
                                                updateValidation(index, { max: e.target.value })
                                              }
                                            />
                                          </div>
                                        </div>
                                      )}
                                      <div
                                        className="form-text text-muted"
                                        style={{ fontSize: '0.75rem', marginTop: '2px' }}
                                      >
                                        {property.validationRule.type === 'array-all' &&
                                          'All array elements must match the specified type and values'}
                                        {property.validationRule.type === 'array-any' &&
                                          'At least one array element must match the specified type and values'}
                                        {property.validationRule.type === 'array-length' &&
                                          'Array must have length within the specified range'}
                                      </div>
                                    </>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              <button
                type="button"
                className="btn btn-sm btn-success mt-2"
                onClick={addRootProperty}
              >
                <i className="fas fa-plus"></i> Add Root Property
              </button>
            </div>

            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <label
                  htmlFor="identity-raw-json"
                  className="form-label fw-bold mb-0 d-flex align-items-center gap-2"
                >
                  Request Schema Raw JSON
                  {rawError ? (
                    <span className="badge text-bg-danger ms-2">
                      <i className="fas fa-exclamation-triangle"></i> Invalid JSON
                    </span>
                  ) : (
                    <span className="badge text-bg-success ms-2">
                      <i className="fas fa-check"></i> Valid JSON
                    </span>
                  )}
                  {rawDirty && !rawError && (
                    <span className="badge text-bg-warning ms-2">Unsynced edits</span>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-primary"
                    onClick={syncRawToVisual}
                    disabled={!!rawError || !rawDirty}
                    title="Apply JSON edits to the visual editor and save"
                  >
                    <i className="fas fa-sync"></i> Sync Visual
                  </button>
                </label>
              </div>
              <textarea
                id="identity-raw-json"
                className={`form-control ${rawError ? 'is-invalid' : rawJson.trim() ? 'is-valid' : ''}`}
                rows={15}
                spellCheck={false}
                value={rawJson}
                onChange={e => handleRawJsonChange(e.target.value)}
                style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '12px' }}
              />
              {rawError && <div className="invalid-feedback d-block">{rawError}</div>}
              <small className="form-text text-muted d-block mt-2">
                Edit the JSON schema directly. Click <strong>Sync Visual</strong> to apply changes
                to the visual editor above. Saved to <code>config.json_schema</code>; identity
                fields are derived from <code>x-identity: true</code> markers and persisted to{' '}
                <code>config.fields</code> for the backend.
              </small>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default IdentityPayloadFullscreenPanel;
