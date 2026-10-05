import React, { useState, useEffect } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import FieldHelp from '../../../shared/FieldHelp';
import type { ConfigPanelProps } from '../types';

const CustomMetadataPanel: React.FC<ConfigPanelProps> = ({ config, updateField, node }) => {
  const entries: Array<{ key: string; value: string; target?: string }> = config.entries || [];
  const [secrets, setSecrets] = useState<
    Array<{ id: string; name: string; secret_id: string; description?: string }>
  >([]);
  const [openSecretsIdx, setOpenSecretsIdx] = useState<number | null>(null);

  useEffect(() => {
    Promise.resolve(apiClient.fetch('/api/v1/secrets/'))
      .then(r => (r?.ok ? r.json() : []))
      .then((data: any[]) => setSecrets(data || []))
      .catch(() => {});
  }, []);

  const addEntry = () => {
    updateField('entries', [...entries, { key: '', value: '', target: 'header' }]);
  };

  const updateEntry = (idx: number, field: string, value: string) => {
    const updated = [...entries];
    updated[idx] = { ...updated[idx], [field]: value };
    updateField('entries', updated);
  };

  const removeEntry = (idx: number) => {
    updateField(
      'entries',
      entries.filter((_, i) => i !== idx)
    );
  };

  return (
    <div className="config-section">
      <label>Inject metadata</label>
      <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
        Key-value pairs injected into this direction&apos;s traffic. Drop another Metadata Injection
        element on the opposite arrow to inject into the other direction.
      </Form.Text>

      {entries.length > 0 && (
        <div className="d-flex align-items-center gap-3 mb-1 small text-muted">
          <span className="d-flex align-items-center gap-1">
            Key
            <FieldHelp testId="field-help-custom-metadata-key" ariaLabel="About Key">
              The name of the field to add, e.g. a header name like X-Request-Source, or a JSON key
              if injecting into the body. Pick the destination in Target below; this Key is just the
              label, the Value field holds the data.
            </FieldHelp>
          </span>
          <span className="d-flex align-items-center gap-1">
            Target
            <FieldHelp testId="field-help-custom-metadata-target" ariaLabel="About Target">
              <p>
                Every value here is added to both the HTTP headers and the protocol's own metadata
                field (<code>_meta</code>). The option picked above doesn't change where it lands.
              </p>
            </FieldHelp>
          </span>
        </div>
      )}

      {entries.map((entry, idx) => (
        <div key={idx} className="custom-metadata-entry mb-2 p-2" style={{ position: 'relative' }}>
          <div className="d-flex gap-1 mb-1">
            <Form.Control
              size="sm"
              type="text"
              placeholder="Key"
              value={entry.key}
              onChange={e => updateEntry(idx, 'key', e.target.value)}
              style={{ flex: 1 }}
            />
            <Form.Control
              size="sm"
              type="text"
              placeholder="Value or $SECRET:name"
              value={entry.value}
              onChange={e => updateEntry(idx, 'value', e.target.value)}
              style={{ flex: 1 }}
            />
            <div>
              <button
                className="btn btn-outline-secondary btn-sm"
                onClick={() => setOpenSecretsIdx(openSecretsIdx === idx ? null : idx)}
                title="Select secret"
                style={{ padding: '2px 6px' }}
              >
                <i className="fas fa-key" />
              </button>
            </div>
            <button
              className="btn btn-outline-danger btn-sm"
              onClick={() => removeEntry(idx)}
              style={{ padding: '2px 8px' }}
            >
              <i className="fas fa-times" />
            </button>
          </div>
          {openSecretsIdx === idx && (
            <ul
              className="dropdown-menu show"
              style={{
                position: 'absolute',
                right: '0.5rem',
                left: '0.5rem',
                top: '100%',
                zIndex: 1000,
                maxHeight: '260px',
                overflowY: 'auto',
              }}
            >
              {secrets.length === 0 ? (
                <li>
                  <span className="dropdown-item-text text-muted" style={{ fontSize: '12px' }}>
                    No secrets configured yet.{' '}
                    <AddResourceLink to={deepLinks.secret} testid="custom-metadata-add-secret-link">
                      Add secret
                    </AddResourceLink>
                  </span>
                </li>
              ) : (
                <>
                  {secrets.map(secret => (
                    <li key={secret.id}>
                      <button
                        type="button"
                        className="dropdown-item"
                        onClick={() => {
                          updateEntry(idx, 'value', `$SECRET:${secret.secret_id}`);
                          setOpenSecretsIdx(null);
                        }}
                      >
                        <div>
                          <strong style={{ fontSize: '12px' }}>{secret.name}</strong>
                          <div className="text-muted" style={{ fontSize: '10px' }}>
                            {secret.secret_id}
                          </div>
                        </div>
                      </button>
                    </li>
                  ))}
                  <li>
                    <hr className="dropdown-divider" />
                  </li>
                  <li>
                    <span className="dropdown-item-text text-muted" style={{ fontSize: '11px' }}>
                      Don&apos;t see the one you need?{' '}
                      <AddResourceLink
                        to={deepLinks.secret}
                        testid="custom-metadata-add-secret-link"
                      >
                        Add secret
                      </AddResourceLink>
                    </span>
                  </li>
                </>
              )}
            </ul>
          )}
          {entry.value?.startsWith('$SECRET:') && (
            <span className="badge text-bg-warning mb-1" style={{ fontSize: '9px' }}>
              <i className="fas fa-key me-1" /> Secret reference
            </span>
          )}
          <div className="d-flex gap-1">
            <Form.Select
              size="sm"
              value={entry.target || 'header'}
              onChange={e => updateEntry(idx, 'target', e.target.value)}
              style={{ flex: 1 }}
            >
              <option value="header">HTTP Header</option>
              <option value="extension">Protocol Extension</option>
              <option value="body">Body (JSON merge)</option>
              <option value="query">Query Parameter</option>
            </Form.Select>
          </div>
        </div>
      ))}

      <button className="btn btn-outline-primary btn-sm w-100" onClick={addEntry}>
        <i className="fas fa-plus me-1" /> Add Entry
      </button>

      <div className="mt-3">
        <label>Dynamic Values</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Optional helpers for <strong>Inject metadata</strong> values. They are resolved when the
          gateway injects the configured entry.
        </Form.Text>
        <div
          className="metadata-dynamic-values p-2 rounded"
          data-testid={`metadata-injection-dynamic-values-${node.id}`}
        >
          <div>
            <code>{'$REQUEST_ID'}</code>: current request trace ID
          </div>
          <div>
            <code>{'$TIMESTAMP'}</code>: injection-time UTC timestamp
          </div>
          <div>
            <code>{'$SURFACE_ID'}</code>: Agent Surface ID
          </div>
          <div>
            <code>{'$SECRET:id'}</code>: secret reference
          </div>
        </div>
      </div>
    </div>
  );
};

export default CustomMetadataPanel;
