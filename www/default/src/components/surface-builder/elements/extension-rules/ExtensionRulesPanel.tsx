import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import FieldHelp from '../../../shared/FieldHelp';

const ExtensionRulesPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const rules: Array<{ extension_uri: string; action: string; condition?: string }> =
    config.rules || [];

  return (
    <>
      <div className="config-section">
        <label className="d-flex align-items-center gap-1">
          Default Behavior
          <FieldHelp
            testId="field-help-extension-rules-default-behavior"
            ariaLabel="About Default Behavior"
          >
            <p>What to do with a protocol extension the gateway has no specific rule for:</p>
            <p>
              <strong>Pass through</strong> lets it continue untouched. It's the simplest option,
              but the destination sees whatever the caller sent, verified or not.
            </p>
            <p>
              <strong>Strip unknown extensions</strong> silently removes it before forwarding. It's
              the safer choice, and the recommended setting for production.
            </p>
            <p>
              <strong>Reject if unknown extensions present</strong> blocks the whole request. It's
              the strictest option; use it once you know every extension you expect.
            </p>
          </FieldHelp>
        </label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Extension Rules only filters inbound (request) extensions. Dropping it on the response
          arrow has no effect on outbound traffic.
        </Form.Text>
        <Form.Select
          size="sm"
          value={config.default_action || 'pass'}
          onChange={e => updateField('default_action', e.target.value)}
        >
          <option value="pass">Pass through (no filtering)</option>
          <option value="strip">Strip unknown extensions</option>
          <option value="reject">Reject if unknown extensions present</option>
        </Form.Select>
      </div>

      <div className="config-section">
        <label>Extension Rules</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Per-extension URI rules override the default behavior.
        </Form.Text>

        {rules.length > 0 && (
          <div className="d-flex align-items-center gap-3 mb-1 small text-muted">
            <span className="d-flex align-items-center gap-1">
              Extension URI
              <FieldHelp
                testId="field-help-extension-rules-extension-uri"
                ariaLabel="About Extension URI"
              >
                The exact identifier for the extension this rule applies to: copy it from the
                extension's own documentation (e.g. https://a2a.dev/extensions/agent-identity/v1). A
                mismatched URI means this rule won't match, so that extension is handled by Default
                Behavior above instead.
              </FieldHelp>
            </span>
            <span className="d-flex align-items-center gap-1">
              Action
              <FieldHelp testId="field-help-extension-rules-action" ariaLabel="About Action">
                <p>
                  What to do specifically with this extension URI (overrides Default Behavior
                  above):
                </p>
                <p>
                  <strong>Require</strong>: every request must include it, or it's rejected.
                </p>
                <p>
                  <strong>Allow</strong>: permitted if present, but optional.
                </p>
                <p>
                  <strong>Strip</strong>: always remove it, even if sent.
                </p>
                <p>
                  <strong>Reject if present</strong>: block any request that includes it at all.
                </p>
              </FieldHelp>
            </span>
          </div>
        )}

        {rules.map((rule, idx) => (
          <div
            key={idx}
            className="mb-2 p-2"
            style={{ border: '1px solid #e9ecef', borderRadius: '6px' }}
          >
            <Form.Group className="mb-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Extension URI (e.g. https://a2a.dev/extensions/...)"
                value={rule.extension_uri}
                onChange={e => {
                  const updated = [...rules];
                  updated[idx] = { ...updated[idx], extension_uri: e.target.value };
                  updateField('rules', updated);
                }}
              />
            </Form.Group>
            <div className="d-flex gap-1">
              <Form.Select
                size="sm"
                value={rule.action}
                onChange={e => {
                  const updated = [...rules];
                  updated[idx] = { ...updated[idx], action: e.target.value };
                  updateField('rules', updated);
                }}
                style={{ flex: 1 }}
              >
                <option value="require">Require</option>
                <option value="allow">Allow</option>
                <option value="strip">Strip</option>
                <option value="reject">Reject if present</option>
              </Form.Select>
              <button
                className="btn btn-outline-danger btn-sm"
                onClick={() =>
                  updateField(
                    'rules',
                    rules.filter((_, i) => i !== idx)
                  )
                }
                style={{ padding: '2px 8px' }}
              >
                <i className="fas fa-times" />
              </button>
            </div>
          </div>
        ))}

        <button
          className="btn btn-outline-primary btn-sm w-100"
          onClick={() => updateField('rules', [...rules, { extension_uri: '', action: 'allow' }])}
        >
          <i className="fas fa-plus me-1" /> Add Rule
        </button>
      </div>
    </>
  );
};

export default ExtensionRulesPanel;
