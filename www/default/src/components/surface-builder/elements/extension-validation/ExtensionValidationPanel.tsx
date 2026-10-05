import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import FieldHelp from '../../../shared/FieldHelp';

const ExtensionValidationPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Required Extensions</label>
      <Form.Control
        size="sm"
        type="text"
        placeholder="https://a2a.dev/extensions/agent-identity/v1"
        value={config.required_extensions || ''}
        onChange={e => updateField('required_extensions', e.target.value)}
      />
      <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
        Comma-separated list of extension URIs that must be present
      </Form.Text>
    </div>

    <div className="config-section">
      <label className="d-flex align-items-center gap-1">
        JSON Schema (optional)
        <FieldHelp
          testId="field-help-extension-validation-json-schema"
          ariaLabel="About JSON Schema"
        >
          A JSON Schema (a structured rulebook describing exactly what shape and fields the
          extension data must have) pasted here. If the incoming extension data doesn't match, the
          request is rejected. Must be valid JSON: if it doesn't parse, this schema is silently
          skipped and won't be enforced. Leave blank to skip this check entirely.
        </FieldHelp>
      </label>
      <Form.Control
        as="textarea"
        rows={5}
        size="sm"
        placeholder={'{\n  "type": "object",\n  "required": ["agentIdentity"]\n}'}
        value={config.schema || ''}
        onChange={e => updateField('schema', e.target.value)}
        style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '11px' }}
      />
    </div>
  </>
);

export default ExtensionValidationPanel;
