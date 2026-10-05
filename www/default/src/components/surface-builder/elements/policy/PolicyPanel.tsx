import React, { useState, useEffect } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { ConfigPanelProps } from '../types';

const PolicyPanel: React.FC<ConfigPanelProps> = ({ node, config, updateField }) => {
  const [policies, setPolicies] = useState<
    Array<{ id: string; name: string; description: string; policy: string }>
  >([]);

  useEffect(() => {
    apiClient
      .fetch('/api/v1/policy-definitions?policy_type=agent_surface')
      .then(r => (r.ok ? r.json() : []))
      .then((data: any[]) => setPolicies(data || []))
      .catch(() => {});
  }, []);

  const selectedPolicy = policies.find(p => p.id === config.policy_definition_id) || null;

  return (
    <>
      {config.applies_to && (
        <div className="config-section">
          <label>Applies To</label>
          <div
            className="d-flex align-items-center gap-2 p-2 rounded"
            style={{ background: '#f8f9fc', border: '1px solid #e9ecef', fontSize: '12px' }}
          >
            <i className="fas fa-link text-muted" />
            <span>
              Attached to edge from <strong>{config.applies_to}</strong>
            </span>
          </div>
          <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
            Policy executes at this point in the pipeline. Drag to a different edge to change.
          </Form.Text>
        </div>
      )}

      <div className="config-section">
        <label>Policy Definition</label>
        <Form.Select
          size="sm"
          value={config.policy_definition_id || ''}
          onChange={e => updateField('policy_definition_id', e.target.value || '')}
          disabled={policies.length === 0}
        >
          <option value="">-- Select a policy --</option>
          {policies.map(policy => (
            <option key={policy.id} value={policy.id}>
              {policy.name}
            </option>
          ))}
        </Form.Select>
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          {policies.length === 0
            ? 'No Agent Surface policies configured yet. '
            : "Don't see the one you need? "}
          <AddResourceLink to={deepLinks.policies} testid="policy-panel-add-policy-link">
            Add policy
          </AddResourceLink>
        </Form.Text>
        {selectedPolicy && (
          <div className="policy-panel-preview mt-2 p-2 rounded">
            <div className="d-flex justify-content-between align-items-center mb-1">
              <strong style={{ fontSize: '11px' }}>{selectedPolicy.name}</strong>
            </div>
            {selectedPolicy.description && (
              <p className="policy-panel-description mb-1" style={{ fontSize: '10px' }}>
                {selectedPolicy.description}
              </p>
            )}
            {selectedPolicy.policy && (
              <pre
                className="policy-panel-code mb-0 p-2 rounded"
                style={{
                  fontSize: '10px',
                  maxHeight: '60vh',
                  minHeight: '180px',
                  overflow: 'auto',
                }}
              >
                <code>{selectedPolicy.policy}</code>
              </pre>
            )}
          </div>
        )}
      </div>

      <div className="config-section">
        <label>Agent Context</label>
        <Form.Group className="mb-2">
          <Form.Check
            type="switch"
            id="policy-require-agent-context"
            label="Enrich policy input with agent context"
            checked={config.require_agent_context === true}
            onChange={e => updateField('require_agent_context', e.target.checked)}
            disabled={node.direction === 'response'}
          />
          <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
            {node.direction === 'response'
              ? 'Agent context enrichment is not available for response policies.'
              : 'Adds trust registry data to the policy input. Increases request latency.'}
          </Form.Text>
        </Form.Group>
      </div>
    </>
  );
};

export default PolicyPanel;
