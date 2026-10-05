import React, { useCallback, useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { apiClient } from '../../../../api';
import FieldHelp from '../../../shared/FieldHelp';

/**
 * Sidebar panel for the synthesised `local-gateway-hop` node.
 *
 * For `kind === 'proxy'` (MCP Proxy hop) the panel exposes MCP tool
 * policy configuration. Writes are routed back to the parent Transit
 * Point via `updateField('mcp_tool_policies', ...)` — the
 * `handleSynthAwareNodeUpdate` in SurfaceBuilder tunnels any field
 * other than `name` straight to the parent node's config when the
 * selected node is a synthetic hop.
 *
 * For `kind === 'fabric'` the panel just shows a description.
 */
const McpProxyPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const kind: 'proxy' | 'fabric' = config?.kind === 'proxy' ? 'proxy' : 'fabric';

  const [mcpPolicies, setMcpPolicies] = useState<
    Array<{ id: string; name: string; description: string }>
  >([]);
  const [policyTools, setPolicyTools] = useState<
    Array<{ tool_name: string; policy_definition_id: string; description: string }>
  >(config?.mcp_tool_policies?.tools || []);
  const [defaultPolicyId, setDefaultPolicyId] = useState<string>(
    config?.mcp_tool_policies?.default_policy_id || ''
  );

  const refreshPolicies = useCallback(() => {
    if (kind !== 'proxy') return;
    apiClient
      .fetch('/api/v1/policy-definitions?policy_type=agent_surface')
      .then(r => (r.ok ? r.json() : []))
      .then((data: any[]) => setMcpPolicies(data || []))
      .catch(() => {});
  }, [kind]);

  useEffect(() => {
    refreshPolicies();
  }, [refreshPolicies]);

  // Keep local state in sync when the parent config changes (e.g. on
  // surface reload the Transit Point's saved policies flow in).
  useEffect(() => {
    setPolicyTools(config?.mcp_tool_policies?.tools || []);
    setDefaultPolicyId(config?.mcp_tool_policies?.default_policy_id || '');
  }, [config?.mcp_tool_policies]);

  if (kind !== 'proxy') {
    return (
      <div className="config-section">
        <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
          Represents the local gateway hop in a gateway-to-gateway fabric:// route. No additional
          configuration is available here.
        </Form.Text>
      </div>
    );
  }

  return (
    <>
      <div className="config-section">
        <label>Default Tool Policy</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Applied to a tool with no exact match in the per-tool list below, on direct calls to this
          proxy. With no default set and at least one per-tool rule below, an unlisted tool is
          denied. With no default and no per-tool rules at all, tool gating is inactive and every
          tool is allowed.
        </Form.Text>
        <Form.Select
          size="sm"
          value={defaultPolicyId}
          onChange={e => {
            const v = e.target.value || '';
            setDefaultPolicyId(v);
            updateField('mcp_tool_policies', {
              default_policy_id: v || undefined,
              tools: policyTools,
            });
          }}
          disabled={mcpPolicies.length === 0}
        >
          {mcpPolicies.length === 0 ? (
            <option value="">Create a policy in the Policies section</option>
          ) : (
            <>
              <option value="">-- No default policy --</option>
              {mcpPolicies.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.description ? ` — ${p.description}` : ''}
                </option>
              ))}
            </>
          )}
        </Form.Select>
      </div>

      <div className="config-section">
        <label>Per-Tool Access Control</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Define OPA policies for individual MCP tools. An exact name match here always wins over
          the Default Tool Policy above; a tool with no entry here falls back to that default (see
          its note above for what happens with no default either).
        </Form.Text>

        {policyTools.length > 0 && (
          <div className="d-flex align-items-center gap-1 mb-1 small text-muted">
            Tool name
            <FieldHelp testId="field-help-local-gateway-hop-tool-name" ariaLabel="About Tool name">
              Enter the exact name of the MCP tool this rule applies to (case-sensitive, must match
              what the tool/server calls it, e.g. create_issue). A typo here means this rule never
              matches, and the tool falls back to the Default Tool Policy above.
            </FieldHelp>
          </div>
        )}

        {policyTools.map((tool, idx) => (
          <div
            key={idx}
            className="mb-2 p-2"
            style={{ border: '1px solid #e9ecef', borderRadius: '6px' }}
          >
            <Form.Group className="mb-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Tool name (e.g. create_issue)"
                value={tool.tool_name}
                onChange={e => {
                  const updated = [...policyTools];
                  updated[idx] = { ...updated[idx], tool_name: e.target.value };
                  setPolicyTools(updated);
                  updateField('mcp_tool_policies', {
                    default_policy_id: defaultPolicyId || undefined,
                    tools: updated,
                  });
                }}
              />
            </Form.Group>
            <Form.Group className="mb-1">
              {mcpPolicies.length > 0 ? (
                <Form.Select
                  size="sm"
                  value={tool.policy_definition_id}
                  onChange={e => {
                    const updated = [...policyTools];
                    updated[idx] = { ...updated[idx], policy_definition_id: e.target.value };
                    setPolicyTools(updated);
                    updateField('mcp_tool_policies', {
                      default_policy_id: defaultPolicyId || undefined,
                      tools: updated,
                    });
                  }}
                >
                  <option value="">-- Select policy --</option>
                  {mcpPolicies.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Form.Select>
              ) : (
                <Form.Select size="sm" disabled>
                  <option value="">Create a policy in the Policies section</option>
                </Form.Select>
              )}
            </Form.Group>
            <div className="d-flex align-items-center gap-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Description (optional)"
                value={tool.description}
                onChange={e => {
                  const updated = [...policyTools];
                  updated[idx] = { ...updated[idx], description: e.target.value };
                  setPolicyTools(updated);
                  updateField('mcp_tool_policies', {
                    default_policy_id: defaultPolicyId || undefined,
                    tools: updated,
                  });
                }}
                style={{ flex: 1 }}
              />
              <button
                className="btn btn-outline-danger btn-sm"
                onClick={() => {
                  const updated = policyTools.filter((_, i) => i !== idx);
                  setPolicyTools(updated);
                  updateField('mcp_tool_policies', {
                    default_policy_id: defaultPolicyId || undefined,
                    tools: updated,
                  });
                }}
                style={{ padding: '2px 8px' }}
              >
                <i className="fas fa-times" />
              </button>
            </div>
          </div>
        ))}

        <button
          className="btn btn-outline-primary btn-sm w-100"
          onClick={() => {
            const updated = [
              ...policyTools,
              { tool_name: '', policy_definition_id: '', description: '' },
            ];
            setPolicyTools(updated);
            updateField('mcp_tool_policies', {
              default_policy_id: defaultPolicyId || undefined,
              tools: updated,
            });
          }}
        >
          <i className="fas fa-plus me-1" /> Add Tool Policy
        </button>
      </div>
    </>
  );
};

export default McpProxyPanel;
