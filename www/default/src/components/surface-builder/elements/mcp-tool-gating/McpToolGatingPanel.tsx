import React from 'react';
import type { ConfigPanelProps } from '../types';

interface Gate {
  id?: string;
  name?: string;
  condition_policy_definition_id?: string | null;
  action?: { effect?: 'allow' | 'deny'; patterns?: unknown };
}

/**
 * Compact sidebar panel for the MCP Tool Gating element. Mirrors the Payment
 * element: it shows a high-level summary of the configured gates and defers
 * the full editor to a fullscreen view via "Configure Tool Gate".
 */
const McpToolGatingPanel: React.FC<ConfigPanelProps> = ({
  config,
  protocol,
  openFullscreenEditor,
}) => {
  const gates: Gate[] = Array.isArray(config?.gates) ? config.gates : [];
  const isMcp = protocol === 'mcp';
  const denyByDefault = config?.default_effect === 'deny';

  const enforced = gates.filter(g => {
    const patterns = Array.isArray(g.action?.patterns)
      ? (g.action!.patterns as unknown[]).filter(
          p => typeof p === 'string' && (p as string).trim() !== ''
        )
      : [];
    return patterns.length > 0;
  });
  const allowCount = enforced.filter(g => g.action?.effect === 'allow').length;
  const denyCount = enforced.filter(g => g.action?.effect !== 'allow').length;
  const conditionalCount = enforced.filter(
    g =>
      typeof g.condition_policy_definition_id === 'string' &&
      g.condition_policy_definition_id.trim() !== ''
  ).length;

  if (!isMcp) {
    return (
      <div className="config-section">
        <div className="alert alert-info py-2 mb-0" style={{ fontSize: '11px' }}>
          <i className="fas fa-info-circle me-1" /> MCP Tool Gating is only available for MCP
          surfaces.
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="config-section">
        <div className="alert alert-info py-2 mb-0" style={{ fontSize: '11px' }}>
          <i className="fas fa-filter me-1" /> A condition-gated allow/deny firewall over this
          surface's MCP tools. Applies to both <code>tools/list</code> and <code>tools/call</code>.
          When a tool matches both an Allow and a Deny gate, Deny wins; a tool matching neither
          falls back to the default above.
        </div>
      </div>

      <div className="config-section">
        <label>Summary</label>
        <div className="p-2 rounded bg-light border" style={{ fontSize: '12px' }}>
          <div className="d-flex justify-content-between mb-1">
            <span className="text-muted">By default, tools are</span>
            <strong
              className={denyByDefault ? 'text-danger' : 'text-success'}
              data-testid="mcp-tool-gating-default-effect-summary"
            >
              {denyByDefault ? 'Denied' : 'Allowed'}
            </strong>
          </div>
          <div className="d-flex justify-content-between mb-1">
            <span className="text-muted">Tool gate rules enforced</span>
            <strong data-testid="mcp-tool-gating-enforced-count">{enforced.length}</strong>
          </div>
          <div className="d-flex justify-content-between mb-1">
            <span className="text-muted">
              <i className="fas fa-check-circle text-success me-1" /> Allow-list gates
            </span>
            <span>{allowCount}</span>
          </div>
          <div className="d-flex justify-content-between mb-1">
            <span className="text-muted">
              <i className="fas fa-ban text-danger me-1" /> Deny gates
            </span>
            <span>{denyCount}</span>
          </div>
          <div className="d-flex justify-content-between">
            <span className="text-muted">
              <i className="fas fa-code-branch me-1" /> Conditional (OPA) gates
            </span>
            <span>{conditionalCount}</span>
          </div>
        </div>
        {gates.length > enforced.length && (
          <div className="alert alert-warning py-2 mt-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            {gates.length - enforced.length} gate(s) have no regex pattern and are ignored.
          </div>
        )}
      </div>

      <div className="config-section">
        <button
          type="button"
          className="btn btn-sm btn-primary w-100"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
          data-testid="mcp-tool-gating-configure"
        >
          <i className="fas fa-sliders-h me-1" /> Configure Tool Gate
        </button>
        {enforced.length === 0 && (
          <div className="text-muted mt-2" style={{ fontSize: '10px' }}>
            {denyByDefault
              ? 'Deny-by-default with no allow gates — every tool is hidden. Add an Allow gate to expose specific tools.'
              : 'Allow-by-default with no gates — every tool is exposed. Add a Deny gate to hide specific tools.'}
          </div>
        )}
      </div>
    </>
  );
};

export default McpToolGatingPanel;
