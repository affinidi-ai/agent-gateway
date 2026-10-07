import React from 'react';

export interface McpProxyWriteResult {
  warnings?: string[];
}

/** Warnings an MCP Proxy create or update response carries, such as a modern-only catalog. */
const WriteWarnings: React.FC<{ warnings?: string[]; className?: string }> = ({
  warnings,
  className = '',
}) =>
  warnings && warnings.length > 0 ? (
    <div
      className={`alert alert-warning text-start ${className}`.trim()}
      role="alert"
      data-testid="mcp-proxy-write-warnings"
    >
      <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
      <strong>Saved with warnings.</strong>
      <ul className="mb-0 mt-2 small">
        {warnings.map((warning, index) => (
          <li key={index}>{warning}</li>
        ))}
      </ul>
    </div>
  ) : null;

export default WriteWarnings;
