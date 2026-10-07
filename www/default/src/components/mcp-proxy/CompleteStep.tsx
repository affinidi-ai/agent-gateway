import React from 'react';
import WriteWarnings from './WriteWarnings';

interface CompleteStepProps {
  proxy: any;
  onFinish: () => void;
  onViewProxy: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ proxy, onFinish, onViewProxy }) => {
  const warnings: string[] = proxy?.warnings ?? [];
  const hasWarnings = warnings.length > 0;
  return (
    <div className="card shadow">
      <div className="card-body text-center py-5">
        <div className="mb-4">
          {hasWarnings ? (
            <i className="fas fa-exclamation-triangle hero-status-icon text-warning"></i>
          ) : (
            <i className="fas fa-check-circle hero-status-icon success"></i>
          )}
        </div>

        <h3 className="mb-3">
          {hasWarnings ? 'MCP Proxy Created with Warnings' : 'MCP Proxy Created Successfully!'}
        </h3>

        <p className="text-muted mb-4">
          Your MCP Proxy <strong>{proxy?.name}</strong> has been created and is now active.
        </p>

        <WriteWarnings warnings={warnings} className="mx-auto" />

        <div className="alert alert-info mx-auto" style={{ maxWidth: '500px' }}>
          <h6 className="font-weight-bold mb-2">
            <i className="fas fa-info-circle me-2"></i>
            Next Steps
          </h6>
          <ul className="text-start mb-0 small">
            {hasWarnings ? (
              <li>Resolve the warnings above before relying on this proxy</li>
            ) : (
              <li>The MCP Proxy is now running and ready to use</li>
            )}
            {proxy?.direct_access === false ? (
              <li>
                It has no route of its own: point a surface at it (target type &quot;via MCP
                Proxy&quot;) to let agents call it
              </li>
            ) : (
              <li>Agents can access your API through MCP tools</li>
            )}
            <li>You can view and manage this proxy from the MCP Proxies page</li>
          </ul>
        </div>

        <div className="mt-4">
          <button className="btn btn-primary me-2" onClick={onFinish}>
            <i className="fas fa-list me-1"></i>
            View All MCP Proxies
          </button>
          <button className="btn btn-outline-secondary" onClick={onViewProxy}>
            <i className="fas fa-eye me-1"></i>
            View This Proxy
          </button>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
