import React, { useState } from 'react';
import { substituteTemplateVariables } from '../../utils/templateVariables';

interface IntegrationPreviewProps {
  template: string;
  variables: Record<string, string>;
  label?: string;
  defaultExpanded?: boolean;
}

/**
 * Preview component showing template with variable substitutions
 * Shows before/after view of template rendering
 */
export const IntegrationPreview: React.FC<IntegrationPreviewProps> = ({
  template,
  variables,
  label = 'Preview',
  defaultExpanded = false,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const rendered = substituteTemplateVariables(template, variables);

  return (
    <div className="card">
      <div
        className="card-header bg-light cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <h6 className="mb-0">
          <i className={`fas fa-chevron-${isExpanded ? 'down' : 'right'} me-2`}></i>
          {label}
        </h6>
      </div>
      {isExpanded && (
        <div className="card-body">
          <div className="mb-3">
            <p className="text-muted small mb-2">
              <strong>Template (with variables)</strong>
            </p>
            <div
              style={{
                padding: '1rem',
                backgroundColor: 'var(--gray-50)',
                borderRadius: '0.25rem',
                border: '1px solid var(--gray-300)',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {template}
            </div>
          </div>

          <hr />

          <div>
            <p className="text-muted small mb-2">
              <strong>Rendered Output</strong>
            </p>
            <div
              style={{
                padding: '1rem',
                backgroundColor: '#d4edda',
                borderRadius: '0.25rem',
                border: '1px solid #c3e6cb',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {rendered}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
