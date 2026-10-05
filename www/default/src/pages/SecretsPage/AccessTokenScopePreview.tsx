import React, { useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';
import type { RequiredHeader } from '../../types';
import {
  ACCESS_TOKEN_RESOURCE_KINDS,
  AccessTokenResourceKind,
  evaluateScopePreview,
  validateScopeConfig,
} from './accessTokenHelpers';

interface AccessTokenScopePreviewProps {
  pattern: string;
  headers: RequiredHeader[];
}

const AccessTokenScopePreview: React.FC<AccessTokenScopePreviewProps> = ({ pattern, headers }) => {
  const [sampleHeaders, setSampleHeaders] = useState<Record<string, string>>({});
  const [resourceKind, setResourceKind] = useState<AccessTokenResourceKind>('gateways');
  const [testId, setTestId] = useState('');
  const preview = useMemo(
    () => evaluateScopePreview(pattern, headers, sampleHeaders, resourceKind, testId),
    [pattern, headers, sampleHeaders, resourceKind, testId]
  );
  const configErrors = useMemo(() => validateScopeConfig(pattern, headers), [pattern, headers]);

  const headerOutcome = (header: RequiredHeader): 'ok' | 'mismatch' | 'invalid-regex' => {
    if (!header.pattern) return 'invalid-regex';
    try {
      const regex = new RegExp(`^(?:${header.pattern})$`, 's');
      return regex.test(sampleHeaders[header.name.trim().toLowerCase()] ?? '') ? 'ok' : 'mismatch';
    } catch {
      return 'invalid-regex';
    }
  };

  if (!pattern.trim() && headers.length === 0) return null;

  return (
    <div className="card bg-light border-0 mt-2" data-testid="access-token-scope-preview">
      <div className="card-body p-2">
        <div className="small fw-semibold text-muted mb-2">
          <i className="fas fa-flask me-1" aria-hidden="true" />
          Test this scope
        </div>
        <div className="small text-muted mb-2">Patterns must match the entire sample value.</div>

        {headers.map((header, index) => {
          const name = header.name.trim().toLowerCase();
          if (!name) return null;
          const outcome = headerOutcome(header);
          return (
            <div className="d-flex align-items-center gap-2 mb-1" key={`${name}-${index}`}>
              <span className="small font-monospace" style={{ minWidth: 160 }}>
                {header.name.trim()}
              </span>
              <Form.Control
                size="sm"
                value={sampleHeaders[name] ?? ''}
                placeholder="sample value"
                onChange={event =>
                  setSampleHeaders(current => ({ ...current, [name]: event.target.value }))
                }
                data-testid={`access-token-test-header-${index}`}
              />
              {outcome === 'ok' && (
                <i
                  className="fas fa-check text-success"
                  aria-hidden="true"
                  data-testid={`access-token-test-header-result-${index}`}
                />
              )}
              {outcome === 'mismatch' && (
                <span
                  className="small text-danger text-nowrap"
                  title="No full-value match"
                  data-testid={`access-token-test-header-result-${index}`}
                >
                  <i className="fas fa-times me-1" aria-hidden="true" />
                  no match
                </span>
              )}
              {outcome === 'invalid-regex' && (
                <span
                  className="badge text-bg-warning"
                  data-testid={`access-token-test-header-result-${index}`}
                >
                  bad regex
                </span>
              )}
            </div>
          );
        })}

        <div className="d-flex align-items-center gap-2 mt-2">
          <span className="small text-muted" style={{ minWidth: 160 }}>
            Resource kind
          </span>
          <Form.Select
            size="sm"
            value={resourceKind}
            onChange={event => setResourceKind(event.target.value as AccessTokenResourceKind)}
            data-testid="access-token-test-resource-kind"
          >
            {ACCESS_TOKEN_RESOURCE_KINDS.map(kind => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </Form.Select>
        </div>

        <div className="d-flex align-items-center gap-2 mt-2">
          <span className="small text-muted" style={{ minWidth: 160 }}>
            Sample entity ID
          </span>
          <Form.Control
            size="sm"
            className="font-monospace"
            value={testId}
            onChange={event => setTestId(event.target.value)}
            data-testid="access-token-test-id"
          />
          {testId.length > 0 && pattern.trim().length > 0 && (
            <span
              className={`badge ${preview.allowed ? 'text-bg-success' : 'text-bg-danger'}`}
              data-testid="access-token-test-result"
            >
              {preview.allowed ? 'allowed' : 'denied'}
            </span>
          )}
        </div>

        {testId.length > 0 && (
          <div className="small mt-2">
            <span className="text-muted me-2">Canonical target</span>
            <code data-testid="access-token-canonical-target">{preview.target}</code>
          </div>
        )}
        {configErrors.length > 0 && (
          <ul className="small text-danger mt-2 mb-0" data-testid="access-token-preview-errors">
            {configErrors.map(error => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default AccessTokenScopePreview;
