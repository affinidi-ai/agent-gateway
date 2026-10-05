import React, { useState } from 'react';
import { Form } from 'react-bootstrap';
import type { RequiredHeader } from '../../types';
import AccessTokenScopePreview from './AccessTokenScopePreview';
import { inferTenantSelection } from './accessTokenHelpers';

const TENANT_PATTERN_EXAMPLE = ['TENANT:', '$', '{x-external-account}:secrets:.*'].join('');

interface AccessTokenResourceScopeFieldProps {
  pattern: string;
  headers: RequiredHeader[];
  onPatternChange: (value: string) => void;
  onHeadersChange: (headers: RequiredHeader[]) => void;
  disabled?: boolean;
  showValidation?: boolean;
}

const AccessTokenResourceScopeField: React.FC<AccessTokenResourceScopeFieldProps> = ({
  pattern,
  headers,
  onPatternChange,
  onHeadersChange,
  disabled = false,
  showValidation = false,
}) => {
  const [expanded, setExpanded] = useState(false);
  const inference = inferTenantSelection(pattern);
  const inferenceText =
    inference.mode === 'tenant'
      ? `Tenant selected by ${inference.headerName}`
      : inference.mode === 'invalid'
        ? inference.headerNames.length > 1
          ? 'Multiple tenant headers are not allowed.'
          : 'A non-empty pattern must select one tenant header.'
        : 'Appliance-wide';

  const updateHeader = (index: number, patch: Partial<RequiredHeader>) => {
    onHeadersChange(
      headers.map((header, itemIndex) => (itemIndex === index ? { ...header, ...patch } : header))
    );
  };

  const toggleExpanded = () => setExpanded(current => !current);
  const handleToggleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggleExpanded();
    }
  };

  return (
    <div className="card shadow mb-4" data-testid="access-token-resource-scope">
      <div
        className="card-header py-3 cursor-pointer"
        onClick={toggleExpanded}
        onKeyDown={handleToggleKeyDown}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-controls="access-token-resource-scope-content"
        data-testid="access-token-resource-scope-toggle"
      >
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas fa-chevron-${expanded ? 'down' : 'right'} me-2`} aria-hidden="true" />
          <i className="fas fa-building-shield me-2" aria-hidden="true" />
          Advanced resource scoping
        </h6>
      </div>
      {expanded && (
        <div
          className="card-body"
          id="access-token-resource-scope-content"
          data-testid="access-token-resource-scope-content"
        >
          <div
            className={`alert ${inference.mode === 'invalid' ? 'alert-danger' : 'alert-info'} py-2`}
          >
            <i className="fas fa-building-shield me-2" aria-hidden="true" />
            {inferenceText}
          </div>
          {inference.mode === 'tenant' && (
            <div
              className="alert alert-warning py-2"
              data-testid="access-token-tenant-selection-warning"
            >
              <strong>The header value selects the tenant.</strong> Its validation pattern defines
              every tenant this token holder may choose. Use an exact-value pattern for a
              single-tenant token, and configure the trusted proxy to overwrite this header.
            </div>
          )}
          <Form.Group className="mb-3" controlId="access-token-resource-pattern-input">
            <Form.Label>Resource pattern</Form.Label>
            <Form.Control
              className="font-monospace"
              value={pattern}
              maxLength={512}
              onChange={event => onPatternChange(event.target.value)}
              placeholder={TENANT_PATTERN_EXAMPLE}
              disabled={disabled}
              data-testid="access-token-resource-pattern"
            />
            <Form.Text muted>
              The whole canonical resource target must match. Leave blank for no ID restriction.
            </Form.Text>
          </Form.Group>

          <div className="d-flex justify-content-between align-items-center mb-2">
            <span className="form-label mb-0">Required headers</span>
            <button
              type="button"
              className="btn btn-outline-primary btn-sm"
              onClick={() => onHeadersChange([...headers, { name: '', pattern: '' }])}
              disabled={disabled || headers.length >= 8}
              data-testid="access-token-add-header"
            >
              <i className="fas fa-plus me-1" aria-hidden="true" /> Add header
            </button>
          </div>
          {headers.length === 0 ? (
            <div className="text-muted small">No required headers.</div>
          ) : (
            <>
              <div className="row g-2 mb-1" aria-hidden="true">
                <div className="col-md-5 form-label mb-0">
                  Header name <span className="text-danger">*</span>
                </div>
                <div className="col form-label mb-0">
                  Validation pattern <span className="text-danger">*</span>
                </div>
                <div className="col-auto" />
              </div>
              {headers.map((header, index) => (
                <div className="row g-2 mb-2" key={index}>
                  <div className="col-md-5">
                    <Form.Label
                      className="visually-hidden"
                      htmlFor={`access-token-header-name-input-${index}`}
                    >
                      Required header {index + 1} name
                    </Form.Label>
                    <Form.Control
                      id={`access-token-header-name-input-${index}`}
                      size="sm"
                      value={header.name}
                      maxLength={64}
                      onChange={event => updateHeader(index, { name: event.target.value })}
                      placeholder="x-external-account"
                      required
                      isInvalid={showValidation && !header.name.trim()}
                      disabled={disabled}
                      data-testid={`access-token-header-name-${index}`}
                    />
                    <Form.Control.Feedback
                      type="invalid"
                      data-testid={`access-token-header-name-error-${index}`}
                    >
                      Header name is required.
                    </Form.Control.Feedback>
                  </div>
                  <div className="col">
                    <Form.Label
                      className="visually-hidden"
                      htmlFor={`access-token-header-pattern-input-${index}`}
                    >
                      Required header {index + 1} validation pattern
                    </Form.Label>
                    <Form.Control
                      id={`access-token-header-pattern-input-${index}`}
                      size="sm"
                      className="font-monospace"
                      value={header.pattern}
                      maxLength={256}
                      onChange={event => updateHeader(index, { pattern: event.target.value })}
                      placeholder="e.g. \d{4}"
                      required
                      isInvalid={showValidation && !header.pattern}
                      disabled={disabled}
                      data-testid={`access-token-header-pattern-${index}`}
                    />
                    <Form.Control.Feedback
                      type="invalid"
                      data-testid={`access-token-header-pattern-error-${index}`}
                    >
                      Validation pattern is required.
                    </Form.Control.Feedback>
                  </div>
                  <div className="col-auto">
                    <button
                      type="button"
                      className="btn btn-outline-danger btn-sm"
                      onClick={() =>
                        onHeadersChange(headers.filter((_, itemIndex) => itemIndex !== index))
                      }
                      title="Remove header"
                      disabled={disabled}
                      data-testid={`access-token-header-remove-${index}`}
                    >
                      <i className="fas fa-times" aria-hidden="true" />
                    </button>
                  </div>
                </div>
              ))}
            </>
          )}

          <AccessTokenScopePreview pattern={pattern} headers={headers} />
        </div>
      )}
    </div>
  );
};

export default AccessTokenResourceScopeField;
