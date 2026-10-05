import React, { useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';

interface AccessTokenScopesFieldProps {
  availableScopes: string[];
  selectedScopes: string[];
  unavailableScopes: string[];
  onChange: (scopes: string[]) => void;
  disabled?: boolean;
}

const AccessTokenScopesField: React.FC<AccessTokenScopesFieldProps> = ({
  availableScopes,
  selectedScopes,
  unavailableScopes,
  onChange,
  disabled = false,
}) => {
  const [filter, setFilter] = useState('');
  const selected = useMemo(() => new Set(selectedScopes), [selectedScopes]);
  const unavailable = useMemo(() => new Set(unavailableScopes), [unavailableScopes]);
  const visibleScopes = useMemo(() => {
    const term = filter.trim().toLowerCase();
    return [...availableScopes]
      .sort()
      .filter(scope => !selected.has(scope) && (!term || scope.toLowerCase().includes(term)));
  }, [availableScopes, filter, selected]);

  const add = (scope: string) => onChange([...selectedScopes, scope].sort());
  const remove = (scope: string) => onChange(selectedScopes.filter(value => value !== scope));

  return (
    <div className="mb-3" data-testid="access-token-scopes-field">
      <div className="d-flex justify-content-between align-items-center mb-1">
        <span className="form-label mb-0" data-testid="access-token-selected-scopes-label">
          Selected scopes{selectedScopes.length > 0 ? ` (${selectedScopes.length})` : ''}
        </span>
        {selectedScopes.length > 0 && !disabled && (
          <button
            type="button"
            className="btn btn-link btn-sm p-0"
            onClick={() => onChange([])}
            data-testid="access-token-clear-scopes"
          >
            Clear all
          </button>
        )}
      </div>
      <div className="access-token-selected border rounded p-2 mb-2">
        {selectedScopes.length === 0 ? (
          <small className="text-muted">
            No scopes selected. The token inherits the bound user&apos;s full role.
          </small>
        ) : (
          <div className="d-flex flex-wrap gap-2">
            {[...selectedScopes].sort().map(scope => (
              <span
                key={scope}
                className={`badge d-inline-flex align-items-center ${
                  unavailable.has(scope) ? 'text-bg-danger' : 'text-bg-primary'
                }`}
                data-testid={`access-token-selected-scope-${scope}`}
              >
                {scope}
                {!disabled && (
                  <button
                    type="button"
                    className="access-token-scope-remove ms-1"
                    onClick={() => remove(scope)}
                    aria-label={`Remove scope ${scope}`}
                    data-testid={
                      unavailable.has(scope)
                        ? `access-token-remove-unavailable-scope-${scope}`
                        : `access-token-scope-remove-${scope}`
                    }
                  >
                    <i className="fas fa-times" aria-hidden="true" />
                  </button>
                )}
              </span>
            ))}
          </div>
        )}
      </div>
      <Form.Group controlId="access-token-scope-filter-input">
        <Form.Label data-testid="access-token-available-scopes-label">Available scopes</Form.Label>
        <Form.Control
          size="sm"
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder="Filter scopes..."
          disabled={disabled}
          data-testid="access-token-scope-filter"
        />
      </Form.Group>
      <div className="access-token-scopes border rounded p-2 mt-2">
        {visibleScopes.length === 0 ? (
          <div className="text-muted small">
            {filter.trim() ? 'No scopes match this filter.' : 'All scopes selected.'}
          </div>
        ) : (
          visibleScopes.map(scope => (
            <button
              key={scope}
              type="button"
              className="badge access-token-scope-pill d-inline-flex align-items-center me-2 mb-2"
              onClick={() => add(scope)}
              disabled={disabled}
              aria-label={`Add scope ${scope}`}
              data-testid={`access-token-scope-add-${scope}`}
            >
              <i className="fas fa-plus me-1" aria-hidden="true" />
              {scope}
            </button>
          ))
        )}
      </div>
      {unavailableScopes.length > 0 && (
        <div
          className="alert alert-danger py-2 mt-2 mb-0"
          data-testid="access-token-unavailable-scopes"
        >
          Remove the red unavailable scopes before saving.
        </div>
      )}
    </div>
  );
};

export default AccessTokenScopesField;
