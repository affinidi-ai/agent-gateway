import React, { useRef, useState } from 'react';
import { validateScopeToken } from './scopes';

interface ScopesInputProps {
  scopes: string[];
  onChange: (scopes: string[]) => void;
}

const ScopesInput: React.FC<ScopesInputProps> = ({ scopes, onChange }) => {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const remove = (scope: string) => {
    onChange(scopes.filter(s => s !== scope));
    inputRef.current?.focus();
  };

  const add = () => {
    const token = input.trim();
    if (!token) return;
    const problem = validateScopeToken(token, scopes);
    if (problem) {
      setError(problem);
      return;
    }
    onChange([...scopes, token]);
    setInput('');
    setError(null);
  };

  return (
    <div className="mb-3" data-testid="caller-auth-scopes">
      <label htmlFor="caller-auth-scope-input" className="form-label fw-bold">
        Required Scopes
      </label>
      {scopes.length > 0 && (
        <ul className="list-unstyled d-flex flex-wrap gap-2 mb-2" aria-label="Required scopes">
          {scopes.map(scope => (
            <li
              key={scope}
              className="bg-light border rounded d-inline-flex align-items-center"
              style={{
                fontSize: '0.875rem',
                color: '#000',
                padding: '0.35rem 0.6rem',
                gap: '0.6rem',
              }}
            >
              {scope}
              <button
                type="button"
                className="btn btn-outline-danger p-0"
                style={{ lineHeight: 1, width: '1.4rem', height: '1.4rem' }}
                aria-label={`Remove scope ${scope}`}
                onClick={() => remove(scope)}
              >
                <i className="fas fa-trash" aria-hidden="true"></i>
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="input-group">
        <input
          ref={inputRef}
          id="caller-auth-scope-input"
          data-testid="caller-auth-scope-input"
          type="text"
          className={`form-control${error ? ' is-invalid' : ''}`}
          placeholder="e.g. agent:invoke"
          value={input}
          aria-describedby={
            error ? 'caller-auth-scope-error caller-auth-scope-help' : 'caller-auth-scope-help'
          }
          aria-invalid={error ? true : undefined}
          onChange={e => {
            setInput(e.target.value);
            setError(null);
          }}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              add();
            }
          }}
        />
        <button
          type="button"
          className="btn btn-outline-secondary"
          data-testid="caller-auth-scope-add"
          onClick={add}
        >
          Add scope
        </button>
      </div>
      <div role="alert">
        {error && (
          <small
            id="caller-auth-scope-error"
            className="text-danger d-block mt-1"
            data-testid="caller-auth-scope-error"
          >
            {error}
          </small>
        )}
      </div>
      <small id="caller-auth-scope-help" className="form-text text-muted">
        A caller&apos;s token must grant every scope listed. When this Access Point declares its
        authorization server, a token short of a required scope gets <code>403</code> with{' '}
        <code>insufficient_scope</code> before policy runs; otherwise it reaches policy as a failed
        caller. Required scopes are advertised in the agent card and the protected resource
        metadata. Press <kbd>Enter</kbd> or <kbd>,</kbd> to add.
      </small>
    </div>
  );
};

export default ScopesInput;
