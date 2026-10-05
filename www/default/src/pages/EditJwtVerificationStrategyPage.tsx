import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatApiError } from '../utils/apiError';
import { usePageTitle } from '../context/PageTitleContext';
import { validateUrl } from '../utils/urlValidation';
import FieldHelp from '../components/shared/FieldHelp';
import { Link } from '../components/shared/Link';
import { DOCS_URL } from '../config/docs';

interface JwksSourceForm {
  type: 'remote' | 'static';
  jwks_uri: string;
  jwks: string; // JSON textarea value
}

interface JwtVerificationStrategyForm {
  name: string;
  expected_issuer: string;
  jwks_source: JwksSourceForm;
}

const EMPTY_FORM: JwtVerificationStrategyForm = {
  name: '',
  expected_issuer: '',
  jwks_source: {
    type: 'remote',
    jwks_uri: '',
    jwks: '',
  },
};

const EditJwtVerificationStrategyPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';
  usePageTitle(isNew ? 'New JWT Verification Strategy' : 'Edit JWT Verification Strategy');

  const [form, setForm] = useState<JwtVerificationStrategyForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jwksUriCheckState, setJwksUriCheckState] = useState<'idle' | 'checking' | 'ok' | 'error'>(
    'idle'
  );
  const [jwksUriCheckError, setJwksUriCheckError] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!isNew) {
      loadStrategy();
    }
  }, [id]);

  const loadStrategy = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch(
        `/api/v1/jwt-verification-strategies/${encodeURIComponent(id!)}`
      );
      if (!response.ok) {
        throw new Error(`Failed to load strategy: ${response.statusText}`);
      }
      const data = await response.json();
      const src = data.jwks_source ?? {};
      setForm({
        name: data.name ?? '',
        expected_issuer: data.expected_issuer ?? '',
        jwks_source: {
          type: src.type === 'static' ? 'static' : 'remote',
          jwks_uri: src.jwks_uri ?? '',
          jwks: src.jwks ? JSON.stringify(src.jwks, null, 2) : '',
        },
      });
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleJwksSourceTypeChange = (type: 'remote' | 'static') => {
    setForm(prev => ({ ...prev, jwks_source: { ...prev.jwks_source, type } }));
    setJwksUriCheckState('idle');
    setJwksUriCheckError(null);
  };

  const handleJwksSourceFieldChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, jwks_source: { ...prev.jwks_source, [name]: value } }));
    if (name === 'jwks_uri') {
      setJwksUriCheckState('idle');
      setJwksUriCheckError(null);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (value.trim()) {
        debounceRef.current = setTimeout(() => checkJwksUri(value.trim()), 800);
      }
    }
  };

  const checkJwksUri = async (uri?: string) => {
    const target = (uri ?? form.jwks_source.jwks_uri).trim();
    if (!target) return;
    setJwksUriCheckState('checking');
    setJwksUriCheckError(null);
    try {
      const response = await apiClient.fetch(
        '/api/v1/jwt-verification-strategies/validate-jwks-uri',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ uri: target }),
        }
      );
      const result = await response.json();
      if (response.ok && result.valid) {
        setJwksUriCheckState('ok');
      } else {
        setJwksUriCheckState('error');
        setJwksUriCheckError(result.error ?? 'JWKS URI returned an invalid response');
      }
    } catch (e: any) {
      setJwksUriCheckState('error');
      setJwksUriCheckError(e.message ?? 'Network error while checking JWKS URI');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError('Name is required.');
      return;
    }
    if (!form.expected_issuer.trim()) {
      setError('Expected Issuer is required.');
      return;
    }
    if (form.jwks_source.type === 'remote' && !form.jwks_source.jwks_uri.trim()) {
      setError('JWKS URI is required for remote JWKS source.');
      return;
    }
    if (form.jwks_source.type === 'remote') {
      const jwksCheck = validateUrl(form.jwks_source.jwks_uri);
      if (!jwksCheck.valid) {
        setError(`JWKS URI: ${jwksCheck.error}`);
        return;
      }
    }
    if (form.jwks_source.type === 'remote' && jwksUriCheckState !== 'ok') {
      if (jwksUriCheckState === 'checking') {
        setError('Please wait, JWKS URI check is still in progress.');
      } else if (jwksUriCheckState === 'error') {
        setError('JWKS URI check failed. Fix the URI before saving.');
      } else {
        // idle — trigger the check and surface a message
        setError('Please verify the JWKS URI is reachable before saving.');
        checkJwksUri();
      }
      return;
    }

    let jwksSourcePayload: any;
    if (form.jwks_source.type === 'remote') {
      jwksSourcePayload = { type: 'remote', jwks_uri: form.jwks_source.jwks_uri.trim() };
    } else {
      let parsedJwks: any[];
      try {
        parsedJwks = JSON.parse(form.jwks_source.jwks || '[]');
        if (!Array.isArray(parsedJwks))
          throw new Error('JWKS must be a JSON array of JWK objects.');
      } catch (e: any) {
        setError(`Invalid JWKS JSON: ${e.message}`);
        return;
      }
      jwksSourcePayload = { type: 'static', jwks: parsedJwks };
    }

    setSaving(true);
    setError(null);

    const body = {
      name: form.name.trim(),
      expected_issuer: form.expected_issuer.trim(),
      jwks_source: jwksSourcePayload,
    };

    try {
      const url = isNew
        ? '/api/v1/jwt-verification-strategies'
        : `/api/v1/jwt-verification-strategies/${encodeURIComponent(id!)}`;
      const method = isNew ? 'POST' : 'PUT';

      const response = await apiClient.fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(formatApiError(response.status, text, response.statusText));
      }

      navigate('/settings?tab=strategies');
    } catch (e: any) {
      setError(e.message ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="container-fluid text-center py-5">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => navigate('/settings?tab=strategies')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">Strategy Configuration</h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          <p className="text-muted mb-3">
            A JWT verification strategy tells the gateway how to check that a bearer token presented
            by a caller is genuine: which issuer to trust, and where to find the public keys used to
            verify the token's signature. Create one before referencing it from a caller-auth
            configuration.{' '}
            <Link href={DOCS_URL.jwtStrategies} external variant="inline">
              Learn more
            </Link>
          </p>

          <form onSubmit={handleSubmit}>
            {/* Name */}
            <div className="mb-3">
              <label htmlFor="name">
                Name <span className="text-danger">*</span>
              </label>
              <input
                id="name"
                name="name"
                type="text"
                className="form-control"
                value={form.name}
                onChange={handleChange}
                placeholder="e.g. Okta Production"
                required
              />
              <small className="form-text text-muted">
                Human-readable label shown in the UI and referenced in channel configs.
              </small>
            </div>

            {/* Expected Issuer */}
            <div className="mb-3">
              <div className="field-label-with-help">
                <label htmlFor="expected_issuer" className="mb-0">
                  Expected Issuer <span className="text-danger">*</span>
                </label>
                <FieldHelp ariaLabel="About Expected Issuer" testId="field-help-expected-issuer">
                  The exact value the token's issuer (<code>iss</code>) field must match, usually
                  your identity provider's base URL.
                </FieldHelp>
              </div>
              <input
                id="expected_issuer"
                name="expected_issuer"
                type="text"
                className="form-control"
                value={form.expected_issuer}
                onChange={handleChange}
                placeholder="https://accounts.example.com"
                required
              />
              <small className="form-text text-muted">
                If a token's issuer doesn't match exactly, it's rejected, even if the signature is
                valid.
              </small>
            </div>

            {/* JWKS Source Type */}
            <div className="mb-3">
              <div className="field-label-with-help">
                <label className="mb-0">
                  JWKS Source <span className="text-danger">*</span>
                </label>
                <FieldHelp ariaLabel="About JWKS Source" testId="field-help-jwks-source">
                  Pick Remote URL if your identity provider publishes a JWKS endpoint, which is true
                  for most providers. Pick Static Keys only for offline or air-gapped setups where
                  the gateway can't reach that endpoint.
                </FieldHelp>
              </div>
              <small className="form-text text-muted d-block mb-2">
                Where the gateway gets the public keys (JWKS = JSON Web Key Set) used to check a
                token's signature.
              </small>
              <div className="d-flex gap-3">
                <div className="form-check me-3">
                  <input
                    className="form-check-input"
                    type="radio"
                    id="jwks-source-remote"
                    name="jwks_source_type"
                    value="remote"
                    checked={form.jwks_source.type === 'remote'}
                    onChange={() => handleJwksSourceTypeChange('remote')}
                  />
                  <label className="form-check-label" htmlFor="jwks-source-remote">
                    Remote URL
                    <small className="d-block text-muted">
                      Fetch JWKS from a URL (with caching)
                    </small>
                  </label>
                </div>
                <div className="form-check">
                  <input
                    className="form-check-input"
                    type="radio"
                    id="jwks-source-static"
                    name="jwks_source_type"
                    value="static"
                    checked={form.jwks_source.type === 'static'}
                    onChange={() => handleJwksSourceTypeChange('static')}
                  />
                  <label className="form-check-label" htmlFor="jwks-source-static">
                    Static Keys
                    <small className="d-block text-muted">Inline JWK array, no HTTP fetch</small>
                  </label>
                </div>
              </div>
            </div>

            {/* Remote: JWKS URI */}
            {form.jwks_source.type === 'remote' && (
              <div className="mb-3">
                <label htmlFor="jwks_uri">
                  JWKS URI <span className="text-danger">*</span>
                </label>
                <div className="input-group">
                  <input
                    id="jwks_uri"
                    name="jwks_uri"
                    type="url"
                    className={`form-control${jwksUriCheckState === 'error' ? ' is-invalid' : jwksUriCheckState === 'ok' ? ' is-valid' : ''}`}
                    value={form.jwks_source.jwks_uri}
                    onChange={handleJwksSourceFieldChange}
                    placeholder="https://accounts.example.com/.well-known/jwks.json"
                    required
                  />
                  <div className="input-group-append">
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={() => checkJwksUri()}
                      disabled={
                        jwksUriCheckState === 'checking' || !form.jwks_source.jwks_uri.trim()
                      }
                    >
                      {jwksUriCheckState === 'checking' ? (
                        <>
                          <span className="spinner-border spinner-border-sm me-1" />
                          Checking…
                        </>
                      ) : (
                        <>
                          <i className="fas fa-plug me-1" />
                          Check URI
                        </>
                      )}
                    </button>
                  </div>
                  {jwksUriCheckState === 'error' && (
                    <div className="invalid-feedback d-block">
                      <i className="fas fa-exclamation-triangle me-1" />
                      {jwksUriCheckError}
                    </div>
                  )}
                  {jwksUriCheckState === 'ok' && (
                    <div className="valid-feedback d-block">
                      <i className="fas fa-check me-1" />
                      JWKS URI is reachable and valid.
                    </div>
                  )}
                </div>
                <small className="form-text text-muted">
                  URL of the JSON Web Key Set endpoint. Keys will be cached with TTL from the
                  server's <code>Cache-Control</code> header (default 24 h).
                </small>
              </div>
            )}

            {/* Static: JWKS JSON array */}
            {form.jwks_source.type === 'static' && (
              <div className="mb-3">
                <label htmlFor="jwks">
                  JWK Array <span className="text-danger">*</span>
                </label>
                <textarea
                  id="jwks"
                  name="jwks"
                  className="form-control font-monospace"
                  rows={10}
                  value={form.jwks_source.jwks}
                  onChange={handleJwksSourceFieldChange}
                  placeholder={
                    '[\n  {\n    "kty": "RSA",\n    "use": "sig",\n    "kid": "my-key-1",\n    ...\n  }\n]'
                  }
                />
                <small className="form-text text-muted">
                  Paste a JSON array of JWK objects. These keys are used to verify incoming tokens
                  without any HTTP requests.
                </small>
              </div>
            )}

            <hr />

            <div className="d-flex">
              <button type="submit" className="btn btn-primary me-2" disabled={saving}>
                {saving ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-1" /> Saving…
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-1"></i>{' '}
                    {isNew ? 'Create Strategy' : 'Save Changes'}
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/settings?tab=strategies')}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditJwtVerificationStrategyPage;
