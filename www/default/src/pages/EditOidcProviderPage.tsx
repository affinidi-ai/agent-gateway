import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatApiError } from '../utils/apiError';
import { validateUrl } from '../utils/urlValidation';
import { useSaveAction } from '../hooks/useSaveAction';

interface OidcProviderForm {
  name: string;
  issuer_url: string;
  expected_issuer: string;
  jwks_uri: string;
  validation_strategy: 'jwt' | 'introspection';
}

const EMPTY_FORM: OidcProviderForm = {
  name: '',
  issuer_url: '',
  expected_issuer: '',
  jwks_uri: '',
  validation_strategy: 'jwt',
};

const EditOidcProviderPage: React.FC = () => {
  const { run, saving, navigate } = useSaveAction();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';

  const [form, setForm] = useState<OidcProviderForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(!isNew);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isNew) {
      loadProvider();
    }
  }, [id]);

  const loadProvider = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch(`/api/v1/oidc-providers/${encodeURIComponent(id!)}`);
      if (!response.ok) {
        throw new Error(`Failed to load provider: ${response.statusText}`);
      }
      const data = await response.json();
      setForm({
        name: data.name ?? '',
        issuer_url: data.issuer_url ?? '',
        expected_issuer: data.expected_issuer ?? '',
        jwks_uri: data.jwks_uri ?? '',
        validation_strategy: data.validation_strategy ?? 'jwt',
      });
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError('Name is required.');
      return;
    }
    if (!form.issuer_url.trim()) {
      setError('Issuer URL is required.');
      return;
    }
    const issuerCheck = validateUrl(form.issuer_url);
    if (!issuerCheck.valid) {
      setError(`Issuer URL: ${issuerCheck.error}`);
      return;
    }
    if (form.jwks_uri.trim()) {
      const jwksCheck = validateUrl(form.jwks_uri);
      if (!jwksCheck.valid) {
        setError(`JWKS URI: ${jwksCheck.error}`);
        return;
      }
    }

    setError(null);

    const body = {
      name: form.name.trim(),
      issuer_url: form.issuer_url.trim(),
      expected_issuer: form.expected_issuer.trim() || undefined,
      jwks_uri: form.jwks_uri.trim() || undefined,
      validation_strategy: form.validation_strategy,
    };

    await run(
      async () => {
        const url = isNew
          ? '/api/v1/oidc-providers'
          : `/api/v1/oidc-providers/${encodeURIComponent(id!)}`;
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
      },
      {
        successMessage: isNew ? 'OIDC provider created!' : 'OIDC provider updated!',
        redirectTo: '/oidc-providers',
        onError: setError,
        errorMessage: 'Save failed',
      }
    );
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
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/oidc-providers')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-id-badge me-2"></i>
          {isNew ? 'New OIDC Provider' : 'Edit OIDC Provider'}
        </h1>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">Provider Configuration</h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

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

            {/* Issuer URL */}
            <div className="mb-3">
              <label htmlFor="issuer_url">
                Issuer URL <span className="text-danger">*</span>
              </label>
              <input
                id="issuer_url"
                name="issuer_url"
                type="url"
                className="form-control"
                value={form.issuer_url}
                onChange={handleChange}
                placeholder="https://accounts.example.com"
                required
              />
              <small className="form-text text-muted">
                Used for JWKS discovery (
                <code>{'<issuer_url>'}/.well-known/openid-configuration</code>) and as the default
                expected <code>iss</code> claim value.
              </small>
            </div>

            {/* Expected Issuer (optional override) */}
            <div className="mb-3">
              <label htmlFor="expected_issuer">
                Expected Issuer <span className="text-muted">(optional)</span>
              </label>
              <input
                id="expected_issuer"
                name="expected_issuer"
                type="text"
                className="form-control"
                value={form.expected_issuer}
                onChange={handleChange}
                placeholder="Override for iss claim validation"
              />
              <small className="form-text text-muted">
                Overrides <strong>Issuer URL</strong> for <code>iss</code> claim validation when the
                provider's <code>iss</code> value differs from its discovery URL. Leave blank to use
                Issuer URL.
              </small>
            </div>

            {/* JWKS URI (optional override) */}
            <div className="mb-3">
              <label htmlFor="jwks_uri">
                JWKS URI <span className="text-muted">(optional)</span>
              </label>
              <input
                id="jwks_uri"
                name="jwks_uri"
                type="url"
                className="form-control"
                value={form.jwks_uri}
                onChange={handleChange}
                placeholder="https://accounts.example.com/.well-known/jwks.json"
              />
              <small className="form-text text-muted">
                Overrides the JWKS URI discovered from the well-known document. Leave blank for
                auto-discovery.
              </small>
            </div>

            {/* Validation Strategy */}
            <div className="mb-3">
              <label htmlFor="validation_strategy">Validation Strategy</label>
              <select
                id="validation_strategy"
                name="validation_strategy"
                className="form-control dropdown-styling"
                value={form.validation_strategy}
                onChange={handleChange}
              >
                <option value="jwt">JWT (local signature verification)</option>
                <option value="introspection">Introspection (not yet implemented)</option>
              </select>
              <small className="form-text text-muted">
                <strong>JWT</strong>: validate the token locally using the provider's JWKS endpoint.
                <br />
                <strong>Introspection</strong>: validate via the provider's token introspection
                endpoint (reserved for future use — will return an error at runtime).
              </small>
            </div>

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
                    {isNew ? 'Create Provider' : 'Save Changes'}
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/oidc-providers')}
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

export default EditOidcProviderPage;
