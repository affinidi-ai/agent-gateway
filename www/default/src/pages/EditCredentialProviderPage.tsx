import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatApiError } from '../utils/apiError';
import AddResourceLink from '../components/shared/AddResourceLink';
import FieldHelp from '../components/shared/FieldHelp';
import { Link } from '../components/shared/Link';
import { usePageTitle } from '../context/PageTitleContext';
import { useSaveAction } from '../hooks/useSaveAction';
import { deepLinks } from '../utils/deepLinks';
import { DOCS_URL } from '../config/docs';

interface Secret {
  id: string;
  name: string;
  secret_id: string;
}

interface CredentialProviderForm {
  name: string;
  provider_id: string;
  provider_type: 'oauth2_authorization_code' | 'oauth2_client_credentials' | 'api_key';
  authorization_endpoint: string;
  token_endpoint: string;
  client_id_secret_ref: string;
  client_secret_secret_ref: string;
  api_key_secret_ref: string;
  default_scopes: string;
  token_refresh_enabled: boolean;
  additional_params: string;
  description: string;
  callback_host: string;
}

interface RoutingConfig {
  available_listen_addresses: string[];
  oauth_callback_route: string;
}

const EMPTY_FORM: CredentialProviderForm = {
  name: '',
  provider_id: '',
  provider_type: 'oauth2_authorization_code',
  authorization_endpoint: '',
  token_endpoint: '',
  client_id_secret_ref: '',
  client_secret_secret_ref: '',
  api_key_secret_ref: '',
  default_scopes: '',
  token_refresh_enabled: true,
  additional_params: '',
  description: '',
  callback_host: '',
};

const EditCredentialProviderPage: React.FC = () => {
  const { run, saving, navigate } = useSaveAction();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';
  usePageTitle(isNew ? 'New Credential Provider' : 'Edit Credential Provider');

  const [form, setForm] = useState<CredentialProviderForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(!isNew);
  const [error, setError] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [loadingSecrets, setLoadingSecrets] = useState(true);
  const [routingConfig, setRoutingConfig] = useState<RoutingConfig | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    loadSecrets();
    loadRoutingConfig();
    if (!isNew) {
      loadProvider();
    }
  }, [id]);

  const loadRoutingConfig = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/config/surface-routing');
      if (response.ok) {
        const config = await response.json();
        setRoutingConfig(config);
      }
    } catch (e) {
      console.error('Failed to load routing config:', e);
    }
  };

  const loadSecrets = async () => {
    setLoadingSecrets(true);
    try {
      const response = await apiClient.fetch('/api/v1/secrets/');
      if (response.ok) {
        const data = await response.json();
        setSecrets(data);
      }
    } catch (e) {
      console.error('Failed to load secrets:', e);
    } finally {
      setLoadingSecrets(false);
    }
  };

  const loadProvider = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch(
        `/api/v1/credential-providers/${encodeURIComponent(id!)}`
      );
      if (!response.ok) {
        throw new Error(`Failed to load: ${response.statusText}`);
      }
      const data = await response.json();

      // Extract host from stored callback_url if present
      let callbackHost = '';
      if (data.callback_url) {
        try {
          const parsed = new URL(data.callback_url);
          callbackHost = `${parsed.protocol}//${parsed.host}`;
        } catch {
          // ignore parse errors
        }
      }

      setForm({
        name: data.name ?? '',
        provider_id: data.provider_id ?? '',
        provider_type: data.provider_type ?? 'oauth2_authorization_code',
        authorization_endpoint: data.authorization_endpoint ?? '',
        token_endpoint: data.token_endpoint ?? '',
        client_id_secret_ref: data.client_id_secret_ref ?? '',
        client_secret_secret_ref: data.client_secret_secret_ref ?? '',
        api_key_secret_ref: data.api_key_secret_ref ?? '',
        default_scopes: (data.default_scopes ?? []).join(', '),
        token_refresh_enabled: data.token_refresh_enabled ?? true,
        additional_params: data.additional_params
          ? JSON.stringify(data.additional_params, null, 2)
          : '',
        description: data.description ?? '',
        callback_host: callbackHost,
      });
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const deriveProviderId = (name: string) =>
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value, type } = e.target;
    if (type === 'checkbox') {
      setForm(prev => ({ ...prev, [name]: (e.target as HTMLInputElement).checked }));
    } else if (name === 'name' && isNew) {
      setForm(prev => ({ ...prev, name: value, provider_id: deriveProviderId(value) }));
    } else if (name === 'provider_id') {
      const sanitized = value.replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-|-$/g, '');
      setForm(prev => ({ ...prev, provider_id: sanitized }));
    } else {
      setForm(prev => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = useCallback(
    async (e?: React.FormEvent) => {
      if (e) e.preventDefault();
      if (!form.name.trim()) {
        setError('Name is required.');
        return;
      }
      if (!form.provider_id.trim()) {
        setError('Provider ID is required.');
        return;
      }

      const isOAuth =
        form.provider_type === 'oauth2_authorization_code' ||
        form.provider_type === 'oauth2_client_credentials';

      if (isOAuth) {
        if (!form.token_endpoint.trim()) {
          setError('Token endpoint is required for OAuth providers.');
          return;
        }
        if (!form.client_id_secret_ref) {
          setError('Client ID secret is required for OAuth providers.');
          return;
        }
        if (!form.client_secret_secret_ref) {
          setError('Client Secret secret is required for OAuth providers.');
          return;
        }
      }

      if (form.provider_type === 'api_key') {
        if (!form.api_key_secret_ref) {
          setError('API Key secret is required.');
          return;
        }
      }

      let additionalParams: Record<string, string> = {};
      if (form.additional_params.trim()) {
        try {
          additionalParams = JSON.parse(form.additional_params);
        } catch {
          setError('Additional Parameters must be valid JSON.');
          return;
        }
      }

      setError(null);

      const scopes = form.default_scopes
        .split(/[,\s]+/)
        .map(s => s.trim())
        .filter(Boolean);

      const body: any = {
        name: form.name.trim(),
        provider_id: form.provider_id.trim(),
        provider_type: form.provider_type,
        default_scopes: scopes,
        token_refresh_enabled: form.token_refresh_enabled,
        description: form.description.trim() || undefined,
      };

      if (isOAuth) {
        body.token_endpoint = form.token_endpoint.trim();
        body.client_id_secret_ref = form.client_id_secret_ref;
        body.client_secret_secret_ref = form.client_secret_secret_ref;
      }

      if (form.provider_type === 'api_key' && form.api_key_secret_ref) {
        body.api_key_secret_ref = form.api_key_secret_ref;
      }

      if (form.authorization_endpoint.trim()) {
        body.authorization_endpoint = form.authorization_endpoint.trim();
      }
      if (Object.keys(additionalParams).length > 0) {
        body.additional_params = additionalParams;
      }

      // Build callback_url from host + path for authorization_code providers
      if (
        form.provider_type === 'oauth2_authorization_code' &&
        form.callback_host &&
        routingConfig
      ) {
        const callbackPath = `${routingConfig.oauth_callback_route}/${encodeURIComponent(form.provider_id.trim())}`;
        body.callback_url = `${form.callback_host}${callbackPath}`;
      }

      await run(
        async () => {
          const url = isNew
            ? '/api/v1/credential-providers'
            : `/api/v1/credential-providers/${encodeURIComponent(id!)}`;
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
          successMessage: isNew ? 'Provider created' : 'Provider updated',
          redirectTo: '/settings?tab=credential-providers',
          onError: setError,
          errorMessage: 'Save failed',
        }
      );
    },
    [form, isNew, id, run]
  );

  // Keyboard shortcut: Ctrl+S / Cmd+S to save
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!saving) {
          handleSubmit();
        }
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => document.removeEventListener('keydown', handleKeyboardSave);
  }, [saving, handleSubmit]);

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
          onClick={() => navigate('/settings?tab=credential-providers')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">Provider Configuration</h6>
          <div>
            <button
              type="button"
              className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
              onClick={() => handleSubmit()}
              disabled={saving}
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {saving ? ' Saving…' : isNew ? ' Create' : ' Save'}
            </button>
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={() => navigate('/settings?tab=credential-providers')}
              disabled={saving}
            >
              Cancel
            </button>
          </div>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          <p className="text-muted mb-3">
            A credential provider tells the gateway how to obtain (and refresh) an access token or
            API key for an upstream service on a caller's behalf. Pick the flow that matches how the
            upstream service authenticates: Authorization Code if a human needs to approve access
            once, Client Credentials or API Key if the gateway can authenticate on its own.{' '}
            <Link href={DOCS_URL.credentials} external variant="inline">
              Learn more
            </Link>
          </p>

          <form ref={formRef} onSubmit={handleSubmit}>
            {/* Name + ID row */}
            <div className="row mb-3">
              <div className={isNew ? 'col-12' : 'col-md-6'}>
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
                  required
                />
                <small className="form-text text-muted">
                  Human-readable name shown in the UI and Transit Credential bindings.
                </small>
              </div>
              {!isNew && id && (
                <div className="col-md-6">
                  <label>ID</label>
                  <input type="text" className="form-control" value={id} readOnly />
                  <small className="form-text text-muted">Read-only unique identifier.</small>
                </div>
              )}
            </div>

            {/* Description — full width, single line */}
            <div className="mb-3">
              <div className="field-label-with-help">
                <label htmlFor="description" className="mb-0">
                  Description
                </label>
                <FieldHelp ariaLabel="About Description" testId="field-help-provider-description">
                  Use it to note what this provider is used for (e.g. "GitHub OAuth for the
                  code-review agent").
                </FieldHelp>
              </div>
              <input
                id="description"
                name="description"
                type="text"
                className="form-control"
                value={form.description}
                onChange={handleChange}
              />
              <small className="form-text text-muted">
                Shown alongside this provider's name in lists.
              </small>
            </div>

            {/* Provider Type */}
            <div className="mb-3">
              <div className="field-label-with-help">
                <label htmlFor="provider_type" className="mb-0">
                  Provider Type
                </label>
                <FieldHelp ariaLabel="About Provider Type" testId="field-help-provider-type">
                  Authorization Code: a person approves access once, in their browser. Client
                  Credentials: the gateway authenticates on its own, no person involved. API Key: a
                  single static key, no OAuth flow at all.
                </FieldHelp>
              </div>
              <select
                id="provider_type"
                name="provider_type"
                className="form-control dropdown-styling"
                value={form.provider_type}
                onChange={handleChange}
              >
                <option value="oauth2_authorization_code">
                  OAuth 2.0, Authorization Code (3-legged, user consent)
                </option>
                <option value="oauth2_client_credentials">
                  OAuth 2.0, Client Credentials (2-legged, machine-to-machine)
                </option>
                <option value="api_key">API Key (static secret)</option>
              </select>
              <small className="form-text text-muted">
                Choose how the gateway obtains credentials for this service.
              </small>
            </div>

            {/* Authorization Endpoint + Token Endpoint row */}
            {form.provider_type !== 'api_key' && (
              <div className="row mb-3">
                {form.provider_type === 'oauth2_authorization_code' && (
                  <div className="col-md-6">
                    <label htmlFor="authorization_endpoint">Authorization Endpoint</label>
                    <input
                      id="authorization_endpoint"
                      name="authorization_endpoint"
                      type="url"
                      className="form-control"
                      value={form.authorization_endpoint}
                      onChange={handleChange}
                    />
                    <small className="form-text text-muted">
                      Where to redirect users for consent. Required for Authorization Code flow.
                    </small>
                  </div>
                )}
                <div
                  className={
                    form.provider_type === 'oauth2_authorization_code' ? 'col-md-6' : 'col-12'
                  }
                >
                  <label htmlFor="token_endpoint">
                    Token Endpoint <span className="text-danger">*</span>
                  </label>
                  <input
                    id="token_endpoint"
                    name="token_endpoint"
                    type="url"
                    className="form-control"
                    value={form.token_endpoint}
                    onChange={handleChange}
                    required
                  />
                  <small className="form-text text-muted">
                    The URL the gateway calls to trade an authorization code (or its own client
                    credentials) for an actual access token.
                  </small>
                </div>
              </div>
            )}

            {/* Callback URL — only for authorization_code flow */}
            {form.provider_type === 'oauth2_authorization_code' && (
              <div className="mb-3">
                <div className="field-label-with-help">
                  <label htmlFor="callback_host" className="mb-0">
                    Callback URL Host
                  </label>
                  <FieldHelp ariaLabel="About Callback URL Host" testId="field-help-callback-host">
                    Most setups only have one option; if there are several, pick the one your OAuth
                    provider can actually reach from the outside. Register this exact URL as an
                    allowed redirect URI with your OAuth provider before saving.
                  </FieldHelp>
                </div>
                <select
                  id="callback_host"
                  name="callback_host"
                  className="form-control dropdown-styling"
                  value={form.callback_host}
                  onChange={handleChange}
                  disabled={!routingConfig || routingConfig.available_listen_addresses.length === 0}
                >
                  {!routingConfig ? (
                    <option value="">Loading…</option>
                  ) : routingConfig.available_listen_addresses.length === 0 ? (
                    <option value="">No addresses available</option>
                  ) : (
                    <>
                      <option value="">-- Select listen address --</option>
                      {routingConfig.available_listen_addresses.map(addr => (
                        <option key={addr} value={addr}>
                          {addr}
                        </option>
                      ))}
                    </>
                  )}
                </select>
                <small className="form-text text-muted">
                  Which of the gateway's public addresses your identity provider should redirect
                  back to after a user approves access.
                </small>

                <label htmlFor="provider_id" className="mt-3">
                  Callback URL Route <span className="text-danger">*</span>
                </label>
                <div className="input-group">
                  <span className="input-group-text" style={{ fontSize: '13px' }}>
                    {routingConfig?.oauth_callback_route ?? '...'}/
                  </span>
                  <input
                    id="provider_id"
                    name="provider_id"
                    type="text"
                    className="form-control"
                    value={form.provider_id}
                    onChange={handleChange}
                    placeholder="e.g. github"
                    required
                    disabled={!isNew}
                  />
                </div>
                <small className="form-text text-muted">
                  Route suffix for the callback URL. Only letters, numbers, dashes, and underscores.
                  Auto-derived from name. Immutable after creation.
                </small>

                {form.callback_host && form.provider_id.trim() && routingConfig && (
                  <div className="alert alert-success mt-2 mb-0" style={{ fontSize: '14px' }}>
                    <i className="fas fa-info-circle me-2"></i>
                    <strong>Callback URL:</strong>{' '}
                    {`${form.callback_host}${routingConfig.oauth_callback_route}/${encodeURIComponent(form.provider_id.trim())}`}
                    <button
                      type="button"
                      className="btn btn-xs ms-2"
                      style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
                      onClick={e => {
                        const url = `${form.callback_host}${routingConfig.oauth_callback_route}/${encodeURIComponent(form.provider_id.trim())}`;
                        navigator.clipboard.writeText(url);
                        const btn = e.currentTarget as HTMLButtonElement;
                        const originalHtml = btn.innerHTML;
                        btn.innerHTML = '<i class="fas fa-check"></i>';
                        setTimeout(() => {
                          btn.innerHTML = originalHtml;
                        }, 2000);
                      }}
                      title="Copy to clipboard"
                    >
                      <i className="fas fa-copy"></i>
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* OAuth Client Credentials (Secret References) */}
            {form.provider_type !== 'api_key' && (
              <>
                <hr />
                <h6 className="font-weight-bold text-primary mb-3">
                  <i className="fas fa-key me-2"></i>OAuth Client Credentials (Secret References)
                </h6>

                {/* Client ID Secret */}
                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label htmlFor="client_id_secret_ref" className="mb-0">
                      Client ID Secret <span className="text-danger">*</span>
                    </label>
                    <FieldHelp
                      ariaLabel="About Client ID Secret"
                      testId="field-help-client-id-secret"
                    >
                      The value itself is never shown or copied into this form, only a reference to
                      where it's stored.
                    </FieldHelp>
                  </div>
                  <select
                    id="client_id_secret_ref"
                    name="client_id_secret_ref"
                    className="form-control dropdown-styling"
                    value={form.client_id_secret_ref}
                    onChange={handleChange}
                    required
                    disabled={loadingSecrets}
                  >
                    <option value="">
                      {loadingSecrets ? '-- Loading secrets... --' : '-- Select a secret --'}
                    </option>
                    {secrets.map(secret => (
                      <option key={secret.id} value={secret.secret_id}>
                        {secret.name} ({secret.secret_id})
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted">
                    Pick the secret holding your OAuth app's client ID.
                  </small>
                  {!loadingSecrets && (
                    <div className="form-text">
                      {secrets.length === 0
                        ? 'No secrets configured yet. '
                        : "Don't see the one you need? "}
                      <AddResourceLink
                        to={deepLinks.secret}
                        testid="credential-provider-add-client-id-secret-link"
                      >
                        Add secret
                      </AddResourceLink>
                    </div>
                  )}
                </div>

                {/* Client Secret Secret */}
                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label htmlFor="client_secret_secret_ref" className="mb-0">
                      Client Secret <span className="text-danger">*</span>
                    </label>
                    <FieldHelp
                      ariaLabel="About Client Secret"
                      testId="field-help-client-secret-secret"
                    >
                      The value itself is never shown or copied into this form, only a reference to
                      where it's stored.
                    </FieldHelp>
                  </div>
                  <select
                    id="client_secret_secret_ref"
                    name="client_secret_secret_ref"
                    className="form-control dropdown-styling"
                    value={form.client_secret_secret_ref}
                    onChange={handleChange}
                    required
                    disabled={loadingSecrets}
                  >
                    <option value="">
                      {loadingSecrets ? '-- Loading secrets... --' : '-- Select a secret --'}
                    </option>
                    {secrets.map(secret => (
                      <option key={secret.id} value={secret.secret_id}>
                        {secret.name} ({secret.secret_id})
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted">
                    Pick the secret holding your OAuth app's client secret.
                  </small>
                  {!loadingSecrets && (
                    <div className="form-text">
                      {secrets.length === 0
                        ? 'No secrets configured yet. '
                        : "Don't see the one you need? "}
                      <AddResourceLink
                        to={deepLinks.secret}
                        testid="credential-provider-add-client-secret-link"
                      >
                        Add secret
                      </AddResourceLink>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* API Key field — only for api_key type */}
            {form.provider_type === 'api_key' && (
              <>
                <hr />
                <h6 className="font-weight-bold text-primary mb-3">
                  <i className="fas fa-key me-2"></i>API Key (Secret Reference)
                </h6>

                <div className="mb-3">
                  <label htmlFor="api_key_secret_ref">
                    API Key Secret <span className="text-danger">*</span>
                  </label>
                  <select
                    id="api_key_secret_ref"
                    name="api_key_secret_ref"
                    className="form-control dropdown-styling"
                    value={form.api_key_secret_ref}
                    onChange={handleChange}
                    required
                    disabled={loadingSecrets}
                  >
                    <option value="">
                      {loadingSecrets ? '-- Loading secrets... --' : '-- Select a secret --'}
                    </option>
                    {secrets.map(secret => (
                      <option key={secret.id} value={secret.secret_id}>
                        {secret.name} ({secret.secret_id})
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted">
                    Secret containing the API key value. Injected directly into upstream requests.
                  </small>
                  {!loadingSecrets && (
                    <div className="form-text">
                      {secrets.length === 0
                        ? 'No secrets configured yet. '
                        : "Don't see the one you need? "}
                      <AddResourceLink
                        to={deepLinks.secret}
                        testid="credential-provider-add-api-key-secret-link"
                      >
                        Add secret
                      </AddResourceLink>
                    </div>
                  )}
                </div>
              </>
            )}

            <hr />

            {/* Default Scopes */}
            <div className="mb-3">
              <label htmlFor="default_scopes">Default Scopes</label>
              <input
                id="default_scopes"
                name="default_scopes"
                type="text"
                className="form-control"
                value={form.default_scopes}
                onChange={handleChange}
              />
              <small className="form-text text-muted">
                Comma-separated default scopes for this credential provider (e.g. openid, email,
                profile). Can be overridden per Transit Credential binding.
              </small>
            </div>

            {/* Token Refresh */}
            <div className="mb-3 form-check">
              <input
                id="token_refresh_enabled"
                name="token_refresh_enabled"
                type="checkbox"
                className="form-check-input"
                checked={form.token_refresh_enabled}
                onChange={handleChange}
              />
              <label htmlFor="token_refresh_enabled" className="form-check-label">
                Enable automatic token refresh
              </label>
              <div>
                <small className="form-text text-muted">
                  Access tokens are refreshed automatically using the stored refresh token whenever
                  one is available, so this connection keeps working without needing to reauthorize.
                </small>
              </div>
            </div>

            {/* Additional Params */}
            <div className="mb-3">
              <div className="field-label-with-help">
                <label htmlFor="additional_params" className="mb-0">
                  Additional Parameters <span className="text-muted">(JSON)</span>
                </label>
                <FieldHelp
                  ariaLabel="About Additional Parameters"
                  testId="field-help-additional-params"
                >
                  Use this to force a consent screen every time, or leave blank if your provider
                  doesn't need any extra parameters.
                </FieldHelp>
              </div>
              <textarea
                id="additional_params"
                name="additional_params"
                className="form-control font-monospace"
                value={form.additional_params}
                onChange={handleChange}
                rows={3}
              />
              <small className="form-text text-muted">
                Extra query parameters to send with the authorization request, as a JSON object
                (e.g. <code>{'{"prompt": "consent"}'}</code>).
              </small>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditCredentialProviderPage;
