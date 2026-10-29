import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatApiError } from '../utils/apiError';
import AddResourceLink from '../components/shared/AddResourceLink';
import FieldHelp from '../components/shared/FieldHelp';
import { Link } from '../components/shared/Link';
import { usePageTitle } from '../context/PageTitleContext';
import { useSaveAction } from '../hooks/useSaveAction';
import { usePermissions } from '../context/PermissionsContext';
import { deepLinks } from '../utils/deepLinks';
import { DOCS_URL } from '../config/docs';
import {
  EMPTY_PROVIDER_FORM,
  PROVIDER_TYPES,
  PROVIDER_TYPE_CAPABILITIES,
  buildProviderBody,
  providerFormFromWire,
  unknownProviderType,
  deriveProviderId,
  validateProviderForm,
  type CredentialProviderForm,
} from '../utils/credentialProviders';

interface Secret {
  id: string;
  name: string;
  secret_id: string;
}

interface RoutingConfig {
  available_listen_addresses: string[];
  oauth_callback_route: string;
}

interface SecretSelectProps {
  id: string;
  label: string;
  value: string;
  required?: boolean;
  help: string;
  helpTestId?: string;
  linkTestId: string;
  secrets: Secret[];
  loading: boolean;
  onChange: (e: React.ChangeEvent<HTMLSelectElement>) => void;
}

const SecretSelect: React.FC<SecretSelectProps> = ({
  id,
  label,
  value,
  required,
  help,
  helpTestId,
  linkTestId,
  secrets,
  loading,
  onChange,
}) => (
  <div className="mb-3">
    <div className="field-label-with-help">
      <label htmlFor={id} className="mb-0">
        {label} {required && <span className="text-danger">*</span>}
      </label>
      {helpTestId && (
        <FieldHelp ariaLabel={`About ${label}`} testId={helpTestId}>
          The value itself is never shown or copied into this form, only a reference to where it's
          stored.
        </FieldHelp>
      )}
    </div>
    <select
      id={id}
      data-testid={`provider-${id.replace(/_/g, '-')}`}
      name={id}
      className="form-control dropdown-styling"
      value={value}
      onChange={onChange}
      required={required}
      disabled={loading}
    >
      <option value="">{loading ? '-- Loading secrets... --' : '-- Select a secret --'}</option>
      {secrets.map(secret => (
        <option key={secret.id} value={secret.secret_id}>
          {secret.name} ({secret.secret_id})
        </option>
      ))}
    </select>
    <small className="form-text text-muted">{help}</small>
    {!loading && (
      <div className="form-text">
        {secrets.length === 0 ? 'No secrets configured yet. ' : "Don't see the one you need? "}
        <AddResourceLink to={deepLinks.secret} testid={linkTestId}>
          Add secret
        </AddResourceLink>
      </div>
    )}
  </div>
);

const EditCredentialProviderPage: React.FC = () => {
  const { run, saving, navigate } = useSaveAction();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';
  const { hasPermission } = usePermissions();
  const [unknownType, setUnknownType] = useState<string | null>(null);
  const mayEdit = hasPermission('credential_providers.edit');
  const canEdit = mayEdit && unknownType === null;
  usePageTitle(isNew ? 'New Credential Provider' : 'Edit Credential Provider');

  const [form, setForm] = useState<CredentialProviderForm>(EMPTY_PROVIDER_FORM);
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

      setUnknownType(unknownProviderType(data));
      setForm(providerFormFromWire(data, callbackHost));
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

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
      const validationError = validateProviderForm(form);
      if (validationError) {
        setError(validationError);
        return;
      }

      setError(null);

      const body = buildProviderBody(
        form,
        routingConfig ? routingConfig.oauth_callback_route : null,
        isNew
      );

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
    [form, isNew, id, run, routingConfig]
  );

  // Keyboard shortcut: Ctrl+S / Cmd+S to save
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!saving && canEdit) {
          handleSubmit();
        }
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => document.removeEventListener('keydown', handleKeyboardSave);
  }, [saving, canEdit, handleSubmit]);

  const caps = PROVIDER_TYPE_CAPABILITIES[form.provider_type];

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
            {canEdit && (
              <button
                type="button"
                className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
                data-testid="provider-save-button"
                onClick={() => handleSubmit()}
                disabled={saving}
              >
                <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
                {saving ? ' Saving…' : isNew ? ' Create' : ' Save'}
              </button>
            )}
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
          {unknownType && (
            <div className="alert alert-warning" role="status" data-testid="provider-unknown-type">
              <i className="fas fa-lock me-2"></i>
              This provider has type <code>{unknownType}</code>, which this dashboard version cannot
              edit. It is shown read-only so saving cannot change its type.
            </div>
          )}
          {!mayEdit && unknownType === null && (
            <div className="alert alert-info" role="status" data-testid="provider-read-only">
              <i className="fas fa-lock me-2" aria-hidden="true"></i>
              Your role can view this provider but not change it.
            </div>
          )}
          {error && (
            <div className="alert alert-danger" role="alert" data-testid="provider-error">
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
            <fieldset disabled={!canEdit} className="border-0 p-0 m-0" style={{ minWidth: 0 }}>
              {/* Name + ID row */}
              <div className="row mb-3">
                <div className={isNew ? 'col-12' : 'col-md-6'}>
                  <label htmlFor="name">
                    Name <span className="text-danger">*</span>
                  </label>
                  <input
                    id="name"
                    data-testid="provider-name"
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
                    Credentials: the gateway authenticates on its own with a client ID and secret.
                    JWT Bearer: the gateway signs an assertion with its own key and trades it for a
                    token (RFC 7523). API Key: a single static key, no OAuth flow at all.
                  </FieldHelp>
                </div>
                <select
                  id="provider_type"
                  data-testid="provider-type"
                  name="provider_type"
                  className="form-control dropdown-styling"
                  value={form.provider_type}
                  onChange={handleChange}
                >
                  {PROVIDER_TYPES.map(type => (
                    <option key={type} value={type}>
                      {PROVIDER_TYPE_CAPABILITIES[type].optionLabel}
                    </option>
                  ))}
                </select>
                <small className="form-text text-muted">
                  Choose how the gateway obtains credentials for this service.
                </small>
              </div>

              {/* Authorization Endpoint + Token Endpoint row */}
              {caps.tokenEndpoint && (
                <div className="row mb-3">
                  {caps.authorizationEndpoint && (
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
                  <div className={caps.authorizationEndpoint ? 'col-md-6' : 'col-12'}>
                    <label htmlFor="token_endpoint">
                      Token Endpoint <span className="text-danger">*</span>
                    </label>
                    <input
                      id="token_endpoint"
                      data-testid="provider-token-endpoint"
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
              {caps.callback && (
                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label htmlFor="callback_host" className="mb-0">
                      Callback URL Host
                    </label>
                    <FieldHelp
                      ariaLabel="About Callback URL Host"
                      testId="field-help-callback-host"
                    >
                      Most setups only have one option; if there are several, pick the one your
                      OAuth provider can actually reach from the outside. Register this exact URL as
                      an allowed redirect URI with your OAuth provider before saving.
                    </FieldHelp>
                  </div>
                  <select
                    id="callback_host"
                    data-testid="provider-callback-host"
                    name="callback_host"
                    className="form-control dropdown-styling"
                    value={form.callback_host}
                    onChange={handleChange}
                    disabled={
                      !routingConfig || routingConfig.available_listen_addresses.length === 0
                    }
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
                    Route suffix for the callback URL. Only letters, numbers, dashes, and
                    underscores. Auto-derived from name. Immutable after creation.
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

              {caps.clientRefs !== 'none' && (
                <>
                  <hr />
                  <h6 className="font-weight-bold text-primary mb-3">
                    <i className="fas fa-key me-2"></i>
                    {caps.clientRefs === 'required'
                      ? 'OAuth Client Credentials (Secret References)'
                      : 'Client Authentication (optional)'}
                  </h6>
                  <SecretSelect
                    id="client_id_secret_ref"
                    label="Client ID Secret"
                    value={form.client_id_secret_ref}
                    required={caps.clientRefs === 'required'}
                    help={
                      caps.clientRefs === 'required'
                        ? "Pick the secret holding your OAuth app's client ID."
                        : 'Only needed when the token endpoint also authenticates the client. Set both the client ID and the client secret, or neither.'
                    }
                    helpTestId="field-help-client-id-secret"
                    linkTestId="credential-provider-add-client-id-secret-link"
                    secrets={secrets}
                    loading={loadingSecrets}
                    onChange={handleChange}
                  />
                  <SecretSelect
                    id="client_secret_secret_ref"
                    label="Client Secret"
                    value={form.client_secret_secret_ref}
                    required={caps.clientRefs === 'required'}
                    help="Pick the secret holding your OAuth app's client secret."
                    helpTestId="field-help-client-secret-secret"
                    linkTestId="credential-provider-add-client-secret-link"
                    secrets={secrets}
                    loading={loadingSecrets}
                    onChange={handleChange}
                  />
                </>
              )}

              {caps.signingKey && (
                <div data-testid="jwt-bearer-section">
                  <hr />
                  <h6 className="font-weight-bold text-primary mb-3">
                    <i className="fas fa-signature me-2"></i>Assertion Signing (RFC 7523)
                  </h6>
                  <div
                    className="alert alert-warning"
                    role="note"
                    data-testid="jwt-bearer-encryption-banner"
                  >
                    <i className="fas fa-lock me-2"></i>
                    Encryption at rest is off by default, so a signing key is stored in plain text
                    under the gateway's storage directory until you turn it on. Enable encryption at
                    rest, or reference a key in AWS Secrets Manager, before you add a real key. The
                    key is never returned by the API.
                  </div>
                  <SecretSelect
                    id="signing_key_secret_ref"
                    label="Signing Key Secret"
                    value={form.signing_key_secret_ref}
                    required
                    help="Secret holding the private key as a PKCS#8 PEM, or a Google service account JSON key. Use the secret type Certificate or General."
                    helpTestId="field-help-signing-key-secret"
                    linkTestId="credential-provider-add-signing-key-secret-link"
                    secrets={secrets}
                    loading={loadingSecrets}
                    onChange={handleChange}
                  />
                  <div className="row mb-3">
                    <div className="col-md-4">
                      <label htmlFor="signing_algorithm">Algorithm</label>
                      <select
                        id="signing_algorithm"
                        data-testid="provider-signing-algorithm"
                        name="signing_algorithm"
                        className="form-control dropdown-styling"
                        value={form.signing_algorithm}
                        onChange={handleChange}
                      >
                        <option value="RS256">RS256</option>
                        <option value="ES256">ES256</option>
                      </select>
                    </div>
                    <div className="col-md-8">
                      <label htmlFor="key_id">
                        Key ID <span className="text-muted">(optional)</span>
                      </label>
                      <input
                        id="key_id"
                        data-testid="provider-key-id"
                        name="key_id"
                        type="text"
                        className="form-control"
                        value={form.key_id}
                        onChange={handleChange}
                      />
                      <small className="form-text text-muted">
                        Sent as the <code>kid</code> header. Leave empty to use the one in a Google
                        service account key.
                      </small>
                    </div>
                  </div>
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <label htmlFor="assertion_issuer">
                        Assertion Issuer <span className="text-danger">*</span>
                      </label>
                      <input
                        id="assertion_issuer"
                        data-testid="provider-assertion-issuer"
                        name="assertion_issuer"
                        type="text"
                        className="form-control"
                        value={form.assertion_issuer}
                        onChange={handleChange}
                        required
                      />
                      <small className="form-text text-muted">
                        The <code>iss</code> claim. The authorization server must trust this issuer.
                      </small>
                    </div>
                    <div className="col-md-6">
                      <label htmlFor="subject">
                        Subject <span className="text-muted">(optional)</span>
                      </label>
                      <input
                        id="subject"
                        data-testid="provider-subject"
                        name="subject"
                        type="text"
                        className="form-control"
                        value={form.subject}
                        onChange={handleChange}
                      />
                      <small className="form-text text-muted">
                        The <code>sub</code> claim. Defaults to the issuer. The assertion audience
                        is always the token endpoint.
                      </small>
                    </div>
                  </div>
                </div>
              )}

              {caps.apiKey && (
                <>
                  <hr />
                  <h6 className="font-weight-bold text-primary mb-3">
                    <i className="fas fa-key me-2"></i>API Key (Secret Reference)
                  </h6>
                  <SecretSelect
                    id="api_key_secret_ref"
                    label="API Key Secret"
                    value={form.api_key_secret_ref}
                    required
                    help="Secret containing the API key value. Injected directly into upstream requests."
                    linkTestId="credential-provider-add-api-key-secret-link"
                    secrets={secrets}
                    loading={loadingSecrets}
                    onChange={handleChange}
                  />
                </>
              )}

              <hr />

              {/* Default Scopes */}
              <div className="mb-3">
                <label htmlFor="default_scopes">Default Scopes</label>
                <input
                  id="default_scopes"
                  data-testid="provider-default-scopes"
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
              {caps.tokenRefresh && (
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
                      Access tokens are refreshed automatically using the stored refresh token
                      whenever one is available, so this connection keeps working without needing to
                      reauthorize.
                    </small>
                  </div>
                </div>
              )}

              {/* Additional Params */}
              {caps.additionalParams && (
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
              )}
            </fieldset>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditCredentialProviderPage;
