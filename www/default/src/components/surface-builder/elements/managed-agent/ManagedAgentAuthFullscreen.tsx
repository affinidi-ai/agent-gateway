import React, { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { ConfigPanelProps } from '../types';
import CredentialProviderPicker from '../_shared/CredentialProviderPicker';
import {
  CREDENTIAL_PROVIDER_AUTH_TYPE,
  PRESERVED_AUTH_TYPE,
  credentialProviderFieldsFromConfig,
} from './targetAuthConfig';
import { credentialProviderAuthError, injectionHeaderName } from '../../../../utils/targetAuth';

interface SecretOption {
  id: string;
  secret_id: string;
  name: string;
}

type StaticAuthType = 'bearer' | 'basic' | 'api_key' | 'custom';
type AuthType = StaticAuthType | typeof CREDENTIAL_PROVIDER_AUTH_TYPE | typeof PRESERVED_AUTH_TYPE;

const AUTH_TYPE_DEFAULTS: Record<StaticAuthType, { headerName: string; headerFormat: string }> = {
  bearer: { headerName: 'Authorization', headerFormat: 'Bearer {value}' },
  basic: { headerName: 'Authorization', headerFormat: 'Basic {value}' },
  api_key: { headerName: 'X-API-Key', headerFormat: '{value}' },
  custom: { headerName: 'Authorization', headerFormat: '{value}' },
};

/**
 * Fullpage editor for Target Authentication on the Managed Agent (target)
 * element. The wire shape is the
 * `TargetAuthConfig` from the backend (`method: static_secret`, `header_name`,
 * `header_format`, `fallback`).
 *
 * Selection of the auth type is shared with the sidebar via
 * `config.target_auth_type` so changes here propagate back when the tab closes.
 */
const ManagedAgentAuthFullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
}) => {
  const authType: AuthType = (config.target_auth_type as AuthType) || 'bearer';
  const endpointType: string = config.endpoint_type || 'url';
  const [secrets, setSecrets] = useState<SecretOption[]>([]);
  const [loadingSecrets, setLoadingSecrets] = useState(false);

  useEffect(() => {
    setLoadingSecrets(true);
    apiClient
      .get('/secrets/')
      .then(res => setSecrets(Array.isArray(res.data) ? res.data : []))
      .catch(() => setSecrets([]))
      .finally(() => setLoadingSecrets(false));
  }, []);

  // Opening the fullscreen editor implies the user wants target auth on.
  // Seed defaults once if not already enabled so the form is usable immediately.
  useEffect(() => {
    if (!config.target_auth_enabled && authType in AUTH_TYPE_DEFAULTS) {
      const d = AUTH_TYPE_DEFAULTS[authType as StaticAuthType];
      updateFields({
        target_auth_enabled: true,
        target_auth_type: authType,
        target_auth_secret_id: config.target_auth_secret_id || '',
        target_auth_header_name: config.target_auth_header_name || d.headerName,
        target_auth_header_format: config.target_auth_header_format || d.headerFormat,
        target_auth_fallback: config.target_auth_fallback || 'reject',
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setAuthType = (newType: AuthType) => {
    if (newType === CREDENTIAL_PROVIDER_AUTH_TYPE) {
      updateFields({
        target_auth_enabled: true,
        target_auth_type: newType,
        target_auth_fallback: config.target_auth_fallback || 'reject',
      });
      return;
    }
    if (newType === PRESERVED_AUTH_TYPE) return;
    const d = AUTH_TYPE_DEFAULTS[newType];
    updateFields({
      target_auth_type: newType,
      target_auth_header_name: d.headerName,
      target_auth_header_format: d.headerFormat,
    });
  };

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-key me-2"></i> Target Authentication
        </h6>
      </div>
      <div className="card-body">
        <small className="form-text text-muted mb-3 d-block">
          Inject credentials into requests sent to the target endpoint. Use this when the target
          requires authentication.
        </small>

        <div className="mb-3">
          <label htmlFor="target-auth-type" className="form-label fw-bold">
            Authentication Type <span className="text-danger">*</span>
          </label>
          <select
            className="form-control dropdown-styling"
            id="target-auth-type"
            data-testid="target-auth-type"
            value={authType}
            onChange={e => setAuthType(e.target.value as AuthType)}
          >
            <option value="bearer">Bearer Token</option>
            <option value="basic">Basic Auth</option>
            <option value="api_key">API Key</option>
            <option value="custom">Custom</option>
            {(endpointType === 'url' || authType === CREDENTIAL_PROVIDER_AUTH_TYPE) && (
              <option value={CREDENTIAL_PROVIDER_AUTH_TYPE}>Credential Provider</option>
            )}
            {authType === PRESERVED_AUTH_TYPE && (
              <option value={PRESERVED_AUTH_TYPE} disabled>
                Unsupported method (kept as saved)
              </option>
            )}
          </select>
          <small className="form-text text-muted">
            How the gateway authenticates to the target. A credential provider fetches and caches an
            OAuth token or API key for the gateway itself.
          </small>
        </div>

        {authType === PRESERVED_AUTH_TYPE && (
          <div className="alert alert-warning" role="status" data-testid="target-auth-preserved">
            This surface uses a Target Authentication method this dashboard cannot edit. It is saved
            unchanged. Pick another type above to replace it, or set Authentication Type to None in
            the Managed Agent panel to remove it.
          </div>
        )}

        {authType === CREDENTIAL_PROVIDER_AUTH_TYPE && (
          <CredentialProviderAuthSection config={config} updateField={updateField} />
        )}

        {authType !== PRESERVED_AUTH_TYPE && authType !== CREDENTIAL_PROVIDER_AUTH_TYPE && (
          <>
            <div className="mb-3">
              <label htmlFor="target-auth-secret" className="form-label fw-bold">
                Secret <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                id="target-auth-secret"
                value={config.target_auth_secret_id || ''}
                onChange={e => updateField('target_auth_secret_id', e.target.value)}
                disabled={loadingSecrets}
              >
                <option value="">
                  {loadingSecrets ? '-- Loading secrets... --' : '-- Select a secret --'}
                </option>
                {secrets.map(s => (
                  <option key={s.id} value={s.secret_id}>
                    {s.name} ({s.secret_id})
                  </option>
                ))}
              </select>
              <small className="form-text text-muted">
                Select a secret containing the credentials for the target endpoint
              </small>
              {!loadingSecrets && (
                <div className="form-text">
                  {secrets.length === 0
                    ? 'No secrets configured yet. '
                    : "Don't see the one you need? "}
                  <AddResourceLink
                    to={deepLinks.secret}
                    testid="managed-agent-auth-add-secret-link"
                  >
                    Add secret
                  </AddResourceLink>
                </div>
              )}
            </div>

            <div className="mb-3">
              <label htmlFor="target-auth-header-name" className="form-label fw-bold">
                Header Name
              </label>
              <input
                type="text"
                className="form-control"
                id="target-auth-header-name"
                value={config.target_auth_header_name || ''}
                onChange={e => updateField('target_auth_header_name', e.target.value)}
                placeholder="Authorization"
              />
              <small className="form-text text-muted">
                The HTTP header name to inject (e.g., Authorization, X-API-Key)
              </small>
            </div>

            {authType === 'custom' && (
              <div className="mb-3">
                <label htmlFor="target-auth-header-format" className="form-label fw-bold">
                  Header Format
                </label>
                <input
                  type="text"
                  className="form-control font-monospace"
                  id="target-auth-header-format"
                  value={config.target_auth_header_format || ''}
                  onChange={e => updateField('target_auth_header_format', e.target.value)}
                  placeholder="Bearer {value}"
                  style={{ fontFamily: 'monospace' }}
                />
                <small className="form-text text-muted">
                  Format for the header value. Use <code>{'{value}'}</code> as a placeholder for the
                  secret value.
                </small>
              </div>
            )}

            <div className="mb-3">
              <label htmlFor="target-auth-fallback" className="form-label fw-bold">
                Fallback Behavior
              </label>
              <select
                className="form-control dropdown-styling"
                id="target-auth-fallback"
                value={config.target_auth_fallback || 'reject'}
                onChange={e => updateField('target_auth_fallback', e.target.value)}
              >
                <option value="reject">Reject request (502 Bad Gateway)</option>
                <option value="passthrough">Pass through without credentials</option>
              </select>
              <small className="form-text text-muted">
                What to do if the secret cannot be resolved
              </small>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

interface SectionProps {
  config: ConfigPanelProps['config'];
  updateField: ConfigPanelProps['updateField'];
}

const CredentialProviderAuthSection: React.FC<SectionProps> = ({ config, updateField }) => {
  const fields = credentialProviderFieldsFromConfig(config);
  const custom = fields.injectAs.type === 'custom_header';
  const error = credentialProviderAuthError(fields);
  const headerName = injectionHeaderName(fields.injectAs) || 'Authorization';

  return (
    <div data-testid="target-auth-credential-provider">
      <div className="mb-3">
        <label htmlFor="target-auth-credential-provider-id" className="form-label fw-bold">
          Credential Provider <span className="text-danger">*</span>
        </label>
        <CredentialProviderPicker
          id="target-auth-credential-provider-id"
          testId="target-auth-credential-provider-select"
          use="target_authentication"
          value={fields.credentialProviderId}
          onChange={v => updateField('target_auth_credential_provider_id', v)}
        />
        <small className="form-text text-muted">
          The gateway signs in with this provider and sends its token on every call to the target,
          including the agent card fetch. Authorization Code providers cannot be used here.
        </small>
      </div>

      <div className="mb-3">
        <label htmlFor="target-auth-scopes" className="form-label fw-bold">
          Scopes
        </label>
        <input
          type="text"
          className="form-control"
          id="target-auth-scopes"
          data-testid="target-auth-scopes"
          value={config.target_auth_scopes || ''}
          onChange={e => updateField('target_auth_scopes', e.target.value)}
          placeholder="Leave empty to use the provider's default scopes"
        />
        <small className="form-text text-muted">
          Comma or space separated. Overrides the provider's default scopes for this surface.
        </small>
      </div>

      <div className="mb-3">
        <label htmlFor="target-auth-inject-as" className="form-label fw-bold">
          Header Shape
        </label>
        <select
          className="form-control dropdown-styling"
          id="target-auth-inject-as"
          data-testid="target-auth-inject-as"
          value={fields.injectAs.type}
          onChange={e => updateField('target_auth_inject_as', e.target.value)}
        >
          <option value="bearer_header">Authorization: Bearer token</option>
          <option value="custom_header">Custom header</option>
        </select>
      </div>

      {custom && (
        <div className="row mb-3">
          <div className="col-md-6">
            <label htmlFor="target-auth-inject-name" className="form-label fw-bold">
              Header Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control"
              id="target-auth-inject-name"
              data-testid="target-auth-inject-name"
              value={config.target_auth_inject_name || ''}
              onChange={e => updateField('target_auth_inject_name', e.target.value)}
              placeholder="X-Api-Token"
            />
          </div>
          <div className="col-md-6">
            <label htmlFor="target-auth-inject-format" className="form-label fw-bold">
              Header Format <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control font-monospace"
              id="target-auth-inject-format"
              data-testid="target-auth-inject-format"
              value={config.target_auth_inject_format || ''}
              onChange={e => updateField('target_auth_inject_format', e.target.value)}
              placeholder="Bearer {value}"
            />
            <small className="form-text text-muted">
              Use <code>{'{value}'}</code> as a placeholder for the token.
            </small>
          </div>
        </div>
      )}

      <div className="alert alert-info py-2" data-testid="target-auth-header-note">
        The <code>{headerName}</code> header is set by the gateway. A surface cannot also delegate a
        credential into the same header.
      </div>

      <div className="mb-3">
        <label htmlFor="target-auth-fallback" className="form-label fw-bold">
          Fallback Behavior
        </label>
        <select
          className="form-control dropdown-styling"
          id="target-auth-fallback"
          value={config.target_auth_fallback || 'reject'}
          onChange={e => updateField('target_auth_fallback', e.target.value)}
        >
          <option value="reject">Reject request (502 Bad Gateway)</option>
          <option value="passthrough">Pass through without credentials</option>
        </select>
        <small className="form-text text-muted">
          What to do if the provider cannot supply a token
        </small>
      </div>

      {error && (
        <div className="text-danger small" role="alert" data-testid="target-auth-error">
          {error}
        </div>
      )}
    </div>
  );
};

export default ManagedAgentAuthFullscreen;
