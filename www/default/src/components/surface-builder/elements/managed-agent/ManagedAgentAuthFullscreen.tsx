import React, { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { ConfigPanelProps } from '../types';
import TargetAuthProviderSelect from '../_shared/TargetAuthProviderSelect';
import TargetAuthProblemNotice from '../_shared/TargetAuthProblemNotice';
import { managedAgentTargetAuthProblems } from './targetAuth';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';

interface SecretOption {
  id: string;
  secret_id: string;
  name: string;
}

type AuthType = 'bearer' | 'basic' | 'api_key' | 'custom';

const AUTH_TYPE_DEFAULTS: Record<AuthType, { headerName: string; headerFormat: string }> = {
  bearer: { headerName: 'Authorization', headerFormat: 'Bearer {value}' },
  basic: { headerName: 'Authorization', headerFormat: 'Basic {value}' },
  api_key: { headerName: 'X-API-Key', headerFormat: '{value}' },
  custom: { headerName: 'Authorization', headerFormat: '{value}' },
};

/**
 * Fullpage editor for Target Authentication on the Managed Agent (target)
 * element. The wire shape is the
 * `TargetAuthConfig` from the backend (`method: static_secret` or
 * `credential_provider`, `header_name`, `header_format`, `fallback`).
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
  const source = config.target_auth_source === 'provider' ? 'provider' : 'secret';
  const [secrets, setSecrets] = useState<SecretOption[]>([]);
  const [loadingSecrets, setLoadingSecrets] = useState(false);
  const accessPointChecksCallers = useOptionalSurfaceMeta()?.accessPointChecksCallers;
  const { errors, advisories, notes } = managedAgentTargetAuthProblems(config, {
    accessPointChecksCallers,
  });

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
    if (!config.target_auth_enabled) {
      const d = AUTH_TYPE_DEFAULTS[authType];
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

        <TargetAuthProblemNotice
          testId="managed-agent-target-auth"
          errors={[]}
          advisories={advisories}
          notes={notes}
        />

        <div className="mb-3">
          <label htmlFor="target-auth-source" className="form-label fw-bold">
            Credential Source
          </label>
          <select
            className="form-control dropdown-styling"
            id="target-auth-source"
            data-testid="managed-agent-target-auth-source"
            value={source}
            onChange={e => updateField('target_auth_source', e.target.value)}
          >
            <option value="secret">Static secret</option>
            <option value="provider">Credential provider</option>
          </select>
          <small className="form-text text-muted">
            A credential provider issues a token (Client Credentials, JWT Bearer, Client Credentials
            JWT) or reads an API key; issued tokens are cached and renewed before they expire.
          </small>
        </div>

        {source === 'provider' && (
          <div className="mb-3">
            <label htmlFor="target-auth-provider" className="form-label fw-bold">
              Credential Provider <span className="text-danger">*</span>
            </label>
            <TargetAuthProviderSelect
              id="target-auth-provider"
              testId="managed-agent-target-auth-provider"
              value={config.target_auth_provider_id || ''}
              onChange={providerId => updateField('target_auth_provider_id', providerId)}
              errorId={errors.target_auth_provider_id ? 'target-auth-provider-error' : undefined}
            />
            <div role="alert">
              {errors.target_auth_provider_id && (
                <div
                  className="text-danger small mt-1"
                  id="target-auth-provider-error"
                  data-testid="managed-agent-target-auth-provider-error"
                >
                  {errors.target_auth_provider_id}
                </div>
              )}
            </div>
          </div>
        )}

        {source === 'provider' && (
          <div className="mb-3">
            <label htmlFor="target-auth-scopes" className="form-label fw-bold">
              Scopes
            </label>
            <input
              type="text"
              className="form-control"
              id="target-auth-scopes"
              data-testid="managed-agent-target-auth-scopes"
              value={config.target_auth_scopes || ''}
              onChange={e => updateField('target_auth_scopes', e.target.value)}
              placeholder="Space-separated; the provider's default scopes when empty"
            />
            <small className="form-text text-muted">
              Scopes to request for this Target. Leave empty to use the provider's default scopes.
            </small>
          </div>
        )}

        {source === 'secret' && (
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
                <AddResourceLink to={deepLinks.secret} testid="managed-agent-auth-add-secret-link">
                  Add secret
                </AddResourceLink>
              </div>
            )}
          </div>
        )}

        <div className="mb-3">
          <label htmlFor="target-auth-type" className="form-label fw-bold">
            Authentication Type <span className="text-danger">*</span>
          </label>
          <select
            className="form-control dropdown-styling"
            id="target-auth-type"
            value={authType}
            onChange={e => setAuthType(e.target.value as AuthType)}
          >
            <option value="bearer">Bearer Token</option>
            <option value="basic">Basic Auth</option>
            <option value="api_key">API Key</option>
            <option value="custom">Custom</option>
          </select>
          <small className="form-text text-muted">
            How to format the credentials in the request header
          </small>
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
            aria-invalid={!!errors.target_auth_header_name}
            aria-describedby={
              errors.target_auth_header_name ? 'target-auth-header-name-error' : undefined
            }
          />
          <div role="alert">
            {errors.target_auth_header_name && (
              <div
                className="text-danger small"
                id="target-auth-header-name-error"
                data-testid="managed-agent-target-auth-header-name-error"
              >
                {errors.target_auth_header_name}
              </div>
            )}
          </div>
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
              aria-invalid={!!errors.target_auth_header_format}
              aria-describedby={
                errors.target_auth_header_format ? 'target-auth-header-format-error' : undefined
              }
            />
            <div role="alert">
              {errors.target_auth_header_format && (
                <div
                  className="text-danger small"
                  id="target-auth-header-format-error"
                  data-testid="managed-agent-target-auth-header-format-error"
                >
                  {errors.target_auth_header_format}
                </div>
              )}
            </div>
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
            <option value="reject">Reject request</option>
            <option value="passthrough">Pass through without credentials</option>
          </select>
          <small className="form-text text-muted">
            What to do if the secret or provider token cannot be resolved
          </small>
        </div>
      </div>
    </div>
  );
};

export default ManagedAgentAuthFullscreen;
