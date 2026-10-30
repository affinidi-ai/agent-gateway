import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { ConfigPanelProps } from '../types';
import type { CallerAuthMethodType } from './methodOptions';
import CallerAuthDiscoverySection from './CallerAuthDiscoverySection';
import {
  readProtectedResource,
  readsAuthorizationHeader,
  usesBearerScheme,
} from './protectedResource';

interface Certificate {
  id: string;
  name: string;
  active: boolean;
  expires_at?: string;
}

interface JwtVerificationStrategy {
  id: string;
  name: string;
  expected_issuer?: string;
}

interface SecretOption {
  id: string;
  name: string;
  secret_id?: string;
  secret_type?: string;
}

type CallerAuthMethodFieldsProps = Pick<
  ConfigPanelProps,
  'config' | 'updateField' | 'updateFields' | 'protocol' | 'allNodes' | 'hasAttemptedSave'
> & {
  /** Prefix for element ids and test ids; radio group names derive from it. */
  idPrefix: string;
  /** Authorization server discovery belongs to the first method only. */
  allowDiscovery: boolean;
};

/**
 * The fields of one caller authentication method, below its method picker:
 * JWT strategy, audiences and token header; API key location and secret;
 * DID Auth session token location; mTLS certificate. Writes the flat
 * method shape that `buildMethod` in `./methods.ts` turns into the runtime
 * `SourceAuthConfig`.
 */
const CallerAuthMethodFields: React.FC<CallerAuthMethodFieldsProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  allNodes,
  hasAttemptedSave,
  idPrefix,
  allowDiscovery,
}) => {
  const namePrefix = idPrefix.replace(/-/g, '_');
  const method: CallerAuthMethodType = (config.method_type as CallerAuthMethodType) || 'jwt_bearer';
  const { surfaceId } = useParams<{ surfaceId: string }>();
  const [jwtStrategies, setJwtStrategies] = useState<JwtVerificationStrategy[]>([]);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [apiKeySecrets, setApiKeySecrets] = useState<SecretOption[]>([]);
  const [loadingCertificates, setLoadingCertificates] = useState(false);
  const [loadingApiKeySecrets, setLoadingApiKeySecrets] = useState(false);
  const [audienceInput, setAudienceInput] = useState('');

  useEffect(() => {
    apiClient
      .fetch('/api/v1/jwt-verification-strategies')
      .then(r => (r.ok ? r.json() : []))
      .then((data: JwtVerificationStrategy[]) => setJwtStrategies(Array.isArray(data) ? data : []))
      .catch(() => setJwtStrategies([]));
  }, []);

  useEffect(() => {
    if (method !== 'mtls') return;
    setLoadingCertificates(true);
    apiClient
      .get('/certificates')
      .then(res => {
        const list: Certificate[] = Array.isArray(res.data) ? res.data : [];
        setCertificates(list.filter(c => c.active));
      })
      .catch(() => setCertificates([]))
      .finally(() => setLoadingCertificates(false));
  }, [method]);

  useEffect(() => {
    if (method !== 'api_key') return;
    setLoadingApiKeySecrets(true);
    apiClient
      .get<SecretOption[]>('/secrets/')
      .then(res => {
        const list: SecretOption[] = Array.isArray(res.data) ? res.data : [];
        setApiKeySecrets(
          list.filter(secret => !secret.secret_type || secret.secret_type === 'ApiKey')
        );
      })
      .catch(() => setApiKeySecrets([]))
      .finally(() => setLoadingApiKeySecrets(false));
  }, [method]);

  const audiences: string[] = Array.isArray(config.audiences) ? config.audiences : [];
  const hasDiscovery = readProtectedResource(config.protected_resource) !== null;
  const discoveryOn = allowDiscovery && method === 'jwt_bearer' && hasDiscovery;
  const showsDiscovery =
    allowDiscovery && method === 'jwt_bearer' && (protocol === 'mcp' || hasDiscovery);
  // While discovery is on, each control the gateway constrains is locked once
  // it holds the required value, and stays editable until then.
  const tokenHeaderLocked = discoveryOn && readsAuthorizationHeader(config);
  const tokenSchemeLocked = discoveryOn && usesBearerScheme(config);
  const forwardHeaderLocked = discoveryOn && config.jwt_forward_header !== true;
  const selectedApiKeySecret = String(config.api_key_secret_id || '');
  const selectedApiKeySecretExists = apiKeySecrets.some(
    secret => (secret.secret_id || secret.id) === selectedApiKeySecret
  );

  const isProtocolSource =
    config.extraction_source === 'mcp_meta' || config.extraction_source === 'a2a_extension';

  return (
    <>
      {method === 'jwt_bearer' && (
        <>
          <p className="text-muted mb-3">
            Validate incoming requests using a bearer token verified against a configured JWT
            verification strategy. Requests without a valid token will receive{' '}
            <code>403 Forbidden</code>.
          </p>

          <div className="mb-3">
            <label className="form-label fw-bold">
              JWT Verification Strategy <span className="text-danger">*</span>
            </label>
            <select
              className="form-control dropdown-styling"
              value={config.jwt_strategy_id || ''}
              onChange={e => updateField('jwt_strategy_id', e.target.value)}
              disabled={jwtStrategies.length === 0}
            >
              <option value="">-- select a strategy --</option>
              {jwtStrategies.map(s => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <small className="form-text text-muted">
              Choose which verification strategy the gateway should use to check that the
              caller&apos;s token is genuine and untampered. Each strategy points to a JWKS (a small
              file of public cryptographic keys published by whoever issued the tokens), which the
              gateway uses to confirm the token wasn&apos;t forged.
            </small>
            <div className="form-text">
              {jwtStrategies.length === 0
                ? 'No JWT verification strategies configured yet. '
                : "Don't see the one you need? "}
              <AddResourceLink
                to={deepLinks.jwtVerificationStrategy}
                testid={`${idPrefix}-add-jwt-strategy-link`}
              >
                Add JWT verification strategy
              </AddResourceLink>
            </div>
          </div>

          <div className="mb-3">
            <label className="form-label fw-bold">Accepted Audiences</label>
            <div className="d-flex flex-wrap gap-2 mb-2">
              {audiences.map((aud, idx) => (
                <span
                  key={idx}
                  className="bg-light border rounded d-inline-flex align-items-center"
                  style={{
                    fontSize: '0.875rem',
                    color: '#000',
                    padding: '0.35rem 0.6rem',
                    gap: '0.6rem',
                  }}
                >
                  {aud}
                  <button
                    type="button"
                    className="btn btn-outline-danger p-0"
                    style={{ lineHeight: 1, width: '1.4rem', height: '1.4rem' }}
                    aria-label="Remove"
                    onClick={() =>
                      updateField(
                        'audiences',
                        audiences.filter((_, i) => i !== idx)
                      )
                    }
                  >
                    <i className="fas fa-trash"></i>
                  </button>
                </span>
              ))}
            </div>
            <div className="input-group">
              <input
                type="text"
                className="form-control"
                placeholder="e.g. https://api.example.com"
                disabled={discoveryOn}
                value={audienceInput}
                onChange={e => setAudienceInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ',') {
                    e.preventDefault();
                    const val = audienceInput.trim();
                    if (val && !audiences.includes(val)) {
                      updateField('audiences', [...audiences, val]);
                    }
                    setAudienceInput('');
                  }
                }}
              />
              <button
                type="button"
                className="btn btn-outline-secondary"
                disabled={discoveryOn}
                onClick={() => {
                  const val = audienceInput.trim();
                  if (val && !audiences.includes(val)) {
                    updateField('audiences', [...audiences, val]);
                  }
                  setAudienceInput('');
                }}
              >
                Add
              </button>
            </div>
            {discoveryOn ? (
              <div className="form-text" data-testid={`${idPrefix}-audiences-discovery-note`}>
                Stays empty while authorization server discovery is on: the gateway accepts only
                tokens whose audience is the resource URL.
              </div>
            ) : (
              audiences.length === 0 && (
                <div className="alert alert-warning py-1 px-2 mt-2 mb-0 small d-flex align-items-center gap-2">
                  <i className="fas fa-exclamation-triangle"></i>
                  <span>
                    No audience configured. <code>aud</code> claim validation will be skipped. It is
                    strongly recommended to set at least one audience value to prevent tokens issued
                    for other services from being accepted.
                  </span>
                </div>
              )
            )}
            <small className="form-text text-muted">
              Optional. When set, the token's <code>aud</code> claim must match at least one of
              these values. Press <kbd>Enter</kbd> or <kbd>,</kbd> to add.
            </small>
          </div>

          <div className="row g-3 mb-3">
            <div className="col-md-7">
              <label htmlFor={`${idPrefix}-jwt-token-header`} className="form-label fw-bold">
                Token Header <span className="text-danger">*</span>
              </label>
              <input
                id={`${idPrefix}-jwt-token-header`}
                type="text"
                className="form-control"
                value={config.jwt_token_header ?? 'Authorization'}
                disabled={tokenHeaderLocked}
                onChange={e => updateField('jwt_token_header', e.target.value)}
                placeholder="Authorization"
              />
              <small className="form-text text-muted">
                HTTP header that carries the token. Defaults to <code>Authorization</code>.
              </small>
            </div>
            <div className="col-md-5">
              <label htmlFor={`${idPrefix}-jwt-token-scheme`} className="form-label fw-bold">
                Scheme
              </label>
              <input
                id={`${idPrefix}-jwt-token-scheme`}
                type="text"
                className="form-control"
                value={config.jwt_token_scheme ?? 'Bearer'}
                disabled={tokenSchemeLocked}
                onChange={e => updateField('jwt_token_scheme', e.target.value)}
                placeholder="Bearer"
              />
              <small className="form-text text-muted">
                Prefix stripped from the header value. Leave blank if the header carries the raw
                token.
              </small>
            </div>
            {discoveryOn && (
              <div className="col-12 mt-0">
                <small className="form-text" data-testid={`${idPrefix}-jwt-token-discovery-note`}>
                  Fixed to the Authorization header with the Bearer scheme while authorization
                  server discovery is on.
                </small>
              </div>
            )}
          </div>

          <div className="form-check mb-3">
            <input
              id={`${idPrefix}-jwt-forward-header`}
              data-testid={`${idPrefix}-jwt-forward-header-checkbox`}
              className="form-check-input"
              type="checkbox"
              checked={config.jwt_forward_header === true}
              disabled={forwardHeaderLocked}
              onChange={e => updateField('jwt_forward_header', e.target.checked)}
            />
            <label className="form-check-label fw-bold" htmlFor={`${idPrefix}-jwt-forward-header`}>
              Forward token header to managed agent
            </label>
            <small className="form-text text-muted d-block">
              Sends the validated JWT header unchanged to the directly managed target. Disabled by
              default and never applied to mirrors or fabric hops.
            </small>
            {discoveryOn && (
              <small
                className="form-text d-block"
                data-testid={`${idPrefix}-jwt-forward-header-discovery-note`}
              >
                Off while authorization server discovery is on: MCP forbids passing the
                caller&apos;s token to the managed agent.
              </small>
            )}
          </div>

          {showsDiscovery && (
            <CallerAuthDiscoverySection
              config={config}
              updateFields={updateFields}
              allNodes={allNodes}
              hasAttemptedSave={hasAttemptedSave}
              strategyIssuer={
                jwtStrategies.find(s => s.id === config.jwt_strategy_id)?.expected_issuer
              }
            />
          )}
        </>
      )}

      {(method === 'api_key' || method === 'api_key_provider') && (
        <>
          <p className="text-muted mb-3">
            {method === 'api_key'
              ? 'Callers send a pre-shared key that must match one stored in your Secrets.'
              : "Like API Key (secret store), but valid keys come from this surface's own API Keys list instead of a Secret."}
          </p>
          <div className="mb-4">
            <label className="form-label fw-bold">API Key Location</label>
            <div className="d-flex gap-3">
              <div className="form-check">
                <input
                  className="form-check-input"
                  type="radio"
                  name={`${namePrefix}_apikey_location`}
                  id={`${idPrefix}-apikey-header`}
                  checked={!isProtocolSource}
                  onChange={() =>
                    updateFields({
                      extraction_source: 'http_header',
                      extraction_field: 'X-API-Key',
                    })
                  }
                />
                <label className="form-check-label" htmlFor={`${idPrefix}-apikey-header`}>
                  HTTP Header
                  <small className="d-block text-muted">
                    Sent as a normal header on every request; works no matter which protocol your
                    agent uses.
                  </small>
                </label>
              </div>
              <div className="form-check">
                <input
                  className="form-check-input"
                  type="radio"
                  name={`${namePrefix}_apikey_location`}
                  id={`${idPrefix}-apikey-protocol`}
                  checked={isProtocolSource}
                  onChange={() =>
                    updateFields({
                      extraction_source: protocol === 'mcp' ? 'mcp_meta' : 'a2a_extension',
                      extraction_field: 'apiKey',
                    })
                  }
                />
                <label className="form-check-label" htmlFor={`${idPrefix}-apikey-protocol`}>
                  Protocol-Specific
                  <small className="d-block text-muted">
                    Sent inside the message itself, using each protocol&apos;s own slot for extra
                    data: the Model Context Protocol (MCP) calls this <code>_meta</code>; the
                    Agent2Agent protocol (A2A/UCP) calls it an extension point.
                  </small>
                </label>
              </div>
            </div>
            <small className="form-text text-muted">
              Pick HTTP Header unless your caller&apos;s integration specifically requires the
              protocol-native option.
            </small>
          </div>

          <div className="mb-4">
            <label htmlFor={`${idPrefix}-api-key-field`} className="form-label fw-bold">
              {!isProtocolSource ? 'HTTP Header Name' : 'Protocol Field Name'}
            </label>
            <input
              type="text"
              className="form-control"
              id={`${idPrefix}-api-key-field`}
              value={config.extraction_field || ''}
              onChange={e => updateField('extraction_field', e.target.value)}
            />
          </div>

          {method === 'api_key' && (
            <div className="mb-4">
              <label htmlFor={`${idPrefix}-secret-id`} className="form-label fw-bold">
                Secret ID <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                id={`${idPrefix}-secret-id`}
                value={selectedApiKeySecret}
                onChange={e => updateField('api_key_secret_id', e.target.value)}
                disabled={loadingApiKeySecrets}
                required
              >
                <option value="">
                  {loadingApiKeySecrets ? 'Loading secrets…' : '-- select an API key secret --'}
                </option>
                {apiKeySecrets.map(secret => (
                  <option key={secret.id} value={secret.secret_id || secret.id}>
                    {secret.name || secret.secret_id || secret.id}
                  </option>
                ))}
                {selectedApiKeySecret && !selectedApiKeySecretExists && (
                  <option value={selectedApiKeySecret}>{selectedApiKeySecret} (not found)</option>
                )}
              </select>
              <small className="form-text text-muted">
                Secret containing comma-separated valid API keys.
              </small>
            </div>
          )}

          {method === 'api_key_provider' && (
            <div className="mb-4">
              <label className="form-label fw-bold">Agent ID</label>
              <input
                type="text"
                className="form-control"
                value={surfaceId || '(assigned when the surface is saved)'}
                readOnly
                disabled
              />
              <small className="form-text text-muted">
                API keys for this surface are managed under its own ID. Create them from the API
                Keys page using this surface as the agent. No configuration is required here.
              </small>
            </div>
          )}
        </>
      )}

      {method === 'did_auth' && (
        <>
          <p className="text-muted mb-3">
            Callers authenticate with a signed session token tied to their decentralized identity
            (DID).
          </p>
          <div className="mb-4">
            <label className="form-label fw-bold">Session Token Location</label>
            <div className="d-flex gap-3">
              <div className="form-check">
                <input
                  className="form-check-input"
                  type="radio"
                  name={`${namePrefix}_didauth_location`}
                  id={`${idPrefix}-didauth-header`}
                  checked={!isProtocolSource}
                  onChange={() =>
                    updateFields({
                      extraction_source: 'http_header',
                      extraction_field: 'X-Session-Token',
                    })
                  }
                />
                <label className="form-check-label" htmlFor={`${idPrefix}-didauth-header`}>
                  HTTP Header
                  <small className="d-block text-muted">
                    Transport-level (works with all protocols)
                  </small>
                </label>
              </div>
              <div className="form-check">
                <input
                  className="form-check-input"
                  type="radio"
                  name={`${namePrefix}_didauth_location`}
                  id={`${idPrefix}-didauth-protocol`}
                  checked={isProtocolSource}
                  onChange={() =>
                    updateFields({
                      extraction_source: protocol === 'mcp' ? 'mcp_meta' : 'a2a_extension',
                      extraction_field: 'sessionId',
                    })
                  }
                />
                <label className="form-check-label" htmlFor={`${idPrefix}-didauth-protocol`}>
                  Protocol-Specific
                  <small className="d-block text-muted">MCP _meta or A2A/UCP extension point</small>
                </label>
              </div>
            </div>
          </div>

          <div className="mb-4">
            <label htmlFor={`${idPrefix}-session-token-field`} className="form-label fw-bold">
              {!isProtocolSource ? 'HTTP Header Name' : 'Protocol Field Name'}
            </label>
            <input
              type="text"
              className="form-control"
              id={`${idPrefix}-session-token-field`}
              value={config.extraction_field || ''}
              onChange={e => updateField('extraction_field', e.target.value)}
            />
          </div>
        </>
      )}

      {method === 'mtls' && (
        <>
          <p className="text-muted mb-3">
            Callers present a client certificate the gateway trusts to verify their identity.
          </p>
          <div className="mb-4">
            <label htmlFor={`${idPrefix}-mtls-certificate`} className="form-label fw-bold">
              Client Certificate
            </label>
            <select
              id={`${idPrefix}-mtls-certificate`}
              className="form-control dropdown-styling"
              value={config.mtls_certificate_id || ''}
              onChange={e => updateField('mtls_certificate_id', e.target.value)}
              disabled={loadingCertificates}
            >
              <option value="">
                {loadingCertificates
                  ? '-- Loading certificates... --'
                  : '-- Select a certificate --'}
              </option>
              {certificates.map(cert => (
                <option key={cert.id} value={cert.id}>
                  {cert.name}
                  {cert.expires_at
                    ? ` (Expires: ${new Date(cert.expires_at).toLocaleDateString()})`
                    : ''}
                </option>
              ))}
            </select>
            <small className="form-text text-muted">
              Select the client certificate to validate against for identity verification.
            </small>
          </div>
        </>
      )}
    </>
  );
};

export default CallerAuthMethodFields;
