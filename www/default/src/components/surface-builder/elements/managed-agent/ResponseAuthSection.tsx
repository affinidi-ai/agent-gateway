import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { CertificateKind, MtlsTrust } from '../../../../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { useApiKeySecrets, useCertificates } from '../caller-auth/useCallerAuthOptions';
import {
  DEFAULT_RESPONSE_AUTH_HEADER,
  isHttpsTarget,
  isResponseAuthTarget,
  newResponseAuth,
  responseAuthMethod,
  responseAuthProblems,
  responseAuthSaveError,
  responseAuthWarnings,
  trustCertificateIds,
  withTrustCertificateIds,
  type ApiKeyResponseAuth,
  type MtlsResponseAuth,
  type ResponseAuth,
  type ResponseAuthMethod,
} from './responseAuth';

interface Props {
  endpoint: string;
  value: unknown;
  onChange: (next: ResponseAuth | null) => void;
}

const T = 'managed-agent-response-auth';

/**
 * Response authentication (`target.response_auth`): how the managed agent's
 * response proves it comes from the registered agent. Holds the wire shape
 * as it is, so a stored setting the operator does not edit saves unchanged.
 */
const ResponseAuthSection: React.FC<Props> = ({ endpoint, value, onChange }) => {
  const meta = useOptionalSurfaceMeta();
  const variant = meta?.activeVariantAlias;
  const method: ResponseAuthMethod = responseAuthMethod(value);
  const https = isHttpsTarget(endpoint);
  const { secrets } = useApiKeySecrets(method === 'api_key');
  const {
    certificates,
    loaded: certificatesLoaded,
    failed: certificatesFailed,
  } = useCertificates(method === 'mtls');

  const signature = JSON.stringify([endpoint, value ?? null]);
  const signatureRef = useRef(signature);
  signatureRef.current = signature;
  const saveWarnings = meta?.saveWarnings;
  const [warnedAt, setWarnedAt] = useState<string | null>(null);
  useEffect(() => {
    setWarnedAt(saveWarnings ? signatureRef.current : null);
  }, [saveWarnings]);
  const savedWarnings = useMemo(
    () => (saveWarnings ? responseAuthWarnings(saveWarnings, variant) : []),
    [saveWarnings, variant]
  );
  const showSavedWarnings = savedWarnings.length > 0 && warnedAt === signature;
  const refusal = responseAuthSaveError(meta?.saveError, variant);
  const problems = responseAuthProblems(endpoint, value);

  const changeMethod = (next: ResponseAuthMethod) => {
    if (next === 'off') onChange(null);
    else if (next === 'api_key' || next === 'mtls') onChange(newResponseAuth(next));
  };

  const apiKey = method === 'api_key' ? (value as ApiKeyResponseAuth).api_key : null;
  const mtls = method === 'mtls' ? (value as MtlsResponseAuth).mtls : null;
  const trust: MtlsTrust | null = mtls?.server_trust ?? null;
  const trustKind: CertificateKind = trust?.type === 'ca' ? 'ca' : 'client_leaf';
  const trustIds = trust ? trustCertificateIds(trust) : [];
  const trustOptions = certificates.filter(c => (c.kind ?? 'server_leaf') === trustKind);
  const missingTrustIds = certificatesLoaded
    ? trustIds.filter(id => !trustOptions.some(c => c.id === id))
    : [];
  const clientOptions = certificates.filter(c => c.kind === 'client_leaf');
  const clientId = mtls?.client_certificate_id ?? '';

  const setMtls = (patch: Partial<MtlsResponseAuth['mtls']>) => {
    if (!mtls) return;
    const next = { ...mtls, ...patch };
    if (!next.client_certificate_id) delete next.client_certificate_id;
    onChange({ mtls: next });
  };

  const toggleTrustId = (id: string, on: boolean) => {
    if (!trust) return;
    const ids = on ? [...trustIds, id] : trustIds.filter(t => t !== id);
    setMtls({ server_trust: withTrustCertificateIds(trust, ids) });
  };

  return (
    <div className="config-section" data-testid={`${T}-section`}>
      <label>Response Authentication</label>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label htmlFor={`${T}-method`} className="small text-muted mb-0">
            Method
          </Form.Label>
          <FieldHelp testId={`field-help-${T}`} ariaLabel="About Response Authentication">
            <p>
              How the managed agent proves that a response comes from it. The gateway checks every
              response before using it and refuses one that fails, so a server that answers at the
              Target address cannot pass itself off as the agent. Off trusts any server there.
            </p>
            <p>
              <strong>API key</strong>: the agent returns one of the keys in a secret in a response
              header. A secret may hold several keys, separated by commas, so a key can be rotated.
            </p>
            <p>
              <strong>mTLS</strong>: the agent&apos;s server certificate must match a pinned
              certificate or chain to a trusted CA. It needs an https:// Target, because only TLS
              proves the agent&apos;s certificate; it is not offered on an http:// Target.
            </p>
          </FieldHelp>
        </div>
        <Form.Select
          id={`${T}-method`}
          size="sm"
          data-testid={`${T}-method`}
          value={method}
          onChange={e => changeMethod(e.target.value as ResponseAuthMethod)}
        >
          {method === 'unsupported' && (
            <option value="unsupported" disabled>
              Set through the API (kept)
            </option>
          )}
          <option value="off">Off</option>
          <option value="api_key">API key</option>
          <option value="mtls" disabled={!https && method !== 'mtls'}>
            {https ? 'mTLS' : 'mTLS (needs an https:// Target)'}
          </option>
        </Form.Select>
      </Form.Group>

      {method === 'unsupported' && (
        <Alert variant="info" className="py-1 px-2 small mb-2" data-testid={`${T}-unsupported`}>
          This surface checks its Target&apos;s responses with a setting the dashboard cannot show.
          It is kept as it is when you save here. Choose another method, or Off, to replace it.
        </Alert>
      )}

      {apiKey && (
        <>
          <Form.Group className="mb-2">
            <Form.Label htmlFor={`${T}-header`} className="small text-muted mb-1">
              Response header
            </Form.Label>
            <Form.Control
              id={`${T}-header`}
              size="sm"
              type="text"
              data-testid={`${T}-header`}
              placeholder={DEFAULT_RESPONSE_AUTH_HEADER}
              value={apiKey.header_name ?? ''}
              onChange={e =>
                onChange({ api_key: { ...apiKey, header_name: e.target.value.trim() } })
              }
            />
          </Form.Group>
          <Form.Group className="mb-2">
            <Form.Label htmlFor={`${T}-secret`} className="small text-muted mb-1">
              Secret holding the key
            </Form.Label>
            <Form.Select
              id={`${T}-secret`}
              size="sm"
              data-testid={`${T}-secret`}
              value={apiKey.secret_id ?? ''}
              onChange={e => onChange({ api_key: { ...apiKey, secret_id: e.target.value } })}
            >
              <option value="">-- select a secret --</option>
              {apiKey.secret_id &&
                !secrets.some(s => (s.secret_id || s.id) === apiKey.secret_id) && (
                  <option value={apiKey.secret_id}>{apiKey.secret_id}</option>
                )}
              {secrets.map(s => (
                <option key={s.id} value={s.secret_id || s.id}>
                  {s.name}
                </option>
              ))}
            </Form.Select>
            <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
              <AddResourceLink to={deepLinks.secret} testid={`${T}-add-secret-link`}>
                Add secret
              </AddResourceLink>
            </Form.Text>
          </Form.Group>
          {isResponseAuthTarget(endpoint) && !https && (
            <Form.Text
              className="d-block text-warning mb-2"
              style={{ fontSize: '10px' }}
              data-testid={`${T}-http-warning`}
            >
              <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
              The key travels unencrypted over http://. Use an https:// Target.
            </Form.Text>
          )}
        </>
      )}

      {mtls && trust && (
        <>
          <Form.Group className="mb-2">
            <Form.Label htmlFor={`${T}-trust-mode`} className="small text-muted mb-1">
              Trust the agent&apos;s server certificate by
            </Form.Label>
            <Form.Select
              id={`${T}-trust-mode`}
              size="sm"
              data-testid={`${T}-trust-mode`}
              value={trust.type}
              onChange={e =>
                setMtls({
                  server_trust:
                    e.target.value === 'ca'
                      ? { type: 'ca', ca_certificate_ids: [] }
                      : { type: 'pinned', certificate_ids: [] },
                })
              }
            >
              <option value="pinned">Pinned certificate</option>
              <option value="ca">Certificate Authority</option>
            </Form.Select>
          </Form.Group>
          <fieldset className="mb-2" data-testid={`${T}-trust-certificates`}>
            <legend className="small text-muted mb-1" style={{ fontSize: 'inherit' }}>
              {trust.type === 'ca' ? 'Trusted CA certificates' : 'Pinned server certificates'}
            </legend>
            {missingTrustIds.map(id => (
              <Form.Check
                key={id}
                type="checkbox"
                id={`${T}-trust-cert-${id}`}
                data-testid={`${T}-trust-cert-${id}`}
                label={`${id} (not in the certificate store)`}
                checked
                onChange={() => toggleTrustId(id, false)}
              />
            ))}
            {trustOptions.map(c => (
              <Form.Check
                key={c.id}
                type="checkbox"
                id={`${T}-trust-cert-${c.id}`}
                data-testid={`${T}-trust-cert-${c.id}`}
                label={c.name || c.id}
                checked={trustIds.includes(c.id)}
                onChange={e => toggleTrustId(c.id, e.target.checked)}
              />
            ))}
            {trustOptions.length === 0 && missingTrustIds.length === 0 && !certificatesFailed && (
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                {trust.type === 'ca'
                  ? 'No CA certificate in the certificate store.'
                  : 'No client leaf certificate in the certificate store.'}
              </Form.Text>
            )}
            <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
              <AddResourceLink
                to={deepLinks.certificate(trustKind)}
                testid={`${T}-add-certificate-link`}
              >
                Add certificate
              </AddResourceLink>
            </Form.Text>
          </fieldset>
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label htmlFor={`${T}-client-cert`} className="small text-muted mb-0">
                Client certificate (optional)
              </Form.Label>
              <FieldHelp
                testId={`field-help-${T}-client-cert`}
                ariaLabel="About Client certificate"
              >
                <p>
                  The certificate the gateway presents to the agent in the TLS handshake, for an
                  agent that asks for one. It must be a client leaf certificate stored with its
                  private key; the gateway refuses the save otherwise.
                </p>
              </FieldHelp>
            </div>
            <Form.Select
              id={`${T}-client-cert`}
              size="sm"
              data-testid={`${T}-client-cert`}
              value={clientId}
              onChange={e => setMtls({ client_certificate_id: e.target.value })}
            >
              <option value="">None</option>
              {clientId && !clientOptions.some(c => c.id === clientId) && (
                <option value={clientId}>{clientId} (not in the certificate store)</option>
              )}
              {clientOptions.map(c => (
                <option key={c.id} value={c.id}>
                  {c.name || c.id}
                </option>
              ))}
            </Form.Select>
          </Form.Group>
          {certificatesFailed && (
            <div
              className="text-danger small mb-1"
              role="alert"
              data-testid={`${T}-certificates-error`}
            >
              The certificate store could not be read.
            </div>
          )}
        </>
      )}

      {showSavedWarnings &&
        savedWarnings.map(warning => (
          <Alert
            key={warning}
            variant="warning"
            className="py-1 px-2 small mb-2"
            data-testid={`${T}-save-warning`}
          >
            {warning}
          </Alert>
        ))}

      {problems.map(problem => (
        <div
          key={problem}
          className="text-danger small mb-1"
          role="alert"
          data-testid={`${T}-problem`}
        >
          {problem}
        </div>
      ))}

      {refusal && (
        <div className="invalid-feedback d-block" role="alert" data-testid={`${T}-save-error`}>
          The gateway refused the last save: {refusal}
        </div>
      )}
    </div>
  );
};

export default ResponseAuthSection;
