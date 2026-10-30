import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Form, Modal } from 'react-bootstrap';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import {
  DEFAULT_API_KEY_HEADER,
  apiKeyHeader,
  callerAuthChoice,
  callerAuthProblems,
  callerAuthSignature,
  exposureWarning,
  hasResourceToken,
  isOpenToAnyCaller,
  newSourceAuth,
  readSourceAuth,
  requiresTransitToken,
  transitPointSaveError,
  warningsForTransitPoint,
  type CallerAuthChoice,
  type TransitSourceAuth,
} from './callerAuth';
import { useApiKeySecrets, useJwtStrategies } from '../caller-auth/useCallerAuthOptions';

interface Props {
  /** The Transit Point node's config. */
  config: Record<string, any>;
  /** The Transit Point's routing alias, which the gateway's messages name it by. */
  alias: string;
  updateField: (field: string, value: any) => void;
  updateFields: (fields: Record<string, any>) => void;
}

const CHOICES: Array<{ value: CallerAuthChoice; label: string; disabled?: boolean }> = [
  { value: 'none', label: 'None' },
  { value: 'api_key', label: 'API key (secret store)' },
  { value: 'api_key_provider', label: 'API key (provider)' },
  { value: 'jwt_bearer', label: 'JWT bearer' },
  { value: 'mtls', label: 'mTLS (set through the API)', disabled: true },
];

/**
 * "Who can call this Transit Point": the transit token, the Transit Point's own
 * caller authentication (`source_auth`), and the explicit marking that it is
 * open to any caller. Applies the gateway's save rules before the save, and
 * shows the gateway's refusals and exposure warnings next to the fields they
 * are about.
 */
const TransitCallerSection: React.FC<Props> = ({ config, alias, updateField, updateFields }) => {
  const meta = useOptionalSurfaceMeta();
  const variant = meta?.activeVariantAlias;
  const sourceAuth = readSourceAuth(config);
  const choice = callerAuthChoice(config);
  const tokenOn = requiresTransitToken(config);
  const resourceToken = hasResourceToken(config);
  const open = isOpenToAnyCaller(config);
  const [confirmingOpen, setConfirmingOpen] = useState(false);

  const { secrets } = useApiKeySecrets(choice === 'api_key');
  const strategies = useJwtStrategies(choice === 'jwt_bearer');
  const [audienceInput, setAudienceInput] = useState('');

  const problems = callerAuthProblems(config);
  const predicted = exposureWarning(config, alias);

  // A warning the last save answered with stays until the Transit Point's
  // caller authentication or address changes: it then no longer describes it.
  const signature = callerAuthSignature(config);
  const signatureRef = useRef(signature);
  signatureRef.current = signature;
  const saveWarnings = meta?.saveWarnings;
  const [warnedAt, setWarnedAt] = useState<{ for: unknown; signature: string } | null>(null);
  useEffect(() => {
    setWarnedAt(saveWarnings ? { for: saveWarnings, signature: signatureRef.current } : null);
  }, [saveWarnings]);
  const savedWarnings = useMemo(
    () => (saveWarnings ? warningsForTransitPoint(saveWarnings, alias, variant) : []),
    [saveWarnings, alias, variant]
  );
  const showSavedWarnings =
    savedWarnings.length > 0 && (!warnedAt || warnedAt.signature === signature);
  // The gateway's text duplicates what this panel already predicts when it
  // names the same exposure, so the prediction is shown only when the save did
  // not already say it.
  const saveSaidExposure =
    showSavedWarnings && savedWarnings.some(w => w.includes('does not authenticate'));
  const refusal = transitPointSaveError(meta?.saveError, alias, variant);

  const setSourceAuth = (next: TransitSourceAuth | null) => {
    updateFields({
      source_auth: next,
      // The gateway refuses the open marking beside a caller authentication.
      ...(next && open ? { allow_unauthenticated_callers: false } : {}),
    });
  };

  const changeChoice = (next: CallerAuthChoice) => {
    if (next === 'none') return setSourceAuth(null);
    if (next === 'mtls') return;
    setSourceAuth(newSourceAuth(next, meta?.surfaceId ?? ''));
  };

  const patchSourceAuth = (patch: Record<string, unknown>) => {
    if (sourceAuth) setSourceAuth({ ...sourceAuth, ...patch });
  };

  const audiences: string[] = Array.isArray(sourceAuth?.audiences)
    ? (sourceAuth!.audiences as string[])
    : [];
  const addAudience = () => {
    const value = audienceInput.trim();
    if (value && !audiences.includes(value)) patchSourceAuth({ audiences: [...audiences, value] });
    setAudienceInput('');
  };

  const canMarkOpen = !tokenOn && !sourceAuth && !resourceToken;

  return (
    <div className="config-section" data-testid="transit-point-caller-section">
      <div role="group" aria-labelledby="tp-caller-title" aria-describedby="tp-caller-help">
        <label id="tp-caller-title">Who can call this Transit Point</label>
        <Form.Text
          id="tp-caller-help"
          className="text-muted d-block mb-2"
          style={{ fontSize: '10px' }}
        >
          Every Transit Point must authenticate its callers or say it is open to any caller. Without
          either, saving is refused.
        </Form.Text>

        <Form.Group className="mb-2">
          <Form.Check
            type="switch"
            id={`tp-require-transit-token-${config.id || 'new'}`}
            data-testid="transit-point-require-transit-token-switch"
            label="Require transit token"
            checked={tokenOn}
            onChange={e =>
              updateFields({
                require_transit_token: e.target.checked,
                ...(e.target.checked && open ? { allow_unauthenticated_callers: false } : {}),
              })
            }
          />
          <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
            When enabled, every call to this transit point must carry a valid{' '}
            <code>X-Transit-Token</code> header issued by the surface's Access Point. Turn it off
            when the caller cannot carry the token, and choose how callers authenticate below, or
            mark the Transit Point open to any caller.
          </Form.Text>
        </Form.Group>

        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-method">
            Caller authentication
          </Form.Label>
          <Form.Select
            id="tp-caller-auth-method"
            size="sm"
            data-testid="transit-point-caller-auth-method"
            value={choice}
            aria-describedby="tp-caller-auth-help"
            onChange={e => changeChoice(e.target.value as CallerAuthChoice)}
          >
            {choice === 'unsupported' && (
              <option value="unsupported" disabled>
                {typeof sourceAuth?.type === 'string'
                  ? `${sourceAuth.type} (not supported here)`
                  : 'Set through the API (kept)'}
              </option>
            )}
            {CHOICES.map(option => (
              <option
                key={option.value}
                value={option.value}
                disabled={option.disabled && choice !== option.value}
              >
                {option.label}
              </option>
            ))}
          </Form.Select>
          <Form.Text
            id="tp-caller-auth-help"
            className="text-muted d-block"
            style={{ fontSize: '10px' }}
          >
            The caller presents its own credential, such as an API key or a JWT. A call without a
            valid one is refused with 401 before anything else runs. The credential is never passed
            on to the target.
          </Form.Text>
        </Form.Group>

        {choice === 'unsupported' && (
          <Alert
            variant="warning"
            className="py-1 px-2 small"
            data-testid="transit-point-caller-auth-unsupported"
          >
            {typeof sourceAuth?.type === 'string' ? (
              <>
                This Transit Point has a caller authentication method the dashboard cannot show (
                <code>{sourceAuth.type}</code>). Choose another method, or remove it.
              </>
            ) : (
              <>
                This Transit Point has a caller authentication that was set through the API and the
                dashboard cannot read. It is kept as it is when you save here. Choose another
                method, or remove it.
              </>
            )}{' '}
            <Button
              variant="outline-secondary"
              size="sm"
              className="py-0"
              data-testid="transit-point-caller-auth-remove"
              onClick={() => setSourceAuth(null)}
            >
              Remove
            </Button>
          </Alert>
        )}

        {choice === 'mtls' && (
          <Alert
            variant="info"
            className="py-1 px-2 small"
            data-testid="transit-point-caller-auth-mtls"
          >
            Callers present a client certificate. This is set through the API and kept as it is when
            you save here. Choose another method, or None, to replace it.
          </Alert>
        )}

        {(choice === 'api_key' || choice === 'api_key_provider') && sourceAuth && (
          <>
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-header">
                Header callers send the key in
              </Form.Label>
              <Form.Control
                id="tp-caller-auth-header"
                size="sm"
                type="text"
                data-testid="transit-point-caller-auth-header"
                placeholder={DEFAULT_API_KEY_HEADER}
                value={apiKeyHeader(sourceAuth)}
                onChange={e =>
                  patchSourceAuth({
                    extraction: { source: 'http_header', field: e.target.value.trim() },
                  })
                }
              />
            </Form.Group>
            {choice === 'api_key' && (
              <Form.Group className="mb-2">
                <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-secret">
                  API key secret
                </Form.Label>
                <Form.Select
                  id="tp-caller-auth-secret"
                  size="sm"
                  data-testid="transit-point-caller-auth-secret"
                  value={String(sourceAuth.secret_id ?? '')}
                  onChange={e => patchSourceAuth({ secret_id: e.target.value })}
                >
                  <option value="">-- select a secret --</option>
                  {String(sourceAuth.secret_id ?? '') &&
                    !secrets.some(s => (s.secret_id || s.id) === sourceAuth.secret_id) && (
                      <option value={String(sourceAuth.secret_id)}>
                        {String(sourceAuth.secret_id)}
                      </option>
                    )}
                  {secrets.map(s => (
                    <option key={s.id} value={s.secret_id || s.id}>
                      {s.name}
                    </option>
                  ))}
                </Form.Select>
                <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                  Every key in this secret is accepted as one caller.{' '}
                  <AddResourceLink to={deepLinks.apiKey} testid="transit-point-add-api-key-link">
                    Add API key
                  </AddResourceLink>
                </Form.Text>
              </Form.Group>
            )}
            {choice === 'api_key_provider' && (
              <Alert
                variant="warning"
                className="py-1 px-2 small mb-2"
                data-testid="transit-point-caller-auth-provider-scope"
              >
                Keys are validated against the API Key Provider for agent{' '}
                <code>{meta?.surfaceId || 'this surface'}</code>; each issued key is one caller.
                These are the same keys an Access Point using the API Key Provider accepts, so its
                callers can call this Transit Point too. To accept a separate set of callers, use an
                API key from the secret store.
              </Alert>
            )}
          </>
        )}

        {choice === 'jwt_bearer' && sourceAuth && (
          <>
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-strategy">
                JWT verification strategy
              </Form.Label>
              <Form.Select
                id="tp-caller-auth-strategy"
                size="sm"
                data-testid="transit-point-caller-auth-strategy"
                value={String(sourceAuth.jwt_verification_strategy_id ?? '')}
                onChange={e => patchSourceAuth({ jwt_verification_strategy_id: e.target.value })}
              >
                <option value="">-- select a strategy --</option>
                {strategies.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </Form.Select>
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                <AddResourceLink
                  to={deepLinks.jwtVerificationStrategy}
                  testid="transit-point-add-jwt-strategy-link"
                >
                  Add JWT verification strategy
                </AddResourceLink>
              </Form.Text>
            </Form.Group>
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-audience">
                Accepted audiences
              </Form.Label>
              <div
                className="d-flex flex-wrap gap-1 mb-1"
                data-testid="transit-point-caller-auth-audiences"
              >
                {audiences.map(audience => (
                  <span key={audience} className="badge bg-light text-dark border">
                    {audience}{' '}
                    <button
                      type="button"
                      className="btn btn-link btn-sm p-0 text-danger"
                      aria-label={`Remove audience ${audience}`}
                      onClick={() =>
                        patchSourceAuth({ audiences: audiences.filter(a => a !== audience) })
                      }
                    >
                      <i className="fas fa-times" />
                    </button>
                  </span>
                ))}
              </div>
              <div className="input-group input-group-sm">
                <Form.Control
                  id="tp-caller-auth-audience"
                  type="text"
                  data-testid="transit-point-caller-auth-audience-input"
                  placeholder="e.g. https://crm.example.com"
                  value={audienceInput}
                  onChange={e => setAudienceInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ',') {
                      e.preventDefault();
                      addAudience();
                    }
                  }}
                />
                <Button
                  variant="outline-secondary"
                  size="sm"
                  data-testid="transit-point-caller-auth-audience-add"
                  onClick={addAudience}
                >
                  Add
                </Button>
              </div>
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                Required. Give this Transit Point an audience of its own: a token issued for the
                Access Point with an audience it also accepts would be accepted here too.{' '}
                <code>{'{{ surface.agent_did }}'}</code> means this surface's agent DID.
              </Form.Text>
            </Form.Group>
            <div className="row g-2 mb-2">
              <div className="col-7">
                <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-token-header">
                  Token header
                </Form.Label>
                <Form.Control
                  id="tp-caller-auth-token-header"
                  size="sm"
                  type="text"
                  data-testid="transit-point-caller-auth-token-header"
                  value={String(sourceAuth.token_header ?? 'Authorization')}
                  onChange={e => patchSourceAuth({ token_header: e.target.value.trim() })}
                />
              </div>
              <div className="col-5">
                <Form.Label className="small text-muted mb-1" htmlFor="tp-caller-auth-token-scheme">
                  Scheme
                </Form.Label>
                <Form.Control
                  id="tp-caller-auth-token-scheme"
                  size="sm"
                  type="text"
                  data-testid="transit-point-caller-auth-token-scheme"
                  value={String(sourceAuth.token_scheme ?? 'Bearer')}
                  onChange={e => patchSourceAuth({ token_scheme: e.target.value.trim() })}
                />
              </div>
            </div>
          </>
        )}

        {(canMarkOpen || open) && (
          <Form.Group className="mb-2 mt-3" data-testid="transit-point-open-group">
            <Form.Check
              type="switch"
              id={`tp-allow-unauthenticated-callers-${config.id || 'new'}`}
              data-testid="transit-point-allow-unauthenticated-callers-switch"
              label="Open to any caller"
              checked={open}
              onChange={e => {
                if (e.target.checked) setConfirmingOpen(true);
                else updateField('allow_unauthenticated_callers', false);
              }}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Serves anyone who reaches this Transit Point, with no check on who they are.
            </Form.Text>
          </Form.Group>
        )}

        {open && (
          <Alert
            variant="warning"
            className="py-1 px-2 small mb-2"
            data-testid="transit-point-allow-unauthenticated-callers-warning"
          >
            Anyone who can reach this Transit Point can call it through this gateway, with the
            credentials it sends to its target. Only keep it open when it sends no credential, or
            only callers you trust can reach it.
          </Alert>
        )}

        {predicted && !saveSaidExposure && (
          <Alert
            variant="danger"
            className="py-1 px-2 small mb-2"
            data-testid="transit-point-exposure-warning"
          >
            {predicted}. Anyone on the internet, or on the network that reaches this address, can
            call it. Add the transit token or a caller authentication method.
          </Alert>
        )}

        {showSavedWarnings &&
          savedWarnings.map(warning => (
            <Alert
              key={warning}
              variant="warning"
              className="py-1 px-2 small mb-2"
              data-testid="transit-point-save-warning"
            >
              {warning}
            </Alert>
          ))}

        {problems.map(problem => (
          <div
            key={problem}
            className="text-danger small mb-1"
            role="alert"
            data-testid="transit-point-caller-auth-problem"
          >
            {problem}
          </div>
        ))}

        {refusal && (
          <div
            className="invalid-feedback d-block"
            role="alert"
            data-testid="transit-point-save-error"
          >
            The gateway refused the last save: {refusal}
          </div>
        )}
      </div>

      <Modal
        show={confirmingOpen}
        onHide={() => setConfirmingOpen(false)}
        centered
        data-testid="transit-point-open-confirm"
      >
        <Modal.Header closeButton>
          <Modal.Title>Open this Transit Point to any caller?</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>
            It will serve anyone who can reach it, with no check on who they are, and use this
            gateway and the credentials it sends to its target on their behalf.
          </p>
          <p className="mb-0">
            Prefer the transit token or a caller authentication method. Open it only when it sends
            no credential, or only callers you trust can reach its address.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button
            variant="secondary"
            data-testid="transit-point-open-cancel"
            onClick={() => setConfirmingOpen(false)}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            data-testid="transit-point-open-confirm-button"
            onClick={() => {
              setConfirmingOpen(false);
              updateField('allow_unauthenticated_callers', true);
            }}
          >
            Open to any caller
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default TransitCallerSection;
