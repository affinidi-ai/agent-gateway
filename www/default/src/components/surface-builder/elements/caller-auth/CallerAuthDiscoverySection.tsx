import React, { useEffect, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import AddResourceLink from '../../../shared/AddResourceLink';
import FieldHelp from '../../../shared/FieldHelp';
import InfoBanner from '../../../shared/InfoBanner';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import type { CanvasNode, Protocol } from '../types';
import {
  DISCOVERY_FIELDS,
  MAX_AUTHORIZATION_SERVERS,
  authorizationServerProblem,
  declaresOn,
  derivedDeclarationNotes,
  discoveryProblems,
  discoverySaveError,
  readProtectedResource,
  resourceMissesRoute,
  scopeProblem,
  strategyPin,
  suggestedResource,
  variantResource,
  type DeclarationStrategy,
  type ProtectedResourceSetting,
} from './protectedResource';
import ScopesInput from './ScopesInput';
import { readRequiredScopes } from './scopes';

const TEST_ID = 'caller-auth-discovery';

interface ValueListProps {
  /** Test id segment for this list, e.g. `authorization-server`. */
  slug: string;
  noun: string;
  label: string;
  required?: boolean;
  help: React.ReactNode;
  hint: string;
  placeholder: string;
  values: string[];
  max?: number;
  problemOf: (value: string) => string | null;
  errors: string[];
  onChange: (values: string[]) => void;
}

/** A removable list of values with an add field, checked one by one as they are added. */
const DiscoveryValueList: React.FC<ValueListProps> = ({
  slug,
  noun,
  label,
  required,
  help,
  hint,
  placeholder,
  values,
  max,
  problemOf,
  errors,
  onChange,
}) => {
  const [draft, setDraft] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const inputId = `${TEST_ID}-${slug}-input`;
  const full = max !== undefined && values.length >= max;

  const add = () => {
    const value = draft.trim();
    if (!value) return;
    const problem = values.includes(value) ? `This ${noun} is already listed` : problemOf(value);
    if (problem) {
      setAddError(problem);
      return;
    }
    onChange([...values, value]);
    setDraft('');
    setAddError(null);
  };

  return (
    <div className="mb-3">
      <div className="d-flex align-items-center gap-1 mb-1">
        <label htmlFor={inputId} className="form-label fw-bold mb-0">
          {label} {required && <span className="text-danger">*</span>}
        </label>
        <FieldHelp testId={`field-help-${TEST_ID}-${slug}`} ariaLabel={`About ${label}`}>
          {help}
        </FieldHelp>
      </div>
      {values.length > 0 && (
        <ul className="list-unstyled d-flex flex-wrap gap-2 mb-2">
          {values.map((value, index) => (
            <li
              key={`${index}:${value}`}
              className="bg-light border rounded d-inline-flex align-items-center"
              style={{
                fontSize: '0.875rem',
                color: '#000',
                padding: '0.35rem 0.6rem',
                gap: '0.6rem',
              }}
              data-testid={`${TEST_ID}-${slug}-${index}`}
            >
              <span className="text-break">{value}</span>
              <button
                type="button"
                className="btn btn-outline-danger p-0"
                style={{ lineHeight: 1, width: '1.4rem', height: '1.4rem' }}
                aria-label={`Remove ${value}`}
                data-testid={`${TEST_ID}-remove-${slug}-${index}-button`}
                onClick={() => onChange(values.filter((_, i) => i !== index))}
              >
                <i className="fas fa-trash" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="input-group">
        <input
          id={inputId}
          type="text"
          className={`form-control${addError ? ' is-invalid' : ''}`}
          placeholder={placeholder}
          value={draft}
          disabled={full}
          data-testid={inputId}
          onChange={e => {
            setDraft(e.target.value);
            setAddError(null);
          }}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
        />
        <button
          type="button"
          className="btn btn-outline-secondary"
          disabled={full || !draft.trim()}
          data-testid={`${TEST_ID}-add-${slug}-button`}
          onClick={add}
        >
          Add
        </button>
      </div>
      {addError && (
        <div className="invalid-feedback d-block" data-testid={`${inputId}-error`}>
          {addError}
        </div>
      )}
      {errors.map(message => (
        <div
          key={message}
          className="invalid-feedback d-block"
          data-testid={`${TEST_ID}-${slug}s-error`}
        >
          {message}
        </div>
      ))}
      <small className="form-text text-muted">{hint}</small>
    </div>
  );
};

interface PinnedServerProps {
  strategy?: DeclarationStrategy;
}

/** The authorization server a derived declaration names, or why it names none. */
const PinnedServer: React.FC<PinnedServerProps> = ({ strategy }) => {
  if (!strategy) return <>Select a JWT verification strategy.</>;
  const pin = strategyPin(strategy);
  if (pin.state === 'pinned') {
    return <code className="text-break">{pin.issuer}</code>;
  }
  if (pin.state === 'static_jwks') {
    return <>The strategy uses static keys, so no authorization server is declared.</>;
  }
  return (
    <>
      {pin.state === 'not_pinned'
        ? 'The strategy has no pinned authorization server. '
        : 'The pinned authorization server no longer matches the strategy. '}
      <AddResourceLink
        to={`/jwt-verification-strategies/${encodeURIComponent(strategy.id)}`}
        testid={`${TEST_ID}-strategy-link`}
      >
        Run Discover on the strategy
      </AddResourceLink>
    </>
  );
};

interface DerivedDeclarationProps {
  config: Record<string, unknown>;
  updateFields: (fields: Record<string, unknown>) => void;
  servesCard: boolean;
  strategy?: DeclarationStrategy;
  accessPointUrl?: string | null;
  saved: boolean;
}

/**
 * What a derived declaration publishes: the strategy's pinned authorization
 * server, the required scopes and the Access Point URL tokens must name as
 * their audience. Never a token or a secret.
 */
const DerivedDeclaration: React.FC<DerivedDeclarationProps> = ({
  config,
  updateFields,
  servesCard,
  strategy,
  accessPointUrl,
  saved,
}) => {
  const scopes = readRequiredScopes(config);
  const audiences = Array.isArray(config.audiences) ? (config.audiences as string[]) : [];
  const listed = !!accessPointUrl && audiences.includes(accessPointUrl);
  const notes = derivedDeclarationNotes(config, accessPointUrl);
  const listedRef = useRef<HTMLSpanElement>(null);
  const [focusListed, setFocusListed] = useState(false);
  useEffect(() => {
    if (!focusListed || !listed) return;
    listedRef.current?.focus();
    setFocusListed(false);
  }, [focusListed, listed]);
  const addAudience = () => {
    if (!accessPointUrl) return;
    setFocusListed(true);
    updateFields({ audiences: [...audiences, accessPointUrl] });
  };
  const heading = servesCard
    ? 'What the agent card declares'
    : 'What the protected resource metadata declares';

  return (
    <div className="mb-3" data-testid={`${TEST_ID}-derived`}>
      <span className="form-label fw-bold d-block mb-1">{heading}</span>
      {scopes.length === 0 ? (
        <small className="form-text text-muted d-block" data-testid={`${TEST_ID}-derived-off`}>
          Add a required scope to declare this Access Point&apos;s authorization server. Until then
          it declares none.
        </small>
      ) : (
        <>
          <dl className="row mb-1 small">
            <dt className="col-sm-4">Authorization server</dt>
            <dd className="col-sm-8" data-testid={`${TEST_ID}-derived-authorization-server`}>
              <PinnedServer strategy={strategy} />
            </dd>
            <dt className="col-sm-4">Scopes</dt>
            <dd className="col-sm-8" data-testid={`${TEST_ID}-derived-scopes`}>
              <code className="text-break">{scopes.join(' ')}</code>
            </dd>
            <dt className="col-sm-4">Audience</dt>
            <dd className="col-sm-8" data-testid={`${TEST_ID}-derived-audience`}>
              {accessPointUrl ? (
                <>
                  <code className="text-break d-block">{accessPointUrl}</code>
                  <span role="status" data-testid={`${TEST_ID}-audience-status`}>
                    {listed && (
                      <span
                        ref={listedRef}
                        tabIndex={-1}
                        data-testid={`${TEST_ID}-audience-listed`}
                      >
                        Listed in Accepted Audiences.
                      </span>
                    )}
                  </span>
                  {!listed && (
                    <button
                      type="button"
                      className="btn btn-outline-secondary btn-sm mt-1"
                      data-testid={`${TEST_ID}-add-audience-button`}
                      onClick={addAudience}
                    >
                      <i className="fas fa-plus me-1" aria-hidden="true" />
                      Add to Accepted Audiences
                    </button>
                  )}
                </>
              ) : accessPointUrl === null ? (
                'The gateway reports no https URL for this Access Point, so it declares nothing.'
              ) : saved ? (
                'The Access Point URL is not available from the gateway yet.'
              ) : (
                'The Access Point URL is shown after the first save.'
              )}
            </dd>
          </dl>
          <div role="status">
            {notes.length > 0 && (
              <div
                className="alert alert-warning py-1 px-2 mb-0 small"
                data-testid={`${TEST_ID}-derived-notes`}
              >
                <ul className="mb-0 ps-3">
                  {notes.map(note => (
                    <li key={note.code} data-testid={`${TEST_ID}-derived-note-${note.code}`}>
                      {note.message}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export interface CallerAuthDiscoverySectionProps {
  config: Record<string, unknown>;
  updateFields: (fields: Record<string, unknown>) => void;
  protocol?: Protocol;
  allNodes?: CanvasNode[];
  hasAttemptedSave?: boolean;
  /** The selected JWT verification strategy, when known. */
  strategy?: DeclarationStrategy;
  /**
   * The Access Point URL the gateway reported for the route edited: null when
   * it reported none, undefined while it is not read.
   */
  accessPointUrl?: string | null;
  /** True once the surface has been saved, so the gateway can report its declaration. */
  saved?: boolean;
}

/**
 * The caller-auth declaration of a JWT Bearer Access Point on an A2A, AP2 or
 * MCP surface: the required scopes, what a derived declaration publishes and,
 * on MCP, the explicit authorization server discovery setting with the rules
 * the gateway enforces while it is on.
 */
const CallerAuthDiscoverySection: React.FC<CallerAuthDiscoverySectionProps> = ({
  config,
  updateFields,
  protocol,
  allNodes,
  hasAttemptedSave,
  strategy,
  accessPointUrl,
  saved = false,
}) => {
  const meta = useOptionalSurfaceMeta();
  const setting = readProtectedResource(config.protected_resource);
  const accessPoint = allNodes?.find(n => n.type === 'access-point')?.config ?? {};
  const route: unknown = accessPoint.route;
  const suggested = suggestedResource(accessPoint.listen_address, route);
  const alias = meta?.activeVariantAlias;
  const isDefaultVariant = !!alias && !!meta?.activeVariantIsDefault;
  const saveError = discoverySaveError(meta?.saveError, setting?.resource);
  const strategyIssuer = strategy?.expected_issuer;
  const offersExplicit = protocol === 'mcp' || !!setting;

  const update = (next: ProtectedResourceSetting) => updateFields({ protected_resource: next });
  const toggle = (on: boolean) =>
    updateFields(
      on
        ? {
            protected_resource: {
              resource: suggested,
              authorization_servers: strategyIssuer ? [strategyIssuer] : [],
              scopes: [],
            },
            audiences: [],
            jwt_forward_header: false,
            jwt_token_header: 'Authorization',
            jwt_token_scheme: 'Bearer',
          }
        : { protected_resource: null }
    );

  const problems = setting && hasAttemptedSave ? discoveryProblems(config, strategyIssuer) : [];
  const errorsFor = (field: string) => problems.filter(p => p.field === field).map(p => p.message);
  const resourceErrors = errorsFor(DISCOVERY_FIELDS.resource);
  if (
    setting &&
    hasAttemptedSave &&
    resourceErrors.length === 0 &&
    resourceMissesRoute(setting.resource, route)
  ) {
    resourceErrors.push(`The resource path must be the Access Point route: ${String(route)}`);
  }
  const ruleErrors = errorsFor(DISCOVERY_FIELDS.rules);

  return (
    <div className="mb-3" data-testid={TEST_ID}>
      {declaresOn(protocol) && (
        <ScopesInput
          scopes={readRequiredScopes(config)}
          onChange={required_scopes => updateFields({ required_scopes })}
        />
      )}

      {declaresOn(protocol) && !setting && (
        <DerivedDeclaration
          config={config}
          updateFields={updateFields}
          servesCard={protocol !== 'mcp'}
          strategy={strategy}
          accessPointUrl={accessPointUrl}
          saved={saved}
        />
      )}

      {offersExplicit && (
        <div data-testid={`${TEST_ID}-explicit`}>
          <Form.Check
            type="switch"
            id={`${TEST_ID}-switch`}
            className="mb-1"
            data-testid={`${TEST_ID}-switch`}
            checked={!!setting}
            onChange={e => toggle(e.target.checked)}
            label={
              <span className="d-flex align-items-center gap-1 fw-bold">
                Authorization server discovery
                <FieldHelp
                  testId={`field-help-${TEST_ID}`}
                  ariaLabel="About authorization server discovery"
                >
                  Publishes protected resource metadata (RFC 9728) naming the authorization servers
                  that issue tokens for this Access Point, so an MCP client finds where to get one.
                </FieldHelp>
              </span>
            }
          />
          <small className="form-text text-muted d-block mb-2">
            Tells MCP clients which authorization servers issue tokens for this Access Point.
          </small>

          {saveError && (
            <div
              className="alert alert-danger py-2 px-3 mb-2"
              role="alert"
              data-testid={`${TEST_ID}-save-error`}
            >
              <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
              {saveError}
            </div>
          )}

          {setting && (
            <>
              <InfoBanner
                className="mb-3"
                title="What changes while discovery is on"
                testIdPrefix={TEST_ID}
                summary={
                  <ul className="mb-0 ps-3">
                    <li>
                      The gateway publishes the metadata at{' '}
                      <code>/.well-known/oauth-protected-resource</code> followed by the route, on
                      this Access Point&apos;s listener. A caller without a valid token gets{' '}
                      <code>401</code> with a <code>WWW-Authenticate</code> challenge pointing at
                      it.
                    </li>
                    <li>
                      A token is accepted only when its audience (<code>aud</code>) is the resource
                      URL, so Accepted Audiences stay empty.
                    </li>
                    <li>
                      The token must arrive in the <code>Authorization</code> header with the{' '}
                      <code>Bearer</code> scheme, and it is never forwarded to the managed agent.
                    </li>
                    <li>
                      The JWT verification strategy still checks every token, so the authorization
                      servers must be exactly its expected issuer, or the save is refused.
                    </li>
                    <li>
                      Required Scopes are enforced: the challenge names them, and a token short of
                      one gets <code>403</code> with <code>insufficient_scope</code>. The metadata
                      lists them in <code>scopes_supported</code>, followed by the advertised scopes
                      below, which are not enforced.
                    </li>
                  </ul>
                }
              />

              {ruleErrors.length > 0 && (
                <div
                  className="alert alert-danger py-2 px-3 mb-2"
                  data-testid={`${TEST_ID}-rules-error`}
                >
                  {ruleErrors.map(message => (
                    <div key={message}>{message}</div>
                  ))}
                </div>
              )}

              <div className="mb-3">
                <div className="d-flex align-items-center gap-1 mb-1">
                  <label htmlFor={`${TEST_ID}-resource-input`} className="form-label fw-bold mb-0">
                    Resource URL <span className="text-danger">*</span>
                  </label>
                  <FieldHelp
                    testId={`field-help-${TEST_ID}-resource`}
                    ariaLabel="About Resource URL"
                  >
                    The canonical https URL of this Access Point: a public URL of its listener
                    followed by its route exactly, for example{' '}
                    <code>https://gateway.example/mcp/alpha</code>. The gateway refuses a resource
                    another surface or MCP Proxy already serves.
                  </FieldHelp>
                </div>
                <div className="input-group">
                  <input
                    id={`${TEST_ID}-resource-input`}
                    type="text"
                    className={`form-control${resourceErrors.length > 0 ? ' is-invalid' : ''}`}
                    placeholder={suggested || 'https://gateway.example/mcp/route'}
                    value={setting.resource}
                    data-testid={`${TEST_ID}-resource-input`}
                    onChange={e => update({ ...setting, resource: e.target.value.trim() })}
                  />
                  {suggested && suggested !== setting.resource && (
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      data-testid={`${TEST_ID}-use-listener-url-button`}
                      onClick={() => update({ ...setting, resource: suggested })}
                    >
                      Use listener URL
                    </button>
                  )}
                </div>
                {resourceErrors.map(message => (
                  <div
                    key={message}
                    className="invalid-feedback d-block"
                    data-testid={`${TEST_ID}-resource-error`}
                  >
                    {message}
                  </div>
                ))}
                <small className="form-text text-muted">
                  Callers&apos; tokens must name this URL as their audience.
                </small>
              </div>

              {alias && (
                <div className="mb-3">
                  <span className="form-label fw-bold d-block mb-1">Resource of this variant</span>
                  <code className="text-break" data-testid={`${TEST_ID}-variant-resource`}>
                    {variantResource(setting.resource || '<resource>', alias)}
                  </code>
                  {isDefaultVariant ? (
                    <small
                      className="form-text text-muted d-block"
                      data-testid={`${TEST_ID}-default-variant-note`}
                    >
                      As the default variant, it also answers on the surface&apos;s route, where it
                      advertises the resource above as written. On <code>${alias}</code> it
                      advertises the resource with <code>${alias}</code> appended. Each accepts only
                      tokens issued for the resource of the route called. Its discovery setting is
                      its own.
                    </small>
                  ) : (
                    <small className="form-text text-muted d-block">
                      This variant advertises the resource with <code>${alias}</code> appended and
                      accepts only tokens issued for it. Its discovery setting is its own.
                    </small>
                  )}
                </div>
              )}

              <DiscoveryValueList
                slug="authorization-server"
                noun="authorization server"
                label="Authorization Servers"
                required
                help={
                  <>
                    Issuer identifiers (RFC 8414) of the servers that issue tokens for this
                    resource: https URLs without credentials, query or fragment. They are advertised
                    exactly as written, since clients compare them byte for byte with the issuer in
                    the server&apos;s own metadata.
                  </>
                }
                hint={`1 to ${MAX_AUTHORIZATION_SERVERS}. Press Enter to add.`}
                placeholder="https://idp.example/realms/agents"
                values={setting.authorization_servers}
                max={MAX_AUTHORIZATION_SERVERS}
                problemOf={authorizationServerProblem}
                errors={errorsFor(DISCOVERY_FIELDS.authorizationServers)}
                onChange={authorization_servers => update({ ...setting, authorization_servers })}
              />

              <DiscoveryValueList
                slug="scope"
                noun="scope"
                label="Advertised Scopes"
                help={
                  <>
                    Further OAuth scopes advertised to clients in <code>scopes_supported</code>,
                    after the required scopes. The gateway does not enforce them.
                  </>
                }
                hint="Optional. Press Enter to add."
                placeholder="tools"
                values={setting.scopes}
                problemOf={scopeProblem}
                errors={errorsFor(DISCOVERY_FIELDS.scopes)}
                onChange={scopes => update({ ...setting, scopes })}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default CallerAuthDiscoverySection;
