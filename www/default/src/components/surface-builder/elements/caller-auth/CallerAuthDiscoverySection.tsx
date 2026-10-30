import React, { useEffect, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import AddResourceLink from '../../../shared/AddResourceLink';
import FieldHelp from '../../../shared/FieldHelp';
import InfoBanner from '../../../shared/InfoBanner';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import type { CanvasNode, Protocol } from '../types';
import {
  DISCOVERY_FIELDS,
  advertisedScopes,
  declaredAudience,
  declaresOn,
  derivedAuthorizationServer,
  discoveryProblems,
  discoverySaveError,
  discoverySaveErrorField,
  readProtectedResource,
  resourceMissesRoute,
  rootVariantProblem,
  strategyPin,
  suggestedResource,
  variantResource,
  withoutStoredAuthorizationServers,
  withoutStoredScopes,
  type DeclarationStrategy,
  type DiscoveryField,
  type ProtectedResourceSetting,
} from './protectedResource';
import ScopesInput from './ScopesInput';
import { readRequiredScopes } from './scopes';

const TEST_ID = 'caller-auth-discovery';

function unique(messages: string[]): string[] {
  return Array.from(new Set(messages));
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

/** What turning discovery on removed from the JWT Bearer settings, or null when nothing. */
function clearedMessage(audiences: number, forwarded: boolean): string | null {
  const removed = audiences > 0 ? `Removed ${plural(audiences, 'accepted audience')}` : null;
  if (removed && forwarded) {
    return `${removed} and turned token forwarding off: tokens must now name the resource URL.`;
  }
  if (removed) return `${removed}: tokens must now name the resource URL.`;
  if (forwarded) {
    return "Turned token forwarding off: the caller's token never reaches the managed agent.";
  }
  return null;
}

interface PinnedServerProps {
  strategy?: DeclarationStrategy;
}

/** Whether the agent card can name the strategy's pinned authorization server, and why not. */
const PinnedServer: React.FC<PinnedServerProps> = ({ strategy }) => {
  if (!strategy) return <>Select a JWT verification strategy.</>;
  const pin = strategyPin(strategy);
  if (pin.state === 'pinned') {
    return <code className="text-break">{pin.issuer}</code>;
  }
  if (pin.state === 'static_jwks') {
    return <>The strategy uses static keys, so the agent card names no security scheme.</>;
  }
  return (
    <>
      {pin.state === 'not_pinned'
        ? 'The strategy has no pinned authorization server, so the agent card names no security scheme. '
        : 'The pinned authorization server no longer matches the strategy, so the agent card names no security scheme. '}
      <AddResourceLink
        to={`/jwt-verification-strategies/${encodeURIComponent(strategy.id)}`}
        testid={`${TEST_ID}-strategy-link`}
      >
        Run Discover on the strategy
      </AddResourceLink>
    </>
  );
};

interface DerivedValuesProps {
  setting: ProtectedResourceSetting;
  requiredScopes: string[];
  servesCard: boolean;
  alias?: string;
  strategy?: DeclarationStrategy;
  strategyName?: string;
}

/**
 * What callers are told while discovery is on: the strategy's issuer, the
 * advertised scopes and the audience tokens must name. Never a token or a secret.
 */
const DerivedValues: React.FC<DerivedValuesProps> = ({
  setting,
  requiredScopes,
  servesCard,
  alias,
  strategy,
  strategyName,
}) => {
  const server = derivedAuthorizationServer(strategy);
  const scopes = advertisedScopes(requiredScopes, setting.scopes);
  const hasExtraScopes = (setting.scopes?.length ?? 0) > 0;
  const audience = setting.resource ? declaredAudience(setting.resource, alias) : '';

  return (
    <div className="mb-3">
      <span className="form-label fw-bold d-block mb-1">What callers are told</span>
      <dl className="row mb-0 small" data-testid={`${TEST_ID}-derived`}>
        <dt className="col-sm-4">Authorization server</dt>
        <dd className="col-sm-8">
          {server.value ? (
            <code className="text-break" data-testid={`${TEST_ID}-derived-authorization-server`}>
              {server.value}
            </code>
          ) : (
            <span data-testid={`${TEST_ID}-derived-authorization-server`}>
              Select a JWT verification strategy.
            </span>
          )}
          {server.source === 'strategy' && strategy && (
            <span
              className="d-block text-muted"
              data-testid={`${TEST_ID}-derived-authorization-server-source`}
            >
              From the JWT verification strategy {strategyName || strategy.id}
            </span>
          )}
        </dd>
        <dt className="col-sm-4">Scopes</dt>
        <dd className="col-sm-8">
          {scopes.length > 0 ? (
            <code className="text-break" data-testid={`${TEST_ID}-derived-scopes`}>
              {scopes.join(' ')}
            </code>
          ) : (
            <span data-testid={`${TEST_ID}-derived-scopes`}>None required</span>
          )}
          <span className="d-block text-muted" data-testid={`${TEST_ID}-derived-scopes-source`}>
            From Required Scopes{hasExtraScopes ? ' and stored extra scopes' : ''}.
            {scopes.length === 0 && ' Callers without a valid token are still refused.'}
          </span>
        </dd>
        <dt className="col-sm-4">Audience</dt>
        <dd className="col-sm-8">
          {audience ? (
            <code className="text-break" data-testid={`${TEST_ID}-derived-audience`}>
              {audience}
            </code>
          ) : (
            <span data-testid={`${TEST_ID}-derived-audience`}>Enter the resource URL</span>
          )}
          <span className="d-block text-muted" data-testid={`${TEST_ID}-derived-audience-source`}>
            The resource URL. A token is accepted when this is one of its <code>aud</code> values.
          </span>
        </dd>
        {servesCard && (
          <>
            <dt className="col-sm-4">Agent card security scheme</dt>
            <dd className="col-sm-8" data-testid={`${TEST_ID}-card-pin`}>
              <PinnedServer strategy={strategy} />
            </dd>
          </>
        )}
      </dl>
    </div>
  );
};

interface StoredOverridesProps {
  setting: ProtectedResourceSetting;
  serverErrors: string[];
  scopeErrors: string[];
  update: (next: ProtectedResourceSetting) => void;
}

/**
 * Lists a stored setting carries beyond its resource. The gateway advertises
 * the strategy's issuer and the required scopes without them, so each can be
 * removed; until then a save sends it back unchanged.
 */
const StoredOverrides: React.FC<StoredOverridesProps> = ({
  setting,
  serverErrors,
  scopeErrors,
  update,
}) => {
  const servers = setting.authorization_servers;
  const scopes = setting.scopes ?? [];
  if (
    servers === undefined &&
    scopes.length === 0 &&
    serverErrors.length === 0 &&
    scopeErrors.length === 0
  ) {
    return null;
  }

  return (
    <div className="mb-3 small" data-testid={`${TEST_ID}-stored-overrides`}>
      {servers !== undefined && (
        <div className="mb-2">
          <span className="d-block">
            This surface stores its authorization server as{' '}
            {servers.length > 0 ? (
              <code className="text-break">{servers.join(' ')}</code>
            ) : (
              'an empty list'
            )}
            . Saving keeps it until you remove it.
          </span>
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm mt-1"
            data-testid={`${TEST_ID}-clear-authorization-servers-button`}
            onClick={() => update(withoutStoredAuthorizationServers(setting))}
          >
            Use the strategy&apos;s issuer
          </button>
        </div>
      )}
      {serverErrors.map(message => (
        <div
          key={message}
          className="invalid-feedback d-block"
          data-testid={`${TEST_ID}-authorization-servers-error`}
        >
          {message}
        </div>
      ))}
      {scopes.length > 0 && (
        <div className="mb-2">
          <span className="d-block">
            This surface also advertises <code className="text-break">{scopes.join(' ')}</code>,
            which the gateway does not enforce.
          </span>
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm mt-1"
            data-testid={`${TEST_ID}-clear-scopes-button`}
            onClick={() => update(withoutStoredScopes(setting))}
          >
            Advertise required scopes only
          </button>
        </div>
      )}
      {scopeErrors.map(message => (
        <div
          key={message}
          className="invalid-feedback d-block"
          data-testid={`${TEST_ID}-scopes-error`}
        >
          {message}
        </div>
      ))}
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
  /** The selected strategy's name, shown as the source of the authorization server. */
  strategyName?: string;
  /** True once the surface has been saved, so turning discovery off warns what a save changes. */
  saved?: boolean;
}

/**
 * Authorization server discovery of a JWT Bearer Access Point on an A2A, AP2
 * or MCP surface: the required scopes, the one switch that writes
 * `caller_authentication.protected_resource`, its resource URL, and what the
 * gateway then tells callers, derived from the strategy and the required scopes.
 */
const CallerAuthDiscoverySection: React.FC<CallerAuthDiscoverySectionProps> = ({
  config,
  updateFields,
  protocol,
  allNodes,
  hasAttemptedSave,
  strategy,
  strategyName,
  saved = false,
}) => {
  const meta = useOptionalSurfaceMeta();
  const setting = readProtectedResource(config.protected_resource);
  const on = setting !== null;
  const accessPoint = allNodes?.find(n => n.type === 'access-point')?.config ?? {};
  const route: unknown = accessPoint.route;
  const suggested = suggestedResource(accessPoint.listen_address, route);
  const alias = meta?.activeVariantAlias;
  const isDefaultVariant = !!alias && !!meta?.activeVariantIsDefault;
  const servesCard = protocol !== 'mcp';
  const requiredScopes = readRequiredScopes(config);
  const offersSwitch = declaresOn(protocol) || on;

  const [storedOn] = useState(on);
  const [focusResource, setFocusResource] = useState(false);
  const [cleared, setCleared] = useState<string | null>(null);
  const resourceRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!focusResource || !on) return;
    resourceRef.current?.focus();
    setFocusResource(false);
  }, [focusResource, on]);

  const update = (next: ProtectedResourceSetting) => updateFields({ protected_resource: next });
  const toggle = (turnOn: boolean) => {
    if (!turnOn) {
      setCleared(null);
      updateFields({ protected_resource: null });
      return;
    }
    const audiences = Array.isArray(config.audiences) ? config.audiences.length : 0;
    setCleared(clearedMessage(audiences, config.jwt_forward_header === true));
    setFocusResource(true);
    updateFields({
      protected_resource: { resource: suggested },
      audiences: [],
      jwt_forward_header: false,
      jwt_token_header: 'Authorization',
      jwt_token_scheme: 'Bearer',
    });
  };

  const saveError = discoverySaveError(meta?.saveError, setting?.resource);
  const saveField = saveError ? discoverySaveErrorField(saveError) : null;
  const alertError =
    saveError && (!on || saveField === 'rules' || saveField === null) ? saveError : null;
  const problems =
    on && hasAttemptedSave ? discoveryProblems(config, strategy?.expected_issuer) : [];
  const errorsFor = (field: DiscoveryField): string[] =>
    unique([
      ...problems.filter(p => p.field === DISCOVERY_FIELDS[field]).map(p => p.message),
      ...(saveError && !alertError && saveField === field ? [saveError] : []),
    ]);

  const rootProblem = on ? rootVariantProblem(route, alias) : null;
  const resourceProblems = errorsFor('resource');
  if (
    setting &&
    hasAttemptedSave &&
    !rootProblem &&
    resourceProblems.length === 0 &&
    resourceMissesRoute(setting.resource, route)
  ) {
    resourceProblems.push(`The resource path must be the Access Point route: ${String(route)}`);
  }
  const resourceErrors = unique([...(rootProblem ? [rootProblem] : []), ...resourceProblems]);
  const ruleErrors = errorsFor('rules');

  return (
    <div className="mb-3" data-testid={TEST_ID}>
      {declaresOn(protocol) && (
        <ScopesInput
          scopes={requiredScopes}
          onChange={required_scopes => updateFields({ required_scopes })}
        />
      )}

      {offersSwitch && (
        <div data-testid={`${TEST_ID}-explicit`}>
          <Form.Check
            type="switch"
            id={`${TEST_ID}-switch`}
            className="mb-1"
            data-testid={`${TEST_ID}-switch`}
            aria-describedby={`${TEST_ID}-switch-help`}
            checked={on}
            onChange={e => toggle(e.target.checked)}
            label={
              <span className="d-flex align-items-center gap-1 fw-bold">
                Authorization server discovery
                <FieldHelp
                  testId={`field-help-${TEST_ID}`}
                  ariaLabel="About authorization server discovery"
                >
                  Publishes protected resource metadata (RFC 9728) naming the authorization server
                  of the selected JWT verification strategy and the required scopes, and answers a
                  caller without a valid token with a challenge, so a client finds where to get a
                  token.
                </FieldHelp>
              </span>
            }
          />
          <small
            id={`${TEST_ID}-switch-help`}
            className="form-text text-muted d-block mb-2"
            data-testid={`${TEST_ID}-switch-help`}
          >
            {servesCard
              ? "Declares the authorization server and scopes in the agent card's security scheme, publishes protected resource metadata (RFC 9728) for this route, and answers a caller without a valid token with a 401 challenge that points at it."
              : 'Publishes protected resource metadata (RFC 9728) for this route and answers a caller without a valid token with a 401 challenge that points at it, so MCP clients find the authorization server.'}
          </small>

          {alertError && (
            <div
              className="alert alert-danger py-2 px-3 mb-2"
              role="alert"
              data-testid={`${TEST_ID}-save-error`}
            >
              <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
              {alertError}
            </div>
          )}

          <div role="status" className="small">
            {on && cleared && (
              <p className="mb-2" data-testid={`${TEST_ID}-cleared`}>
                {cleared}
              </p>
            )}
            {!on && saved && storedOn && (
              <p
                className="alert alert-warning py-1 px-2 mb-2"
                data-testid={`${TEST_ID}-off-warning`}
              >
                When saved, the gateway stops refusing failed callers on this route itself. Make
                sure a policy denies <code>source_auth.method == &quot;failed&quot;</code>.
              </p>
            )}
          </div>

          {!setting && (
            <p className="form-text text-muted mb-2" data-testid={`${TEST_ID}-off-summary`}>
              {servesCard
                ? "Off. The agent card keeps the managed agent's own security and no protected resource metadata is published."
                : 'Off. No protected resource metadata is published.'}{' '}
              A caller whose token is missing, invalid or short of a scope reaches policy as{' '}
              <code>source_auth.method == &quot;failed&quot;</code>: add a policy that denies it.
            </p>
          )}

          {setting && (
            <>
              <InfoBanner
                className="mb-3"
                title="What changes while authorization server discovery is on"
                testIdPrefix={TEST_ID}
                summary={
                  <ul className="mb-0 ps-3">
                    <li>
                      The gateway publishes protected resource metadata at{' '}
                      <code>/.well-known/oauth-protected-resource</code> followed by the route, on
                      this Access Point&apos;s listener.
                    </li>
                    <li>
                      A caller without a valid token gets <code>401</code> with a{' '}
                      <code>WWW-Authenticate</code> challenge pointing at it, and a token short of a
                      required scope gets <code>403</code> with <code>insufficient_scope</code>.
                      This happens before rate limiting, any policy, the AP2 gate and payment,
                      whatever policy allows.
                    </li>
                    <li>
                      A token is accepted when the resource URL is one of its audiences (
                      <code>aud</code>), so Accepted Audiences stay empty.
                    </li>
                    <li>
                      The token must arrive in the <code>Authorization</code> header with the{' '}
                      <code>Bearer</code> scheme, and it is never forwarded to the managed agent.
                    </li>
                    {servesCard && (
                      <li>
                        The agent card served to callers declares the same authorization server and
                        scopes.
                      </li>
                    )}
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
                    <code>https://gateway.example/a2a/buyer</code>. The gateway refuses a resource
                    another surface or MCP Proxy already serves.
                  </FieldHelp>
                </div>
                <div className="input-group">
                  <input
                    ref={resourceRef}
                    id={`${TEST_ID}-resource-input`}
                    type="text"
                    className={`form-control${resourceErrors.length > 0 ? ' is-invalid' : ''}`}
                    placeholder={suggested || 'https://gateway.example/a2a/route'}
                    value={setting.resource}
                    aria-invalid={resourceErrors.length > 0}
                    aria-describedby={
                      resourceErrors.length > 0
                        ? `${TEST_ID}-resource-hint ${TEST_ID}-resource-error`
                        : `${TEST_ID}-resource-hint`
                    }
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
                {resourceErrors.map((message, index) => (
                  <div
                    key={message}
                    id={index === 0 ? `${TEST_ID}-resource-error` : undefined}
                    className="invalid-feedback d-block"
                    data-testid={`${TEST_ID}-resource-error`}
                  >
                    {message}
                  </div>
                ))}
                <small
                  id={`${TEST_ID}-resource-hint`}
                  className="form-text text-muted"
                  data-testid={`${TEST_ID}-resource-hint`}
                >
                  {suggested
                    ? "A public https URL of this Access Point's listener followed by its route. Register it as the API (audience) at the authorization server: callers' tokens must name it."
                    : "This Access Point's listener has no https URL, so there is nothing to suggest. Choose an https listener, or type the https URL callers use for this route; the gateway refuses a resource its listener does not serve."}
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

              <DerivedValues
                setting={setting}
                requiredScopes={requiredScopes}
                servesCard={servesCard}
                alias={alias}
                strategy={strategy}
                strategyName={strategyName}
              />

              <StoredOverrides
                setting={setting}
                serverErrors={errorsFor('authorizationServers')}
                scopeErrors={errorsFor('scopes')}
                update={update}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default CallerAuthDiscoverySection;
