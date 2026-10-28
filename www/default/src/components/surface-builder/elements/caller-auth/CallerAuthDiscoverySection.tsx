import React, { useState } from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import InfoBanner from '../../../shared/InfoBanner';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import type { CanvasNode } from '../types';
import {
  DISCOVERY_FIELDS,
  MAX_AUTHORIZATION_SERVERS,
  authorizationServerProblem,
  discoveryProblems,
  discoverySaveError,
  readProtectedResource,
  resourceMissesRoute,
  scopeProblem,
  suggestedResource,
  variantResource,
  type ProtectedResourceSetting,
} from './protectedResource';

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

export interface CallerAuthDiscoverySectionProps {
  config: Record<string, unknown>;
  updateFields: (fields: Record<string, unknown>) => void;
  allNodes?: CanvasNode[];
  hasAttemptedSave?: boolean;
}

/**
 * Authorization server discovery for an MCP Access Point's JWT Bearer caller
 * authentication: the switch, the resource URL, the authorization servers and
 * the scopes, with the rules the gateway enforces while it is on.
 */
const CallerAuthDiscoverySection: React.FC<CallerAuthDiscoverySectionProps> = ({
  config,
  updateFields,
  allNodes,
  hasAttemptedSave,
}) => {
  const meta = useOptionalSurfaceMeta();
  const setting = readProtectedResource(config.protected_resource);
  const accessPoint = allNodes?.find(n => n.type === 'access-point')?.config ?? {};
  const route: unknown = accessPoint.route;
  const suggested = suggestedResource(accessPoint.listen_address, route);
  const alias = meta?.activeVariantAlias;
  const isDefaultVariant = !!alias && !!meta?.activeVariantIsDefault;
  const saveError = discoverySaveError(meta?.saveError, setting?.resource);

  const update = (next: ProtectedResourceSetting) => updateFields({ protected_resource: next });
  const toggle = (on: boolean) =>
    updateFields(
      on
        ? {
            protected_resource: { resource: suggested, authorization_servers: [], scopes: [] },
            audiences: [],
            jwt_forward_header: false,
            jwt_token_header: 'Authorization',
            jwt_token_scheme: 'Bearer',
          }
        : { protected_resource: null }
    );

  const problems = setting && hasAttemptedSave ? discoveryProblems(config) : [];
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
              Publishes protected resource metadata (RFC 9728) naming the authorization servers that
              issue tokens for this Access Point, so an MCP client finds where to get one.
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
                  <code>/.well-known/oauth-protected-resource</code> followed by the route, on this
                  Access Point&apos;s listener. A caller without a valid token gets <code>401</code>{' '}
                  with a <code>WWW-Authenticate</code> challenge pointing at it.
                </li>
                <li>
                  A token is accepted only when its audience (<code>aud</code>) is the resource URL,
                  so Accepted Audiences stay empty.
                </li>
                <li>
                  The token must arrive in the <code>Authorization</code> header with the{' '}
                  <code>Bearer</code> scheme, and it is never forwarded to the managed agent.
                </li>
                <li>
                  The JWT verification strategy still checks every token, so its expected issuer
                  should be one of the authorization servers.
                </li>
                <li>Scopes are advertised to clients but not enforced.</li>
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
              <FieldHelp testId={`field-help-${TEST_ID}-resource`} ariaLabel="About Resource URL">
                The canonical https URL of this Access Point: a public URL of its listener followed
                by its route exactly, for example <code>https://gateway.example/mcp/alpha</code>.
                The gateway refuses a resource another surface or MCP Proxy already serves.
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
                  advertises the resource above as written. On <code>${alias}</code> it advertises
                  the resource with <code>${alias}</code> appended. Each accepts only tokens issued
                  for the resource of the route called. Its discovery setting is its own.
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
                Issuer identifiers (RFC 8414) of the servers that issue tokens for this resource:
                https URLs without credentials, query or fragment. They are advertised exactly as
                written, since clients compare them byte for byte with the issuer in the
                server&apos;s own metadata.
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
            label="Scopes"
            help={
              <>
                OAuth scopes advertised to clients as <code>scopes_supported</code>. The gateway
                does not enforce them.
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
  );
};

export default CallerAuthDiscoverySection;
