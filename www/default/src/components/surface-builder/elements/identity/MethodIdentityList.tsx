import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import type { CallerAuthMethodConfig } from '../caller-auth/methods';
import {
  methodGetsIdentity,
  methodLabel,
  newMethodIdentity,
  ownIdentityType,
  REFUSED_WITHOUT_OWN_IDENTITY,
  USES_SURFACE_IDENTITY,
} from './sourceMethods';

interface Props {
  /** This inbound Identity's extraction type, the identity of a method that sets none. */
  surfaceType: unknown;
  methods: CallerAuthMethodConfig[];
  onChange: (methods: CallerAuthMethodConfig[]) => void;
}

const OWN_IDENTITY_LABEL = {
  from_jwt_claim: 'From JWT Claims',
  from_api_key: 'From API Key',
} as const;

/**
 * The caller identity of each Caller Context method: this Identity, or the
 * method's own one, read from the credential the method verifies. A method
 * that sets none, whose credential this Identity cannot read, has its callers
 * refused.
 */
const MethodIdentityList: React.FC<Props> = ({ surfaceType, methods, onChange }) => {
  const update = (position: number, patch: Partial<CallerAuthMethodConfig>) =>
    onChange(methods.map((method, i) => (i === position ? { ...method, ...patch } : method)));

  return (
    <div className="config-section" data-testid="identity-panel-method-identities">
      <label className="d-flex align-items-center gap-1">
        Caller identity per method
        <FieldHelp
          testId="field-help-identity-method-identities"
          ariaLabel="About the caller identity per method"
        >
          Each Caller Context method can derive its callers&apos; identity from the credential it
          verifies: a JWT claim, or the API key the caller presents. A method without its own
          identity uses this Identity, and its callers are refused when this Identity cannot read
          its credential.
        </FieldHelp>
      </label>
      {methods.map((method, position) => {
        const testId = `identity-panel-method-identity-${position}`;
        const offered = ownIdentityType(method);
        const own = method.identity?.type === offered ? method.identity : undefined;
        const status = own
          ? null
          : methodGetsIdentity(surfaceType, method)
            ? USES_SURFACE_IDENTITY
            : REFUSED_WITHOUT_OWN_IDENTITY;
        return (
          <div key={position} className="mb-2" data-testid={testId}>
            <Form.Label className="small mb-1" htmlFor={`${testId}-select`}>
              {methodLabel(method, position)}
            </Form.Label>
            {offered ? (
              <Form.Select
                id={`${testId}-select`}
                size="sm"
                className="dropdown-styling"
                data-testid={`${testId}-select`}
                value={own?.type ?? ''}
                onChange={e =>
                  update(position, {
                    identity: e.target.value ? newMethodIdentity(offered) : undefined,
                  })
                }
              >
                <option value="">This Identity</option>
                <option value={offered}>{OWN_IDENTITY_LABEL[offered]}</option>
              </Form.Select>
            ) : null}
            {own?.type === 'from_jwt_claim' && (
              <Form.Control
                size="sm"
                type="text"
                className="mt-1"
                aria-label={`JWT claim of method ${position + 1}`}
                data-testid={`${testId}-claim`}
                placeholder="oid"
                value={own.claim}
                onChange={e => update(position, { identity: { ...own, claim: e.target.value } })}
              />
            )}
            {status && (
              <Form.Text
                className={`d-block ${status === REFUSED_WITHOUT_OWN_IDENTITY ? 'text-danger' : 'text-muted'}`}
                data-testid={`${testId}-status`}
              >
                {status}
              </Form.Text>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default MethodIdentityList;
