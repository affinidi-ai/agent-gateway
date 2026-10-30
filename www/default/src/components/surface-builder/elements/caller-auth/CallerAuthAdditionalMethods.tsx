import React, { useRef } from 'react';
import type { ConfigPanelProps } from '../types';
import {
  CALLER_AUTH_METHOD_OPTIONS,
  type CallerAuthMethodType,
  isSelectableCallerAuthMethod,
} from './methodOptions';
import CallerAuthMethodFields from './CallerAuthMethodFields';
import {
  type CallerAuthMethodConfig,
  allMethodConfigs,
  credentialLocation,
  defaultMethodConfig,
  methodSelectionProblems,
  readAdditionalMethods,
} from './methods';
import { readProtectedResource } from './protectedResource';

const NEW_METHOD_PREFERENCE: CallerAuthMethodType[] = [
  'api_key',
  'jwt_bearer',
  'did_auth',
  'api_key_provider',
];

/** A selectable method whose default credential location is still free. */
function nextMethod(config: CallerAuthMethodConfig): CallerAuthMethodConfig {
  const used = new Set(allMethodConfigs(config).map(credentialLocation));
  const type =
    NEW_METHOD_PREFERENCE.find(
      candidate => !used.has(credentialLocation(defaultMethodConfig(candidate)))
    ) ?? 'api_key';
  return defaultMethodConfig(type);
}

/** The first method's own fields, without the list or its discovery setting. */
function firstMethodFields(config: CallerAuthMethodConfig): CallerAuthMethodConfig {
  const { additional_methods: _list, protected_resource: _discovery, ...fields } = config;
  return fields;
}

/**
 * Stable React keys for the additional methods, so a method keeps its own
 * editor state when the list is reordered or shortened.
 */
function useMethodKeys(count: number) {
  const next = useRef(0);
  const keys = useRef<number[]>([]);
  while (keys.current.length < count) keys.current.push(next.current++);
  if (keys.current.length > count) keys.current = keys.current.slice(0, count);
  return {
    keys: keys.current,
    remove: (position: number) => keys.current.splice(position, 1),
    swap: (position: number, other: number) => {
      [keys.current[position], keys.current[other]] = [keys.current[other], keys.current[position]];
    },
    renew: (position: number) => {
      keys.current[position] = next.current++;
    },
  };
}

type CallerAuthAdditionalMethodsProps = Pick<
  ConfigPanelProps,
  'config' | 'updateField' | 'updateFields' | 'protocol' | 'allNodes' | 'hasAttemptedSave'
>;

/**
 * Methods 2..n of the caller-auth element, stored in `additional_methods`.
 * Their order breaks ties when a request carries more than one method's
 * credential. Method 2 can move up into the first place, swapping with the
 * element's own method, except while authorization server discovery is on.
 */
const CallerAuthAdditionalMethods: React.FC<CallerAuthAdditionalMethodsProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  allNodes,
  hasAttemptedSave,
}) => {
  const extras = readAdditionalMethods(config);
  const methodKeys = useMethodKeys(extras.length);
  const problems = methodSelectionProblems(config);
  const discoveryOn = readProtectedResource(config.protected_resource) !== null;
  const setExtras = (next: CallerAuthMethodConfig[]) => updateField('additional_methods', next);
  const patchExtra = (position: number, patch: Record<string, unknown>) =>
    setExtras(
      extras.map((method, index) =>
        index === position ? ({ ...method, ...patch } as CallerAuthMethodConfig) : method
      )
    );
  const moveUp = (position: number) => {
    if (position === 0) {
      methodKeys.renew(0);
      updateFields({
        ...extras[0],
        protected_resource: null,
        additional_methods: [firstMethodFields(config), ...extras.slice(1)],
      });
      return;
    }
    const next = [...extras];
    [next[position - 1], next[position]] = [next[position], next[position - 1]];
    methodKeys.swap(position - 1, position);
    setExtras(next);
  };
  const remove = (position: number) => {
    methodKeys.remove(position);
    setExtras(extras.filter((_, index) => index !== position));
  };

  return (
    <div className="mt-4 pt-3 border-top" data-testid="caller-auth-additional-methods">
      <h6 className="fw-bold">Additional methods</h6>
      <p className="text-muted small">
        Accept more than one kind of credential on this surface, for example a JWT for internal
        users and an API key for partner agents. The gateway verifies each request with the first
        method, in this order, whose credential the request carries, and never retries a rejected
        credential with another method. Each method must read its own header. Policy sees which
        method verified the caller as <code>input.source_auth.method</code>.
      </p>

      {extras.map((extra, position) => {
        const idPrefix = `caller-auth-extra-${position}`;
        const number = position + 2;
        const type: CallerAuthMethodType = extra.method_type || 'api_key';
        const moveUpBlocked = position === 0 && discoveryOn;
        return (
          <div key={methodKeys.keys[position]} className="card mb-3" data-testid={idPrefix}>
            <div className="card-header d-flex justify-content-between align-items-center">
              <span className="fw-bold">Method {number}</span>
              <div className="btn-group btn-group-sm">
                <button
                  type="button"
                  className="btn btn-outline-secondary"
                  aria-label={`Move method ${number} up`}
                  title={
                    moveUpBlocked
                      ? 'Authorization server discovery keeps JWT Bearer as method 1'
                      : undefined
                  }
                  data-testid={`${idPrefix}-move-up-button`}
                  disabled={moveUpBlocked}
                  onClick={() => moveUp(position)}
                >
                  <i className="fas fa-arrow-up" />
                </button>
                <button
                  type="button"
                  className="btn btn-outline-secondary"
                  aria-label={`Move method ${number} down`}
                  data-testid={`${idPrefix}-move-down-button`}
                  disabled={position === extras.length - 1}
                  onClick={() => moveUp(position + 1)}
                >
                  <i className="fas fa-arrow-down" />
                </button>
                <button
                  type="button"
                  className="btn btn-outline-danger"
                  aria-label={`Remove method ${number}`}
                  data-testid={`${idPrefix}-remove-button`}
                  onClick={() => remove(position)}
                >
                  <i className="fas fa-trash" />
                </button>
              </div>
            </div>
            <div className="card-body">
              <div className="mb-3">
                <label htmlFor={`${idPrefix}-mode-select`} className="form-label fw-bold">
                  Authentication Method
                </label>
                <select
                  id={`${idPrefix}-mode-select`}
                  data-testid={`${idPrefix}-mode-select`}
                  className="form-control dropdown-styling"
                  value={type}
                  onChange={e => {
                    const nextType = e.target.value as CallerAuthMethodType;
                    if (isSelectableCallerAuthMethod(nextType)) {
                      patchExtra(position, defaultMethodConfig(nextType, extra));
                    }
                  }}
                >
                  {CALLER_AUTH_METHOD_OPTIONS.map(option => (
                    <option key={option.value} value={option.value} disabled={option.disabled}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <CallerAuthMethodFields
                config={extra}
                updateField={(field, value) => patchExtra(position, { [field]: value })}
                updateFields={patch => patchExtra(position, patch)}
                protocol={protocol}
                allNodes={allNodes}
                hasAttemptedSave={hasAttemptedSave}
                idPrefix={idPrefix}
                allowDiscovery={false}
              />
            </div>
          </div>
        );
      })}

      {problems.map(problem => (
        <div
          key={problem.message}
          className="invalid-feedback d-block mb-2"
          data-testid="caller-auth-method-selection-error"
        >
          {problem.message}
        </div>
      ))}

      <button
        type="button"
        className="btn btn-outline-primary btn-sm"
        data-testid="caller-auth-add-method-button"
        onClick={() => setExtras([...extras, nextMethod(config)])}
      >
        <i className="fas fa-plus me-1" /> Add method
      </button>
    </div>
  );
};

export default CallerAuthAdditionalMethods;
