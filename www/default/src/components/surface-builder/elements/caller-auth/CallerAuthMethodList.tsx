import React, { useState } from 'react';
import { CALLER_AUTH_METHOD_OPTIONS, type CallerAuthMethodType } from './methodOptions';
import {
  CALLER_AUTH_METHOD_SHORT_LABEL,
  type CallerAuthConfig,
  type CallerAuthMethodConfig,
  credentialLocation,
  defaultMethodConfig,
  methodProblem,
  readMethods,
} from './methods';
import { readProtectedResource } from './protectedResource';

interface CallerAuthMethodListProps {
  config: CallerAuthConfig;
  updateFields: (fields: Record<string, unknown>) => void;
  /** Opens a method's settings; also called with a method just added. */
  onConfigure: (position: number) => void;
  /** Test id prefix, so the sidebar and editor lists stay distinct. */
  area: 'caller-auth-panel' | 'caller-auth-editor';
  /** Highlights the method whose settings are open. */
  selected?: number;
  /** Shows the Make primary and remove buttons. */
  editable?: boolean;
}

/**
 * The caller-auth element's methods, one row each: whether the method is
 * ready, what it reads, and a Configure button. The first is the primary
 * method, which checks a request carrying no credential, or credentials for
 * several methods, and is the only one that can publish authorization server
 * discovery; while discovery is on, the primary stays primary.
 */
const CallerAuthMethodList: React.FC<CallerAuthMethodListProps> = ({
  config,
  updateFields,
  onConfigure,
  area,
  selected,
  editable = false,
}) => {
  const [adding, setAdding] = useState(false);
  const methods = readMethods(config);
  const discoveryOn =
    methods[0]?.method_type === 'jwt_bearer' &&
    readProtectedResource(config.protected_resource) !== null;
  const setMethods = (next: CallerAuthMethodConfig[], extra: Record<string, unknown> = {}) =>
    updateFields({ methods: next, ...extra });
  const makePrimary = (position: number) => {
    setMethods([methods[position], ...methods.filter((_, index) => index !== position)]);
    if (selected === position) onConfigure(0);
    else if (selected !== undefined && selected < position) onConfigure(selected + 1);
  };
  const remove = (position: number) => {
    setMethods(
      methods.filter((_, index) => index !== position),
      position === 0 ? { protected_resource: null } : {}
    );
    if (selected !== undefined && selected >= position && selected > 0) onConfigure(selected - 1);
  };
  const add = (type: CallerAuthMethodType) => {
    setAdding(false);
    setMethods([...methods, defaultMethodConfig(type)]);
    onConfigure(methods.length);
  };

  return (
    <div data-testid={`${area}-methods`}>
      <ul className="list-group mb-2">
        {methods.map((method, position) => {
          const problem = methodProblem(methods, position);
          const type: CallerAuthMethodType = method.method_type || 'jwt_bearer';
          const rowId = `${area}-method-${position}`;
          return (
            <li
              key={position}
              className={`list-group-item d-flex align-items-center gap-2${
                selected === position ? ' bg-light' : ''
              }`}
              data-testid={rowId}
              aria-current={selected === position ? 'true' : undefined}
            >
              <i
                className={`fas ${
                  problem ? 'fa-circle-exclamation text-warning' : 'fa-circle-check text-success'
                } fa-lg`}
                title={problem ?? 'Ready'}
                aria-label={problem ?? 'Ready'}
                data-testid={`${rowId}-status`}
              />
              <div className="flex-grow-1 text-truncate">
                <div className="fw-bold">
                  {CALLER_AUTH_METHOD_SHORT_LABEL[type]}
                  {position === 0 && methods.length > 1 && (
                    <span
                      className="badge bg-primary ms-2"
                      title="Checks requests that carry no credential, or credentials for several methods"
                    >
                      Primary
                    </span>
                  )}
                  {position === 0 && discoveryOn && (
                    <span className="badge bg-info text-dark ms-2">discovery</span>
                  )}
                </div>
                <small className="text-muted d-block text-truncate">
                  {problem ?? `Reads ${credentialLocation(method)}`}
                </small>
              </div>
              {editable && (
                <div className="d-flex align-items-center gap-1">
                  {position > 0 && (
                    <button
                      type="button"
                      className="btn btn-sm btn-link text-nowrap"
                      title={
                        discoveryOn
                          ? 'Authorization server discovery keeps method 1 primary'
                          : undefined
                      }
                      data-testid={`${rowId}-make-primary-button`}
                      disabled={discoveryOn}
                      onClick={() => makePrimary(position)}
                    >
                      Make primary
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-danger"
                    aria-label={`Remove method ${position + 1}`}
                    data-testid={`${rowId}-remove-button`}
                    disabled={methods.length === 1}
                    onClick={() => remove(position)}
                  >
                    <i className="fas fa-trash" />
                  </button>
                </div>
              )}
              <button
                type="button"
                className="btn btn-sm btn-outline-primary rounded-pill text-nowrap"
                data-testid={`${rowId}-configure-button`}
                onClick={() => onConfigure(position)}
              >
                Configure <span aria-hidden="true">↗</span>
              </button>
            </li>
          );
        })}
      </ul>

      <div className="position-relative">
        <button
          type="button"
          className="btn btn-sm btn-link px-0"
          aria-expanded={adding}
          data-testid={`${area}-add-method-button`}
          onClick={() => setAdding(open => !open)}
        >
          <i className="fas fa-plus me-1" /> Add method
        </button>
        {adding && (
          <div className="dropdown-menu show" data-testid={`${area}-add-method-menu`}>
            {CALLER_AUTH_METHOD_OPTIONS.map(option => (
              <button
                key={option.value}
                type="button"
                className="dropdown-item"
                disabled={option.disabled}
                data-testid={`${area}-add-method-${option.value}`}
                onClick={() => add(option.value)}
              >
                {option.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default CallerAuthMethodList;
