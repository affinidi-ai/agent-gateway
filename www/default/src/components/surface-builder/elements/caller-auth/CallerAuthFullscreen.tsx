import React from 'react';
import type { ConfigPanelProps } from '../types';
import {
  CALLER_AUTH_METHOD_OPTIONS,
  type CallerAuthMethodType,
  isSelectableCallerAuthMethod,
} from './methodOptions';
import CallerAuthMethodFields from './CallerAuthMethodFields';
import CallerAuthMethodList from './CallerAuthMethodList';
import { defaultMethodConfig, readMethods } from './methods';
import { useSelectedMethod } from './selectedMethod';

/**
 * Fullscreen editor for the Caller Auth canvas element: the method list,
 * and below it the settings of the method selected there (JWT strategy,
 * audiences, token header and discovery; API key location and secret; DID
 * Auth session token; mTLS certificate). Each method keeps the flat shape
 * `buildMethod` in `./methods.ts` turns into the runtime `SourceAuthConfig`;
 * the discovery setting stays on the element, with the first method.
 */
const CallerAuthFullscreen: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateFields,
  protocol,
  allNodes,
  closeFullscreenEditor,
  hasAttemptedSave,
}) => {
  const methods = readMethods(config);
  const [requested, select] = useSelectedMethod(node.id);
  const position = Math.min(requested, Math.max(methods.length - 1, 0));
  const method = methods[position] ?? {};
  const type: CallerAuthMethodType = method.method_type || 'jwt_bearer';
  const isFirst = position === 0;
  const fieldsConfig = isFirst
    ? { ...method, protected_resource: config.protected_resource }
    : method;

  const patchMethod = (patch: Record<string, unknown>) => {
    const { protected_resource, ...fields } = patch;
    updateFields({
      methods: methods.map((current, index) =>
        index === position ? { ...current, ...fields } : current
      ),
      ...(isFirst && 'protected_resource' in patch ? { protected_resource } : {}),
    });
  };
  const setType = (newType: CallerAuthMethodType) => {
    if (!isSelectableCallerAuthMethod(newType)) return;
    updateFields({
      methods: methods.map((current, index) =>
        index === position ? defaultMethodConfig(newType, current) : current
      ),
      ...(isFirst && newType !== 'jwt_bearer' ? { protected_resource: null } : {}),
    });
  };

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header">
        <div className="d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-key me-2" /> Caller Context Extraction
          </h6>
          {closeFullscreenEditor && (
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={closeFullscreenEditor}
            >
              <i className="fas fa-times me-1" /> Close tab
            </button>
          )}
        </div>
      </div>
      <div className="card-body">
        <h6 className="fw-bold">Authentication methods</h6>
        <p className="text-muted small">
          Accept more than one kind of credential, for example a JWT for internal users and an API
          key for partner agents. The gateway verifies each request with the method whose credential
          it carries. The primary method checks a request that carries none, and a request carrying
          credentials for several methods fails source authentication. Each method must read its own
          header. Policy sees which method verified the caller as{' '}
          <code>input.source_auth.method</code>.
        </p>
        <CallerAuthMethodList
          config={config}
          updateFields={updateFields}
          onConfigure={select}
          area="caller-auth-editor"
          selected={position}
          editable
        />

        {methods.length > 0 && (
          <div className="mt-4 pt-3 border-top" data-testid="caller-auth-editor-method-settings">
            <h6 className="fw-bold mb-3">Method {position + 1} settings</h6>
            <div className="mb-4">
              <label htmlFor="caller-auth-mode-select" className="form-label fw-bold">
                Authentication Method
              </label>
              <select
                id="caller-auth-mode-select"
                className="form-control dropdown-styling"
                value={type}
                onChange={e => setType(e.target.value as CallerAuthMethodType)}
              >
                {CALLER_AUTH_METHOD_OPTIONS.map(option => (
                  <option key={option.value} value={option.value} disabled={option.disabled}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small className="form-text text-muted">
                Select how the Gateway should authenticate incoming requests.
              </small>
            </div>

            <CallerAuthMethodFields
              key={position}
              config={fieldsConfig}
              updateField={(field, value) => patchMethod({ [field]: value })}
              updateFields={patchMethod}
              protocol={protocol}
              allNodes={allNodes}
              hasAttemptedSave={hasAttemptedSave}
              allowDiscovery={isFirst}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default CallerAuthFullscreen;
