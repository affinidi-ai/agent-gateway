import React from 'react';
import type { ConfigPanelProps } from '../types';
import {
  CALLER_AUTH_METHOD_OPTIONS,
  type CallerAuthMethodType,
  isSelectableCallerAuthMethod,
} from './methodOptions';
import CallerAuthMethodFields from './CallerAuthMethodFields';
import CallerAuthAdditionalMethods from './CallerAuthAdditionalMethods';
import { defaultMethodConfig } from './methods';

/**
 * Fullscreen editor for the Caller Auth canvas element. Mirrors the
 * field layout the AP-side "Caller Authentication" editor used to
 * provide — JWT strategy dropdown, audience chips, HTTP/protocol
 * extraction radios, mTLS certificate dropdown — but writes to the
 * caller-auth element's flat config shape (`method_type`,
 * `jwt_strategy_id`, `audiences`, `extraction_source`,
 * `extraction_field`, `api_key_secret_id`, `mtls_certificate_id`), with
 * further methods under `additional_methods`. `buildPayload` in
 * `./definition.ts` reshapes those into the runtime `SourceAuthConfig`
 * wire format.
 */
const CallerAuthFullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  allNodes,
  closeFullscreenEditor,
  hasAttemptedSave,
}) => {
  const method: CallerAuthMethodType = (config.method_type as CallerAuthMethodType) || 'jwt_bearer';

  const setType = (newType: CallerAuthMethodType) => {
    if (!isSelectableCallerAuthMethod(newType)) return;
    updateFields({
      ...defaultMethodConfig(newType, config),
      ...(newType === 'jwt_bearer' ? {} : { protected_resource: null }),
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
        <div className="mb-4">
          <label htmlFor="caller-auth-mode-select" className="form-label fw-bold">
            Authentication Method
          </label>
          <select
            id="caller-auth-mode-select"
            className="form-control dropdown-styling"
            value={method}
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
          config={config}
          updateField={updateField}
          updateFields={updateFields}
          protocol={protocol}
          allNodes={allNodes}
          hasAttemptedSave={hasAttemptedSave}
          idPrefix="caller-auth"
          allowDiscovery
        />

        <CallerAuthAdditionalMethods
          config={config}
          updateField={updateField}
          updateFields={updateFields}
          protocol={protocol}
          allNodes={allNodes}
          hasAttemptedSave={hasAttemptedSave}
        />
      </div>
    </div>
  );
};

export default CallerAuthFullscreen;
