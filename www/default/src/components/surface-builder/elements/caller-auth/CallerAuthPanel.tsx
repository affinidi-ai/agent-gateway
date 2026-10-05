import React from 'react';
import { Form } from 'react-bootstrap';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { CALLER_AUTH_METHOD_OPTIONS, isSelectableCallerAuthMethod } from './methodOptions';

/**
 * Compact sidebar panel for the Caller Auth element. Picks the method
 * and defers all method-specific configuration (JWT strategy dropdown,
 * audience chips, mTLS certificate dropdown, etc.) to the fullscreen
 * editor — same pattern the Access Point used before caller-auth was
 * promoted to its own canvas element.
 */
const CallerAuthPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const method = config.method_type || 'jwt_bearer';

  return (
    <>
      <Form.Text className="text-muted d-block mb-1" style={{ fontSize: '10px' }}>
        Extracts and verifies the caller&apos;s identity before any policy or payment gate runs. It
        does not refuse the request on its own: a missing or invalid credential is reported to the
        policy layer as <code>source_auth.method == &quot;failed&quot;</code>. Add a policy that
        denies unverified callers, otherwise the request is forwarded with no asserted identity.
      </Form.Text>
      <InfoBanner
        title="Why does this matter to the rest of the pipeline?"
        icon="fa-circle-info"
        summary={
          <>
            <p>
              This exposes the caller&apos;s context to the rest of the pipeline: used by OPA
              policies (<code>input.source_auth</code>) and by workload binding to populate{' '}
              <code>userIdentity</code> in the outbound / response VP (Verifiable Presentation, a
              signed identity document).
            </p>
            <p>
              Without this, downstream stages only see the agent identity, not the human (or
              service) on whose behalf the call is being made.
            </p>
          </>
        }
      />

      <div className="config-section">
        <label htmlFor="caller-auth-panel-mode-select">Authentication Method</label>
        <Form.Select
          id="caller-auth-panel-mode-select"
          size="sm"
          value={method}
          onChange={e => {
            const nextMethod = e.target
              .value as (typeof CALLER_AUTH_METHOD_OPTIONS)[number]['value'];
            if (isSelectableCallerAuthMethod(nextMethod)) {
              updateField('method_type', nextMethod);
            }
          }}
        >
          {CALLER_AUTH_METHOD_OPTIONS.map(option => (
            <option key={option.value} value={option.value} disabled={option.disabled}>
              {option.label}
            </option>
          ))}
        </Form.Select>
        <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '10px' }}>
          Choose how the gateway checks the identity of whoever calls this agent. Click
          &quot;Configure…&quot; below for details on each option. Default: JWT Bearer, the standard
          choice unless you specifically need an API key or client certificate.
        </Form.Text>
        <button
          className="btn btn-outline-primary btn-sm w-100 mt-2"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
        >
          <i className="fas fa-pen-to-square me-1" /> Configure…
        </button>
      </div>
    </>
  );
};

export default CallerAuthPanel;
