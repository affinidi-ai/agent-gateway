import React, { useEffect, useState } from 'react';
import { Badge, Button, Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import type { WorkloadBindingCallerSource, WorkloadBindingFormConfig } from './config';
import FieldHelp from '../../../shared/FieldHelp';

/** Common OIDC/JWT caller claims offered as one-click additions. */
const SUGGESTED_CLAIMS = ['sub', 'email', 'name', 'org'] as const;

const CALLER_SOURCE_OPTIONS: Array<{ value: WorkloadBindingCallerSource; label: string }> = [
  { value: 'transit_token', label: 'Transit token' },
  { value: 'authorization_bearer_jwt', label: 'Authorization bearer JWT' },
  { value: 'did', label: 'DID authentication' },
];

/**
 * Config panel for the per-Transit-Point Workload Binding element.
 *
 * Edits the new Transit-Point-scoped shape only (`enabled`,
 * `caller_source`, `caller_context_fields`, `chain_caller_credentials`).
 * The legacy `agent_fields` / `user_fields` editor has been removed with
 * Credential Delegation's Workload Binding split. Serialization +
 * validation live in `./config`.
 */
const WorkloadBindingPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  errorByField,
}) => {
  const cfg = config as WorkloadBindingFormConfig;
  const enabled = cfg?.enabled === true;
  // The primary-target (MA→EXT) node parents on the Managed Agent (canonical
  // id `target`); a per-Transit-Point node parents on its TP. On the target
  // leg there is no transit token, so caller context always comes from the
  // inbound Authorization bearer JWT.
  const isTargetLeg = node?.parentId === 'target';
  const callerFields: string[] = Array.isArray(cfg?.caller_context_fields)
    ? cfg.caller_context_fields
    : [];
  const [draft, setDraft] = useState('');

  // Force the bearer-JWT source on the target leg (the backend ignores
  // `transit_token` there) so the stored config matches runtime behaviour.
  // `did` is permitted on the target leg because the target-leg builder
  // has access to the authenticated identity.
  useEffect(() => {
    if (
      isTargetLeg &&
      enabled &&
      cfg?.caller_source !== 'authorization_bearer_jwt' &&
      cfg?.caller_source !== 'did'
    ) {
      updateField('caller_source', 'authorization_bearer_jwt');
    }
  }, [isTargetLeg, enabled, cfg?.caller_source, updateField]);

  const callerSourceOptions = isTargetLeg
    ? CALLER_SOURCE_OPTIONS.filter(o => o.value === 'authorization_bearer_jwt' || o.value === 'did')
    : CALLER_SOURCE_OPTIONS;

  const addField = (raw: string) => {
    const name = raw.trim();
    if (!name) return;
    if (callerFields.includes(name)) {
      setDraft('');
      return;
    }
    updateField('caller_context_fields', [...callerFields, name]);
    setDraft('');
  };

  const removeField = (name: string) => {
    updateField(
      'caller_context_fields',
      callerFields.filter(f => f !== name)
    );
  };

  return (
    <>
      <div className="config-section">
        <Form.Check
          type="switch"
          id="workload-binding-enable-toggle"
          data-testid="workload-binding-enable-toggle"
          label={
            <span className="d-flex align-items-center gap-1">
              {isTargetLeg
                ? 'Enable workload binding for this target (MA → External)'
                : 'Enable workload binding for this Transit Point'}
              <FieldHelp
                testId="field-help-workload-binding-enable-workload-binding"
                ariaLabel="About Enable Workload Binding"
              >
                <p>
                  When this is on, the gateway bundles this agent's own identity together with
                  selected details about whoever originally called it (the "caller claims" picked
                  below) into one signed, tamper-proof credential: a VP, or Verifiable Presentation.
                </p>
                <p>
                  That credential is attached to outbound requests, so the next gateway in line can
                  verify exactly which agent, acting on whose behalf, is making this call.
                </p>
              </FieldHelp>
            </span>
          }
          checked={enabled}
          onChange={e => updateField('enabled', e.target.checked)}
        />
      </div>

      {enabled && (
        <>
          <div className="config-section">
            <label>Caller context source</label>
            <Form.Select
              size="sm"
              data-testid="workload-binding-caller-source"
              value={cfg.caller_source}
              disabled={isTargetLeg && callerSourceOptions.length === 1}
              onChange={e =>
                updateField('caller_source', e.target.value as WorkloadBindingCallerSource)
              }
            >
              {callerSourceOptions.map(o => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Form.Select>
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              {cfg.caller_source === 'did'
                ? 'Sources the caller identity from a DID-authenticated session. Requires DID Auth source authentication on this surface; the resolved DID becomes the caller identity and its SHA-256 hash is used as the delegation-vault key.'
                : isTargetLeg
                  ? 'On the MA → External leg the gateway reads caller claims from the inbound Authorization bearer JWT.'
                  : 'Where GW1 reads caller claims from before binding them.'}
            </Form.Text>
          </div>

          <div className="config-section">
            <label>Caller field allowlist</label>
            <Form.Text className="text-muted d-block mb-2" style={{ fontSize: '10px' }}>
              Only these top-level caller claims are copied into the binding. Leave empty to bind no
              caller claims (agent identity only). Nested paths (<code>a.b</code>) are not allowed.
            </Form.Text>

            {callerFields.length > 0 && (
              <div
                className="d-flex flex-wrap gap-1 mb-2"
                data-testid="workload-binding-field-list"
              >
                {callerFields.map(name => (
                  <Badge
                    key={name}
                    bg="secondary"
                    className="d-inline-flex align-items-center"
                    data-testid={`workload-binding-field-${name}`}
                  >
                    {name}
                    <button
                      type="button"
                      className="btn-close btn-close-white ms-1"
                      style={{ fontSize: '8px' }}
                      aria-label={`Remove ${name}`}
                      data-testid={`workload-binding-remove-field-${name}`}
                      onClick={() => removeField(name)}
                    />
                  </Badge>
                ))}
              </div>
            )}

            <div className="d-flex gap-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Claim name (e.g. sub)"
                value={draft}
                data-testid="workload-binding-add-field-input"
                isInvalid={!!errorByField?.caller_context_fields}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addField(draft);
                  }
                }}
              />
              <Button
                size="sm"
                variant="outline-secondary"
                data-testid="workload-binding-add-field-button"
                onClick={() => addField(draft)}
              >
                Add
              </Button>
            </div>
            {errorByField?.caller_context_fields && (
              <div className="text-danger mt-1" style={{ fontSize: '10px' }}>
                {errorByField.caller_context_fields}
              </div>
            )}

            <div className="d-flex flex-wrap gap-1 mt-2">
              {SUGGESTED_CLAIMS.filter(c => !callerFields.includes(c)).map(c => (
                <Button
                  key={c}
                  size="sm"
                  variant="outline-primary"
                  className="py-0"
                  style={{ fontSize: '10px' }}
                  data-testid={`workload-binding-suggest-${c}`}
                  onClick={() => addField(c)}
                >
                  + {c}
                </Button>
              ))}
            </div>
          </div>

          <div className="config-section">
            <Form.Check
              type="switch"
              id="workload-binding-chain-toggle"
              data-testid="workload-binding-chain-toggle"
              label={
                <span className="d-flex align-items-center gap-1">
                  Chain caller-supplied credentials
                  <FieldHelp
                    testId="field-help-workload-binding-chain-caller-supplied-credentials"
                    ariaLabel="About Chain caller-supplied credentials"
                  >
                    <p>
                      If the original caller presented their own signed credential, such as a VC
                      (Verifiable Credential) or VP, when they called in, turn this on to include it
                      inside this agent's own credential bundle.
                    </p>
                    <p>
                      That way the next gateway in line can see the entire chain of
                      who-acted-for-whom, not just this agent's own identity.
                    </p>
                  </FieldHelp>
                </span>
              }
              checked={cfg.chain_caller_credentials === true}
              onChange={e => updateField('chain_caller_credentials', e.target.checked)}
            />
          </div>
        </>
      )}
    </>
  );
};

export default WorkloadBindingPanel;
