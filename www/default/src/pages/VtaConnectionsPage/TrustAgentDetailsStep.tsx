import React from 'react';
import type { NewVtaConnection } from './types';

interface Props {
  draft: NewVtaConnection;
  onChange: (draft: NewVtaConnection) => void;
  disabled?: boolean;
}

/** Whether the four things pairing needs have been entered. */
export const detailsComplete = (draft: NewVtaConnection): boolean =>
  draft.name.trim() !== '' &&
  draft.endpoint.trim() !== '' &&
  draft.vta_did.trim() !== '' &&
  draft.default_context_id.trim() !== '';

/**
 * The first wizard step: the four things needed before a trust agent can be paired.
 *
 * The context is **required** here rather than later: pairing refuses without
 * one, because the grant has to be scoped to a single context. Asking for it
 * up front turns a confusing refusal mid-wizard into an ordinary field.
 *
 * No control key is collected — the gateway mints its own per connection, so
 * key material never travels through a form.
 */
export const TrustAgentDetailsStep: React.FC<Props> = ({ draft, onChange, disabled }) => {
  const set = (field: keyof NewVtaConnection) => (value: string) =>
    onChange({ ...draft, [field]: value });

  return (
    <>
      <p className="text-muted">
        Connect your own Verifiable Trust Agent so this gateway can sign through it. You keep
        administration of the agent: the gateway only ever receives a grant for the one context
        named here, never the admin role.
      </p>

      <div className="mb-3">
        <label htmlFor="vta-name">
          Name <span className="text-danger">*</span>
        </label>
        <input
          id="vta-name"
          className="form-control"
          value={draft.name}
          onChange={e => set('name')(e.target.value)}
          placeholder="e.g. Production trust agent"
          disabled={disabled}
          data-testid="wizard-trust-agent-name-input"
        />
      </div>

      <div className="mb-3">
        <label htmlFor="vta-endpoint">
          Address <span className="text-danger">*</span>
        </label>
        <input
          id="vta-endpoint"
          className="form-control"
          value={draft.endpoint}
          onChange={e => set('endpoint')(e.target.value)}
          placeholder="https://vta.example.com"
          disabled={disabled}
          data-testid="wizard-trust-agent-endpoint-input"
        />
        <small className="form-text text-muted">
          Where this gateway reaches the agent. The gateway dials it over HTTPS.
        </small>
      </div>

      <div className="mb-3">
        <label htmlFor="vta-did">
          Agent DID <span className="text-danger">*</span>
        </label>
        <input
          id="vta-did"
          className="form-control"
          value={draft.vta_did}
          onChange={e => set('vta_did')(e.target.value)}
          placeholder="did:webvh:…"
          disabled={disabled}
          data-testid="wizard-trust-agent-did-input"
        />
        <small className="form-text text-muted">
          Pinned at pairing, so a different agent at the same address is refused.
        </small>
      </div>

      <div className="mb-1">
        <label htmlFor="vta-context">
          Context <span className="text-danger">*</span>
        </label>
        <input
          id="vta-context"
          className="form-control"
          value={draft.default_context_id}
          onChange={e => set('default_context_id')(e.target.value)}
          placeholder="e.g. gateway"
          disabled={disabled}
          data-testid="wizard-trust-agent-context-input"
        />
        <small className="form-text text-muted">
          The grant is scoped to this one context — the agent must already have it.
        </small>
      </div>
    </>
  );
};
