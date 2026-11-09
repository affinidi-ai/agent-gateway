import React from 'react';
import { TRANSPORT_LABELS } from './vtaConnectionHelpers';
import type { VtaTransport, WizardBackend } from './types';

interface BackendStepProps {
  value: WizardBackend;
  bundledAvailable: boolean;
  onChange: (backend: WizardBackend) => void;
}

export const BackendStep: React.FC<BackendStepProps> = ({ value, bundledAvailable, onChange }) => (
  <fieldset>
    <legend className="h6 text-primary">Where should your keys live?</legend>
    <div className="form-check mb-3">
      <input
        className="form-check-input"
        type="radio"
        id="vta-backend-bundled"
        checked={value === 'bundled'}
        disabled={!bundledAvailable}
        onChange={() => onChange('bundled')}
      />
      <label className="form-check-label" htmlFor="vta-backend-bundled">
        <strong>Bundled agent</strong>
        <div className="small text-muted">
          Runs inside this gateway&apos;s deployment unit. Nothing extra to install.{' '}
          <strong>Not a key custody tier</strong> — same host, same operator as the gateway.
          {!bundledAvailable && ' Not available on this deployment.'}
        </div>
      </label>
    </div>
    <div className="form-check">
      <input
        className="form-check-input"
        type="radio"
        id="vta-backend-own"
        checked={value === 'own'}
        onChange={() => onChange('own')}
      />
      <label className="form-check-label" htmlFor="vta-backend-own">
        <strong>Connect my own VTA</strong>
        <div className="small text-muted">
          Self-hosted, in your cloud, or on a device at home. You keep administration of the agent;
          this gateway only ever gets a sign-only grant in one context.
        </div>
      </label>
    </div>
  </fieldset>
);

interface TransportStepProps {
  value: VtaTransport;
  onChange: (transport: VtaTransport) => void;
}

const TRANSPORT_NOTES: Record<VtaTransport, { note: string; enabled: boolean }> = {
  https: {
    note: 'The gateway dials your VTA. Simplest when the agent has an address the gateway can reach.',
    enabled: true,
  },
  didcomm: {
    note: 'Your VTA connects outbound to a mediator and the gateway addresses it by DID. Use this when the agent is behind NAT and has no public address.',
    enabled: true,
  },
  unix: {
    note: 'A socket on this host. Not yet wired.',
    enabled: false,
  },
};

export const TransportStep: React.FC<TransportStepProps> = ({ value, onChange }) => (
  <fieldset>
    <legend className="h6 text-primary">How should the gateway reach it?</legend>
    {(Object.keys(TRANSPORT_NOTES) as VtaTransport[]).map(transport => {
      const { note, enabled } = TRANSPORT_NOTES[transport];
      return (
        <div className="form-check mb-3" key={transport}>
          <input
            className="form-check-input"
            type="radio"
            id={`vta-transport-${transport}`}
            checked={value === transport}
            disabled={!enabled}
            onChange={() => onChange(transport)}
          />
          <label className="form-check-label" htmlFor={`vta-transport-${transport}`}>
            <strong>{TRANSPORT_LABELS[transport]}</strong>
            <div className="small text-muted">{note}</div>
          </label>
        </div>
      );
    })}
  </fieldset>
);
