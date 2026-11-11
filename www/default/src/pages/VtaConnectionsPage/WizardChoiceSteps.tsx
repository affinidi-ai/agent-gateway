import React from 'react';
import { TRANSPORT_LABELS } from './vtaConnectionHelpers';
import type { VtaTransport } from './types';

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
