import React from 'react';
import { AppButton } from './AppButton';
import { CopyButton } from './CopyButton';
import { topAndTail } from '../../utils/stringUtils';

/** One DID the mediator must admit before the pairing continues. */
export interface MediatorAccessDid {
  role: string;
  label: string;
  did: string;
}

/** The DID the mediator still refuses, from a `409 mediator_access_refused`. */
export interface MediatorAccessRefusal {
  label: string;
  did: string;
}

interface MediatorAccessStepProps {
  dids: MediatorAccessDid[];
  mediatorName: string;
  refusal?: MediatorAccessRefusal | null;
  error?: string;
  continuing: boolean;
  onContinue: () => void;
  onLater: () => void;
}

/**
 * The pause of a pairing on a mediator that only admits known DIDs: shows the
 * DIDs the gateway minted for the mediator's administrator to add, and
 * continues when the user says they are allowed.
 */
const MediatorAccessStep: React.FC<MediatorAccessStepProps> = ({
  dids,
  mediatorName,
  refusal,
  error,
  continuing,
  onContinue,
  onLater,
}) => (
  <div className="card shadow" data-testid="wizard-step-mediator-access">
    <div className="card-header py-3">
      <h6 className="m-0 font-weight-bold text-primary">
        <i className="fas fa-user-shield me-2" aria-hidden="true"></i>
        Allow these DIDs on the mediator
      </h6>
    </div>
    <div className="card-body">
      <p>
        These DIDs are for you to know. Make sure they are allowed on mediator{' '}
        <strong>{mediatorName}</strong> before you continue.
      </p>
      <ul>
        <li>
          If it is an <code>explicit_deny</code> mediator or a public mediator, you can continue
          right away.
        </li>
        <li>
          Otherwise, contact the mediator&apos;s administrator to add these DIDs, each with the
          right to manage its own access list. You can leave this page and continue later from
          Connections.
        </li>
      </ul>

      <ul className="list-group mb-2">
        {dids.map(item => (
          <li
            key={item.role}
            className="list-group-item d-flex justify-content-between align-items-center gap-2"
            data-testid={`mediator-access-did-${item.role}`}
          >
            <div className="text-break">
              <div className="small text-muted">{item.label}</div>
              <code title={item.did}>{topAndTail(item.did, 16, 16)}</code>
            </div>
            <CopyButton
              text={item.did}
              title={`Copy ${item.label}`}
              data-testid={`mediator-access-copy-button-${item.role}`}
            />
          </li>
        ))}
      </ul>
      <CopyButton
        text={dids.map(item => item.did).join('\n')}
        variant="outline-primary"
        label="Copy all DIDs"
        title="Copy all DIDs, one per line"
        data-testid="mediator-access-copy-all"
      />

      {refusal && (
        <div className="alert alert-danger mt-3" role="alert" data-testid="mediator-access-refused">
          <i className="fas fa-exclamation-circle me-2" aria-hidden="true"></i>
          Mediator {mediatorName} still refuses the {refusal.label} (
          {topAndTail(refusal.did, 16, 16)}). Ask its administrator to add it, then continue.
        </div>
      )}
      {error && (
        <div className="alert alert-danger mt-3" role="alert" data-testid="mediator-access-error">
          {error}
        </div>
      )}

      <div className="d-flex justify-content-between mt-4">
        <AppButton
          type="button"
          variant="secondary"
          size="md"
          onClick={onLater}
          iconStart={<i className="fas fa-clock" aria-hidden="true"></i>}
          data-testid="mediator-access-later-button"
        >
          Continue later
        </AppButton>
        <AppButton
          type="button"
          variant="primary"
          size="md"
          onClick={onContinue}
          loading={continuing}
          iconEnd={<i className="fas fa-arrow-right" aria-hidden="true"></i>}
          data-testid="mediator-access-continue-button"
        >
          Continue
        </AppButton>
      </div>
    </div>
  </div>
);

export default MediatorAccessStep;
