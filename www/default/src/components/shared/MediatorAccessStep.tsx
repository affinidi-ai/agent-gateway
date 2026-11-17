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
  /** The mediator refused a DID again after the user tested the connection. */
  refusal?: MediatorAccessRefusal | null;
  error?: string;
  continuing: boolean;
  onContinue: () => void;
  onLater: () => void;
}

/**
 * The pause of a pairing on a DIDComm Mediator that admits only the DIDs it
 * allows. Shown when the mediator refused the gateway's new DIDs, or when the
 * user continues a paused pairing from Connections: the DIDs to add to its
 * allow list, once as one bundle and once each on its own.
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
        Add These DIDs to the DIDComm Mediator&apos;s Allow List
      </h6>
    </div>
    <div className="card-body">
      <p data-testid="mediator-access-explanation">
        DIDComm Mediator <strong>{mediatorName}</strong> most probably uses{' '}
        <strong>Explicit Allow</strong>, so it only accepts connections from DIDs on its ACL. This
        gateway was blocked because the DIDs below aren&apos;t on it yet. Add them to let it
        connect.
      </p>
      <ul>
        <li>
          <strong>Hosted by Affinidi:</strong> in the Affinidi Portal, go to DIDComm Mediator,
          select <strong>Edit</strong> under <strong>Access Controls</strong>, add the DIDs below,
          and save.
        </li>
        <li>
          <strong>Self-hosted:</strong> ask its administrator to add each DID below to the allow
          list.
        </li>
      </ul>

      <div className="mb-3">
        <CopyButton
          text={dids.map(item => item.did).join('\n')}
          variant="outline-primary"
          label="Copy All DIDs as a Bundle"
          title="Copy all the DIDs at once, one per line"
          data-testid="mediator-access-copy-all"
        />
        <div className="small text-muted mt-1">
          All {dids.length} DIDs in one copy, for the Affinidi Portal.
        </div>
      </div>

      <div className="small text-muted mb-1">Or copy each DID on its own:</div>
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
      <div className="small text-muted" data-testid="mediator-access-one-way">
        Use one or the other: all the DIDs as a bundle, or each DID on its own. Not both.
      </div>

      <p className="mt-3 mb-0">
        Once the DIDs are allowed, select <strong>Test Connection</strong>. Or select{' '}
        <strong>Continue Later</strong> and continue from Connections.
      </p>

      {refusal && (
        <div className="alert alert-danger mt-3" role="alert" data-testid="mediator-access-refused">
          <i className="fas fa-exclamation-circle me-2" aria-hidden="true"></i>
          DIDComm Mediator {mediatorName} still refuses the {refusal.label} (
          {topAndTail(refusal.did, 16, 16)}). Make sure it is allowed, then select Test Connection
          again.
        </div>
      )}
      {error && (
        <div className="alert alert-danger mt-3" role="alert" data-testid="mediator-access-error">
          {error}
        </div>
      )}

      <div className="d-flex justify-content-end gap-2 mt-4">
        <AppButton
          type="button"
          variant="secondary"
          size="md"
          onClick={onLater}
          iconStart={<i className="fas fa-clock" aria-hidden="true"></i>}
          data-testid="mediator-access-later-button"
        >
          Continue Later
        </AppButton>
        <AppButton
          type="button"
          variant="primary"
          size="md"
          onClick={onContinue}
          loading={continuing}
          iconStart={<i className="fas fa-plug" aria-hidden="true"></i>}
          data-testid="mediator-access-continue-button"
        >
          Test Connection
        </AppButton>
      </div>
    </div>
  </div>
);

export default MediatorAccessStep;
