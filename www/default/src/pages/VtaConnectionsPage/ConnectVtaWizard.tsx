import React, { useCallback, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { showToast } from '../../utils/toaster';
import { applianceSigningPayload } from './vtaConnectionHelpers';
import { BackendStep, TransportStep } from './WizardChoiceSteps';
import { PairStep, VerifyStep } from './WizardPairSteps';
import { WizardFinishStep } from './WizardFinishStep';
import { WIZARD_STEPS } from './wizardSteps';
import type {
  PairingPayload,
  VtaConnection,
  VtaDeploymentStatus,
  VtaTransport,
  WizardBackend,
} from './types';

interface ConnectVtaWizardProps {
  connection: VtaConnection;
  deployment: VtaDeploymentStatus | null;
  onPair: (connection: VtaConnection) => Promise<PairingPayload>;
  onVerify: (connection: VtaConnection) => Promise<VtaConnection>;
  onProvisionKey: (connection: VtaConnection) => Promise<VtaConnection>;
  onClose: () => void;
}

/**
 * The operator-facing half of pairing (VTA-24): choose a backend, choose a
 * transport, approve exactly one grant on your own agent, watch it verify.
 *
 * The gateway never performs the grant itself — that is the whole point, and
 * the copy says so at the step where the user is asked to act.
 *
 * The final step also mints the signing key and can adopt the agent as the
 * appliance default, so a light operator never has to know that a usable
 * connection is assembled from three separate screens. Both remain editable
 * in their own places afterwards.
 */
export const ConnectVtaWizard: React.FC<ConnectVtaWizardProps> = ({
  connection,
  deployment,
  onPair,
  onVerify,
  onProvisionKey,
  onClose,
}) => {
  const [stepIndex, setStepIndex] = useState(0);
  const [backend, setBackend] = useState<WizardBackend>(
    deployment?.self_administered ? 'bundled' : 'own'
  );
  const [transport, setTransport] = useState<VtaTransport>(connection.transport);
  const [payload, setPayload] = useState<PairingPayload | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verified, setVerified] = useState<VtaConnection | null>(null);
  const [makeDefault, setMakeDefault] = useState(false);
  const [finishing, setFinishing] = useState(false);

  const issuePayload = useCallback(async () => {
    setPairError(null);
    setPayload(null);
    try {
      setPayload(await onPair(connection));
    } catch (e) {
      setPairError(e instanceof Error ? e.message : 'Could not start pairing.');
    }
  }, [connection, onPair]);

  const runVerify = useCallback(async () => {
    setChecking(true);
    setVerifyError(null);
    try {
      const updated = await onVerify(connection);
      setVerified(updated);
      setStepIndex(WIZARD_STEPS.length - 1);
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : 'Verification failed.');
    } finally {
      setChecking(false);
    }
  }, [connection, onVerify]);

  const goNext = useCallback(async () => {
    const next = stepIndex + 1;
    if (WIZARD_STEPS[next] === 'Pair') await issuePayload();
    if (WIZARD_STEPS[next] === 'Verify') {
      setStepIndex(next);
      await runVerify();
      return;
    }
    setStepIndex(next);
  }, [stepIndex, issuePayload, runVerify]);

  const step = WIZARD_STEPS[stepIndex];
  const isLast = stepIndex === WIZARD_STEPS.length - 1;

  /**
   * Adopt the agent appliance-wide, then close.
   *
   * A failure here is reported but still closes: the connection itself is
   * already paired and keyed, and leaving the operator trapped in a wizard
   * over an optional step would be worse than pointing them at Settings.
   */
  const finish = useCallback(async () => {
    const target = verified;
    if (!makeDefault || !target) {
      onClose();
      return;
    }
    const default_signing = applianceSigningPayload(target);
    if (!default_signing) {
      showToast('error', 'That connection has no context and key yet, so it cannot sign.');
      onClose();
      return;
    }
    setFinishing(true);
    try {
      const response = await apiClient.fetch('/api/v1/settings', {
        // The settings write route is POST, not PUT.
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ default_signing }),
      });
      if (!response.ok) throw new Error(await response.text());
      showToast('success', `${target.name} now signs for this appliance.`);
    } catch (e) {
      showToast(
        'error',
        e instanceof Error
          ? `Connected, but could not make it the default: ${e.message}`
          : 'Connected, but could not make it the default.'
      );
    } finally {
      setFinishing(false);
      onClose();
    }
  }, [makeDefault, verified, onClose]);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-link me-2" aria-hidden="true" />
          Connect {connection.name}
        </h6>
        <AppButton variant="outline-secondary" size="sm" onClick={onClose}>
          Close
        </AppButton>
      </div>
      <div className="card-body">
        <ol className="nav nav-pills mb-4 gap-2 list-unstyled d-flex">
          {WIZARD_STEPS.map((label, index) => (
            <li key={label}>
              <span
                className={`badge ${index === stepIndex ? 'bg-primary' : index < stepIndex ? 'bg-success' : 'bg-secondary'}`}
              >
                {index + 1}. {label}
              </span>
            </li>
          ))}
        </ol>

        {step === 'Backend' && (
          <BackendStep
            value={backend}
            bundledAvailable={Boolean(deployment?.self_administered)}
            onChange={setBackend}
          />
        )}
        {step === 'Transport' && <TransportStep value={transport} onChange={setTransport} />}
        {step === 'Pair' && (
          <PairStep payload={payload} error={pairError} onReissue={issuePayload} />
        )}
        {step === 'Verify' && (
          <VerifyStep
            checking={checking}
            error={verifyError}
            connection={connection}
            onRetry={runVerify}
          />
        )}
        {step === 'Done' && verified && (
          <WizardFinishStep
            connection={verified}
            onProvisionKey={onProvisionKey}
            onSettled={setVerified}
            onDefaultChoice={setMakeDefault}
          />
        )}
      </div>
      <div className="card-footer d-flex justify-content-between">
        <AppButton
          variant="outline-secondary"
          disabled={stepIndex === 0 || checking}
          onClick={() => setStepIndex(index => Math.max(0, index - 1))}
        >
          Back
        </AppButton>
        {isLast ? (
          <AppButton variant="primary" disabled={finishing} onClick={() => void finish()}>
            {finishing ? 'Finishing…' : 'Done'}
          </AppButton>
        ) : (
          <AppButton
            variant="primary"
            disabled={checking || (step === 'Pair' && !payload)}
            onClick={goNext}
          >
            {step === 'Pair' ? 'I have run the command' : 'Continue'}
          </AppButton>
        )}
      </div>
    </div>
  );
};
