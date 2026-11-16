import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import './OnboardWizard.css';
import { apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import WizardProgress from '../components/shared/WizardProgress';
import { ROUTES } from '../routes';
import { showToast } from '../utils/toaster';
import { TrustAgentDetailsStep, detailsComplete } from './VtaConnectionsPage/TrustAgentDetailsStep';
import { PairStep, VerifyStep } from './VtaConnectionsPage/WizardPairSteps';
import { WizardFinishStep } from './VtaConnectionsPage/WizardFinishStep';
import { useVtaConnections } from './VtaConnectionsPage/useVtaConnections';
import { applianceSigningPayload } from './VtaConnectionsPage/vtaConnectionHelpers';
import type { NewVtaConnection, PairingPayload, VtaConnection } from './VtaConnectionsPage/types';

type WizardStep = 'details' | 'grant' | 'verify' | 'complete';

const STEPS: ReadonlyArray<{ key: WizardStep; label: string }> = [
  { key: 'details', label: 'Enter Details' },
  { key: 'grant', label: 'Grant Access' },
  { key: 'verify', label: 'Verify' },
  { key: 'complete', label: 'Complete' },
];

const EMPTY: NewVtaConnection = { name: '', endpoint: '', vta_did: '', default_context_id: '' };

/**
 * Connects a Verifiable Trust Agent: enter its details, approve exactly one grant on your own
 * agent, watch it verify, then make it usable. `?id=<connection id>` resumes a connection that
 * was created but not finished, at the grant step (or at the last step when it is connected).
 *
 * The gateway never performs the grant itself — that is the whole point, and the copy says so
 * at the step where the user is asked to act.
 */
const ConnectTrustAgentWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const resumeId = searchParams.get('id') ?? '';
  const { connections, loading, create, pair, verify, provisionKey, reload } = useVtaConnections();

  const [step, setStep] = useState<WizardStep>('details');
  const [draft, setDraft] = useState<NewVtaConnection>(EMPTY);
  const [connection, setConnection] = useState<VtaConnection | null>(null);
  const [busy, setBusy] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  const [payload, setPayload] = useState<PairingPayload | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verified, setVerified] = useState<VtaConnection | null>(null);
  const [makeDefault, setMakeDefault] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const resumed = useRef(false);

  const leave = useCallback(() => navigate(ROUTES.TRUST_AGENTS_TAB), [navigate]);

  const issuePayload = useCallback(
    async (target: VtaConnection) => {
      setPairError(null);
      setPayload(null);
      try {
        setPayload(await pair(target));
      } catch (e) {
        setPairError(e instanceof Error ? e.message : 'Could not start pairing.');
      }
    },
    [pair]
  );

  const runVerify = useCallback(
    async (target: VtaConnection) => {
      setChecking(true);
      setVerifyError(null);
      try {
        const updated = await verify(target);
        setVerified(updated);
        setStep('complete');
      } catch (e) {
        setVerifyError(e instanceof Error ? e.message : 'Verification failed.');
      } finally {
        setChecking(false);
      }
    },
    [verify]
  );

  // A resumed connection is read from the list once it has loaded: a connected one goes straight
  // to the last step, any other to the grant step, where its command is issued again.
  useEffect(() => {
    if (!resumeId || resumed.current || loading) return;
    const found = connections.find(c => c.id === resumeId);
    if (!found) return;
    resumed.current = true;
    setConnection(found);
    if (found.pairing.state === 'connected') {
      setVerified(found);
      setStep('complete');
      return;
    }
    setStep('grant');
    void issuePayload(found);
  }, [resumeId, loading, connections, issuePayload]);

  const createAndPair = useCallback(async () => {
    setBusy(true);
    setDetailsError(null);
    try {
      const created = await create(draft);
      setConnection(created);
      setStep('grant');
      await issuePayload(created);
    } catch (e) {
      setDetailsError(e instanceof Error ? e.message : 'Could not create the connection.');
    } finally {
      setBusy(false);
    }
  }, [create, draft, issuePayload]);

  /**
   * Adopt the agent appliance-wide, then leave.
   *
   * A failure here is reported but still leaves: the connection itself is already paired and
   * keyed, and trapping the operator in a wizard over an optional step would be worse than
   * pointing them at Key management.
   */
  const finish = useCallback(async () => {
    const target = verified;
    if (!makeDefault || !target) {
      await reload();
      leave();
      return;
    }
    const default_signing = applianceSigningPayload(target);
    if (!default_signing) {
      showToast('error', 'That connection has no context and key yet, so it cannot sign.');
      leave();
      return;
    }
    setFinishing(true);
    try {
      const response = await apiClient.fetch('/api/v1/settings', {
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
      leave();
    }
  }, [makeDefault, verified, leave, reload]);

  const currentIndex = STEPS.findIndex(s => s.key === step);

  const renderStep = () => {
    switch (step) {
      case 'details':
        return (
          <div className="card shadow" data-testid="wizard-step-details">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2" aria-hidden="true" /> Enter Trust Agent
                Details
              </h6>
            </div>
            <div className="card-body">
              {detailsError && (
                <div
                  className="alert alert-danger"
                  role="alert"
                  data-testid="wizard-trust-agent-error"
                >
                  {detailsError}
                </div>
              )}
              <TrustAgentDetailsStep draft={draft} onChange={setDraft} disabled={busy} />
            </div>
            <div className="card-footer d-flex justify-content-between">
              <AppButton
                variant="outline-secondary"
                onClick={leave}
                disabled={busy}
                data-testid="wizard-cancel"
              >
                Cancel
              </AppButton>
              <AppButton
                variant="primary"
                onClick={() => void createAndPair()}
                disabled={busy || !detailsComplete(draft)}
                data-testid="wizard-next"
              >
                {busy ? 'Creating…' : 'Create and pair'}
              </AppButton>
            </div>
          </div>
        );
      case 'grant':
        return (
          <div className="card shadow" data-testid="wizard-step-grant">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-key me-2" aria-hidden="true" /> Grant Access
                {connection ? ` — ${connection.name}` : ''}
              </h6>
            </div>
            <div className="card-body">
              <PairStep
                payload={payload}
                error={pairError}
                onReissue={() => (connection ? issuePayload(connection) : Promise.resolve())}
              />
            </div>
            <div className="card-footer d-flex justify-content-between">
              <AppButton variant="outline-secondary" onClick={leave} data-testid="wizard-cancel">
                Finish later
              </AppButton>
              <AppButton
                variant="primary"
                disabled={!payload || !connection}
                onClick={() => {
                  if (!connection) return;
                  setStep('verify');
                  void runVerify(connection);
                }}
                data-testid="wizard-next"
              >
                I have run the command
              </AppButton>
            </div>
          </div>
        );
      case 'verify':
        return (
          <div className="card shadow" data-testid="wizard-step-verify">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-check-circle me-2" aria-hidden="true" /> Verify
              </h6>
            </div>
            <div className="card-body">
              {connection && (
                <VerifyStep
                  checking={checking}
                  error={verifyError}
                  connection={connection}
                  onRetry={() => runVerify(connection)}
                />
              )}
            </div>
            <div className="card-footer d-flex justify-content-between">
              <AppButton
                variant="outline-secondary"
                disabled={checking}
                onClick={() => setStep('grant')}
                data-testid="wizard-back"
              >
                Back
              </AppButton>
              <AppButton variant="outline-secondary" onClick={leave} data-testid="wizard-cancel">
                Finish later
              </AppButton>
            </div>
          </div>
        );
      case 'complete':
        return (
          <div className="card shadow" data-testid="wizard-step-complete">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-flag-checkered me-2" aria-hidden="true" /> Complete
              </h6>
            </div>
            <div className="card-body">
              {verified && (
                <WizardFinishStep
                  connection={verified}
                  onProvisionKey={provisionKey}
                  onSettled={setVerified}
                  onDefaultChoice={setMakeDefault}
                />
              )}
            </div>
            <div className="card-footer d-flex justify-content-end">
              <AppButton
                variant="primary"
                disabled={finishing}
                onClick={() => void finish()}
                data-testid="wizard-submit"
              >
                {finishing ? 'Finishing…' : 'Done'}
              </AppButton>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid" data-testid="wizard-add-trust-agent">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-robot me-2" aria-hidden="true"></i>
          Connect a Trust Agent
        </h1>
      </div>

      <WizardProgress steps={STEPS} currentIndex={currentIndex} />

      <div className="wizard-content">{renderStep()}</div>
    </div>
  );
};

export default ConnectTrustAgentWizardPage;
