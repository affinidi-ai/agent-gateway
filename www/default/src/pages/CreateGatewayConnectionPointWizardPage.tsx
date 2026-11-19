import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';
import MediatorAccessStep, { MediatorAccessRefusal } from '../components/shared/MediatorAccessStep';
import ResumeUnavailableCard from '../components/shared/ResumeUnavailableCard';
import { formatDateTime } from '../utils/stringUtils';
import { AppButton } from '../components/shared/AppButton';
import {
  CONNECTION_POINT_DID_LABELS,
  MediatorAccess,
  labelledDids,
  mediatorAccessRefusal,
  mediatorAccessExpired,
} from '../utils/mediatorAccess';

// Import step components
import SelectMediatorStep from '../components/gateway-create-connection-point/SelectMediatorStep';
import EnterDetailsStep from '../components/gateway-create-connection-point/EnterDetailsStep';
import CompleteStep from '../components/gateway-create-connection-point/CompleteStep';

// Define wizard steps
type WizardStep = 'select-mediator' | 'enter-details' | 'mediator-access' | 'complete';

interface ConnectionPointDetails {
  gatewayId: string | null;
  name: string;
  description: string;
  secret: string;
  expirySeconds?: number;
  didMethod: string;
}

interface WizardState extends ConnectionPointDetails {
  currentStep: WizardStep;
  mediatorId: string | null;
  connectionPoint: any;
  mediatorAccess: MediatorAccess | null;
}

const CreateGatewayConnectionPointWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const resumeId = searchParams.get('resume');

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'select-mediator',
    mediatorId: null,
    gatewayId: null,
    name: '',
    description: '',
    secret: '',
    didMethod: 'web',
    connectionPoint: null,
    mediatorAccess: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [continuing, setContinuing] = useState(false);
  const [refusal, setRefusal] = useState<MediatorAccessRefusal | null>(null);
  const [continueError, setContinueError] = useState('');
  // The first, automatic try failed for a reason other than a refusal.
  const [firstTryError, setFirstTryError] = useState('');
  const [retrying, setRetrying] = useState(false);
  const autoTried = useRef<string | null>(null);

  /**
   * Continues a paused connection point. `auto` is the wizard's own first try,
   * made behind the usual spinner: a mediator that admits the DIDs goes straight
   * to Complete, as before the pause existed, and only a refusal shows the
   * Mediator Access step (without a "still refuses" alert). Any other failure of
   * the first try offers to try again, since nothing says the DIDs are refused.
   */
  const tryContinue = async (connectionPointId: string, auto: boolean) => {
    try {
      if (!auto) setContinuing(true);
      setRefusal(null);
      setContinueError('');
      setFirstTryError('');
      const response = await apiClient.post(`/connection-points/${connectionPointId}/continue`, {});
      setWizardState(prev => ({
        ...prev,
        connectionPoint: response.data.connection_point,
        mediatorAccess: null,
        currentStep: 'complete',
      }));
    } catch (err: any) {
      const refused = mediatorAccessRefusal(err, CONNECTION_POINT_DID_LABELS);
      const message = err.message || 'Failed to continue. Please try again.';
      if (refused) {
        if (!auto) setRefusal(refused);
        setWizardState(prev => ({ ...prev, currentStep: 'mediator-access' }));
      } else if (auto) {
        setFirstTryError(message);
      } else {
        setContinueError(message);
      }
    } finally {
      setContinuing(false);
    }
  };

  /** Tries a paused connection point's DIDs once, before asking the user for anything. */
  const autoTry = async (connectionPointId: string) => {
    if (autoTried.current === connectionPointId) return;
    autoTried.current = connectionPointId;
    await tryContinue(connectionPointId, true);
  };

  const resumed = useRef<string | null>(null);
  // Why `?resume=` cannot continue: the record is gone or already continued, or expired.
  const [resumeUnavailable, setResumeUnavailable] = useState('');

  useEffect(() => {
    if (!resumeId || resumed.current === resumeId) return;
    resumed.current = resumeId;
    const resume = async () => {
      try {
        setSaving(true);
        const id = encodeURIComponent(resumeId);
        const [connectionPoint, access] = await Promise.all([
          apiClient.get(`/connection-points/${id}`),
          apiClient.get<MediatorAccess>(`/connection-points/${id}/mediator-access`),
        ]);
        if (mediatorAccessExpired(access.data)) {
          setResumeUnavailable(
            `Its invitation expired on ${formatDateTime(access.data.expires_at, true)}. Delete this connection point on Connections and create a new one.`
          );
          return;
        }
        setWizardState(prev => ({
          ...prev,
          mediatorId: connectionPoint.data.mediator_id,
          connectionPoint: connectionPoint.data,
          mediatorAccess: access.data,
          // Continuing from Connections shows the DIDs at once; the user tests the connection.
          currentStep: 'mediator-access',
        }));
      } catch (err: any) {
        setResumeUnavailable(err.message || 'Failed to load the connection point.');
      } finally {
        setSaving(false);
      }
    };
    resume();
  }, [resumeId]);

  // Mediator Access is listed only once the mediator has refused the DIDs.
  const [accessStepShown, setAccessStepShown] = useState(false);
  useEffect(() => {
    if (wizardState.currentStep === 'mediator-access') setAccessStepShown(true);
  }, [wizardState.currentStep]);

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'select-mediator', label: 'Select Mediator' },
    { key: 'enter-details', label: 'Enter Details' },
    ...(accessStepShown || wizardState.currentStep === 'mediator-access'
      ? [{ key: 'mediator-access' as WizardStep, label: 'Mediator Access' }]
      : []),
    { key: 'complete', label: 'Complete' },
  ];

  const currentStepIndex = steps.findIndex(s => s.key === wizardState.currentStep);

  const goToStep = (step: WizardStep) => {
    setWizardState(prev => ({ ...prev, currentStep: step }));
  };

  const nextStep = () => {
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < steps.length) {
      goToStep(steps[nextIndex].key);
    }
  };

  const prevStep = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) {
      goToStep(steps[prevIndex].key);
    }
  };

  const handleMediatorSelected = (mediatorId: string) => {
    setWizardState(prev => ({ ...prev, mediatorId }));
    nextStep();
  };

  /** Keeps the details, so a failed creation can be retried, and creates the connection point. */
  const handleDetailsSubmit = async (
    gatewayId: string,
    name: string,
    description: string,
    secret: string,
    expirySeconds?: number,
    didMethod?: string
  ) => {
    const details: ConnectionPointDetails = {
      gatewayId,
      name,
      description,
      secret,
      expirySeconds,
      didMethod: didMethod || 'web',
    };
    setWizardState(prev => ({ ...prev, ...details }));
    try {
      setSaving(true);
      setError('');

      const response = await apiClient.post('/connection-points', {
        gateway_id: details.gatewayId,
        mediator_id: wizardState.mediatorId,
        name: details.name,
        description: details.description,
        secret: details.secret,
        expiry_seconds: details.expirySeconds,
        did_method: details.didMethod,
        await_mediator_access: true,
      });

      setWizardState(prev => ({
        ...prev,
        connectionPoint: response.data.connection_point,
        mediatorAccess: response.data.mediator_access ?? null,
        currentStep: response.data.mediator_access ? prev.currentStep : 'complete',
      }));
      if (response.data.mediator_access) await autoTry(response.data.connection_point.id);
    } catch (err: any) {
      console.error('Failed to create connection point:', err);
      setError(err.message || 'Failed to create connection point. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleContinue = () => tryContinue(wizardState.connectionPoint.id, false);

  const handleRetryFirstTry = async () => {
    setRetrying(true);
    try {
      await tryContinue(wizardState.connectionPoint.id, true);
    } finally {
      setRetrying(false);
    }
  };

  const handleFinish = () => {
    navigate('/connections?tab=gateways');
  };

  const handleCancel = () => {
    navigate('/connections?tab=gateways');
  };

  // Render current step
  const renderStep = () => {
    if (resumeUnavailable) {
      return <ResumeUnavailableCard message={resumeUnavailable} onBack={handleCancel} />;
    }
    if (saving) {
      return (
        <div className="card shadow">
          <div className="card-body text-center py-5">
            <div className="spinner-border text-primary mb-3" role="status">
              <span className="visually-hidden"></span>
            </div>
            <p className="text-muted">
              {resumeId ? 'Loading the connection point...' : 'Creating connection point...'}
            </p>
          </div>
        </div>
      );
    }

    if (firstTryError && wizardState.currentStep === 'enter-details') {
      return (
        <div className="card shadow" data-testid="wizard-step-first-try-failed">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-plug me-2" aria-hidden="true"></i>
              Connection Point Saved, Not Connected Yet
            </h6>
          </div>
          <div className="card-body">
            <div className="alert alert-danger" role="alert" data-testid="first-try-error">
              {firstTryError}
            </div>
            <p className="mb-0">
              The connection point is saved. Select <strong>Try Again</strong>, or select{' '}
              <strong>Continue Later</strong> and continue from Connections.
            </p>
            <div className="d-flex justify-content-end gap-2 mt-4">
              <AppButton
                type="button"
                variant="secondary"
                size="md"
                onClick={handleCancel}
                iconStart={<i className="fas fa-clock" aria-hidden="true"></i>}
                data-testid="first-try-later-button"
              >
                Continue Later
              </AppButton>
              <AppButton
                type="button"
                variant="primary"
                size="md"
                onClick={handleRetryFirstTry}
                loading={retrying}
                iconStart={<i className="fas fa-redo" aria-hidden="true"></i>}
                data-testid="first-try-retry-button"
              >
                Try Again
              </AppButton>
            </div>
          </div>
        </div>
      );
    }

    switch (wizardState.currentStep) {
      case 'select-mediator':
        return (
          <SelectMediatorStep
            onNext={handleMediatorSelected}
            onCancel={handleCancel}
            initialMediatorId={wizardState.mediatorId}
          />
        );
      case 'enter-details':
        return (
          <EnterDetailsStep
            onCreate={handleDetailsSubmit}
            onBack={prevStep}
            onCancel={handleCancel}
            initialGatewayId={wizardState.gatewayId}
            initialName={wizardState.name}
            initialDescription={wizardState.description}
            initialSecret={wizardState.secret}
            initialExpirySeconds={wizardState.expirySeconds}
            initialDidMethod={wizardState.didMethod}
          />
        );
      case 'mediator-access':
        return wizardState.mediatorAccess ? (
          <MediatorAccessStep
            dids={labelledDids(wizardState.mediatorAccess, CONNECTION_POINT_DID_LABELS)}
            mediatorName={wizardState.mediatorAccess.mediator_name}
            refusal={refusal}
            error={continueError}
            continuing={continuing}
            onContinue={handleContinue}
            onLater={handleCancel}
          />
        ) : null;
      case 'complete':
        return (
          <CompleteStep connectionPoint={wizardState.connectionPoint} onFinish={handleFinish} />
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid" data-testid="page-gateway-publish">
      {/* Page Header */}
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-share-alt me-2"></i>
          Create Gateway Connection Point
        </h1>
      </div>
      <p className="text-muted mb-4">
        A connection point is a reusable invitation link, until it's revoked or expires. Share it
        with the administrator of the gateway you want to connect to. Once they use it, the two
        appliances are linked over the fabric (the gateway-to-gateway network this appliance
        participates in).
      </p>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError('')}
            aria-label="Close"
          />
        </div>
      )}

      {/* Progress Bar */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <div className="wizard-progress">
            <div className="wizard-steps">
              {steps.map((step, index) => (
                <div
                  key={step.key}
                  className={`wizard-step ${
                    index === currentStepIndex
                      ? 'active'
                      : index < currentStepIndex
                        ? 'completed'
                        : ''
                  }`}
                >
                  <div className="wizard-step-circle">
                    {index < currentStepIndex ? (
                      <i className="fas fa-check"></i>
                    ) : (
                      <span>{index + 1}</span>
                    )}
                  </div>
                  <div className="wizard-step-label">{step.label}</div>
                  {index < steps.length - 1 && <div className="wizard-step-line"></div>}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Step Content */}
      <div className="wizard-content">{renderStep()}</div>
      <br />
    </div>
  );
};

export default CreateGatewayConnectionPointWizardPage;
