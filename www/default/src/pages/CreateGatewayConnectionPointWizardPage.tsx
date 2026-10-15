import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import SelectMediatorStep from '../components/gateway-create-connection-point/SelectMediatorStep';
import EnterDetailsStep from '../components/gateway-create-connection-point/EnterDetailsStep';
import CompleteStep from '../components/gateway-create-connection-point/CompleteStep';

// Define wizard steps
type WizardStep = 'select-mediator' | 'enter-details' | 'complete';

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
}

const CreateGatewayConnectionPointWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'select-mediator',
    mediatorId: null,
    gatewayId: null,
    name: '',
    description: '',
    secret: '',
    didMethod: 'web',
    connectionPoint: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'select-mediator', label: 'Select Mediator' },
    { key: 'enter-details', label: 'Enter Details' },
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
      });

      setWizardState(prev => ({
        ...prev,
        connectionPoint: response.data.connection_point,
        currentStep: 'complete',
      }));
    } catch (err: any) {
      console.error('Failed to create connection point:', err);
      setError(err.message || 'Failed to create connection point. Please try again.');
    } finally {
      setSaving(false);
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
    if (saving) {
      return (
        <div className="card shadow">
          <div className="card-body text-center py-5">
            <div className="spinner-border text-primary mb-3" role="status">
              <span className="visually-hidden"></span>
            </div>
            <p className="text-muted">Creating connection point...</p>
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
      case 'complete':
        return (
          <CompleteStep connectionPoint={wizardState.connectionPoint} onFinish={handleFinish} />
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid">
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
