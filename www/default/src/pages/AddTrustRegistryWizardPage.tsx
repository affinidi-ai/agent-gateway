import React, { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './OnboardWizard.css';

// Import step components
import EnterOobUrlStep from '../components/trust-registry/EnterOobUrlStep';
import ConnectingStep from '../components/trust-registry/ConnectingStep';
import CompleteStep from '../components/trust-registry/CompleteStep';

// Define wizard steps
type WizardStep = 'enter-oob-url' | 'connecting' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  name: string;
  description: string;
  oobUrl: string;
  didMethod: string;
  trustRegistry: any;
}

const AddTrustRegistryWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'enter-oob-url',
    name: '',
    description: '',
    oobUrl: '',
    didMethod: 'web',
    trustRegistry: null,
  });

  const [error, setError] = useState('');

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'enter-oob-url', label: 'Enter Details' },
    { key: 'connecting', label: 'Connecting' },
    { key: 'complete', label: 'Complete' },
  ];

  const currentStepIndex = steps.findIndex(s => s.key === wizardState.currentStep);

  const handleOobUrlEntered = (
    name: string,
    description: string,
    oobUrl: string,
    didMethod: string
  ) => {
    setError('');
    setWizardState(prev => ({
      ...prev,
      name,
      description,
      oobUrl,
      didMethod,
      currentStep: 'connecting',
    }));
  };

  const handleConnectionComplete = useCallback((trustRegistry: any) => {
    setWizardState(prev => ({
      ...prev,
      trustRegistry,
      currentStep: 'complete',
    }));
  }, []);

  const handleConnectionError = useCallback((errorMessage: string) => {
    setError(errorMessage);
    setWizardState(prev => ({
      ...prev,
      currentStep: 'enter-oob-url',
    }));
  }, []);

  const handleFinish = () => {
    navigate('/connections?tab=trust-registries');
  };

  const handleCancel = () => {
    navigate('/connections?tab=trust-registries');
  };

  const handleViewTrustRegistry = () => {
    if (wizardState.trustRegistry?.id) {
      navigate(`/trust-registries/${wizardState.trustRegistry.id}`);
    }
  };

  // Render current step
  const renderStep = () => {
    switch (wizardState.currentStep) {
      case 'enter-oob-url':
        return <EnterOobUrlStep onNext={handleOobUrlEntered} onCancel={handleCancel} />;
      case 'connecting':
        return (
          <ConnectingStep
            name={wizardState.name}
            description={wizardState.description}
            oobUrl={wizardState.oobUrl}
            didMethod={wizardState.didMethod}
            onComplete={handleConnectionComplete}
            onError={handleConnectionError}
            onBack={() => setWizardState(prev => ({ ...prev, currentStep: 'enter-oob-url' }))}
            onCancel={handleCancel}
          />
        );
      case 'complete':
        return (
          <CompleteStep
            trustRegistry={wizardState.trustRegistry}
            onFinish={handleFinish}
            onViewTrustRegistry={handleViewTrustRegistry}
          />
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
          <i className="fas fa-shield-alt me-2"></i>
          Add Trust Registry
        </h1>
      </div>
      <p className="text-muted mb-4">
        Paste the trust registry's out-of-band (OOB) connection URL, provided by the registry
        operator. This establishes a DIDComm connection the gateway will use for Trust Check
        queries.
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

export default AddTrustRegistryWizardPage;
