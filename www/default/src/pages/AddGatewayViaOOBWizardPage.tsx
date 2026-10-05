import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './OnboardWizard.css';

// Import step components
import EnterDetailsStep from '../components/gateway-add-via-oob/EnterDetailsStep';
import EnterOOBLinkStep from '../components/gateway-add-via-oob/EnterOOBLinkStep';
import ConnectStep from '../components/gateway-add-via-oob/ConnectStep';
import CompleteStep from '../components/gateway-add-via-oob/CompleteStep';

// Define wizard steps
type WizardStep = 'enter-details' | 'enter-link' | 'connect' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  name: string | null;
  description: string | null;
  didMethod: string;
  oobLink: string | null;
  secret: string | null;
  gateway: any;
}

const AddGatewayViaOOBWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'enter-details',
    name: null,
    description: null,
    didMethod: 'web',
    oobLink: null,
    secret: null,
    gateway: null,
  });

  const [error, setError] = useState('');

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'enter-details', label: 'Enter Details' },
    { key: 'enter-link', label: 'Enter Connection Point Link' },
    { key: 'connect', label: 'Connect' },
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

  const handleDetailsEntered = (name: string, description: string, didMethod: string) => {
    setWizardState(prev => ({ ...prev, name, description, didMethod }));
    nextStep();
  };

  const handleOOBLinkEntered = (link: string, secret: string) => {
    setWizardState(prev => ({ ...prev, oobLink: link, secret }));
    nextStep();
  };

  const handleConnected = (gateway: any) => {
    setWizardState(prev => ({ ...prev, gateway }));
    nextStep();
  };

  const handleFinish = () => {
    navigate('/connections?tab=gateways');
  };

  const handleViewGateway = () => {
    if (wizardState.gateway?.id) {
      navigate(`/gateways/${wizardState.gateway.id}`);
    }
  };

  const handleCancel = () => {
    navigate('/connections?tab=gateways');
  };

  // Render current step
  const renderStep = () => {
    switch (wizardState.currentStep) {
      case 'enter-details':
        return (
          <EnterDetailsStep
            onNext={handleDetailsEntered}
            onCancel={handleCancel}
            initialName={wizardState.name || ''}
            initialDescription={wizardState.description || ''}
            initialDidMethod={wizardState.didMethod}
          />
        );
      case 'enter-link':
        return (
          <EnterOOBLinkStep
            onNext={handleOOBLinkEntered}
            onBack={prevStep}
            onCancel={handleCancel}
            initialLink={wizardState.oobLink || ''}
            initialSecret={wizardState.secret || ''}
          />
        );
      case 'connect':
        return (
          <ConnectStep
            oobLink={wizardState.oobLink || ''}
            secret={wizardState.secret || ''}
            name={wizardState.name || ''}
            description={wizardState.description || ''}
            didMethod={wizardState.didMethod}
            onConnected={handleConnected}
            onBack={prevStep}
            onCancel={handleCancel}
          />
        );
      case 'complete':
        return (
          <CompleteStep
            gateway={wizardState.gateway}
            onFinish={handleFinish}
            onViewGateway={handleViewGateway}
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
          <i className="fas fa-network-wired me-2"></i>
          Connect to Gateway via Connection Point
        </h1>
      </div>
      <p className="text-muted mb-4">
        Paste the connection point link, and its connection secret, that the other gateway's
        administrator shared with you. This creates a two-way connection between the two appliances
        over the fabric (the gateway-to-gateway network this appliance participates in).
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
                      <i className="fas fa-check  me-1"></i>
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

export default AddGatewayViaOOBWizardPage;
