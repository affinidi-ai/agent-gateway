import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import EnterDidStep from '../components/mediator/EnterDidStep';
import ResolveStep from '../components/mediator/ResolveStep';
import ConfirmStep from '../components/mediator/ConfirmStep';
import CompleteStep from '../components/mediator/CompleteStep';

// Define wizard steps
type WizardStep = 'enter-did' | 'resolve' | 'configure' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  did: string | null;
  didDocument: any;
  mediator: any;
}

const AddMediatorWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'enter-did',
    did: null,
    didDocument: null,
    mediator: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'enter-did', label: 'Enter DID' },
    { key: 'resolve', label: 'Resolve' },
    { key: 'configure', label: 'Configure' },
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

  const handleDidEntered = (did: string) => {
    setWizardState(prev => ({ ...prev, did }));
    nextStep();
  };

  const handleDidResolved = (didDocument: any) => {
    setWizardState(prev => ({ ...prev, didDocument }));
    nextStep();
  };

  const handleConfigure = async (name: string, description: string) => {
    try {
      setSaving(true);
      setError('');

      // Create the mediator via the API, including the resolved DID document
      const response = await apiClient.post('/mediators', {
        name,
        description,
        did: wizardState.did,
        did_document: wizardState.didDocument,
      });

      setWizardState(prev => ({ ...prev, mediator: response.data }));
      nextStep();
    } catch (err: any) {
      console.error('Failed to create mediator:', err);
      setError(err.message || 'Failed to create mediator. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleFinish = () => {
    navigate('/connections?tab=mediators');
  };

  const handleCancel = () => {
    navigate('/connections?tab=mediators');
  };

  const handleViewMediator = () => {
    if (wizardState.mediator?.id) {
      navigate(`/mediators/${wizardState.mediator.id}`);
    }
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
            <p className="text-muted">Creating mediator...</p>
          </div>
        </div>
      );
    }

    switch (wizardState.currentStep) {
      case 'enter-did':
        return <EnterDidStep onNext={handleDidEntered} onCancel={handleCancel} />;
      case 'resolve':
        return (
          <ResolveStep
            did={wizardState.did!}
            onResolved={handleDidResolved}
            onBack={prevStep}
            onCancel={handleCancel}
          />
        );
      case 'configure':
        return (
          <ConfirmStep
            did={wizardState.did!}
            didDocument={wizardState.didDocument}
            onConfirm={handleConfigure}
            onBack={prevStep}
            onCancel={handleCancel}
          />
        );
      case 'complete':
        return (
          <CompleteStep
            mediator={wizardState.mediator}
            onFinish={handleFinish}
            onViewMediator={handleViewMediator}
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
          <i className="fas fa-exchange-alt me-2"></i>
          Add Mediator
        </h1>
      </div>
      <p className="text-muted mb-4">
        Enter the DID of a mediator service, often provided by your DIDComm infrastructure operator.
        We'll resolve its DID document and warn you if it doesn't look like it supports mediation,
        but you can still continue.
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

export default AddMediatorWizardPage;
