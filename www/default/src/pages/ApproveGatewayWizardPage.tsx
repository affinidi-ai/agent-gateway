import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import EnterDetailsStep from '../components/gateway-approve/EnterDetailsStep';
import ApproveStep from '../components/gateway-approve/ApproveStep';
import CompleteStep from '../components/gateway-approve/CompleteStep';
import { AppButton } from '../components/shared/AppButton';

// Define wizard steps
type WizardStep = 'enter-details' | 'approve' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  name: string | null;
  description: string | null;
  gateway: any;
}

const ApproveGatewayWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'enter-details',
    name: null,
    description: null,
    gateway: null,
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pendingGateway, setPendingGateway] = useState<any>(null);

  // Load the pending gateway details
  useEffect(() => {
    const loadGateway = async () => {
      try {
        const response = await apiClient.get(`/gateways/${id}`);
        if (response.data.status !== 'awaiting-approval') {
          setError('This gateway is not awaiting approval');
          return;
        }
        setPendingGateway(response.data);
        setWizardState(prev => ({
          ...prev,
          name: response.data.name || '',
          description: response.data.description || '',
        }));
      } catch (err: any) {
        console.error('Failed to load gateway:', err);
        const errorMsg = err.message || err.response?.data || 'Failed to load gateway';
        setError(errorMsg);
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      loadGateway();
    }
  }, [id]);

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'enter-details', label: 'Enter Details' },
    { key: 'approve', label: 'Approve' },
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

  const handleDetailsEntered = (name: string, description: string) => {
    setWizardState(prev => ({ ...prev, name, description }));
    nextStep();
  };

  const handleApproved = (gateway: any) => {
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
    if (loading) {
      return (
        <div className="card shadow">
          <div className="card-body text-center">
            <div className="spinner-border text-primary" role="status">
              <span className="sr-only">Loading...</span>
            </div>
            <p className="mt-3 text-muted">Loading gateway details...</p>
          </div>
        </div>
      );
    }

    if (error || !pendingGateway) {
      return (
        <div className="card shadow">
          <div className="card-body">
            <div className="alert alert-danger">{error || 'Gateway not found'}</div>
            <AppButton
              variant="secondary"
              size="md"
              onClick={handleCancel}
              iconStart={<i className="fas fa-arrow-left"></i>}
            >
              Back to Gateways
            </AppButton>
          </div>
        </div>
      );
    }

    switch (wizardState.currentStep) {
      case 'enter-details':
        return (
          <EnterDetailsStep
            onNext={handleDetailsEntered}
            onCancel={handleCancel}
            initialName={wizardState.name || ''}
            initialDescription={wizardState.description || ''}
            gatewayDid={pendingGateway.did}
          />
        );
      case 'approve':
        return (
          <ApproveStep
            gatewayId={id!}
            name={wizardState.name || ''}
            description={wizardState.description || ''}
            gatewayDid={pendingGateway.did}
            onApproved={handleApproved}
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
          <i className="fas fa-check-circle me-2"></i>
          Approve Gateway Connection
        </h1>
      </div>
      <p className="text-muted mb-4">
        Another gateway has requested to connect to this one. Approving creates a two-way connection
        over the fabric (the gateway-to-gateway network this appliance participates in). You can
        disable it later from the Gateways list.
      </p>

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
                      <i className="fas fa-check me-1"></i>
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

export default ApproveGatewayWizardPage;
