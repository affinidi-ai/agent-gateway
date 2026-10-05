import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import SelectMediatorStep from '../components/gateway-create-connection-point/SelectMediatorStep';
import EnterDetailsStep from '../components/gateway-create-connection-point/EnterDetailsStep';
import {
  integrationIntegration,
  IntegrationsStep,
} from '../components/connection-points/IntegrationsStep';
import CompleteStep from '../components/gateway-create-connection-point/CompleteStep';
import { getRuntimeVariablesForCategories } from '../utils/runtimeVariables';
import { AppButton } from '../components/shared/AppButton';
import { Link } from '../components/shared/Link';

// Define wizard steps
type WizardStep = 'select-mediator' | 'enter-details' | 'integrations' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  mediatorId: string | null;
  gatewayId: string | null;
  name: string;
  description: string;
  secret: string;
  expirySeconds?: number;
  didMethod: string;
  integrations: integrationIntegration[];
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
    integrations: [] as any[],
    connectionPoint: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [integrationValidationErrors, setIntegrationValidationErrors] = useState(false);
  const [runtimeVariables, setRuntimeVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});

  // Fetch integrations and runtime variables for integrations step
  useEffect(() => {
    const fetchIntegrations = async () => {
      try {
        const response = await apiClient.get('/integrations');
        setIntegrations(response.data || []);
      } catch (err) {
        console.error('Failed to fetch integrations:', err);
      }
    };

    const fetchRuntimeVars = async () => {
      try {
        const vars = await getRuntimeVariablesForCategories(['general', 'connection_point']);
        setRuntimeVariables(vars);
      } catch (err) {
        console.error('Failed to fetch runtime variables:', err);
      }
    };

    fetchIntegrations();
    fetchRuntimeVars();
  }, []);

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'select-mediator', label: 'Select Mediator' },
    { key: 'enter-details', label: 'Enter Details' },
    { key: 'integrations', label: 'Integrations' },
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

  const handleDetailsSubmit = (
    gatewayId: string,
    name: string,
    description: string,
    secret: string,
    expirySeconds?: number,
    didMethod?: string
  ) => {
    setWizardState(prev => ({
      ...prev,
      gatewayId,
      name,
      description,
      secret,
      expirySeconds,
      didMethod: didMethod || 'web',
    }));
    nextStep();
  };

  const handleIntegrationsSubmit = () => {
    nextStep();
  };

  const handleCreate = async () => {
    try {
      setSaving(true);
      setError('');

      // Create the connection point via the API
      const payload: any = {
        gateway_id: wizardState.gatewayId,
        mediator_id: wizardState.mediatorId,
        name: wizardState.name,
        description: wizardState.description,
        secret: wizardState.secret,
        expiry_seconds: wizardState.expirySeconds,
        integrations: wizardState.integrations,
        did_method: wizardState.didMethod,
      };

      const response = await apiClient.post('/connection-points', payload);

      setWizardState(prev => ({
        ...prev,
        connectionPoint: response.data.connection_point,
      }));
      nextStep();
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
      case 'integrations':
        return (
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-plug me-2"></i>
                Integrations
              </h6>
            </div>
            <div className="card-body">
              <p className="text-muted mb-4">
                Integrations let this connection point forward events, such as notifications, to
                external services like email or Slack. As this step is optional, you can add or
                change integrations later from the{' '}
                <Link href="/integrations" variant="inline" external>
                  Integrations page
                </Link>
                .
              </p>
              <IntegrationsStep
                integrations={wizardState.integrations}
                onChange={integrations => setWizardState(prev => ({ ...prev, integrations }))}
                availableIntegrations={integrations}
                onValidationChange={setIntegrationValidationErrors}
                runtimeVariables={runtimeVariables}
                category="connection_point"
                bareSelector
              />
              <div className="mt-4 d-flex justify-content-between">
                <AppButton
                  variant="secondary"
                  size="md"
                  onClick={handleCancel}
                  iconStart={<i className="fas fa-times"></i>}
                >
                  Cancel
                </AppButton>
                <div className="d-flex gap-2">
                  <AppButton
                    variant="secondary"
                    size="md"
                    onClick={prevStep}
                    iconStart={<i className="fas fa-arrow-left"></i>}
                  >
                    Back
                  </AppButton>
                  <AppButton
                    variant="primary"
                    size="md"
                    onClick={handleCreate}
                    disabled={integrationValidationErrors}
                    title={
                      integrationValidationErrors
                        ? 'Please fill in all integration variable values'
                        : ''
                    }
                    iconStart={<i className="fas fa-check"></i>}
                  >
                    Create
                  </AppButton>
                </div>
              </div>
            </div>
          </div>
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
