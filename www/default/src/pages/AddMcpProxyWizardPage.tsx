import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import NameStep from '../components/mcp-proxy/NameStep';
import ConfigureStep from '../components/mcp-proxy/ConfigureStep';
import ApiSpecStep from '../components/mcp-proxy/ApiSpecStep';
import CompleteStep from '../components/mcp-proxy/CompleteStep';

// Define wizard steps
type WizardStep = 'name' | 'configure' | 'api-spec' | 'creating' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  name: string;
  description: string;
  selectedHostPort: string;
  selectedPrefix: string;
  customPath: string;
  baseUrl: string;
  directAccess: boolean;
  proxy: any;
}

const AddMcpProxyWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'name',
    name: '',
    description: '',
    selectedHostPort: '',
    selectedPrefix: '',
    customPath: '',
    baseUrl: '',
    directAccess: true,
    proxy: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'name', label: 'Name' },
    { key: 'configure', label: 'Configure' },
    { key: 'api-spec', label: 'API Spec' },
    { key: 'creating', label: 'Creating' },
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

  const handleNameEntered = (name: string, description: string) => {
    setWizardState(prev => ({ ...prev, name, description }));
    nextStep();
  };

  const handleConfigured = (
    selectedHostPort: string,
    selectedPrefix: string,
    customPath: string,
    baseUrl: string,
    directAccess: boolean
  ) => {
    setWizardState(prev => ({
      ...prev,
      selectedHostPort,
      selectedPrefix,
      customPath,
      baseUrl,
      directAccess,
    }));
    nextStep();
  };

  const handleApiSpecEntered = async (openApiSpec: string) => {
    // Update state and move to creating step
    setWizardState(prev => ({ ...prev, currentStep: 'creating' }));

    try {
      setSaving(true);
      setError('');

      // Compute the channel_prefix and endpoint_path from network configuration
      const channelPrefix = wizardState.selectedPrefix;
      const endpointPath = wizardState.customPath;

      // Create the MCP Proxy via the API
      const response = await apiClient.post('/mcp-proxies', {
        name: wizardState.name,
        description: wizardState.description,
        channel_prefix: channelPrefix,
        base_url: wizardState.baseUrl,
        endpoint_path: endpointPath,
        openapi_spec: openApiSpec,
        status: 'active',
        direct_access: wizardState.directAccess,
      });

      setWizardState(prev => ({ ...prev, proxy: response.data, currentStep: 'complete' }));
    } catch (err: any) {
      console.error('Failed to create MCP Proxy:', err);
      setError(err.message || 'Failed to create MCP Proxy. Please try again.');
      // Go back to api-spec step on error
      setWizardState(prev => ({ ...prev, currentStep: 'api-spec' }));
    } finally {
      setSaving(false);
    }
  };

  const handleFinish = () => {
    navigate('/proxies');
  };

  const handleViewProxy = () => {
    if (wizardState.proxy?.id) {
      navigate(`/proxies/mcp-proxies/${wizardState.proxy.id}`);
    }
  };

  const handleCancel = () => {
    navigate('/proxies');
  };

  // Render current step
  const renderStep = () => {
    switch (wizardState.currentStep) {
      case 'name':
        return (
          <NameStep
            initialName={wizardState.name}
            initialDescription={wizardState.description}
            onNext={handleNameEntered}
            onCancel={handleCancel}
          />
        );
      case 'configure':
        return (
          <ConfigureStep
            initialSelectedHostPort={wizardState.selectedHostPort}
            initialSelectedPrefix={wizardState.selectedPrefix}
            initialCustomPath={wizardState.customPath}
            initialBaseUrl={wizardState.baseUrl}
            initialDirectAccess={wizardState.directAccess}
            onNext={handleConfigured}
            onBack={prevStep}
            onCancel={handleCancel}
          />
        );
      case 'api-spec':
        return (
          <ApiSpecStep
            baseUrl={wizardState.baseUrl}
            onNext={handleApiSpecEntered}
            onBack={prevStep}
            onCancel={handleCancel}
          />
        );
      case 'creating':
        return (
          <div className="card shadow">
            <div className="card-body text-center py-5">
              <div className="spinner-border text-primary mb-3" role="status">
                <span className="visually-hidden"></span>
              </div>
              <p className="text-muted">Creating MCP Proxy...</p>
            </div>
          </div>
        );
      case 'complete':
        return (
          <CompleteStep
            proxy={wizardState.proxy}
            onFinish={handleFinish}
            onViewProxy={handleViewProxy}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid">
      {wizardState.currentStep !== 'complete' && (
        <div className="mb-3">
          <button className="btn btn-sm btn-secondary" onClick={handleCancel}>
            <i className="fas fa-arrow-left"></i>
          </button>
        </div>
      )}
      {/* Page Header */}
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-plug me-2"></i>
          Add MCP Proxy Wizard
        </h1>
      </div>

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

export default AddMcpProxyWizardPage;
