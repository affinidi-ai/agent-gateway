import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import './OnboardWizard.css';
import { apiClient } from '../api';
import WizardProgress from '../components/shared/WizardProgress';
import MediatorAccessStep, { MediatorAccessRefusal } from '../components/shared/MediatorAccessStep';
import { ADD_GATEWAY_DID_LABELS, MediatorAccess, labelledDids } from '../utils/mediatorAccess';

// Import step components
import EnterDetailsStep from '../components/gateway-add-via-oob/EnterDetailsStep';
import EnterOOBLinkStep from '../components/gateway-add-via-oob/EnterOOBLinkStep';
import ConnectStep from '../components/gateway-add-via-oob/ConnectStep';
import CompleteStep from '../components/gateway-add-via-oob/CompleteStep';

// Define wizard steps
type WizardStep = 'enter-details' | 'enter-link' | 'mediator-access' | 'connect' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  name: string | null;
  description: string | null;
  didMethod: string;
  acceptorMediatorId: string;
  oobLink: string | null;
  secret: string | null;
  gateway: any;
  mediatorAccess: MediatorAccess | null;
}

const AddGatewayViaOOBWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const resumeId = searchParams.get('resume');

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'enter-details',
    name: null,
    description: null,
    didMethod: 'web',
    acceptorMediatorId: '',
    oobLink: null,
    secret: null,
    gateway: null,
    mediatorAccess: null,
  });

  const [error, setError] = useState('');
  const [pausing, setPausing] = useState(false);
  const [refusal, setRefusal] = useState<MediatorAccessRefusal | null>(null);

  useEffect(() => {
    if (!resumeId) return;
    const resume = async () => {
      try {
        setPausing(true);
        const [gateway, access] = await Promise.all([
          apiClient.get(`/gateways/${resumeId}`),
          apiClient.get<MediatorAccess>(`/gateways/${resumeId}/mediator-access`),
        ]);
        setWizardState(prev => ({
          ...prev,
          name: gateway.data.name,
          description: gateway.data.description,
          gateway: gateway.data,
          mediatorAccess: access.data,
          currentStep: 'mediator-access',
        }));
      } catch (err: any) {
        setError(err.message || 'Failed to load the gateway.');
      } finally {
        setPausing(false);
      }
    };
    resume();
  }, [resumeId]);

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'enter-details', label: 'Enter Details' },
    { key: 'enter-link', label: 'Enter Connection Point Link' },
    { key: 'mediator-access', label: 'Mediator Access' },
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

  const handleDetailsEntered = (
    name: string,
    description: string,
    didMethod: string,
    acceptorMediatorId: string
  ) => {
    setWizardState(prev => ({ ...prev, name, description, didMethod, acceptorMediatorId }));
    nextStep();
  };

  /** Accepts the link up to the pause: the gateway mints its DIDs and waits for the mediator. */
  const handleOOBLinkEntered = async (link: string, secret: string) => {
    setWizardState(prev => ({ ...prev, oobLink: link, secret }));
    try {
      setPausing(true);
      setError('');
      const response = await apiClient.post('/gateways/connect-via-oob', {
        oob_url: link,
        secret,
        name: wizardState.name,
        description: wizardState.description,
        did_method: wizardState.didMethod || 'web',
        acceptor_mediator_id: wizardState.acceptorMediatorId || undefined,
        await_mediator_access: true,
      });
      const access: MediatorAccess | undefined = response.data.mediator_access;
      setWizardState(prev => ({
        ...prev,
        gateway: response.data.gateway,
        mediatorAccess: access ?? null,
        currentStep: access ? 'mediator-access' : 'complete',
      }));
    } catch (err: any) {
      setError(err.message || 'Failed to accept the connection point link.');
    } finally {
      setPausing(false);
    }
  };

  const handleMediatorAccessConfirmed = () => {
    setRefusal(null);
    goToStep('connect');
  };

  const handleRefused = (refused: MediatorAccessRefusal) => {
    setRefusal(refused);
    goToStep('mediator-access');
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
    if (pausing) {
      return (
        <div className="card shadow">
          <div className="card-body text-center py-5">
            <div className="spinner-border text-primary mb-3" role="status">
              <span className="visually-hidden"></span>
            </div>
            <p className="text-muted">Preparing the connection...</p>
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
            initialDidMethod={wizardState.didMethod}
            initialAcceptorMediatorId={wizardState.acceptorMediatorId}
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
      case 'mediator-access':
        return wizardState.mediatorAccess ? (
          <MediatorAccessStep
            dids={labelledDids(wizardState.mediatorAccess, ADD_GATEWAY_DID_LABELS)}
            mediatorName={wizardState.mediatorAccess.mediator_name}
            expiresAt={wizardState.mediatorAccess.expires_at}
            note="This is the inviting gateway's mediator, so its administrator may be in another organisation."
            refusal={refusal}
            continuing={false}
            onContinue={handleMediatorAccessConfirmed}
            onLater={handleCancel}
          />
        ) : null;
      case 'connect':
        return (
          <ConnectStep
            continueGatewayId={wizardState.gateway?.id}
            onRefused={handleRefused}
            oobLink={wizardState.oobLink || ''}
            secret={wizardState.secret || ''}
            name={wizardState.name || ''}
            description={wizardState.description || ''}
            didMethod={wizardState.didMethod}
            acceptorMediatorId={wizardState.acceptorMediatorId}
            onConnected={handleConnected}
            onBack={() => goToStep('mediator-access')}
            onCancel={handleCancel}
          />
        );
      case 'complete':
        return <CompleteStep onFinish={handleFinish} onViewGateway={handleViewGateway} />;
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid" data-testid="page-gateway-connect">
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

      <WizardProgress steps={steps} currentIndex={currentStepIndex} />

      {/* Step Content */}
      <div className="wizard-content">{renderStep()}</div>
      <br />
    </div>
  );
};

export default AddGatewayViaOOBWizardPage;
