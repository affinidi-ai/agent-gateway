import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import './OnboardWizard.css';
import WizardProgress from '../components/shared/WizardProgress';
import EnterDetailsStep from '../components/gateway-add-via-oob/EnterDetailsStep';
import EnterOOBLinkStep from '../components/gateway-add-via-oob/EnterOOBLinkStep';
import ConnectStep from '../components/gateway-add-via-oob/ConnectStep';
import CompleteStep from '../components/gateway-add-via-oob/CompleteStep';
import { ROUTES, paymentGatewayPath } from '../routes';
import type { GatewayRecord } from '../utils/gateways';
import AwaitApprovalStep from './AddPaymentGatewayWizardPage/AwaitApprovalStep';
import VerifyPaymentGatewayStep from './AddPaymentGatewayWizardPage/VerifyPaymentGatewayStep';
import {
  COMPLETE_WORDING,
  DETAILS_WORDING,
  LINK_WORDING,
} from './AddPaymentGatewayWizardPage/wording';

type WizardStep = 'enter-details' | 'enter-link' | 'connect' | 'approval' | 'verify' | 'complete';

const STEPS: ReadonlyArray<{ key: WizardStep; label: string }> = [
  { key: 'enter-details', label: 'Enter Details' },
  { key: 'enter-link', label: 'Connection Point Link' },
  { key: 'connect', label: 'Connect' },
  { key: 'approval', label: 'Awaiting Approval' },
  { key: 'verify', label: 'Verify' },
  { key: 'complete', label: 'Complete' },
];

interface Details {
  name: string;
  description: string;
  didMethod: string;
  acceptorMediatorId: string;
  oobLink: string;
  secret: string;
}

/**
 * Connects an agent-pay payment gateway. `?id=<gateway id>` resumes a created
 * one at the approval step, which moves on to Verify once it is active.
 */
const AddPaymentGatewayWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const resumeId = searchParams.get('id') ?? '';
  const [step, setStep] = useState<WizardStep>(resumeId ? 'approval' : 'enter-details');
  const [gatewayId, setGatewayId] = useState(resumeId);
  const [details, setDetails] = useState<Details>({
    name: '',
    description: '',
    didMethod: 'web',
    acceptorMediatorId: '',
    oobLink: '',
    secret: '',
  });

  const currentIndex = STEPS.findIndex(s => s.key === step);
  const leave = () => navigate(ROUTES.PAYMENT_GATEWAYS_TAB);

  const handleConnected = (gateway: GatewayRecord) => {
    setGatewayId(gateway.id);
    setSearchParams({ id: gateway.id }, { replace: true });
    setStep('approval');
  };

  const renderStep = () => {
    switch (step) {
      case 'enter-details':
        return (
          <EnterDetailsStep
            onNext={(name, description, didMethod, acceptorMediatorId) => {
              setDetails(prev => ({ ...prev, name, description, didMethod, acceptorMediatorId }));
              setStep('enter-link');
            }}
            onCancel={leave}
            initialName={details.name}
            initialDescription={details.description}
            initialDidMethod={details.didMethod}
            initialAcceptorMediatorId={details.acceptorMediatorId}
            wording={DETAILS_WORDING}
          />
        );
      case 'enter-link':
        return (
          <EnterOOBLinkStep
            onNext={(oobLink, secret) => {
              setDetails(prev => ({ ...prev, oobLink, secret }));
              setStep('connect');
            }}
            onBack={() => setStep('enter-details')}
            onCancel={leave}
            initialLink={details.oobLink}
            initialSecret={details.secret}
            wording={LINK_WORDING}
          />
        );
      case 'connect':
        return (
          <ConnectStep
            oobLink={details.oobLink}
            secret={details.secret}
            name={details.name}
            description={details.description}
            didMethod={details.didMethod}
            acceptorMediatorId={details.acceptorMediatorId}
            onConnected={handleConnected}
            onBack={() => setStep('enter-link')}
            onCancel={leave}
            endpoint="/payment-gateways/connect-via-oob"
            title="Connecting to Payment Gateway"
          />
        );
      case 'approval':
        return (
          <AwaitApprovalStep
            gatewayId={gatewayId}
            onApproved={() => setStep('verify')}
            onLeave={leave}
          />
        );
      case 'verify':
        return (
          <VerifyPaymentGatewayStep
            gatewayId={gatewayId}
            onVerified={() => setStep('complete')}
            onLeave={leave}
          />
        );
      case 'complete':
        return (
          <CompleteStep
            onFinish={leave}
            onViewGateway={() => navigate(paymentGatewayPath(gatewayId))}
            wording={COMPLETE_WORDING}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid" data-testid="wizard-add-payment-gateway">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-credit-card me-2" aria-hidden="true"></i>
          Connect a Payment Gateway
        </h1>
      </div>
      <p className="text-muted mb-4">
        Connect to an agent-pay payment gateway with the Connection Point Link, and its connection
        secret, that agent-pay&apos;s administrator shared with you. Once they approve the
        connection, surfaces on this gateway can charge through it.
      </p>

      <WizardProgress steps={STEPS} currentIndex={currentIndex} />

      <div className="wizard-content">{renderStep()}</div>
      <br />
    </div>
  );
};

export default AddPaymentGatewayWizardPage;
