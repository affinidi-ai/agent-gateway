import React, { useEffect } from 'react';
import PaymentGatewayOfferSummary from '../../components/payment-gateways/PaymentGatewayOfferSummary';
import {
  GATEWAY_INFO_PROBLEM_TEXT,
  usePaymentGatewayInfo,
} from '../../components/payment-gateways/usePaymentGatewayInfo';
import { AppButton } from '../../components/shared/AppButton';

export const VERIFY_RETRY_MS = 5000;

interface VerifyPaymentGatewayStepProps {
  gatewayId: string;
  onVerified: () => void;
  onLeave: () => void;
}

/**
 * Asks the payment gateway what it offers. It passes when the gateway answers
 * as a payment gateway; one exposing no payment surface passes with a warning.
 * An unreachable gateway is asked again by itself.
 */
const VerifyPaymentGatewayStep: React.FC<VerifyPaymentGatewayStepProps> = ({
  gatewayId,
  onVerified,
  onLeave,
}) => {
  const { info, loading, problem, reload } = usePaymentGatewayInfo(gatewayId);

  useEffect(() => {
    if (problem !== 'unreachable') return;
    const timer = setTimeout(reload, VERIFY_RETRY_MS);
    return () => clearTimeout(timer);
  }, [problem, reload]);

  return (
    <div className="card shadow" data-testid="wizard-step-verify">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-check-double me-2" aria-hidden="true"></i> Verify Payment Gateway
        </h6>
      </div>
      <div className="card-body">
        {loading ? (
          <div className="text-center py-4" data-testid="payment-gateway-verify-loading">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Verifying</span>
            </div>
            <p className="text-muted mt-2 mb-0">Asking agent-pay what it offers…</p>
          </div>
        ) : problem ? (
          <div
            className={`alert ${problem === 'unreachable' ? 'alert-warning' : 'alert-danger'}`}
            role="alert"
            data-testid="payment-gateway-verify-error"
          >
            <i className="fas fa-exclamation-circle me-2" aria-hidden="true"></i>
            {GATEWAY_INFO_PROBLEM_TEXT[problem]}
            {problem === 'unreachable' && ' Trying again shortly.'}
          </div>
        ) : (
          info && (
            <>
              {info.payable_count > 0 ? (
                <div
                  className="alert alert-success"
                  role="status"
                  data-testid="payment-gateway-verify-ok"
                >
                  <i className="fas fa-check-circle me-2" aria-hidden="true"></i>
                  agent-pay answered as a payment gateway. Surfaces on this gateway can now charge
                  through it.
                </div>
              ) : (
                <div
                  className="alert alert-warning"
                  role="alert"
                  data-testid="payment-gateway-verify-no-surface"
                >
                  <i className="fas fa-triangle-exclamation me-2" aria-hidden="true"></i>
                  agent-pay is connected but exposes no payment surface to this gateway, so no
                  surface can charge through it yet. In agent-pay, expose a payment surface on the
                  connection point it shared with you, then Re-check.
                </div>
              )}
              <PaymentGatewayOfferSummary info={info} testId="payment-gateway-verify-offer" />
            </>
          )
        )}

        <div className="d-flex justify-content-between mt-4">
          <AppButton
            type="button"
            variant="secondary"
            size="md"
            onClick={onLeave}
            iconStart={<i className="fas fa-arrow-left" aria-hidden="true"></i>}
            data-testid="wizard-cancel"
          >
            Back to Connections
          </AppButton>
          <div className="d-flex gap-2">
            <AppButton
              type="button"
              variant="secondary"
              size="md"
              onClick={reload}
              disabled={loading}
              iconStart={<i className="fas fa-redo" aria-hidden="true"></i>}
              data-testid="payment-gateway-verify-recheck-button"
            >
              Re-check
            </AppButton>
            <AppButton
              type="button"
              variant="primary"
              size="md"
              onClick={onVerified}
              disabled={loading || !info}
              iconEnd={<i className="fas fa-arrow-right" aria-hidden="true"></i>}
              data-testid="wizard-next"
            >
              Next
            </AppButton>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VerifyPaymentGatewayStep;
