import React from 'react';
import PaymentGatewayOfferSummary from '../../components/payment-gateways/PaymentGatewayOfferSummary';
import {
  GATEWAY_INFO_PROBLEM_TEXT,
  usePaymentGatewayInfo,
} from '../../components/payment-gateways/usePaymentGatewayInfo';
import type { GatewayListItem } from '../../utils/gateways';

/** What an active payment gateway offers; a failed read never blocks the list. */
const PaymentGatewayOfferCell: React.FC<{ gateway: GatewayListItem }> = ({ gateway }) => {
  const active = gateway.status === 'active';
  const { info, loading, problem } = usePaymentGatewayInfo(gateway.id, active);

  if (!active) return <span className="text-muted">—</span>;
  if (loading) {
    return (
      <span
        className="spinner-border spinner-border-sm text-muted"
        role="status"
        data-testid={`payment-gateways-offer-loading-${gateway.id}`}
      >
        <span className="visually-hidden">Loading</span>
      </span>
    );
  }
  if (problem || !info) {
    return (
      <small
        className="text-warning"
        title={GATEWAY_INFO_PROBLEM_TEXT[problem ?? 'failed']}
        data-testid={`payment-gateways-offer-error-${gateway.id}`}
      >
        <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
        {problem === 'unreachable' ? 'Not reachable' : 'Offer unavailable'}
      </small>
    );
  }
  return (
    <>
      <PaymentGatewayOfferSummary info={info} testId={`payment-gateways-offer-${gateway.id}`} />
      {info.payable_count === 0 && (
        <small
          className="text-warning d-block"
          data-testid={`payment-gateways-offer-empty-${gateway.id}`}
        >
          Exposes no payment surface to this gateway
        </small>
      )}
    </>
  );
};

export default PaymentGatewayOfferCell;
