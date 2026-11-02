import React from 'react';
import { Badge } from '../shared/Badge';
import type { GatewayInfo, PaymentMethodSummary } from '../../types';

export const protocolLabel = (protocol: string): string =>
  protocol.toLowerCase() === 'mpp' ? 'MPP' : protocol;

/** A payment method as a short chip: the network or provider, and what it settles through. */
export function paymentMethodLabel(method: PaymentMethodSummary): string {
  const where = method.kind === 'onChain' ? method.network : method.provider;
  const via = method.settles_via ? ` via ${method.settles_via}` : '';
  return `${where || protocolLabel(method.protocol)}${via}`;
}

export const payableCountLabel = (count: number): string =>
  count === 1 ? '1 payment surface' : `${count} payment surfaces`;

interface PaymentGatewayOfferSummaryProps {
  info: GatewayInfo;
  testId: string;
}

/** Protocols, payment method chips and the payment surface count a payment gateway offers. */
const PaymentGatewayOfferSummary: React.FC<PaymentGatewayOfferSummaryProps> = ({
  info,
  testId,
}) => {
  const methods = Array.from(new Set((info.payment_methods ?? []).map(paymentMethodLabel)));
  return (
    <div className="d-flex flex-wrap gap-1 align-items-center" data-testid={testId}>
      {(info.protocols ?? []).map(protocol => (
        <Badge key={`p-${protocol}`} value={protocolLabel(protocol)} tone="primary" size="sm" />
      ))}
      {methods.map(label => (
        <Badge key={`m-${label}`} value={label} tone="light" size="sm" />
      ))}
      <span className="small text-muted" data-testid={`${testId}-payable-count`}>
        {payableCountLabel(info.payable_count ?? 0)}
      </span>
    </div>
  );
};

export default PaymentGatewayOfferSummary;
