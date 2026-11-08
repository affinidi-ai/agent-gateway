import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PaymentGatewayOfferSummary, {
  paymentMethodLabel,
  payableCountLabel,
} from '../PaymentGatewayOfferSummary';
import { gatewayInfoProblem } from '../usePaymentGatewayInfo';
import { ApiError } from '../../../api';

describe('PaymentGatewayOfferSummary', () => {
  it('lists the protocols, one chip per distinct method and the payment surface count', () => {
    render(
      <PaymentGatewayOfferSummary
        testId="offer"
        info={{
          info_version: '1',
          role: 'payment',
          protocols: ['x402', 'mpp'],
          payment_methods: [
            { protocol: 'x402', kind: 'onChain', network: 'base' },
            { protocol: 'x402', kind: 'onChain', network: 'base' },
            { protocol: 'mpp', kind: 'settled', provider: 'google_pay', settles_via: 'stripe' },
          ],
          payable_count: 2,
          units: ['USDC'],
        }}
      />
    );

    const offer = screen.getByTestId('offer');
    expect(offer).toHaveTextContent('x402');
    expect(offer).toHaveTextContent('MPP');
    expect(screen.getAllByText('base')).toHaveLength(1);
    expect(offer).toHaveTextContent('google_pay via stripe');
    expect(screen.getByTestId('offer-payable-count')).toHaveTextContent('2 payment surfaces');
  });

  it('labels a method with neither network nor provider by its protocol', () => {
    expect(paymentMethodLabel({ protocol: 'mpp', kind: 'settled' })).toBe('MPP');
    expect(payableCountLabel(1)).toBe('1 payment surface');
    expect(payableCountLabel(0)).toBe('0 payment surfaces');
  });
});

describe('gatewayInfoProblem', () => {
  it('tells an unreachable gateway from one that is not a payment gateway', () => {
    expect(gatewayInfoProblem(new ApiError('x', 503))).toBe('unreachable');
    expect(gatewayInfoProblem(new ApiError('x', 502))).toBe('not-payment');
    expect(gatewayInfoProblem(new ApiError('x', 500))).toBe('failed');
    expect(gatewayInfoProblem(new Error('Request timeout'))).toBe('failed');
  });
});
