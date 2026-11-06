import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PaymentManifestPreview from '../payment/PaymentManifestPreview';
import { paymentLogoUrl } from '../payment/manifest';
import type { PaymentManifest, PaymentPoint } from '../../../../types';

const HASH = 'a'.repeat(64);

const point = (id: string, protocol: 'x402' | 'mpp', sha256?: string): PaymentPoint => ({
  id,
  label: id,
  protocol,
  credential: 'eip3009_signature',
  detail: { kind: 'onChain', scheme: 'exact', network: 'eip155:8453', pay_to: '0xabc' },
  ...(sha256 ? { logo: { id: 'base', media_type: 'image/svg+xml', sha256 } } : {}),
});

const manifest = (points: PaymentPoint[]): PaymentManifest => ({
  version: '1',
  payable: { id: 'pay-ch', name: 'Premium' },
  amount: { amount: '0.01', unit: 'USDC' },
  payment_points: points,
});

const renderPreview = (points: PaymentPoint[]) =>
  render(
    <PaymentManifestPreview
      manifest={manifest(points)}
      source="live"
      loading={false}
      error={null}
      drift={[]}
      onRefresh={jest.fn()}
    />
  );

describe('payment point logos', () => {
  it('shows the logo the payment gateway sent for a point', () => {
    renderPreview([point('x402:base', 'x402', HASH)]);

    expect(screen.getByTestId('payment-manifest-point-logo-x402:base')).toHaveAttribute(
      'src',
      `/api/v1/gateways/payment-logos/${HASH}`
    );
  });

  it('falls back to a generic icon when the logo cannot be loaded', () => {
    renderPreview([point('x402:base', 'x402', HASH)]);

    fireEvent.error(screen.getByTestId('payment-manifest-point-logo-x402:base'));

    expect(screen.queryByTestId('payment-manifest-point-logo-x402:base')).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-manifest-point-icon-x402:base')).toHaveClass('fa-coins');
  });

  it('shows the generic icon for a point without a logo', () => {
    renderPreview([point('mpp:stripe:card', 'mpp')]);

    expect(screen.getByTestId('payment-manifest-point-icon-mpp:stripe:card')).toHaveClass(
      'fa-credit-card'
    );
  });

  it('builds no logo URL from a name that is not a lowercase hex SHA-256', () => {
    expect(paymentLogoUrl(point('p', 'x402', HASH))).toBe(`/api/v1/gateways/payment-logos/${HASH}`);
    expect(paymentLogoUrl(point('p', 'x402', '../../admin'))).toBeNull();
    expect(paymentLogoUrl(point('p', 'x402', HASH.toUpperCase()))).toBeNull();
    expect(paymentLogoUrl(point('p', 'x402'))).toBeNull();
  });
});
