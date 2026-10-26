import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import PaymentPanel from '../payment/PaymentPanel';
import type { PaymentNodeConfig } from '../payment/types';
import type { CanvasNode } from '../types';
import { apiClient } from '../../../../api';
import type { PaymentManifest } from '../../../../types';

jest.mock('../../../../api', () => ({
  apiClient: {
    get: jest.fn(),
    getPaymentManifest: jest.fn(),
  },
}));

const mockGet = apiClient.get as jest.Mock;
const mockManifest = apiClient.getPaymentManifest as jest.Mock;

const manifest = (
  amount: string,
  points = [{ id: 'x402:base', label: 'USDC on Base' }]
): PaymentManifest => ({
  version: '1',
  payable: { id: 'pay-ch', name: 'Premium tools' },
  amount: { amount, unit: 'USDC' },
  payment_points: points.map(p => ({
    ...p,
    protocol: 'x402' as const,
    credential: 'eip3009_signature',
    detail: { kind: 'onChain' as const, scheme: 'exact', network: 'base', pay_to: '0xabc' },
  })),
  variants: [{ alias: 'eu', name: 'Europe', is_default: false }],
});

function mockDiscovery() {
  mockGet.mockImplementation((url: string) => {
    if (url === '/gateways') {
      return Promise.resolve({
        data: [
          { id: 'gw-pay', name: 'Agent Pay', gateway_type: 'remote', creation_type: 'user' },
          { id: 'gw-other', name: 'Other', gateway_type: 'remote', creation_type: 'user' },
          { id: 'gw-local', name: 'Local', gateway_type: 'local', creation_type: 'system' },
        ],
      });
    }
    if (url === '/gateways/payment-providers') return Promise.resolve({ data: [{ id: 'gw-pay' }] });
    if (url.startsWith('/gateways/gw-pay/surfaces')) {
      return Promise.resolve({
        data: [
          { config_id: 'pay-ch', name: 'pay-ch', is_payment_surface: true },
          { config_id: 'card-ch', name: 'card-ch', payment_manifest: manifest('1.00') },
          { config_id: 'free-ch', name: 'free-ch', is_payment_surface: false },
        ],
      });
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

const updates: Array<Record<string, unknown>> = [];
let lastConfig: PaymentNodeConfig = {};

const node: CanvasNode = { id: 'pay', type: 'payment', label: 'Payment', configured: true };

const Harness: React.FC<{ initial: PaymentNodeConfig; protocol?: 'mcp' | 'a2a' }> = ({
  initial,
  protocol = 'mcp',
}) => {
  const [config, setConfig] = useState<PaymentNodeConfig>(initial);
  lastConfig = config;
  const apply = (fields: Record<string, unknown>) => {
    updates.push(fields);
    setConfig(c => ({ ...c, ...fields }));
  };
  return (
    <MemoryRouter>
      <PaymentPanel
        node={node}
        config={config}
        updateField={(field, value) => apply({ [field]: value })}
        updateFields={apply}
        protocol={protocol}
        openFullscreenEditor={jest.fn()}
      />
    </MemoryRouter>
  );
};

beforeEach(() => {
  jest.clearAllMocks();
  updates.length = 0;
  mockDiscovery();
});

describe('PaymentPanel', () => {
  it('lists only payment gateways and payment surfaces', async () => {
    render(<Harness initial={{}} />);

    const gatewaySelect = await screen.findByTestId('payment-gateway-select');
    await waitFor(() => expect(within(gatewaySelect).queryByText('Other')).not.toBeInTheDocument());
    expect(within(gatewaySelect).getByText('Agent Pay')).toBeInTheDocument();
    expect(within(gatewaySelect).queryByText('Local')).not.toBeInTheDocument();

    fireEvent.change(gatewaySelect, { target: { value: 'gw-pay' } });
    const surfaceSelect = await screen.findByTestId('payment-surface-select');
    await waitFor(() => expect(within(surfaceSelect).getByText('pay-ch')).toBeInTheDocument());
    expect(within(surfaceSelect).getByText('card-ch')).toBeInTheDocument();
    expect(within(surfaceSelect).queryByText('free-ch')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('payment-only-filter-toggle'));
    await waitFor(() => expect(within(surfaceSelect).getByText('free-ch')).toBeInTheDocument());
  });

  it('previews the live manifest of the chosen surface', async () => {
    mockManifest.mockResolvedValue(manifest('0.01'));
    render(<Harness initial={{ payment_gateway_id: 'gw-pay' }} />);

    const surfaceSelect = await screen.findByTestId('payment-surface-select');
    await waitFor(() => expect(within(surfaceSelect).getByText('pay-ch')).toBeInTheDocument());
    fireEvent.change(surfaceSelect, { target: { value: 'pay-ch' } });

    expect(await screen.findByTestId('payment-manifest-amount')).toHaveTextContent('0.01 USDC');
    expect(mockManifest).toHaveBeenCalledWith('gw-pay', 'pay-ch', false);
    const preview = screen.getByTestId('payment-manifest-preview');
    expect(preview).toHaveTextContent('USDC on Base');
    expect(preview).toHaveTextContent('eip3009_signature');
    expect(preview).toHaveTextContent('$eu');
    expect(preview).toHaveTextContent('(live from agent-pay)');
    expect(screen.queryByTestId('payment-manifest-drift')).not.toBeInTheDocument();
  });

  it('shows a manifest error without blocking the panel', async () => {
    mockManifest.mockRejectedValue(new Error('Request timeout'));
    render(<Harness initial={{ payment_gateway_id: 'gw-pay', payment_surface_id: 'pay-ch' }} />);

    expect(await screen.findByTestId('payment-manifest-error')).toHaveTextContent(
      'agent-pay did not answer in time'
    );
    expect(screen.queryByTestId('payment-manifest-amount')).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-configure-triggers-button')).toBeEnabled();
  });

  it.each([
    ['payment_manifest_not_found', 'has no payment manifest for this surface'],
    ['payment_gateway_unavailable', 'not connected or did not answer'],
    ['payment_manifest_rejected', 'could not be used'],
    ['gateway_not_found', 'not known to this gateway'],
    ['invalid_payment_surface_id', 'not a valid payment surface id'],
  ])('maps the %s error code to a readable message', async (code, text) => {
    mockManifest.mockRejectedValue(Object.assign(new Error(`${code} (400)`), { code }));
    render(<Harness initial={{ payment_gateway_id: 'gw-pay', payment_surface_id: 'pay-ch' }} />);

    const error = await screen.findByTestId('payment-manifest-error');
    expect(error).toHaveTextContent(text);
    expect(error).not.toHaveTextContent(code);
  });

  it('shows the saved snapshot and flags drift after a refresh', async () => {
    mockManifest.mockResolvedValue(
      manifest('0.05', [
        { id: 'x402:base', label: 'USDC on Base' },
        { id: 'mpp:stripe:card', label: 'Card' },
      ])
    );
    render(
      <Harness
        initial={{
          payment_gateway_id: 'gw-pay',
          payment_surface_id: 'pay-ch',
          manifest_snapshot: manifest('0.01'),
        }}
      />
    );

    const preview = await screen.findByTestId('payment-manifest-preview');
    expect(preview).toHaveTextContent('(saved snapshot)');
    expect(screen.getByTestId('payment-manifest-amount')).toHaveTextContent('0.01 USDC');
    expect(mockManifest).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('payment-manifest-refresh-button'));

    await waitFor(() => expect(mockManifest).toHaveBeenCalledWith('gw-pay', 'pay-ch', true));
    const drift = await screen.findByTestId('payment-manifest-drift');
    expect(drift).toHaveTextContent('Price changed from 0.01 USDC to 0.05 USDC');
    expect(drift).toHaveTextContent('New payment methods: Card');
    expect(screen.getByTestId('payment-manifest-amount')).toHaveTextContent('0.05 USDC');
  });

  it('accepts a manually entered surface id with a variant alias', async () => {
    mockManifest.mockResolvedValue(null);
    render(<Harness initial={{ payment_gateway_id: 'gw-pay' }} />);

    fireEvent.click(await screen.findByTestId('payment-surface-manual-toggle-button'));
    const input = screen.getByTestId('payment-surface-manual-input');
    expect(input).toHaveAttribute('placeholder', expect.stringContaining('$alias'));
    fireEvent.change(input, { target: { value: 'pay-ch$eu' } });

    expect(await screen.findByTestId('payment-manifest-empty')).toBeInTheDocument();
    expect(mockManifest).toHaveBeenCalledWith('gw-pay', 'pay-ch$eu', false);
    expect(within(screen.getByTestId('payment-surface-select')).getByText(/variant/)).toBeTruthy();
  });

  it('leaves sharing the payer email off by default', async () => {
    render(<Harness initial={{}} />);

    const toggle = await screen.findByTestId('payment-share-email-toggle');
    expect(toggle).not.toBeChecked();
    fireEvent.click(toggle);
    expect(updates).toContainEqual({ share_payer_email: true });
    expect(screen.getByTestId('payment-require-all-toggle')).not.toBeChecked();
    expect(screen.getByTestId('payment-timeout-input')).toHaveAttribute('placeholder', '15000');
  });

  it('flags a local payment policy and migrates it keeping the triggers', async () => {
    render(
      <Harness
        initial={{
          unsupported_legacy: 'x402',
          original: {
            type: 'x402',
            verification_mode: 'mock',
            mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] },
          },
        }}
      />
    );

    expect(screen.getByTestId('payment-legacy-unsupported-banner')).toHaveTextContent(
      'returns 503'
    );
    expect(screen.queryByTestId('payment-gateway-select')).not.toBeInTheDocument();
    expect(mockGet).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('payment-legacy-migrate-button'));

    expect(updates).toEqual([
      {
        unsupported_legacy: undefined,
        original: undefined,
        mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] },
      },
    ]);
    expect(screen.queryByTestId('payment-legacy-unsupported-banner')).not.toBeInTheDocument();
    expect(await screen.findByTestId('payment-gateway-select')).toBeInTheDocument();
    expect(screen.getByTestId('payment-triggers-summary')).toHaveTextContent(
      'Tools matching 1 pattern'
    );
  });

  describe('the saved snapshot', () => {
    const saved = {
      payment_gateway_id: 'gw-pay',
      payment_surface_id: 'pay-ch',
      manifest_snapshot: manifest('0.01'),
    };

    it('is dropped when another payment surface is chosen', async () => {
      mockManifest.mockResolvedValue(manifest('0.05'));
      render(<Harness initial={saved} />);

      expect(await screen.findByTestId('payment-manifest-preview')).toHaveTextContent(
        '(saved snapshot)'
      );
      const surfaceSelect = await screen.findByTestId('payment-surface-select');
      await waitFor(() => expect(within(surfaceSelect).getByText('card-ch')).toBeInTheDocument());

      fireEvent.change(surfaceSelect, { target: { value: 'card-ch' } });

      expect(updates).toStrictEqual([
        { payment_surface_id: 'card-ch', manifest_snapshot: undefined },
      ]);
      await waitFor(() =>
        expect(screen.getByTestId('payment-manifest-preview')).toHaveTextContent(
          '(live from agent-pay)'
        )
      );
      expect(screen.getByTestId('payment-manifest-amount')).toHaveTextContent('0.05 USDC');
      expect(screen.queryByTestId('payment-manifest-drift')).not.toBeInTheDocument();
      expect(mockManifest).toHaveBeenCalledWith('gw-pay', 'card-ch', false);
    });

    it('does not return as the new surface price when the panel is rebuilt after a save', async () => {
      mockManifest.mockResolvedValue(manifest('2.00'));
      const { rerender } = render(<Harness initial={saved} />);
      const surfaceSelect = await screen.findByTestId('payment-surface-select');
      await waitFor(() => expect(within(surfaceSelect).getByText('card-ch')).toBeInTheDocument());
      fireEvent.change(surfaceSelect, { target: { value: 'card-ch' } });
      await screen.findByTestId('payment-manifest-amount');

      rerender(<Harness key="rebuilt" initial={lastConfig} />);

      await waitFor(() =>
        expect(screen.getByTestId('payment-manifest-preview')).toHaveTextContent(
          '(live from agent-pay)'
        )
      );
      expect(screen.getByTestId('payment-manifest-amount')).toHaveTextContent('2.00 USDC');
      expect(screen.getByTestId('payment-manifest-preview')).not.toHaveTextContent(
        '(saved snapshot)'
      );
    });

    it('is dropped, with the surface id, when another gateway is chosen', async () => {
      mockManifest.mockResolvedValue(manifest('0.07'));
      render(<Harness initial={saved} />);
      await screen.findByTestId('payment-manifest-preview');

      fireEvent.click(await screen.findByTestId('payment-only-filter-toggle'));
      const gatewaySelect = screen.getByTestId('payment-gateway-select');
      await waitFor(() => expect(within(gatewaySelect).getByText('Other')).toBeInTheDocument());
      fireEvent.change(gatewaySelect, { target: { value: 'gw-other' } });

      expect(updates).toStrictEqual([
        {
          payment_gateway_id: 'gw-other',
          payment_surface_id: undefined,
          manifest_snapshot: undefined,
        },
      ]);
      expect(lastConfig.payment_surface_id).toBeUndefined();
      expect(screen.queryByTestId('payment-manifest-preview')).not.toBeInTheDocument();
      expect(screen.getByTestId('payment-surface-select')).toHaveValue('');
    });

    it('leaves the surface id alone when the same gateway is chosen again', async () => {
      render(<Harness initial={saved} />);
      const gatewaySelect = await screen.findByTestId('payment-gateway-select');

      fireEvent.change(gatewaySelect, { target: { value: 'gw-pay' } });

      expect(updates).toEqual([]);
      expect(lastConfig.payment_surface_id).toBe('pay-ch');
    });

    it('closes the manual surface entry when another gateway is chosen', async () => {
      mockManifest.mockResolvedValue(null);
      render(<Harness initial={saved} />);

      fireEvent.click(await screen.findByTestId('payment-surface-manual-toggle-button'));
      expect(screen.getByTestId('payment-surface-manual-input')).toHaveValue('pay-ch');

      fireEvent.click(await screen.findByTestId('payment-only-filter-toggle'));
      const gatewaySelect = screen.getByTestId('payment-gateway-select');
      await waitFor(() => expect(within(gatewaySelect).getByText('Other')).toBeInTheDocument());
      fireEvent.change(gatewaySelect, { target: { value: 'gw-other' } });

      expect(screen.queryByTestId('payment-surface-manual-input')).not.toBeInTheDocument();
    });

    it('is dropped when a surface id is typed in', async () => {
      mockManifest.mockResolvedValue(null);
      render(<Harness initial={saved} />);
      await screen.findByTestId('payment-manifest-preview');

      fireEvent.click(await screen.findByTestId('payment-surface-manual-toggle-button'));
      fireEvent.change(screen.getByTestId('payment-surface-manual-input'), {
        target: { value: 'pay-ch$eu' },
      });

      expect(updates).toStrictEqual([
        { payment_surface_id: 'pay-ch$eu', manifest_snapshot: undefined },
      ]);
      expect(await screen.findByTestId('payment-manifest-empty')).toBeInTheDocument();
      expect(screen.getByTestId('payment-manifest-preview')).not.toHaveTextContent(
        '(saved snapshot)'
      );
    });

    it('stays while the selection is untouched', async () => {
      render(<Harness initial={saved} />);

      expect(await screen.findByTestId('payment-manifest-preview')).toHaveTextContent(
        '(saved snapshot)'
      );
      expect(updates).toEqual([]);
      expect(mockManifest).not.toHaveBeenCalled();
    });
  });

  describe('the timeout field', () => {
    const type = async (value: string) => {
      render(<Harness initial={{}} />);
      const input = await screen.findByTestId('payment-timeout-input');
      fireEvent.change(input, { target: { value } });
      return input;
    };

    it('offers the gateway range', async () => {
      render(<Harness initial={{}} />);

      const input = await screen.findByTestId('payment-timeout-input');
      expect(input).toHaveAttribute('min', '1000');
      expect(input).toHaveAttribute('max', '120000');
      expect(input).toHaveAttribute('placeholder', '15000');
      expect(input).not.toHaveClass('is-invalid');
      expect(screen.queryByTestId('payment-timeout-error')).not.toBeInTheDocument();
    });

    it.each(['500', '999', '0', '-1000', '120001', '200000', '1500.5'])(
      'flags %s as outside 1000 to 120000 whole milliseconds',
      async value => {
        const input = await type(value);

        expect(updates).toEqual([{ timeout_ms: Number(value) }]);
        expect(input).toHaveClass('is-invalid');
        expect(screen.getByTestId('payment-timeout-error')).toHaveTextContent(
          'Timeout must be a whole number of milliseconds from 1000 to 120000.'
        );
      }
    );

    it.each(['1000', '15000', '120000'])('accepts %s', async value => {
      const input = await type(value);

      expect(updates).toEqual([{ timeout_ms: Number(value) }]);
      expect(input).not.toHaveClass('is-invalid');
      expect(screen.queryByTestId('payment-timeout-error')).not.toBeInTheDocument();
    });

    it.each(['1000', '1500', '4999'])(
      'warns that %s ms can cut off a slow payment',
      async value => {
        const input = await type(value);

        expect(input).not.toHaveClass('is-invalid');
        expect(screen.getByTestId('payment-timeout-warning')).toHaveTextContent(
          'Below 5000 ms a card or wallet payment can be taken after the gateway stops waiting'
        );
      }
    );

    it.each(['5000', '15000', ''])('does not warn for %s', async value => {
      await type(value);

      expect(screen.queryByTestId('payment-timeout-warning')).not.toBeInTheDocument();
    });

    it('treats an emptied field as the default', async () => {
      render(<Harness initial={{ timeout_ms: 500 }} />);
      const input = await screen.findByTestId('payment-timeout-input');
      expect(screen.getByTestId('payment-timeout-error')).toBeInTheDocument();

      fireEvent.change(input, { target: { value: '' } });

      expect(updates).toEqual([{ timeout_ms: undefined }]);
      expect(screen.queryByTestId('payment-timeout-error')).not.toBeInTheDocument();
    });
  });

  it('notes a disabled local policy and still offers agent-pay', async () => {
    render(<Harness initial={{ preserved_policy: { type: 'x402', enabled: false } }} />);

    expect(screen.getByTestId('payment-disabled-legacy-note')).toHaveTextContent('charges nothing');
    expect(screen.queryByTestId('payment-legacy-unsupported-banner')).not.toBeInTheDocument();
    expect(await screen.findByTestId('payment-gateway-select')).toBeInTheDocument();
  });
});
