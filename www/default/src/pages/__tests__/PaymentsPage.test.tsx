import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import PaymentsPage from '../PaymentsPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
  },
}));

jest.mock('react-chartjs-2', () => ({
  Bar: () => null,
}));

let mockGrantedPermissions: string[] = [];
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    permissions: {},
    loading: false,
    error: null,
    refetchPermissions: jest.fn(),
    hasPermission: (feature: string) => mockGrantedPermissions.includes(feature),
  }),
}));

const verification = {
  id: 'ver-1',
  type: 'verification',
  status: 'verified',
  channel_id: 'surface-1',
  amount: '1000',
  decimals: 6,
  asset: 'USDC',
  network: 'base-sepolia',
  created_at: 1_700_000_000,
};

function mockPayments() {
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) => {
    if (url.startsWith('/api/admin/x402/payments/all')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ payments: [verification], total: 1 }),
      });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({ transactions: [] }) });
  });
}

function renderPage() {
  return render(
    <MemoryRouter>
      <PaymentsPage />
    </MemoryRouter>
  );
}

describe('PaymentsPage transaction deletion', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPayments();
  });

  it('offers deletion to a caller holding payments.delete', async () => {
    mockGrantedPermissions = ['payments.view', 'payments.delete'];
    renderPage();
    expect(await screen.findByTitle('Delete Transaction')).toBeInTheDocument();
  });

  it('hides deletion from a caller who can only read payments', async () => {
    mockGrantedPermissions = ['payments.view'];
    renderPage();
    expect(await screen.findByText('surface-1')).toBeInTheDocument();
    expect(screen.queryByTitle('Delete Transaction')).not.toBeInTheDocument();
  });
});
