import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../api';
import type { TrustRecorderStatus } from '../../../types';
import {
  SurfaceMetaProvider,
  type SurfaceMetaValue,
} from '../../surface-builder/SurfaceMetaContext';
import { TrustRecorderLastOutcome } from '../TrustRecorderLastOutcome';

jest.mock('../../../api', () => ({
  apiClient: { getSurfaceTrustRecorderStatus: jest.fn() },
}));

const getStatus = apiClient.getSurfaceTrustRecorderStatus as jest.Mock;

const noop = () => undefined;

const meta = (overrides: Partial<SurfaceMetaValue> = {}): SurfaceMetaValue => ({
  name: 'surface',
  description: '',
  tagsCsv: '',
  status: 'active',
  protocol: 'a2a',
  publishToDid: false,
  terminateTraceId: false,
  issuerId: '',
  didwebvh: {
    enabled: false,
    auto_create: true,
    identity_id: '',
    did_path: '',
    injection_mode: 'header',
  },
  readOnly: false,
  protocolLocked: false,
  isCreate: false,
  surfaceId: 'surface-1',
  setName: noop,
  setDescription: noop,
  setTagsCsv: noop,
  setStatus: noop,
  setProtocol: noop,
  setPublishToDid: noop,
  setTerminateTraceId: noop,
  setIssuerId: noop,
  setDidwebvh: noop,
  ...overrides,
});

const renderOutcome = (value: SurfaceMetaValue | null = meta()) =>
  render(
    value ? (
      <SurfaceMetaProvider value={value}>
        <TrustRecorderLastOutcome />
      </SurfaceMetaProvider>
    ) : (
      <TrustRecorderLastOutcome />
    )
  );

const status = (overrides: Partial<TrustRecorderStatus> = {}): TrustRecorderStatus => ({
  state: 'recorded',
  reason: null,
  last_attempt_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
  entries: [
    {
      trust_registry_id: 'reg-a',
      state: 'recorded',
      reason: null,
      created: 2,
      already_existed: 1,
      failed: 0,
    },
    {
      trust_registry_id: 'reg-b',
      state: 'recorded',
      reason: null,
      created: 1,
      already_existed: 0,
      failed: 0,
    },
  ],
  ...overrides,
});

describe('TrustRecorderLastOutcome', () => {
  beforeEach(() => {
    getStatus.mockReset();
  });

  it('shows a quiet loading state, then the status', async () => {
    getStatus.mockResolvedValue(status());
    renderOutcome();

    expect(screen.getByTestId('trust-recorder-last-outcome')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByTestId('trust-recorder-last-outcome-loading')).toBeInTheDocument();

    expect(await screen.findByTestId('trust-recorder-last-outcome-state')).toHaveTextContent(
      'Recorded'
    );
    expect(screen.getByTestId('trust-recorder-last-outcome')).toHaveAttribute('aria-busy', 'false');
    expect(screen.queryByTestId('trust-recorder-last-outcome-loading')).not.toBeInTheDocument();
    expect(getStatus).toHaveBeenCalledWith('surface-1');
  });

  it('shows the relative time and the totals across entries', async () => {
    getStatus.mockResolvedValue(status());
    renderOutcome();

    expect(await screen.findByTestId('trust-recorder-last-outcome-time')).toHaveTextContent(
      '5 minutes ago'
    );
    expect(screen.getByTestId('trust-recorder-last-outcome-counts')).toHaveTextContent(
      'created 3, already existed 1, failed 0'
    );
    expect(screen.queryByTestId('trust-recorder-last-outcome-reason')).not.toBeInTheDocument();
  });

  it('shows the reason text when the outcome has one', async () => {
    getStatus.mockResolvedValue(
      status({ state: 'skipped', reason: 'no_surface_issuer', entries: [] })
    );
    renderOutcome();

    expect(await screen.findByTestId('trust-recorder-last-outcome-state')).toHaveTextContent(
      'Skipped'
    );
    expect(screen.getByTestId('trust-recorder-last-outcome-reason')).toHaveTextContent(
      'Surface has no Issuer'
    );
    expect(screen.queryByTestId('trust-recorder-last-outcome-counts')).not.toBeInTheDocument();
  });

  it('shows the failed state with its reason', async () => {
    getStatus.mockResolvedValue(status({ state: 'failed', reason: 'rejected' }));
    renderOutcome();

    expect(await screen.findByTestId('trust-recorder-last-outcome-state')).toHaveTextContent(
      'Failed'
    );
    expect(screen.getByTestId('trust-recorder-last-outcome-reason')).toHaveTextContent(
      'Registry rejected the record'
    );
  });

  it('says No attempt yet when the gateway has nothing for the surface', async () => {
    getStatus.mockResolvedValue(null);
    renderOutcome();

    expect(await screen.findByTestId('trust-recorder-last-outcome-empty')).toHaveTextContent(
      'No attempt yet'
    );
    expect(screen.queryByTestId('trust-recorder-last-outcome-state')).not.toBeInTheDocument();
  });

  it('shows a quiet Status unavailable when the fetch fails', async () => {
    getStatus.mockRejectedValue(new Error('boom'));
    renderOutcome();

    expect(await screen.findByTestId('trust-recorder-last-outcome-unavailable')).toHaveTextContent(
      'Status unavailable'
    );
    expect(screen.queryByText('boom')).not.toBeInTheDocument();
  });

  it('exposes an accessible group name', async () => {
    getStatus.mockResolvedValue(null);
    renderOutcome();

    await screen.findByTestId('trust-recorder-last-outcome-empty');
    expect(screen.getByRole('group', { name: 'Trust Recorder last outcome' })).toBeInTheDocument();
  });

  it('renders nothing and fetches nothing for a surface that is not saved yet', () => {
    renderOutcome(meta({ isCreate: true }));

    expect(screen.queryByTestId('trust-recorder-last-outcome')).not.toBeInTheDocument();
    expect(getStatus).not.toHaveBeenCalled();
  });

  it('renders nothing when the surface has no id', () => {
    renderOutcome(meta({ surfaceId: undefined }));

    expect(screen.queryByTestId('trust-recorder-last-outcome')).not.toBeInTheDocument();
    expect(getStatus).not.toHaveBeenCalled();
  });

  it('renders nothing outside the surface builder', () => {
    renderOutcome(null);

    expect(screen.queryByTestId('trust-recorder-last-outcome')).not.toBeInTheDocument();
    expect(getStatus).not.toHaveBeenCalled();
  });

  it('drops the previous surface status while another one loads', async () => {
    getStatus.mockResolvedValueOnce(status());
    const { rerender } = renderOutcome(meta({ surfaceId: 'surface-1' }));
    await screen.findByTestId('trust-recorder-last-outcome-state');

    getStatus.mockReturnValueOnce(new Promise(() => undefined));
    rerender(
      <SurfaceMetaProvider value={meta({ surfaceId: 'surface-2' })}>
        <TrustRecorderLastOutcome />
      </SurfaceMetaProvider>
    );

    await waitFor(() => expect(getStatus).toHaveBeenLastCalledWith('surface-2'));
    expect(screen.getByTestId('trust-recorder-last-outcome-loading')).toBeInTheDocument();
    expect(screen.queryByTestId('trust-recorder-last-outcome-state')).not.toBeInTheDocument();
  });
});
