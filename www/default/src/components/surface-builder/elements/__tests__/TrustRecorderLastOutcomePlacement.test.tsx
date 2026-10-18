import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import TrustRecorderPanel from '../trust-recorder/TrustRecorderPanel';
import TrustRecorderFullscreenPanel from '../trust-recorder/TrustRecorderFullscreenPanel';

jest.mock('../../../../api', () => ({
  apiClient: {
    getSurfaceTrustRecorderStatus: jest.fn(),
    listTrustRegistries: jest.fn(),
    listIssuers: jest.fn(),
    listAuthorities: jest.fn(),
  },
}));

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

const props = (): ConfigPanelProps => ({
  node: { id: 'tr-1', type: 'trust-recorder', label: '', configured: true, config: {} },
  config: {},
  updateField: jest.fn(),
  updateFields: jest.fn(),
  openFullscreenEditor: jest.fn(),
  closeFullscreenEditor: jest.fn(),
});

const inSurface = (ui: React.ReactElement, value: SurfaceMetaValue) =>
  render(<SurfaceMetaProvider value={value}>{ui}</SurfaceMetaProvider>);

describe('Trust Recorder Last outcome placement', () => {
  beforeEach(() => {
    (apiClient.getSurfaceTrustRecorderStatus as jest.Mock).mockResolvedValue({
      state: 'skipped',
      reason: 'no_surface_issuer',
      last_attempt_at: null,
      entries: [],
    });
    (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([]);
    (apiClient.listIssuers as jest.Mock).mockResolvedValue([]);
    (apiClient.listAuthorities as jest.Mock).mockResolvedValue([]);
  });

  it('shows the last outcome in the sidebar panel of a saved surface', async () => {
    inSurface(<TrustRecorderPanel {...props()} />, meta());

    expect(await screen.findByTestId('trust-recorder-last-outcome-state')).toHaveTextContent(
      'Skipped'
    );
    expect(screen.getByTestId('trust-recorder-last-outcome-reason')).toHaveTextContent(
      'Surface has no Issuer'
    );
  });

  it('shows the last outcome in the fullscreen panel of a saved surface', async () => {
    inSurface(<TrustRecorderFullscreenPanel {...props()} />, meta());

    expect(await screen.findByTestId('trust-recorder-last-outcome-state')).toHaveTextContent(
      'Skipped'
    );
  });

  it('hides it in both panels while the surface is still being created', () => {
    const create = meta({ isCreate: true });
    const { unmount } = inSurface(<TrustRecorderPanel {...props()} />, create);
    expect(screen.queryByTestId('trust-recorder-last-outcome')).not.toBeInTheDocument();
    unmount();

    inSurface(<TrustRecorderFullscreenPanel {...props()} />, create);
    expect(screen.queryByTestId('trust-recorder-last-outcome')).not.toBeInTheDocument();
    expect(apiClient.getSurfaceTrustRecorderStatus).not.toHaveBeenCalled();
  });

  it('keeps the panel usable when the status cannot be loaded', async () => {
    (apiClient.getSurfaceTrustRecorderStatus as jest.Mock).mockRejectedValue(new Error('down'));
    inSurface(<TrustRecorderPanel {...props()} />, meta());

    expect(await screen.findByTestId('trust-recorder-last-outcome-unavailable')).toHaveTextContent(
      'Status unavailable'
    );
    expect(screen.getByTestId('trust-recorder-panel-configure')).toBeEnabled();
  });
});
