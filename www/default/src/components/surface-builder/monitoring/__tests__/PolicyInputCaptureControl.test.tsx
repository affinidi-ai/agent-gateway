import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../../api';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import PolicyInputCaptureControl from '../PolicyInputCaptureControl';

jest.mock('../../../../api', () => ({
  apiClient: {
    setSurfacePolicyInputCapture: jest.fn(),
    clearSurfacePolicyInputCapture: jest.fn(),
  },
}));

let mockGranted: Set<string>;
jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockGranted.has(p), loading: false }),
}));

const setCapture = apiClient.setSurfacePolicyInputCapture as jest.Mock;
const clearCapture = apiClient.clearSurfacePolicyInputCapture as jest.Mock;

function renderControl(
  meta: Partial<SurfaceMetaValue>,
  initialUntil?: string | null,
  onChange?: (until: string | null) => void
) {
  const value = {
    isCreate: false,
    readOnly: false,
    surfaceId: 'surface-1',
    ...meta,
  } as SurfaceMetaValue;
  return render(
    <SurfaceMetaProvider value={value}>
      <PolicyInputCaptureControl initialUntil={initialUntil} onChange={onChange} />
    </SurfaceMetaProvider>
  );
}

const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

beforeEach(() => {
  jest.clearAllMocks();
  mockGranted = new Set(['surfaces.edit', 'policies.edit']);
});

describe('PolicyInputCaptureControl', () => {
  it('is hidden while creating a surface', () => {
    renderControl({ isCreate: true, surfaceId: undefined });
    expect(screen.queryByTestId('policy-input-capture-switch')).not.toBeInTheDocument();
  });

  it('is hidden without a saved surface id', () => {
    renderControl({ surfaceId: undefined });
    expect(screen.queryByTestId('policy-input-capture-switch')).not.toBeInTheDocument();
  });

  it('is disabled without policies.edit', () => {
    mockGranted = new Set(['surfaces.edit']);
    renderControl({});
    expect(screen.getByTestId('policy-input-capture-switch')).toBeDisabled();
  });

  it('shows the stored state but is disabled in read-only mode', () => {
    renderControl({ readOnly: true }, inMinutes(10));
    expect(screen.getByTestId('policy-input-capture-switch')).toBeChecked();
    expect(screen.getByTestId('policy-input-capture-switch')).toBeDisabled();
    expect(screen.getByTestId('policy-input-capture-until')).toHaveTextContent('On until');
  });

  it('shows a stored end time in the past as off', () => {
    renderControl({}, inMinutes(-1));
    expect(screen.getByTestId('policy-input-capture-switch')).not.toBeChecked();
    expect(screen.queryByTestId('policy-input-capture-until')).not.toBeInTheDocument();
  });

  it('says for how long capture runs while it is off', () => {
    renderControl({});
    expect(screen.getByTestId('policy-input-capture-duration')).toHaveTextContent('for 30 minutes');
  });

  it('switching on sends 30 minutes and shows the end time', async () => {
    const until = inMinutes(30);
    const onChange = jest.fn();
    setCapture.mockResolvedValue({
      surface_id: 'surface-1',
      policy_input_capture_until: until,
    });
    renderControl({}, undefined, onChange);

    fireEvent.click(screen.getByTestId('policy-input-capture-switch'));

    expect(await screen.findByTestId('policy-input-capture-until')).toHaveTextContent('On until');
    expect(setCapture).toHaveBeenCalledWith('surface-1', 30);
    expect(screen.getByTestId('policy-input-capture-switch')).toBeChecked();
    expect(onChange).toHaveBeenCalledWith(until);
  });

  it('switching off sends DELETE and shows it off', async () => {
    clearCapture.mockResolvedValue({ surface_id: 'surface-1', policy_input_capture_until: null });
    renderControl({}, inMinutes(10));

    fireEvent.click(screen.getByTestId('policy-input-capture-switch'));

    await waitFor(() =>
      expect(screen.getByTestId('policy-input-capture-switch')).not.toBeChecked()
    );
    expect(clearCapture).toHaveBeenCalledWith('surface-1');
    expect(screen.queryByTestId('policy-input-capture-until')).not.toBeInTheDocument();
  });

  it('shows an inline error when the request fails and stays off', async () => {
    setCapture.mockRejectedValue(new Error('Forbidden'));
    renderControl({});

    fireEvent.click(screen.getByTestId('policy-input-capture-switch'));

    expect(await screen.findByTestId('policy-input-capture-error')).toHaveTextContent('Forbidden');
    expect(screen.getByTestId('policy-input-capture-switch')).not.toBeChecked();
  });
});
