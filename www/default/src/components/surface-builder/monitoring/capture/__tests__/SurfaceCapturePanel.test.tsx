import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SurfaceCapturePanel from '../SurfaceCapturePanel';

jest.mock('../../../../../context/AppContext', () => ({
  useApp: () => ({
    state: { wsStatus: 'CONNECTED' },
    actions: { setWsKeepAlive: jest.fn() },
  }),
}));

jest.mock('../../../../../utils/useFabricResolver', () => ({
  useFabricResolver: () => ({ formatFabric: () => null }),
}));

jest.mock('../../PolicyInputCaptureControl', () => ({
  __esModule: true,
  default: ({ payloadPaused }: { payloadPaused?: boolean }) => (
    <div data-testid="policy-input-capture" data-payload-paused={String(Boolean(payloadPaused))} />
  ),
}));

jest.mock('../../../../../utils/featureFlags', () => ({
  usePolicyInputCaptureFlag: () => ({ enabled: true, loaded: true }),
}));

const dispatch = (detail: Record<string, unknown>) =>
  act(() => {
    window.dispatchEvent(
      new CustomEvent('ws-message', { detail: { config_id: 'surface-1', ...detail } })
    );
  });

const policyInputCaptured = () =>
  dispatch({
    type: 'policy_input_captured',
    timestamp: '2026-11-18T10:00:00Z',
    plane: 'surface',
    engine: 'surface-1',
    slot: 'target',
    decision: 'allow',
    input: { a2a: { text: 'hello policy' } },
  });

const renderPanel = () =>
  render(<SurfaceCapturePanel surfaceId="surface-1" surface={null} onClose={jest.fn()} />);

describe('SurfaceCapturePanel', () => {
  it('keeps recording policy input while payload capture is paused', () => {
    renderPanel();
    expect(screen.getByTestId('policy-input-capture')).toHaveAttribute(
      'data-payload-paused',
      'false'
    );
    fireEvent.click(screen.getByRole('button', { name: /Pause/ }));
    expect(screen.getByTestId('policy-input-capture')).toHaveAttribute(
      'data-payload-paused',
      'true'
    );

    policyInputCaptured();
    dispatch({ type: 'policy_input_skipped', skipped: 2 });

    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(1);
    expect(screen.getByTestId('policy-input-capture-skipped')).toHaveTextContent(
      '2 policy evaluations were not shown'
    );
  });

  it('still drops payloads while payload capture is paused', () => {
    renderPanel();
    fireEvent.click(screen.getByRole('button', { name: /Pause/ }));

    dispatch({ type: 'payload_captured', timestamp: '2026-11-18T10:00:00Z', payload: {} });

    expect(screen.queryByText(/Last updated:/)).not.toBeInTheDocument();
  });
});
