import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import PolicyInputCaptureControl from '../PolicyInputCaptureControl';

const mockListen = jest.fn();
let mockWsStatus = 'CONNECTED';
jest.mock('../../../../context/AppContext', () => ({
  useApp: () => ({
    state: { wsStatus: mockWsStatus },
    actions: { listenToPolicyInput: mockListen },
  }),
}));

let mockGranted: Set<string>;
jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockGranted.has(p), loading: false }),
}));

const control = (
  surfaceId: string | undefined = 'surface-1',
  meta: Partial<SurfaceMetaValue> = {}
) => (
  <SurfaceMetaProvider
    value={{ isCreate: false, readOnly: false, surfaceId, ...meta } as SurfaceMetaValue}
  >
    <PolicyInputCaptureControl />
  </SurfaceMetaProvider>
);

const answer = (detail: Record<string, unknown>) =>
  act(() => {
    window.dispatchEvent(
      new CustomEvent('ws-message', {
        detail: { type: 'policy_input_capture', surface_id: 'surface-1', ...detail },
      })
    );
  });

const listenButton = () => screen.getByTestId('policy-input-capture-listen');

beforeEach(() => {
  jest.clearAllMocks();
  mockWsStatus = 'CONNECTED';
  mockGranted = new Set(['surfaces.edit', 'policies.edit']);
});

describe('PolicyInputCaptureControl', () => {
  it('is hidden while creating a surface', () => {
    render(control('surface-1', { isCreate: true, surfaceId: undefined }));
    expect(screen.queryByTestId('policy-input-capture-listen')).not.toBeInTheDocument();
  });

  it('is hidden without a saved surface id', () => {
    render(control('surface-1', { surfaceId: undefined }));
    expect(screen.queryByTestId('policy-input-capture-listen')).not.toBeInTheDocument();
  });

  it.each([['surfaces.edit'], ['policies.edit']])(
    'is disabled and says why with only %s',
    permission => {
      mockGranted = new Set([permission]);
      render(control());
      expect(listenButton()).toBeDisabled();
      expect(screen.getByTestId('policy-input-capture-not-allowed')).toHaveTextContent(
        'Needs permission to edit surfaces and policies'
      );
    }
  );

  it('starts listening, shows it, and stops with one request on a second click', () => {
    render(control());
    expect(listenButton()).toHaveTextContent('Listen to policy input');

    fireEvent.click(listenButton());
    expect(mockListen).toHaveBeenLastCalledWith('surface-1', true);
    expect(screen.getByTestId('policy-input-capture-listening')).toHaveTextContent('Listening');
    expect(listenButton()).toHaveTextContent('Stop listening');

    mockListen.mockClear();
    fireEvent.click(listenButton());
    expect(mockListen).toHaveBeenCalledTimes(1);
    expect(mockListen).toHaveBeenCalledWith('surface-1', false, true);
    expect(screen.queryByTestId('policy-input-capture-listening')).not.toBeInTheDocument();
  });

  it('stops listening when the view closes', () => {
    const { unmount } = render(control());
    fireEvent.click(listenButton());
    mockListen.mockClear();

    unmount();

    expect(mockListen).toHaveBeenCalledWith('surface-1', false, true);
  });

  it('does not stop listening on a re-render', () => {
    const { rerender } = render(control());
    fireEvent.click(listenButton());
    mockListen.mockClear();

    rerender(control());

    expect(mockListen).not.toHaveBeenCalled();
  });

  it('moves listening to the new surface when the surface changes', () => {
    const { rerender } = render(control('surface-1'));
    fireEvent.click(listenButton());
    mockListen.mockClear();

    rerender(control('surface-2'));

    expect(mockListen).toHaveBeenCalledWith('surface-1', false, true);
    expect(mockListen).toHaveBeenLastCalledWith('surface-2', true);
  });

  it('keeps showing why the gateway refused, without sending a stop of its own', () => {
    render(control());
    fireEvent.click(listenButton());
    mockListen.mockClear();

    answer({ listening: false, error: 'needs surfaces.edit and policies.edit' });

    expect(mockListen).toHaveBeenCalledWith('surface-1', false, false);
    expect(screen.queryByTestId('policy-input-capture-listening')).not.toBeInTheDocument();
    expect(screen.getByTestId('policy-input-capture-error')).toHaveTextContent(
      'needs surfaces.edit and policies.edit'
    );

    answer({ listening: false });
    expect(screen.getByTestId('policy-input-capture-error')).toHaveTextContent(
      'needs surfaces.edit and policies.edit'
    );
  });

  it('clears the refusal once the user tries again', () => {
    render(control());
    fireEvent.click(listenButton());
    answer({ listening: false, error: 'listening to too many surfaces on this connection' });

    fireEvent.click(listenButton());

    expect(screen.queryByTestId('policy-input-capture-error')).not.toBeInTheDocument();
  });

  it('says it is waiting while the dashboard connection is down', () => {
    mockWsStatus = 'DISCONNECTED';
    render(control());
    fireEvent.click(listenButton());

    expect(screen.queryByTestId('policy-input-capture-listening')).not.toBeInTheDocument();
    expect(screen.getByTestId('policy-input-capture-waiting')).toHaveTextContent(
      'Waiting for the dashboard connection'
    );
  });

  it('ignores answers about another surface', () => {
    render(control());
    fireEvent.click(listenButton());

    answer({ surface_id: 'surface-2', listening: false, error: 'refused' });

    expect(screen.getByTestId('policy-input-capture-listening')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-error')).not.toBeInTheDocument();
  });
});
