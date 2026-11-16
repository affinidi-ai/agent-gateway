import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import PolicyInputCaptureControl from '../PolicyInputCaptureControl';

const mockListen = jest.fn();
jest.mock('../../../../context/AppContext', () => ({
  useApp: () => ({ actions: { listenToPolicyInput: mockListen } }),
}));

let mockGranted: Set<string>;
jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockGranted.has(p), loading: false }),
}));

function renderControl(meta: Partial<SurfaceMetaValue> = {}) {
  const value = {
    isCreate: false,
    readOnly: false,
    surfaceId: 'surface-1',
    ...meta,
  } as SurfaceMetaValue;
  return render(
    <SurfaceMetaProvider value={value}>
      <PolicyInputCaptureControl />
    </SurfaceMetaProvider>
  );
}

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
  mockGranted = new Set(['surfaces.edit', 'policies.edit']);
});

describe('PolicyInputCaptureControl', () => {
  it('is hidden while creating a surface', () => {
    renderControl({ isCreate: true, surfaceId: undefined });
    expect(screen.queryByTestId('policy-input-capture-listen')).not.toBeInTheDocument();
  });

  it('is hidden without a saved surface id', () => {
    renderControl({ surfaceId: undefined });
    expect(screen.queryByTestId('policy-input-capture-listen')).not.toBeInTheDocument();
  });

  it.each([['surfaces.edit'], ['policies.edit']])(
    'is disabled and says why with only %s',
    permission => {
      mockGranted = new Set([permission]);
      renderControl();
      expect(listenButton()).toBeDisabled();
      expect(screen.getByTestId('policy-input-capture-not-allowed')).toHaveTextContent(
        'Needs permission to edit surfaces and policies'
      );
    }
  );

  it('starts listening, shows it, and stops on a second click', () => {
    renderControl();
    expect(listenButton()).toHaveTextContent('Listen to policy input');

    fireEvent.click(listenButton());
    expect(mockListen).toHaveBeenLastCalledWith('surface-1', true);
    expect(screen.getByTestId('policy-input-capture-listening')).toHaveTextContent('Listening');
    expect(listenButton()).toHaveTextContent('Stop listening');

    fireEvent.click(listenButton());
    expect(mockListen).toHaveBeenLastCalledWith('surface-1', false);
    expect(screen.queryByTestId('policy-input-capture-listening')).not.toBeInTheDocument();
  });

  it('stops listening when the view closes', () => {
    const { unmount } = renderControl();
    fireEvent.click(listenButton());
    mockListen.mockClear();

    unmount();

    expect(mockListen).toHaveBeenCalledWith('surface-1', false);
  });

  it('does not stop listening on a re-render', () => {
    const { rerender } = renderControl();
    fireEvent.click(listenButton());
    mockListen.mockClear();

    rerender(
      <SurfaceMetaProvider
        value={{ isCreate: false, readOnly: false, surfaceId: 'surface-1' } as SurfaceMetaValue}
      >
        <PolicyInputCaptureControl />
      </SurfaceMetaProvider>
    );

    expect(mockListen).not.toHaveBeenCalled();
  });

  it('shows the gateway refusing to listen and goes back to not listening', () => {
    renderControl();
    fireEvent.click(listenButton());

    answer({ listening: false, error: 'needs surfaces.edit and policies.edit' });

    expect(screen.getByTestId('policy-input-capture-error')).toHaveTextContent(
      'needs surfaces.edit and policies.edit'
    );
    expect(screen.queryByTestId('policy-input-capture-listening')).not.toBeInTheDocument();
  });

  it('ignores answers about another surface', () => {
    renderControl();
    fireEvent.click(listenButton());

    answer({ surface_id: 'surface-2', listening: false, error: 'refused' });

    expect(screen.getByTestId('policy-input-capture-listening')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-error')).not.toBeInTheDocument();
  });
});
