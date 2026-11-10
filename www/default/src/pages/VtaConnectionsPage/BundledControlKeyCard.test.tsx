import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { BundledControlKeyCard } from './BundledControlKeyCard';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import type { VtaBootstrapStatus } from './types';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;
const toast = showToast as jest.Mock;

const DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

const bootstrap = (overrides: Partial<VtaBootstrapStatus> = {}): VtaBootstrapStatus => ({
  state: 'connected',
  advice: '',
  context_id: 'gateway',
  previously_connected: true,
  owner: 'unclaimed',
  control_did: DID,
  control_key_rotation_days: 90,
  ...overrides,
});

const answer = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: 'x',
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
    json: () => Promise.resolve(body),
  });

beforeEach(() => {
  mockFetch.mockReset();
  toast.mockReset();
});

describe('BundledControlKeyCard', () => {
  it('shows the control DID, when it was rotated and when it is next due', () => {
    render(
      <BundledControlKeyCard
        bootstrap={bootstrap({
          control_key_rotated_at: '2026-10-01T10:00:00Z',
          control_key_next_rotation_at: '2026-12-30T10:00:00Z',
        })}
        canRotate
        onRotated={jest.fn()}
      />
    );

    expect(screen.getByTestId('bundled-control-key-did')).toHaveAttribute('title', DID);
    expect(screen.getByTestId('bundled-control-key-rotated-at')).toHaveTextContent(
      /Rotated .*2026/
    );
    expect(screen.getByTestId('bundled-control-key-next')).toHaveTextContent(
      /Next automatic rotation .*2026/
    );
  });

  it('says so when the key was never rotated and when automatic rotation is off', () => {
    render(
      <BundledControlKeyCard
        bootstrap={bootstrap({ control_key_rotation_days: 0 })}
        canRotate
        onRotated={jest.fn()}
      />
    );

    expect(screen.getByTestId('bundled-control-key-rotated-at')).toHaveTextContent('Never rotated');
    expect(screen.getByTestId('bundled-control-key-next')).toHaveTextContent(
      'Automatic rotation is off'
    );
  });

  it('offers no button to someone who cannot edit key management', () => {
    render(
      <BundledControlKeyCard bootstrap={bootstrap()} canRotate={false} onRotated={jest.fn()} />
    );
    expect(screen.queryByTestId('bundled-control-key-rotate')).not.toBeInTheDocument();
  });

  it('disables the button while the trust agent is not connected', () => {
    render(
      <BundledControlKeyCard
        bootstrap={bootstrap({ state: 'waiting_for_vta' })}
        canRotate
        onRotated={jest.fn()}
      />
    );
    expect(screen.getByTestId('bundled-control-key-rotate')).toBeDisabled();
  });

  it('asks first, then rotates and refreshes', async () => {
    const onRotated = jest.fn();
    mockFetch.mockReturnValue(
      answer(200, {
        previous_control_did: DID,
        control_did: 'did:key:z6MkNEWNEWNEWNEWNEWNEWNEW',
        rotated_at: '2026-11-10T10:00:00Z',
      })
    );
    render(<BundledControlKeyCard bootstrap={bootstrap()} canRotate onRotated={onRotated} />);

    await userEvent.click(screen.getByTestId('bundled-control-key-rotate'));
    expect(mockFetch).not.toHaveBeenCalled();
    expect(screen.getByTestId('bundled-control-key-confirm-text')).toHaveTextContent(
      /Signing keys and issuer DIDs do not change/
    );

    await userEvent.click(screen.getByTestId('bundled-control-key-confirm'));

    await waitFor(() => expect(onRotated).toHaveBeenCalled());
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/vta/control-key/rotate', { method: 'POST' });
    expect(toast).toHaveBeenCalledWith('success', expect.stringContaining('z6MkNEWNEW'));
    expect(screen.queryByTestId('bundled-control-key-confirm')).not.toBeInTheDocument();
  });

  it('cancelling sends nothing', async () => {
    render(<BundledControlKeyCard bootstrap={bootstrap()} canRotate onRotated={jest.fn()} />);

    await userEvent.click(screen.getByTestId('bundled-control-key-rotate'));
    await userEvent.click(screen.getByTestId('bundled-control-key-cancel'));

    expect(mockFetch).not.toHaveBeenCalled();
    expect(screen.queryByTestId('bundled-control-key-confirm')).not.toBeInTheDocument();
  });

  it('tells the operator how long to wait after a recent rotation', async () => {
    mockFetch.mockReturnValue(
      answer(429, { error: 'rotated moments ago' }, { 'retry-after': '420' })
    );
    const onRotated = jest.fn();
    render(<BundledControlKeyCard bootstrap={bootstrap()} canRotate onRotated={onRotated} />);

    await userEvent.click(screen.getByTestId('bundled-control-key-rotate'));
    await userEvent.click(screen.getByTestId('bundled-control-key-confirm'));

    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith('error', 'Try again in 7 minutes.');
    expect(onRotated).not.toHaveBeenCalled();
  });

  it('shows the message the gateway gave when it could not rotate', async () => {
    mockFetch.mockReturnValue(
      answer(502, {
        error: 'the trust agent did not accept the rotation; the current control key still works',
      })
    );
    render(<BundledControlKeyCard bootstrap={bootstrap()} canRotate onRotated={jest.fn()} />);

    await userEvent.click(screen.getByTestId('bundled-control-key-rotate'));
    await userEvent.click(screen.getByTestId('bundled-control-key-confirm'));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        'error',
        'the trust agent did not accept the rotation; the current control key still works'
      )
    );
  });
});
