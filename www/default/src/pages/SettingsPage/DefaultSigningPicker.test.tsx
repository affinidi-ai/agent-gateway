import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { DefaultSigningPicker } from './DefaultSigningPicker';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockFetch = apiClient.fetch as jest.Mock;

const connection = (overrides: Record<string, unknown> = {}) => ({
  id: 'vta-a',
  name: 'Production agent',
  enabled: true,
  transport: 'https',
  endpoint: 'https://vta.example',
  vta_did: 'did:webvh:vta.example',
  default_context_id: 'gateway',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: { active: { key_id: 'key-1' } },
  created_at: '',
  updated_at: '',
  ...overrides,
});

const respondWith = (connections: unknown[], settings: unknown = {}) => {
  mockFetch.mockImplementation((url: string) => {
    if (url.includes('/vta/connections')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(connections) });
    }
    if (url.includes('/settings')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(settings) });
    }
    return Promise.resolve({
      ok: false,
      statusText: 'unexpected',
      text: () => Promise.resolve(''),
    });
  });
};

beforeEach(() => mockFetch.mockReset());

describe('DefaultSigningPicker', () => {
  /**
   * The settings write route is POST. A PUT returns 405, the save silently
   * fails, and the operator sees their choice revert on reload — which is
   * exactly how this shipped broken once.
   */
  it('saves with POST, not PUT', async () => {
    respondWith([connection()]);
    render(<DefaultSigningPicker onChanged={jest.fn()} />);

    await screen.findByRole('option', { name: /Production agent/ });
    await userEvent.selectOptions(screen.getByRole('combobox'), 'vta-a');
    mockFetch.mockClear();
    respondWith([connection()]);
    await userEvent.click(screen.getByRole('button', { name: /save signing backend/i }));

    await waitFor(() =>
      expect(
        mockFetch.mock.calls.find(([url, init]) => url.includes('/settings') && init?.method)
      ).toBeDefined()
    );
    const save = mockFetch.mock.calls.find(
      ([url, init]) => url.includes('/settings') && init?.method
    );
    expect(save![1].method).toBe('POST');
  });

  /**
   * A JWT names its key, so an appliance default without one resolves to
   * nothing — the operator would see a saved setting and no effect.
   */
  it('sends the context and key alongside the connection', async () => {
    respondWith([connection()]);
    render(<DefaultSigningPicker onChanged={jest.fn()} />);

    await screen.findByRole('option', { name: /Production agent/ });
    await userEvent.selectOptions(screen.getByRole('combobox'), 'vta-a');
    await userEvent.click(screen.getByRole('button', { name: /save signing backend/i }));

    await waitFor(() => {
      const save = mockFetch.mock.calls.find(
        ([url, init]) => url.includes('/settings') && init?.method
      );
      expect(JSON.parse(save![1].body).default_signing).toEqual({
        backend: 'vta',
        connection_id: 'vta-a',
        context_id: 'gateway',
        key_id: 'key-1',
      });
    });
  });

  /** Clearing the override is an empty block, not a null or a missing field. */
  it('clears the override by sending an empty block', async () => {
    respondWith([connection()], { default_signing: { connection_id: 'vta-a' } });
    render(<DefaultSigningPicker onChanged={jest.fn()} />);

    await waitFor(() => expect(screen.getByRole('combobox')).toHaveValue('vta-a'));
    await userEvent.selectOptions(screen.getByRole('combobox'), '__local__');
    await userEvent.click(screen.getByRole('button', { name: /save signing backend/i }));

    await waitFor(() => {
      const save = mockFetch.mock.calls.find(
        ([url, init]) => url.includes('/settings') && init?.method
      );
      expect(JSON.parse(save![1].body).default_signing).toEqual({});
    });
  });

  /**
   * Mirrors the backend's `assert_usable`: a connection that is paired but
   * has no key cannot sign, so offering it would save a setting that does
   * nothing.
   */
  it('does not offer a connection with no active key', async () => {
    respondWith([connection({ keys: {} })]);
    render(<DefaultSigningPicker onChanged={jest.fn()} />);

    await screen.findByRole('option', { name: /Production agent/ });
    const option = screen.getByRole('option', { name: /Production agent/ }) as HTMLOptionElement;
    expect(option.disabled).toBe(true);
  });
});
