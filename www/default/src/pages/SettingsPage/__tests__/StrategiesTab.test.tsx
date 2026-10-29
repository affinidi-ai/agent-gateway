import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import StrategiesTab from '../StrategiesTab';

const mockFetch = jest.fn();
jest.mock('../../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));

const strategy = (id: string, withServer: boolean) => ({
  id,
  name: `Strategy ${id}`,
  expected_issuer: `https://${id}.example.com`,
  jwks_source: { type: 'remote', jwks_uri: `https://${id}.example.com/jwks` },
  created_at: '2026-10-12T08:58:00Z',
  updated_at: '2026-10-12T08:58:00Z',
  ...(withServer
    ? {
        authorization_server: {
          issuer: `https://${id}.example.com`,
          metadata_url: `https://${id}.example.com/.well-known/openid-configuration`,
          token_endpoint: `https://${id}.example.com/token`,
          jwks_uri: `https://${id}.example.com/jwks`,
        },
      }
    : {}),
});

const json = (body: unknown, ok = true) => ({
  ok,
  statusText: ok ? 'OK' : 'Conflict',
  json: async () => body,
});

let surfaces: unknown;
let deleteReply: ReturnType<typeof json>;

beforeEach(() => {
  jest.clearAllMocks();
  surfaces = [
    {
      surface_id: 'sf1',
      name: 'Helpdesk',
      access_point: {
        caller_authentication: { methods: [{ jwt_verification_strategy_id: 'a' }] },
      },
    },
  ];
  deleteReply = json({});
  mockFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
    if (init?.method === 'DELETE') return deleteReply;
    if (url === '/api/v1/surfaces') return json(surfaces);
    return json([strategy('a', true), strategy('b', false)]);
  });
});

const renderTab = () =>
  render(
    <MemoryRouter>
      <StrategiesTab />
    </MemoryRouter>
  );

describe('Strategies list', () => {
  it('marks only strategies with a pinned authorization server as Discovered', async () => {
    renderTab();
    await screen.findByText('Strategy a');
    const badges = screen.getAllByTestId('strategy-discovered-badge');
    expect(badges).toHaveLength(1);
    expect(badges[0]).toHaveTextContent('Discovered');
  });

  it('confirms in the page, names the surfaces that use the strategy and states the outcome', async () => {
    const confirm = jest.spyOn(window, 'confirm');
    renderTab();
    await screen.findByText('Strategy a');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy a' }));
    const panel = await screen.findByTestId('strategy-delete-confirm');
    expect(confirm).not.toHaveBeenCalled();
    expect(panel).toHaveAttribute('role', 'alertdialog');
    await waitFor(() => expect(panel).toHaveTextContent('Helpdesk'));
    expect(panel).toHaveTextContent('A surface that still references it cannot verify tokens.');
    expect(mockFetch.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('deletes only after the confirm button and removes the row', async () => {
    renderTab();
    await screen.findByText('Strategy b');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy b' }));
    await waitFor(() =>
      expect(screen.getByTestId('strategy-delete-confirm')).toHaveTextContent(/No surface/)
    );
    fireEvent.click(screen.getByTestId('strategy-delete-confirm-button'));
    await waitFor(() => expect(screen.queryByText('Strategy b')).not.toBeInTheDocument());
    const call = mockFetch.mock.calls.find(([, init]) => init?.method === 'DELETE');
    expect(call?.[0]).toBe('/api/v1/jwt-verification-strategies/b');
  });

  it('cancels without deleting', async () => {
    renderTab();
    await screen.findByText('Strategy b');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy b' }));
    fireEvent.click(await screen.findByTestId('strategy-delete-cancel-button'));
    expect(screen.queryByTestId('strategy-delete-confirm')).not.toBeInTheDocument();
    expect(screen.getByText('Strategy b')).toBeInTheDocument();
  });

  it('says so when the surface check fails and shows a refused delete inline', async () => {
    surfaces = null;
    mockFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === 'DELETE') return json({}, false);
      if (url === '/api/v1/surfaces') throw new Error('offline');
      return json([strategy('b', false)]);
    });
    renderTab();
    await screen.findByText('Strategy b');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy b' }));
    await waitFor(() =>
      expect(screen.getByTestId('strategy-delete-confirm')).toHaveTextContent(/could not check/i)
    );
    fireEvent.click(screen.getByTestId('strategy-delete-confirm-button'));
    const error = await screen.findByTestId('strategy-delete-error');
    expect(error).toHaveAttribute('role', 'alert');
    expect(error).toHaveTextContent('Delete failed: Conflict');
    expect(screen.getByText('Strategy b')).toBeInTheDocument();
  });

  it('moves focus into the confirmation and back to the Delete button on Cancel', async () => {
    renderTab();
    await screen.findByText('Strategy b');
    const trigger = screen.getByRole('button', { name: 'Delete strategy Strategy b' });
    trigger.focus();
    fireEvent.click(trigger);
    const panel = await screen.findByTestId('strategy-delete-confirm');
    await waitFor(() => expect(panel).toHaveFocus());
    fireEvent.click(screen.getByTestId('strategy-delete-cancel-button'));
    expect(screen.queryByTestId('strategy-delete-confirm')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('closes on Escape without deleting and returns focus to the Delete button', async () => {
    renderTab();
    await screen.findByText('Strategy b');
    const trigger = screen.getByRole('button', { name: 'Delete strategy Strategy b' });
    trigger.focus();
    fireEvent.click(trigger);
    const panel = await screen.findByTestId('strategy-delete-confirm');
    fireEvent.keyDown(panel, { key: 'Escape' });
    expect(screen.queryByTestId('strategy-delete-confirm')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(mockFetch.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('moves focus to the list heading after a confirmed delete', async () => {
    renderTab();
    await screen.findByText('Strategy b');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy b' }));
    await waitFor(() =>
      expect(screen.getByTestId('strategy-delete-confirm')).toHaveTextContent(/No surface/)
    );
    fireEvent.click(screen.getByTestId('strategy-delete-confirm-button'));
    await waitFor(() => expect(screen.queryByText('Strategy b')).not.toBeInTheDocument());
    expect(screen.getByRole('heading', { name: /JWT Verification Strategies/ })).toHaveFocus();
  });

  it('shows the surfaces of the strategy asked about last when an earlier check answers late', async () => {
    const pending: Array<(body: unknown) => void> = [];
    mockFetch.mockImplementation(async (url: string) => {
      if (url === '/api/v1/surfaces') {
        return new Promise(resolve => pending.push(body => resolve(json(body))));
      }
      return json([strategy('a', true), strategy('b', false)]);
    });
    renderTab();
    await screen.findByText('Strategy b');
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy b' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete strategy Strategy a' }));
    await waitFor(() => expect(pending).toHaveLength(2));
    const panel = screen.getByTestId('strategy-delete-confirm');
    expect(panel).toHaveTextContent('Delete JWT verification strategy "Strategy a"?');

    pending[1](surfaces);
    await waitFor(() => expect(panel).toHaveTextContent('Helpdesk'));
    pending[0]([]);
    await waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(3));
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(panel).toHaveTextContent('Helpdesk');
    expect(panel).not.toHaveTextContent('No surface uses it.');
  });
});
