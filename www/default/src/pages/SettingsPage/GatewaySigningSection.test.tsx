import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { GatewaySigningSection } from './GatewaySigningSection';
import { apiClient } from '../../api';

const mockNavigate = jest.fn();
let mockPermissions: Record<string, boolean> = {};

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('react-router-dom', () => ({ useNavigate: () => mockNavigate }));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockPermissions[p] === true }),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const agent = {
  id: 'agent-1',
  name: 'Production agent',
  enabled: true,
  transport: 'https',
  endpoint: 'https://vta.example.com',
  vta_did: 'did:webvh:abc:vta.example.com',
  default_context_id: 'gateway',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: { active: { key_id: 'key-1' } },
};

let stored: Record<string, unknown> | null;
let agents: unknown[];
let posts: unknown[];

const respond = () => {
  mockFetch.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
    if (url === '/api/v1/settings' && init?.method === 'POST') {
      posts.push(JSON.parse(init.body ?? '{}'));
      return Promise.resolve({ ok: true, text: () => Promise.resolve('') });
    }
    if (url === '/api/v1/settings') {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(stored ? { default_signing: stored } : {}),
      });
    }
    if (url.includes('/vta/status')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ default_resolution: { backend: 'local' } }),
      });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(agents) });
  });
};

const typeSelect = () => screen.getByTestId('surface-signing-type-select') as HTMLSelectElement;
const saveButton = () => screen.getByTestId('gateway-signing-save-button');
const confirmSave = async () => {
  await userEvent.click(saveButton());
  await userEvent.click(await screen.findByTestId('gateway-signing-confirm-dialog-confirm'));
};

const mount = async () => {
  render(<GatewaySigningSection />);
  await screen.findByTestId('surface-signing-type-select');
};

beforeEach(() => {
  mockFetch.mockReset();
  mockNavigate.mockReset();
  mockPermissions = {
    'settings.edit': true,
    'key_management.edit': true,
    'vta_connections.edit': true,
  };
  stored = null;
  agents = [agent];
  posts = [];
  respond();
});

describe('GatewaySigningSection', () => {
  it('is titled Gateway signing, with no scope label and no text above the source', async () => {
    await mount();

    expect(screen.getByText('Gateway signing')).toBeInTheDocument();
    expect(screen.queryByTestId('gateway-signing-scope')).not.toBeInTheDocument();
    expect(screen.queryByText('Gateway-wide default')).not.toBeInTheDocument();
    expect(screen.getByText('Signing key source')).toBeInTheDocument();
    expect(screen.queryByText(/Signing with/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Deployment/)).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-signing-inherited')).not.toBeInTheDocument();
  });

  it('offers the same two sources as a surface', async () => {
    await mount();

    expect(Array.from(typeSelect().options).map(o => o.textContent)).toEqual([
      'Gateway secret',
      'Verifiable Trust Agent',
    ]);
  });

  it('shows a stored agent default as Verifiable Trust Agent with that agent', async () => {
    stored = { backend: 'vta', connection_id: 'agent-1', context_id: 'gateway', key_id: 'key-1' };
    await mount();

    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
    await screen.findByRole('option', { name: 'Production agent' });
    expect(screen.getByTestId('surface-signing-agent-select')).toHaveValue('agent-1');
  });

  it('saves Gateway secret as the gateway-wide default and says so', async () => {
    stored = { backend: 'vta', connection_id: 'agent-1', context_id: 'gateway', key_id: 'key-1' };
    await mount();
    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
    expect(saveButton()).toBeDisabled();

    await userEvent.selectOptions(typeSelect(), 'local');
    await confirmSave();

    await screen.findByTestId('gateway-signing-saved');
    expect(posts).toEqual([{ default_signing: { backend: 'local' } }]);
    expect(saveButton()).toBeDisabled();
  });

  it('saves a chosen agent with its context and key', async () => {
    await mount();

    await userEvent.selectOptions(typeSelect(), 'remote');
    expect(saveButton()).toBeDisabled();
    await screen.findByRole('option', { name: 'Production agent' });
    await userEvent.selectOptions(screen.getByTestId('surface-signing-agent-select'), 'agent-1');
    await confirmSave();

    await screen.findByTestId('gateway-signing-saved');
    expect(posts).toEqual([
      {
        default_signing: {
          backend: 'vta',
          connection_id: 'agent-1',
          context_id: 'gateway',
          key_id: 'key-1',
        },
      },
    ]);
  });

  it('offers Connect VTA in the card header only while Verifiable Trust Agent is chosen', async () => {
    await mount();
    expect(typeSelect()).toHaveValue('local');
    expect(screen.queryByTestId('gateway-signing-connect-button')).not.toBeInTheDocument();

    await userEvent.selectOptions(typeSelect(), 'remote');
    const connect = await screen.findByTestId('gateway-signing-connect-button');
    expect(connect).toHaveTextContent('Connect VTA');
    expect(screen.queryByText(/Connect my own VTA/)).not.toBeInTheDocument();
    await userEvent.click(connect);
    expect(mockNavigate).toHaveBeenCalledWith('/connections/trust-agents/connect');

    await userEvent.selectOptions(typeSelect(), 'local');
    await waitFor(() =>
      expect(screen.queryByTestId('gateway-signing-connect-button')).not.toBeInTheDocument()
    );
  });

  it('shows no agent list while no Verifiable Trust Agent is connected, and points to Connect VTA', async () => {
    agents = [];
    await mount();

    await userEvent.selectOptions(typeSelect(), 'remote');

    expect(await screen.findByTestId('surface-signing-no-agents')).toHaveTextContent(
      'No Verifiable Trust Agent is connected yet. Connect one with Connect VTA'
    );
    expect(screen.queryByTestId('surface-signing-agent-select')).not.toBeInTheDocument();
    expect(screen.getByTestId('gateway-signing-connect-button')).toBeInTheDocument();
    expect(saveButton()).toBeDisabled();
  });

  it('asks before saving and lists what changing the gateway signer does', async () => {
    await mount();
    await userEvent.selectOptions(typeSelect(), 'remote');
    await userEvent.selectOptions(typeSelect(), 'local');

    await userEvent.click(saveButton());

    const dialog = screen.getByRole('dialog', { name: 'Change gateway signing' });
    expect(dialog).toHaveTextContent('carries its issuer DID');
    expect(dialog).toHaveTextContent('must trust the new issuer DID');
    expect(dialog).toHaveTextContent('keep the key that signed them');
    expect(posts).toEqual([]);
  });

  it('saves nothing when the confirmation is cancelled', async () => {
    await mount();
    await userEvent.selectOptions(typeSelect(), 'remote');
    await userEvent.selectOptions(typeSelect(), 'local');

    await userEvent.click(saveButton());
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByTestId('gateway-signing-confirm-dialog')).not.toBeInTheDocument();
    expect(posts).toEqual([]);
    expect(saveButton()).toBeEnabled();
  });

  it.each([
    ['settings.edit only', { 'settings.edit': true }],
    ['key_management.edit only', { 'key_management.edit': true }],
  ])('is read-only without Save to a user with %s', async (_label, permissions) => {
    mockPermissions = permissions;
    await mount();

    expect(typeSelect()).toBeDisabled();
    expect(screen.queryByTestId('gateway-signing-save-button')).not.toBeInTheDocument();
  });

  it('shows the choice read-only, without Save or Connect, to a user who cannot change it', async () => {
    mockPermissions = {};
    stored = { backend: 'vta', connection_id: 'agent-1', context_id: 'gateway', key_id: 'key-1' };
    await mount();
    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));

    expect(typeSelect()).toBeDisabled();
    expect(screen.queryByTestId('gateway-signing-save-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('gateway-signing-connect-button')).not.toBeInTheDocument();
  });

  it('says why when the setting cannot be saved', async () => {
    await mount();
    mockFetch.mockImplementation((url: string, init?: { method?: string }) =>
      init?.method === 'POST'
        ? Promise.resolve({
            ok: false,
            statusText: 'Bad Request',
            text: () => Promise.resolve('default_signing is not valid'),
          })
        : Promise.resolve({ ok: true, json: () => Promise.resolve([agent]) })
    );

    await userEvent.selectOptions(typeSelect(), 'remote');
    await userEvent.selectOptions(typeSelect(), 'local');
    await confirmSave();

    expect(await screen.findByTestId('gateway-signing-error')).toHaveTextContent(
      'default_signing is not valid'
    );
  });
});
