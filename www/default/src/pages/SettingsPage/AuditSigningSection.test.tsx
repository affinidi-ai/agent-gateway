import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { AuditSigningSection } from './AuditSigningSection';
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
    return Promise.resolve({ ok: true, json: () => Promise.resolve([agent]) });
  });
};

const typeSelect = () => screen.getByTestId('surface-signing-type-select') as HTMLSelectElement;
const saveButton = () => screen.getByTestId('audit-signing-save-button');

const mount = async () => {
  render(<AuditSigningSection />);
  await screen.findByTestId('surface-signing-type-select');
};

beforeEach(() => {
  mockFetch.mockReset();
  mockNavigate.mockReset();
  mockPermissions = { 'settings.edit': true, 'vta_connections.edit': true };
  stored = null;
  posts = [];
  respond();
});

describe('AuditSigningSection', () => {
  it('is titled Audit signing, labelled as the gateway-wide default, and has no text above the source', async () => {
    await mount();

    expect(screen.getByText('Audit signing')).toBeInTheDocument();
    expect(screen.getByTestId('audit-signing-scope')).toHaveTextContent('Gateway-wide default');
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
    await userEvent.click(saveButton());

    await screen.findByTestId('audit-signing-saved');
    expect(posts).toEqual([{ default_signing: { backend: 'local' } }]);
    expect(saveButton()).toBeDisabled();
  });

  it('saves a chosen agent with its context and key', async () => {
    await mount();

    await userEvent.selectOptions(typeSelect(), 'remote');
    expect(saveButton()).toBeDisabled();
    await screen.findByRole('option', { name: 'Production agent' });
    await userEvent.selectOptions(screen.getByTestId('surface-signing-agent-select'), 'agent-1');
    await userEvent.click(saveButton());

    await screen.findByTestId('audit-signing-saved');
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

  it('keeps Connect my own VTA as a button beside the source, which opens the wizard', async () => {
    await mount();

    await userEvent.click(screen.getByTestId('audit-signing-connect-button'));

    expect(mockNavigate).toHaveBeenCalledWith('/connections/trust-agents/connect');
  });

  it('shows the choice read-only, without Save or Connect, to a user who cannot change it', async () => {
    mockPermissions = {};
    await mount();

    expect(typeSelect()).toBeDisabled();
    expect(screen.queryByTestId('audit-signing-save-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('audit-signing-connect-button')).not.toBeInTheDocument();
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
    await userEvent.click(saveButton());

    expect(await screen.findByTestId('audit-signing-error')).toHaveTextContent(
      'default_signing is not valid'
    );
  });
});
