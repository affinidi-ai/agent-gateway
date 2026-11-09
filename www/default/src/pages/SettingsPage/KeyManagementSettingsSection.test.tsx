import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { KeyManagementSettingsSection } from './KeyManagementSettingsSection';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
jest.mock('react-router-dom', () => ({ useNavigate: () => jest.fn() }));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const bundledStatus = {
  enabled: true,
  tier: 'bundled',
  custody_claim: false,
  default_resolution: {
    backend: 'bundled',
    reason: 'the [vta] block is enabled, so this appliance signs through its bundled trust agent',
    explicit: true,
  },
};

const bootstrap = {
  id: 'vta-bootstrap',
  name: 'Bootstrap VTA',
  enabled: true,
  transport: 'https',
  endpoint: 'http://127.0.0.1:8100',
  vta_did: 'did:key:z6MkBundled',
  default_context_id: 'gateway',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: {},
};

const custom = {
  ...bootstrap,
  id: 'vta-custom',
  name: 'Custom VTA',
  endpoint: 'http://127.0.0.1:3000',
  default_context_id: 'custom',
  keys: { active: { key_id: 'custom-key' } },
};

let settings: Record<string, unknown> = {};

const respond = () => {
  mockFetch.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
    if (url.includes('/vta/status')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(bundledStatus) });
    }
    if (url.includes('/vta/connections')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve([bootstrap, custom]) });
    }
    if (url.includes('/settings')) {
      if (init?.method === 'POST') {
        const body = JSON.parse(init.body ?? '{}');
        settings = {
          default_signing: Object.keys(body.default_signing ?? {}).length
            ? body.default_signing
            : null,
        };
        return Promise.resolve({ ok: true, text: () => Promise.resolve('') });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(settings) });
    }
    return Promise.resolve({
      ok: false,
      statusText: 'unexpected',
      text: () => Promise.resolve(''),
    });
  });
};

const open = async () => {
  render(<KeyManagementSettingsSection />);
  await userEvent.click(screen.getByTestId('key-management-settings-toggle'));
  return screen.findByRole('combobox');
};

beforeEach(() => {
  mockFetch.mockReset();
  settings = {};
  respond();
});

describe('KeyManagementSettingsSection with the bundled trust agent', () => {
  it('shows the bundled agent as the current choice, not the gateway’s own key', async () => {
    const picker = await open();
    await screen.findByRole('option', { name: /Custom VTA/ });

    const options = within(picker)
      .getAllByRole('option')
      .map(o => o.textContent);
    expect(options).toContain('The bundled trust agent (default)');
    expect(options.join('|')).not.toMatch(/own key/);
    expect(options.join('|')).not.toMatch(/Bootstrap VTA/);
    expect(picker).toHaveValue('__local__');
    expect(
      (picker as HTMLSelectElement).options[(picker as HTMLSelectElement).selectedIndex].text
    ).toBe('The bundled trust agent (default)');
  });

  it('says what changed after saving another default, and keeps saying it', async () => {
    const picker = await open();

    await screen.findByRole('option', { name: /Custom VTA/ });
    await userEvent.selectOptions(picker, 'vta-custom');
    await userEvent.click(screen.getByRole('button', { name: /save signing backend/i }));

    expect(await screen.findByText(/Signing backend updated/)).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId('key-management-settings-signing-with')).toHaveTextContent(
        'Custom VTA'
      )
    );
    expect(screen.getByText(/Signing backend updated/)).toBeInTheDocument();
  });
});
