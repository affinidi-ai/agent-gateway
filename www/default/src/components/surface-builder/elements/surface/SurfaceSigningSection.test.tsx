import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SurfaceSigningSection } from './SurfaceSigningSection';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockFetch = apiClient.fetch as jest.Mock;

const connection = (overrides: Record<string, unknown> = {}) => ({
  id: 'vta-custom',
  name: 'Custom VTA',
  enabled: true,
  transport: 'https',
  endpoint: 'http://127.0.0.1:3000',
  vta_did: 'did:key:z6MkCustom',
  default_context_id: 'custom',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: { active: { key_id: 'custom-key' } },
  ...overrides,
});

const bundled = connection({
  id: 'vta-bootstrap',
  name: 'Bootstrap VTA',
  endpoint: 'http://127.0.0.1:8100',
  default_context_id: 'gateway',
  keys: {},
});

const optionTexts = () =>
  within(screen.getByRole('combobox'))
    .getAllByRole('option')
    .map(o => o.textContent);

const renderWith = async (connections: unknown[], signing?: Record<string, string>) => {
  mockFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve(connections) });
  render(<SurfaceSigningSection signing={signing as never} setSigning={jest.fn()} />);
  await screen.findByRole('option', { name: /Inherit the appliance default/ });
};

beforeEach(() => mockFetch.mockReset());

describe('SurfaceSigningSection', () => {
  it('does not offer the bundled trust agent as if it were waiting to be set up', async () => {
    // A surface cannot name the bundled agent: it uses it through "Inherit".
    await renderWith([bundled, connection()]);
    await screen.findByRole('option', { name: 'Custom VTA' });

    expect(optionTexts()).toEqual([
      'Inherit the appliance default',
      "This gateway's own key (local)",
      'Custom VTA',
    ]);
  });

  it('still lists a paired connection that has no key yet, with the reason', async () => {
    await renderWith([connection({ keys: {} })]);

    const option = (await screen.findByRole('option', { name: /Custom VTA/ })) as HTMLOptionElement;
    expect(option.disabled).toBe(true);
    expect(option.textContent).toMatch(/not ready/);
  });

  it('keeps a saved choice of the bundled record visible instead of a blank select', async () => {
    await renderWith([bundled], { backend: 'vta', connection_id: 'vta-bootstrap' });
    await screen.findByRole('option', { name: /used through/ });

    const select = screen.getByRole('combobox') as HTMLSelectElement;
    const shown = select.options[select.selectedIndex];
    expect(shown.value).toBe('vta-bootstrap');
    expect(shown.textContent).toMatch(/Inherit the appliance default/);
    expect(shown.disabled).toBe(true);
  });
});
