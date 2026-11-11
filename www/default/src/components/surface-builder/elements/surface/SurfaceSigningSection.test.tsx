import React from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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

const configNotReady = connection({
  id: 'vta-bootstrap',
  name: 'Configured VTA',
  endpoint: 'http://127.0.0.1:8100',
  default_context_id: 'gateway',
  status: 'unpaired',
  pairing: { state: 'draft' },
  keys: {},
});

const configBlock = connection({
  id: 'vta-bootstrap',
  name: 'Configured VTA',
  endpoint: 'http://127.0.0.1:8100',
  default_context_id: 'gateway',
  keys: { active: { key_id: 'gateway-jwt-1' } },
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
  it('offers the [vta] block connection once it is connected', async () => {
    await renderWith([configBlock, connection()]);
    await screen.findByRole('option', { name: 'Custom VTA' });

    expect(optionTexts()).toEqual([
      'Inherit the appliance default',
      "This gateway's own key (local)",
      'Configured VTA',
      'Custom VTA',
    ]);
    const option = screen.getByRole('option', { name: 'Configured VTA' }) as HTMLOptionElement;
    expect(option.disabled).toBe(false);
  });

  it('saves the [vta] block connection with its context and key when chosen', async () => {
    mockFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve([configBlock]) });
    const setSigning = jest.fn();
    render(<SurfaceSigningSection setSigning={setSigning} />);
    await screen.findByRole('option', { name: 'Configured VTA' });

    await userEvent.selectOptions(screen.getByRole('combobox'), 'vta-bootstrap');

    expect(setSigning).toHaveBeenCalledWith({
      backend: 'vta',
      connection_id: 'vta-bootstrap',
      context_id: 'gateway',
      key_id: 'gateway-jwt-1',
    });
  });

  it('does not offer the [vta] block connection while it is not connected', async () => {
    // Offering it greyed out as "not ready" would suggest the operator has
    // something to set up.
    await renderWith([configNotReady, connection()]);
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

  it('keeps a saved choice of the [vta] block connection visible even when it is not ready', async () => {
    await renderWith([configNotReady], { backend: 'vta', connection_id: 'vta-bootstrap' });
    await screen.findByRole('option', { name: /Configured VTA/ });

    const select = screen.getByRole('combobox') as HTMLSelectElement;
    const shown = select.options[select.selectedIndex];
    expect(shown.value).toBe('vta-bootstrap');
    expect(shown.textContent).toMatch(/Configured VTA.*not ready/);
  });
});
