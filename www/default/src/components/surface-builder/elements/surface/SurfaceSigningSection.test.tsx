import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
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

const typeSelect = () => screen.getByTestId('surface-signing-type-select') as HTMLSelectElement;
const agentSelect = () => screen.getByTestId('surface-signing-agent-select') as HTMLSelectElement;
const agentOptions = () =>
  within(agentSelect())
    .getAllByRole('option')
    .map(o => o.textContent);

const respond = (connections: unknown[], defaultBackend = 'local') => {
  mockFetch.mockImplementation((url: string) => {
    if (url.includes('/vta/status')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ default_resolution: { backend: defaultBackend } }),
      });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(connections) });
  });
};

const mountSection = async (
  connections: unknown[],
  signing?: Record<string, string>,
  setSigning: jest.Mock = jest.fn(),
  defaultBackend = 'local'
) => {
  respond(connections, defaultBackend);
  render(<SurfaceSigningSection signing={signing as never} setSigning={setSigning} />);
  await waitFor(() => expect(mockFetch).toHaveBeenCalledWith('/api/v1/vta/connections'));
  return setSigning;
};

beforeEach(() => mockFetch.mockReset());

describe('SurfaceSigningSection', () => {
  it('offers exactly two key sources, Gateway secret and Verifiable Trust Agent', async () => {
    await mountSection([connection()]);

    expect(
      within(typeSelect())
        .getAllByRole('option')
        .map(o => o.textContent)
    ).toEqual(['Gateway secret', 'Verifiable Trust Agent']);
  });

  it('follows the appliance default and says so until a type is chosen', async () => {
    await mountSection([connection()]);

    expect(typeSelect()).toHaveValue('local');
    await waitFor(() =>
      expect(screen.getByTestId('surface-signing-inherited')).toHaveTextContent(
        'Following the gateway-wide default (Gateway secret)'
      )
    );
    expect(screen.queryByTestId('surface-signing-reset')).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-signing-agent-select')).not.toBeInTheDocument();
  });

  it('says the gateway-wide default could not be read rather than naming one', async () => {
    mockFetch.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('/vta/status')
          ? { ok: false, status: 403, json: () => Promise.resolve({}) }
          : { ok: true, json: () => Promise.resolve([connection()]) }
      )
    );
    render(<SurfaceSigningSection signing={undefined} setSigning={jest.fn()} />);

    await waitFor(() =>
      expect(screen.getByTestId('surface-signing-inherited')).toHaveTextContent(
        'Following the gateway-wide default, which could not be read.'
      )
    );
    expect(screen.getByTestId('surface-signing-inherited')).not.toHaveTextContent('Gateway secret');
  });

  it('shows Remote and the agent picker when the appliance default signs through an agent', async () => {
    await mountSection([connection()], undefined, jest.fn(), 'vta');

    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
    expect(agentSelect()).toBeInTheDocument();
  });

  it('saves Local when it is chosen', async () => {
    const setSigning = await mountSection([connection()], {
      backend: 'vta',
      connection_id: 'vta-custom',
    });

    await userEvent.selectOptions(typeSelect(), 'local');

    expect(setSigning).toHaveBeenCalledWith({ backend: 'local' });
  });

  it('lists the connected agents when Remote is chosen, and saves the chosen one with its context and key', async () => {
    const setSigning = await mountSection([configBlock, connection()]);

    await userEvent.selectOptions(typeSelect(), 'remote');
    await screen.findByRole('option', { name: 'Custom VTA' });

    expect(agentOptions()).toEqual([
      'Select a Verifiable Trust Agent…',
      'Configured VTA',
      'Custom VTA',
    ]);
    const option = screen.getByRole('option', { name: 'Configured VTA' }) as HTMLOptionElement;
    expect(option.disabled).toBe(false);

    await userEvent.selectOptions(agentSelect(), 'vta-bootstrap');

    expect(setSigning).toHaveBeenLastCalledWith({
      backend: 'vta',
      connection_id: 'vta-bootstrap',
      context_id: 'gateway',
      key_id: 'gateway-jwt-1',
    });
  });

  it('stores nothing for Remote until an agent is chosen, and says what applies meanwhile', async () => {
    const setSigning = await mountSection([connection()]);

    await userEvent.selectOptions(typeSelect(), 'remote');

    expect(setSigning).toHaveBeenLastCalledWith(undefined);
    expect(typeSelect()).toHaveValue('remote');
    expect(screen.getByTestId('surface-signing-pick-agent')).toHaveTextContent(
      'follows the gateway-wide default'
    );
  });

  it('does not offer the [vta] block connection while it is not connected', async () => {
    // Offering it greyed out as "not ready" would suggest the operator has
    // something to set up.
    await mountSection([configNotReady, connection()]);
    await userEvent.selectOptions(typeSelect(), 'remote');
    await screen.findByRole('option', { name: 'Custom VTA' });

    expect(agentOptions()).toEqual(['Select a Verifiable Trust Agent…', 'Custom VTA']);
  });

  it('still lists a paired connection that has no key yet, disabled, with the reason', async () => {
    await mountSection([connection({ keys: {} })]);
    await userEvent.selectOptions(typeSelect(), 'remote');

    const option = (await screen.findByRole('option', { name: /Custom VTA/ })) as HTMLOptionElement;
    expect(option.disabled).toBe(true);
    expect(option.textContent).toMatch(/not ready/);
  });

  it('keeps a saved choice of the [vta] block connection visible even when it is not ready', async () => {
    await mountSection([configNotReady], { backend: 'vta', connection_id: 'vta-bootstrap' });
    await screen.findByRole('option', { name: /Configured VTA/ });

    expect(typeSelect()).toHaveValue('remote');
    const select = agentSelect();
    const shown = select.options[select.selectedIndex];
    expect(shown.value).toBe('vta-bootstrap');
    expect(shown.textContent).toMatch(/Configured VTA.*not ready/);
  });

  it('hands the choice back to the appliance default', async () => {
    const setSigning = await mountSection([connection()], { backend: 'local' });

    await userEvent.click(screen.getByTestId('surface-signing-reset'));

    expect(setSigning).toHaveBeenCalledWith(undefined);
  });

  it('links to the connect wizard in a new tab and can refresh the list', async () => {
    await mountSection([connection()]);
    await userEvent.selectOptions(typeSelect(), 'remote');

    const link = screen.getByTestId('surface-signing-connect-link');
    expect(link).toHaveAttribute('href', '/connections/trust-agents/connect');
    expect(link).toHaveAttribute('target', '_blank');

    mockFetch.mockClear();
    await userEvent.click(screen.getByTestId('surface-signing-refresh'));
    await waitFor(() => expect(mockFetch).toHaveBeenCalledWith('/api/v1/vta/connections'));
  });

  it('says so when the agents cannot be listed', async () => {
    mockFetch.mockResolvedValue({ ok: false, json: () => Promise.resolve([]) });
    render(<SurfaceSigningSection setSigning={jest.fn()} />);

    expect(await screen.findByText(/could not be listed/)).toBeInTheDocument();
  });

  it('shows a read-only choice with its agent and no listing error when the agents cannot be listed', async () => {
    mockFetch.mockResolvedValue({ ok: false, json: () => Promise.resolve([]) });
    render(
      <SurfaceSigningSection
        disabled
        signing={{ backend: 'vta', connection_id: 'vta-custom' } as never}
        setSigning={jest.fn()}
      />
    );

    await waitFor(() => expect(agentSelect()).toHaveValue('vta-custom'));
    expect(typeSelect()).toBeDisabled();
    expect(agentSelect()).toBeDisabled();
    expect(screen.queryByTestId('surface-signing-load-error')).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-signing-no-agents')).not.toBeInTheDocument();
  });

  it('follows the issuer that owns the surface, and says so', async () => {
    respond([connection()]);
    render(
      <SurfaceSigningSection
        setSigning={jest.fn()}
        owner={{
          name: 'Research',
          signing: { backend: 'vta', connection_id: 'vta-custom' },
        }}
      />
    );

    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
    expect(screen.getByTestId('surface-signing-inherited')).toHaveTextContent(
      'Following its issuer, Research (Verifiable Trust Agent)'
    );
    await screen.findByRole('option', { name: 'Custom VTA' });
    expect(agentSelect()).toHaveValue('vta-custom');
  });

  it('keeps the surface on its own choice over its issuer', async () => {
    respond([connection()]);
    render(
      <SurfaceSigningSection
        signing={{ backend: 'local' }}
        setSigning={jest.fn()}
        owner={{ name: 'Research', signing: { backend: 'vta', connection_id: 'vta-custom' } }}
      />
    );

    await waitFor(() => expect(typeSelect()).toHaveValue('local'));
    expect(screen.queryByTestId('surface-signing-inherited')).not.toBeInTheDocument();
  });

  it('words the inherited note for an issuer', async () => {
    respond([connection()]);
    render(<SurfaceSigningSection setSigning={jest.fn()} subject="issuer" />);

    expect(await screen.findByTestId('surface-signing-inherited')).toHaveTextContent(
      "Choose a source to set this issuer's own."
    );
  });

  it('shows no agent list while no Verifiable Trust Agent is connected, but still offers Add VTA', async () => {
    await mountSection([]);

    await userEvent.selectOptions(typeSelect(), 'remote');

    expect(await screen.findByTestId('surface-signing-no-agents')).toHaveTextContent(
      'No Verifiable Trust Agent is connected yet.'
    );
    expect(screen.queryByTestId('surface-signing-agent-select')).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-signing-pick-agent')).not.toBeInTheDocument();
    expect(screen.getByTestId('surface-signing-connect-link')).toHaveTextContent('Add VTA');
  });

  it('lists the agents once one is connected', async () => {
    await mountSection([connection()]);

    await userEvent.selectOptions(typeSelect(), 'remote');

    await waitFor(() => expect(agentOptions()).toContain('Custom VTA'));
    expect(screen.queryByTestId('surface-signing-no-agents')).not.toBeInTheDocument();
  });

  describe('as the gateway-wide default', () => {
    const respondWithBlock = (backend: string) =>
      mockFetch.mockImplementation((url: string) =>
        Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve(
              url.includes('/vta/status')
                ? { enabled: true, default_resolution: { backend } }
                : [configNotReady]
            ),
        })
      );

    it('says it follows the [vta] block rather than that no agent is connected', async () => {
      respondWithBlock('vta');
      render(<SurfaceSigningSection subject="gateway" setSigning={jest.fn()} />);

      await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
      expect(screen.getByTestId('surface-signing-inherited')).toHaveTextContent(
        'Following the [vta] configuration block.'
      );
      expect(screen.queryByTestId('surface-signing-no-agents')).not.toBeInTheDocument();
      expect(screen.queryByTestId('surface-signing-pick-agent')).not.toBeInTheDocument();
      expect(screen.queryByTestId('surface-signing-reset')).not.toBeInTheDocument();
    });

    it('offers the [vta] block back once another source is chosen', async () => {
      respondWithBlock('local');
      const setSigning = jest.fn();
      render(
        <SurfaceSigningSection
          subject="gateway"
          signing={{ backend: 'local' } as never}
          setSigning={setSigning}
        />
      );

      const reset = await screen.findByTestId('surface-signing-reset');
      expect(reset).toHaveTextContent('Use the [vta] configuration block');
      await userEvent.click(reset);
      expect(setSigning).toHaveBeenLastCalledWith(undefined);
    });

    it('shows no inherited note and no way back to one, and reports the source shown', async () => {
      respond([connection()]);
      const onTypeChange = jest.fn();
      render(
        <SurfaceSigningSection
          subject="gateway"
          setSigning={jest.fn()}
          onTypeChange={onTypeChange}
        />
      );

      await waitFor(() => expect(typeSelect()).toHaveValue('local'));
      expect(onTypeChange).toHaveBeenLastCalledWith('local');
      await userEvent.selectOptions(typeSelect(), 'remote');
      expect(onTypeChange).toHaveBeenLastCalledWith('remote');
      await userEvent.selectOptions(typeSelect(), 'local');
      expect(screen.queryByTestId('surface-signing-inherited')).not.toBeInTheDocument();
      expect(screen.queryByTestId('surface-signing-reset')).not.toBeInTheDocument();
    });

    it('asks for an agent before saving and reports that one is still to be picked', async () => {
      respond([connection()]);
      const pending = jest.fn();
      render(
        <SurfaceSigningSection
          subject="gateway"
          setSigning={jest.fn()}
          onRemotePendingChange={pending}
        />
      );

      await userEvent.selectOptions(typeSelect(), 'remote');

      expect(screen.getByTestId('surface-signing-pick-agent')).toHaveTextContent(
        'Choose a Verifiable Trust Agent before saving.'
      );
      expect(pending).toHaveBeenLastCalledWith(true);
      expect(screen.queryByTestId('surface-signing-connect-link')).not.toBeInTheDocument();
    });
  });
});
