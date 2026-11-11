import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WizardFinishStep } from './WizardFinishStep';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

let mockPermissions = ['key_management.edit', 'settings.edit'];
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (name: string) => mockPermissions.includes(name),
  }),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const connection = (overrides: Record<string, unknown> = {}) =>
  ({
    id: 'vta-a',
    name: 'Production agent',
    enabled: true,
    transport: 'https',
    endpoint: 'https://vta.example',
    vta_did: 'did:webvh:vta.example',
    default_context_id: 'gateway',
    status: 'connected',
    pairing: { state: 'connected', granted_role: 'initiator', granted_contexts: ['gateway'] },
    keys: {},
    created_at: '',
    updated_at: '',
    ...overrides,
  }) as never;

const settingsReturning = (defaultSigning: unknown) => {
  mockFetch.mockImplementation((url: string) => {
    if (url.includes('/settings')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ default_signing: defaultSigning }),
      });
    }
    return Promise.resolve({ ok: false, statusText: 'unexpected' });
  });
};

const noop = () => undefined;

beforeEach(() => {
  mockPermissions = ['key_management.edit', 'settings.edit'];
  mockFetch.mockReset();
});

describe('WizardFinishStep', () => {
  it('mints a signing key when the connection has none', async () => {
    settingsReturning(null);
    const provision = jest
      .fn()
      .mockResolvedValue(connection({ keys: { active: { key_id: 'gateway-jwt-1' } } }));

    render(
      <WizardFinishStep
        connection={connection()}
        onProvisionKey={provision}
        onSettled={noop}
        onDefaultChoice={noop}
      />
    );

    await waitFor(() => expect(provision).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('gateway-jwt-1')).toBeInTheDocument();
  });

  it('does not re-provision a connection that already has a key', async () => {
    // Provisioning rotates: a second pass would retire a key that is still
    // signing, so an already-keyed connection must be left alone.
    settingsReturning(null);
    const provision = jest.fn();

    render(
      <WizardFinishStep
        connection={connection({ keys: { active: { key_id: 'existing-key' } } })}
        onProvisionKey={provision}
        onSettled={noop}
        onDefaultChoice={noop}
      />
    );

    await screen.findByText('existing-key');
    expect(provision).not.toHaveBeenCalled();
  });

  it('pre-checks the default when the appliance has no agent default yet', async () => {
    settingsReturning(null);
    const onDefaultChoice = jest.fn();

    render(
      <WizardFinishStep
        connection={connection({ keys: { active: { key_id: 'k' } } })}
        onProvisionKey={jest.fn()}
        onSettled={noop}
        onDefaultChoice={onDefaultChoice}
      />
    );

    const checkbox = await screen.findByLabelText(/Use this agent for all signing/);
    await waitFor(() => expect(checkbox).toBeChecked());
    expect(onDefaultChoice).toHaveBeenCalledWith(true);
  });

  it('leaves the default unchecked when one is already set', async () => {
    // Connecting a second agent must never silently repoint signing for
    // everything already running against the first.
    settingsReturning({ connection_id: 'vta-other' });
    const onDefaultChoice = jest.fn();

    render(
      <WizardFinishStep
        connection={connection({ keys: { active: { key_id: 'k' } } })}
        onProvisionKey={jest.fn()}
        onSettled={noop}
        onDefaultChoice={onDefaultChoice}
      />
    );

    const checkbox = await screen.findByLabelText(/Use this agent for all signing/);
    await waitFor(() => expect(onDefaultChoice).toHaveBeenCalledWith(false));
    expect(checkbox).not.toBeChecked();
    expect(await screen.findByText(/already the appliance default/)).toBeInTheDocument();
  });

  it('explains who to ask when the operator cannot provision keys', async () => {
    mockPermissions = ['settings.edit'];
    settingsReturning(null);
    const provision = jest.fn();

    render(
      <WizardFinishStep
        connection={connection()}
        onProvisionKey={provision}
        onSettled={noop}
        onDefaultChoice={noop}
      />
    );

    expect(await screen.findByText(/key_management.edit/)).toBeInTheDocument();
    expect(provision).not.toHaveBeenCalled();
    expect(screen.getByText(/cannot sign yet/)).toBeInTheDocument();
  });

  it('keeps the connection usable when minting fails', async () => {
    settingsReturning(null);
    const provision = jest.fn().mockRejectedValue(new Error('VTA refused'));

    render(
      <WizardFinishStep
        connection={connection()}
        onProvisionKey={provision}
        onSettled={noop}
        onDefaultChoice={noop}
      />
    );

    expect(await screen.findByText(/VTA refused/)).toBeInTheDocument();
    expect(screen.getByText(/Secrets → Key Management/)).toBeInTheDocument();
  });
});
