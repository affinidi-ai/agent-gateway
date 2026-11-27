import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import KeyManagementTab from './KeyManagementTab';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

const connection = (id: string, name: string) => ({
  connection_id: id,
  name,
  enabled: true,
  transport: 'https',
  vta_did: `did:webvh:${id}.example`,
  pairing_state: 'connected',
  usable: true,
  keys: [{ key_id: `${id}-key-1`, status: 'active' }],
});

const rotations: { url: string; body: unknown }[] = [];

beforeEach(() => {
  rotations.length = 0;
  mockFetch.mockReset();
  mockFetch.mockImplementation((url: string, init?: { body?: string }) => {
    if (url.includes('/rotate')) {
      rotations.push({ url, body: JSON.parse(init?.body ?? '{}') });
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }
    return Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          tier: 'trust agent',
          custody_claim: true,
          connections: [connection('agent-a', 'Agent A'), connection('agent-b', 'Agent B')],
          mappings: [],
          orphaned_contexts: [],
        }),
    });
  });
});

const fields = async () => {
  await screen.findByText('Agent B');
  return {
    inputs: screen.getAllByLabelText('New key id'),
    rotates: screen.getAllByRole('button', { name: 'Rotate' }),
  };
};

describe('KeyManagementTab rotation', () => {
  it('rotates a connection to the key id typed on its own card', async () => {
    render(<KeyManagementTab />);
    const { inputs, rotates } = await fields();

    await userEvent.type(inputs[0], 'key-a-2');
    await userEvent.click(rotates[0]);
    await userEvent.click(rotates[0]);

    await waitFor(() => expect(rotations).toHaveLength(1));
    expect(rotations[0].url).toContain('agent-a');
    expect(rotations[0].body).toEqual({ key_id: 'key-a-2' });
  });

  it("keeps each card's key id to itself", async () => {
    render(<KeyManagementTab />);
    const { inputs, rotates } = await fields();

    await userEvent.type(inputs[0], 'key-a-2');

    expect(inputs[1]).toHaveValue('');
    expect(rotates[1]).toBeDisabled();
  });

  it('asks again when the key id changes after the first click', async () => {
    render(<KeyManagementTab />);
    const { inputs, rotates } = await fields();

    await userEvent.type(inputs[0], 'key-a-2');
    await userEvent.click(rotates[0]);
    await userEvent.type(inputs[0], 'x');
    await userEvent.click(rotates[0]);

    expect(rotations).toHaveLength(0);
    await userEvent.click(rotates[0]);
    await waitFor(() => expect(rotations).toHaveLength(1));
    expect(rotations[0].body).toEqual({ key_id: 'key-a-2x' });
  });
});

describe('KeyManagementTab custody', () => {
  const inventory = (custodyClaim: boolean) =>
    mockFetch.mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve({
            tier: 'self-hosted',
            custody_claim: custodyClaim,
            connections: [],
            mappings: [],
            orphaned_contexts: [],
          }),
      })
    );

  it('says the trust agent holds the signing keys only while the gateway signs nothing with its own', async () => {
    inventory(true);
    render(<KeyManagementTab />);

    expect(
      await screen.findByText(
        /signed by a separately-operated trust agent\. Some keys stay on the gateway/
      )
    ).toBeInTheDocument();
  });

  it("says the gateway's own key still signs while it does", async () => {
    inventory(false);
    render(<KeyManagementTab />);

    expect(
      await screen.findByText(/Some tokens are still signed with the gateway's own key/)
    ).toBeInTheDocument();
  });
});
