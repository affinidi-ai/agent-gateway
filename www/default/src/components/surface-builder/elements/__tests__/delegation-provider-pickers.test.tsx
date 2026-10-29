import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import OutboundCredentialsListSection, {
  type OutboundCredentialFormRow,
} from '../_shared/OutboundCredentialsListSection';
import TransitCredentialBindingSection, {
  EMPTY_TRANSIT_CREDENTIALS,
} from '../_shared/TransitCredentialBindingSection';

const mockFetch = jest.fn();

jest.mock('../../../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));

const providers = [
  { id: 'p-ac', name: 'GitHub', provider_id: 'github', provider_type: 'oauth2_authorization_code' },
  { id: 'p-key', name: 'Static key', provider_id: 'key', provider_type: 'api_key' },
  { id: 'p-future', name: 'Future', provider_id: 'future', provider_type: 'future_type' },
];

const row: OutboundCredentialFormRow = {
  credential_provider_id: '',
  scopes: '',
  consent_mode: 'on_demand',
  required_for_mode: 'all',
  inject_as_type: 'bearer_header',
};

const optionLabels = (select: HTMLElement) =>
  within(select)
    .getAllByRole('option')
    .map(o => o.textContent);

beforeEach(() => {
  jest.clearAllMocks();
  mockFetch.mockResolvedValue({ ok: true, json: async () => providers });
});

describe('delegation provider pickers', () => {
  it('lists only provider types that allow delegation in the outbound bindings editor', async () => {
    render(
      <MemoryRouter>
        <OutboundCredentialsListSection rows={[row]} onChange={jest.fn()} />
      </MemoryRouter>
    );
    const select = await screen.findByRole('combobox', { name: 'Credential Provider' });
    await waitFor(() => expect(select).not.toBeDisabled());
    expect(optionLabels(select)).toEqual([
      '-- Select provider --',
      'GitHub (github)',
      'Static key (key)',
    ]);
  });

  it('keeps a saved provider of an unknown type selectable and labelled in the outbound editor', async () => {
    render(
      <MemoryRouter>
        <OutboundCredentialsListSection
          rows={[{ ...row, credential_provider_id: 'p-future' }]}
          onChange={jest.fn()}
        />
      </MemoryRouter>
    );
    const select = await screen.findByRole('combobox', { name: 'Credential Provider' });
    await waitFor(() => expect(select).not.toBeDisabled());
    expect(optionLabels(select)).toContain('Future (future_type, not usable here)');
    expect(select).toHaveValue('p-future');
  });

  it('lists only provider types that allow delegation in the Transit Point binding', async () => {
    render(
      <TransitCredentialBindingSection value={EMPTY_TRANSIT_CREDENTIALS} onChange={jest.fn()} />
    );
    const select = await screen.findByRole('combobox', { name: 'Credential Provider' });
    await waitFor(() => expect(select).not.toBeDisabled());
    expect(optionLabels(select)).toEqual([
      '-- Select provider --',
      'GitHub (github)',
      'Static key (key)',
    ]);
  });

  it('keeps a saved provider of an unknown type selectable in the Transit Point binding', async () => {
    render(
      <TransitCredentialBindingSection
        value={{ ...EMPTY_TRANSIT_CREDENTIALS, credential_provider_id: 'p-future' }}
        onChange={jest.fn()}
      />
    );
    const select = await screen.findByRole('combobox', { name: 'Credential Provider' });
    await waitFor(() =>
      expect(optionLabels(select)).toContain('Future (future_type, not usable here)')
    );
    expect(select).toHaveValue('p-future');
  });
});
