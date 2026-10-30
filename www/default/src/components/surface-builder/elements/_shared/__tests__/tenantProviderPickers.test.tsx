import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import TargetAuthProviderSelect from '../TargetAuthProviderSelect';
import TransitCredentialBindingSection, {
  EMPTY_TRANSIT_CREDENTIALS,
} from '../TransitCredentialBindingSection';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import { apiClient } from '../../../../../api';

jest.mock('../../../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const providers = [
  { id: 'wide', name: 'Wide', provider_type: 'oauth2_client_credentials' },
  { id: 'acme-1', name: 'Acme', provider_type: 'oauth2_client_credentials', tenant_id: 'acme' },
  { id: 'other-1', name: 'Other', provider_type: 'api_key', tenant_id: 'other' },
];

const withTenant = (tenantId: string | null | undefined, child: React.ReactElement) => (
  <SurfaceMetaProvider value={{ tenantId } as unknown as SurfaceMetaValue}>
    {child}
  </SurfaceMetaProvider>
);

const optionTexts = (el: HTMLElement) =>
  within(el)
    .getAllByRole('option')
    .map(o => o.textContent);

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(providers),
  });
});

describe('TargetAuthProviderSelect tenant scope', () => {
  it('lists only the surface tenant providers and labels a stored appliance-wide one', async () => {
    render(
      withTenant(
        'acme',
        <TargetAuthProviderSelect id="p" testId="p-select" value="wide" onChange={() => {}} />
      )
    );
    const select = await screen.findByTestId('p-select');
    await screen.findByText('Acme');
    expect(optionTexts(select)).toEqual([
      '-- Select a credential provider --',
      'Acme',
      'Wide (appliance-wide, stops working when enforced)',
    ]);
    expect(select).toHaveValue('wide');
  });

  it('does not list a provider of another tenant unless it is the stored choice', async () => {
    render(
      withTenant(
        'acme',
        <TargetAuthProviderSelect id="p" testId="p-select" value="" onChange={() => {}} />
      )
    );
    const select = await screen.findByTestId('p-select');
    await screen.findByText('Acme');
    expect(optionTexts(select)).not.toContain('Other');
    expect(optionTexts(select)).not.toContain('Wide');
  });

  it('lists only appliance-wide providers for an appliance-wide surface', async () => {
    render(
      withTenant(
        null,
        <TargetAuthProviderSelect id="p" testId="p-select" value="" onChange={() => {}} />
      )
    );
    const select = await screen.findByTestId('p-select');
    await screen.findByText('Wide');
    expect(optionTexts(select)).toEqual(['-- Select a credential provider --', 'Wide']);
  });

  it('lists every usable provider while the surface is being created', async () => {
    render(
      withTenant(
        undefined,
        <TargetAuthProviderSelect id="p" testId="p-select" value="" onChange={() => {}} />
      )
    );
    const select = await screen.findByTestId('p-select');
    await screen.findByText('Acme');
    expect(optionTexts(select)).toEqual([
      '-- Select a credential provider --',
      'Wide',
      'Acme',
      'Other',
    ]);
  });
});

describe('TransitCredentialBindingSection tenant scope', () => {
  it('lists the tenant providers and keeps a stored appliance-wide choice labelled', async () => {
    render(
      withTenant(
        'acme',
        <TransitCredentialBindingSection
          value={{ ...EMPTY_TRANSIT_CREDENTIALS, credential_provider_id: 'wide' }}
          onChange={() => {}}
        />
      )
    );
    await screen.findByText('Acme');
    const select = screen.getAllByRole('combobox')[0];
    expect(optionTexts(select)).toEqual([
      '-- Select provider --',
      'Acme',
      'Wide (appliance-wide, stops working when enforced)',
    ]);
  });
});
