import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import TargetAuthProviderSelect from '../TargetAuthProviderSelect';
import OutboundCredentialsListSection from '../OutboundCredentialsListSection';
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
  { id: 'wide-code', name: 'Wide Code', provider_type: 'oauth2_authorization_code' },
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

  it('labels a stored provider of another tenant as refused', async () => {
    render(
      withTenant(
        'acme',
        <TargetAuthProviderSelect id="p" testId="p-select" value="other-1" onChange={() => {}} />
      )
    );
    const select = await screen.findByTestId('p-select');
    await screen.findByText('Acme');
    expect(optionTexts(select)).toEqual([
      '-- Select a credential provider --',
      'Acme',
      'Other (another tenant, refused by the gateway)',
    ]);
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
      'Wide Code',
      'Wide (appliance-wide, stops working when enforced)',
    ]);
  });

  it('labels a stored provider of another tenant as refused', async () => {
    render(
      withTenant(
        'acme',
        <TransitCredentialBindingSection
          value={{ ...EMPTY_TRANSIT_CREDENTIALS, credential_provider_id: 'other-1' }}
          onChange={() => {}}
        />
      )
    );
    await screen.findByText('Acme');
    const select = screen.getAllByRole('combobox')[0];
    expect(optionTexts(select)).toEqual([
      '-- Select provider --',
      'Acme',
      'Wide Code',
      'Other (another tenant, refused by the gateway)',
    ]);
  });

  it('offers an appliance-wide surface no tenant provider, even an authorization code one', async () => {
    (apiClient.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve([
          ...providers,
          {
            id: 'acme-code',
            name: 'Acme Code',
            provider_type: 'oauth2_authorization_code',
            tenant_id: 'acme',
          },
        ]),
    });
    render(
      withTenant(
        null,
        <TransitCredentialBindingSection
          value={{ ...EMPTY_TRANSIT_CREDENTIALS }}
          onChange={() => {}}
        />
      )
    );
    await screen.findByText('Wide Code');
    const select = screen.getAllByRole('combobox')[0];
    expect(optionTexts(select)).toEqual(['-- Select provider --', 'Wide', 'Wide Code']);
  });
});

describe('stored appliance-wide provider with an issuer', () => {
  const withIssuer = [
    ...providers,
    {
      id: 'wide-consent',
      name: 'Wide Consent',
      provider_type: 'oauth2_authorization_code',
      issuer: 'https://issuer.example',
    },
  ];

  beforeEach(() => {
    (apiClient.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(withIssuer),
    });
  });

  it('is labelled as refused in the transit binding picker', async () => {
    render(
      withTenant(
        'acme',
        <TransitCredentialBindingSection
          value={{ ...EMPTY_TRANSIT_CREDENTIALS, credential_provider_id: 'wide-consent' }}
          onChange={() => {}}
        />
      )
    );
    await screen.findByText('Acme');
    const select = screen.getAllByRole('combobox')[0];
    expect(optionTexts(select)).toEqual([
      '-- Select provider --',
      'Acme',
      'Wide Code',
      'Wide Consent (appliance-wide, refused by the gateway)',
    ]);
  });

  it('is labelled as refused in the outbound credentials picker', async () => {
    render(
      withTenant(
        'acme',
        <OutboundCredentialsListSection
          rows={[
            {
              credential_provider_id: 'wide-consent',
              scopes: '',
              consent_mode: 'on_demand',
              required_for_mode: 'all',
              inject_as_type: 'bearer_header',
            },
          ]}
          onChange={() => {}}
        />
      )
    );
    await screen.findByText('Acme');
    const select = screen.getAllByRole('combobox')[0];
    expect(optionTexts(select)).toEqual([
      '-- Select provider --',
      'Acme',
      'Wide Code',
      'Wide Consent (appliance-wide, refused by the gateway)',
    ]);
  });
});
