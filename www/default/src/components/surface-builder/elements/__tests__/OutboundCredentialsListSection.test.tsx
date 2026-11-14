import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import OutboundCredentialsListSection, {
  type OutboundCredentialFormRow,
} from '../_shared/OutboundCredentialsListSection';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockedApi = apiClient as unknown as { fetch: jest.Mock };

beforeEach(() => {
  // The project resets mocks between tests, so the answer is set here.
  mockedApi.fetch.mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve([
        { id: 'vendor', name: 'Vendor' },
        { id: 'other', name: 'Other' },
      ]),
  });
});

function row(consent_mode: OutboundCredentialFormRow['consent_mode']): OutboundCredentialFormRow {
  return {
    credential_provider_id: 'vendor',
    scopes: 'read',
    consent_mode,
    required_for_mode: 'all',
    inject_as_type: 'custom_header',
    inject_as_custom_name: 'X-Vendor-Token',
    inject_as_custom_format: 'token {value}',
    ...(consent_mode === 'external' ? { subject: 'owner' as const } : {}),
  } as OutboundCredentialFormRow;
}

/** Every select and text input of the row: the provider, the consent mode, the
 * requests it is required for and the injection, then the scopes and the custom
 * header's name and format. */
function fields(): HTMLElement[] {
  return [...screen.getAllByRole('combobox'), ...screen.getAllByRole('textbox')];
}

describe('Credential Delegation binding', () => {
  it('shows an external consent binding read-only, all but its removal', async () => {
    render(<OutboundCredentialsListSection rows={[row('external')]} onChange={() => {}} />);
    await waitFor(() => expect(mockedApi.fetch).toHaveBeenCalled());
    await screen.findByText('Vendor');
    const inputs = fields();
    expect(inputs).toHaveLength(7);
    for (const input of inputs) {
      expect(input).toBeDisabled();
    }
    expect(screen.getByTitle('Remove binding')).toBeEnabled();
    expect(screen.getByTestId('credential-delegation-binding-subject')).toHaveTextContent(
      'Changing or removing this binding revokes its grants.'
    );
  });

  it('offers no second binding, and no gateway callback, beside an external consent binding', async () => {
    render(<OutboundCredentialsListSection rows={[row('external')]} onChange={() => {}} />);
    await screen.findByText('Vendor');
    expect(screen.getByTestId('credential-delegation-add')).toBeDisabled();
    expect(screen.getByTestId('credential-delegation-add-blocked')).toHaveTextContent(
      "the Access Point Target's only binding"
    );
    expect(screen.queryByText('Gateway-held credential callback URL')).toBeNull();
  });

  it('offers another binding and the gateway callback beside one without external consent', async () => {
    render(<OutboundCredentialsListSection rows={[row('on_demand')]} onChange={() => {}} />);
    await screen.findByText('Vendor');
    expect(screen.getByTestId('credential-delegation-add')).toBeEnabled();
    expect(screen.queryByTestId('credential-delegation-add-blocked')).toBeNull();
    expect(screen.getByText('Gateway-held credential callback URL')).toBeInTheDocument();
  });

  it('leaves a binding without external consent editable', async () => {
    render(<OutboundCredentialsListSection rows={[row('on_demand')]} onChange={() => {}} />);
    await screen.findByText('Vendor');
    const inputs = fields();
    expect(inputs).toHaveLength(7);
    await waitFor(() => {
      for (const input of inputs) {
        expect(input).toBeEnabled();
      }
    });
    expect(screen.queryByTestId('credential-delegation-binding-subject')).toBeNull();
    expect(screen.queryByTestId('credential-delegation-binding-consent-limit')).toBeNull();
  });

  it('shows a consent time limit set through the API', async () => {
    render(
      <OutboundCredentialsListSection
        rows={[{ ...row('on_demand'), max_consent_age_secs: 2_592_000 }]}
        onChange={() => {}}
      />
    );
    await screen.findByText('Vendor');
    expect(screen.getByTestId('credential-delegation-binding-consent-limit')).toHaveTextContent(
      'Consent time limit: 30 days, set through the API.'
    );
  });
});
