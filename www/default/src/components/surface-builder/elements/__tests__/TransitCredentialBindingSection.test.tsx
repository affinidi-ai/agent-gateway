import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import TransitCredentialBindingSection, {
  type TransitCredentialsForm,
} from '../_shared/TransitCredentialBindingSection';
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

function binding(consent_mode: TransitCredentialsForm['consent_mode']): TransitCredentialsForm {
  return {
    credential_provider_id: 'vendor',
    scopes: 'read',
    consent_mode,
    inject_as_type: 'custom_header',
    inject_as_custom_name: 'X-Vendor-Token',
    inject_as_custom_format: 'token {value}',
    ...(consent_mode === 'external' ? { subject: 'owner' as const } : {}),
  };
}

/** Every select and text input of the section: the provider, the consent mode and the
 * injection, then the scopes and the custom header's name and format. */
function fields(): HTMLElement[] {
  return [...screen.getAllByRole('combobox'), ...screen.getAllByRole('textbox')];
}

describe('Transit Point credential binding', () => {
  it('shows an external consent binding read-only, all but its removal', async () => {
    render(<TransitCredentialBindingSection value={binding('external')} onChange={() => {}} />);
    await waitFor(() => expect(mockedApi.fetch).toHaveBeenCalled());
    await screen.findByText('Vendor');
    const inputs = fields();
    expect(inputs).toHaveLength(6);
    for (const input of inputs) {
      expect(input).toBeDisabled();
    }
    expect(screen.getByRole('checkbox', { name: 'Inject outbound credential' })).toBeEnabled();
    expect(screen.getByTestId('transit-point-binding-subject')).toHaveTextContent(
      'Changing or removing this binding revokes its grants.'
    );
  });

  it('leaves a binding without external consent editable', async () => {
    render(<TransitCredentialBindingSection value={binding('on_demand')} onChange={() => {}} />);
    await screen.findByText('Vendor');
    const inputs = fields();
    expect(inputs).toHaveLength(6);
    await waitFor(() => {
      for (const input of inputs) {
        expect(input).toBeEnabled();
      }
    });
    expect(screen.queryByTestId('transit-point-binding-subject')).toBeNull();
    expect(screen.queryByTestId('transit-point-binding-consent-limit')).toBeNull();
  });

  it('shows a consent time limit set through the API', async () => {
    render(
      <TransitCredentialBindingSection
        value={{ ...binding('on_demand'), max_consent_age_secs: 21_600 }}
        onChange={() => {}}
      />
    );
    await screen.findByText('Vendor');
    expect(screen.getByTestId('transit-point-binding-consent-limit')).toHaveTextContent(
      'Consent time limit: 6 hours, set through the API.'
    );
  });
});
