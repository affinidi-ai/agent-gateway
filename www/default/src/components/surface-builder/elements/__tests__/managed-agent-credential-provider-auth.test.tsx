import React from 'react';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import ManagedAgentAuthFullscreen from '../managed-agent/ManagedAgentAuthFullscreen';

const mockHasPermission = jest.fn();
const mockFetch = jest.fn();
const mockGet = jest.fn();

jest.mock('../../../../api', () => ({
  apiClient: {
    fetch: (...args: unknown[]) => mockFetch(...args),
    get: (...args: unknown[]) => mockGet(...args),
  },
}));

jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission }),
}));

const providers = [
  {
    id: 'p-cc',
    name: 'Foundry',
    provider_id: 'foundry',
    provider_type: 'oauth2_client_credentials',
  },
  { id: 'p-jwt', name: 'Vertex', provider_id: 'vertex', provider_type: 'oauth2_jwt_bearer' },
  { id: 'p-key', name: 'Static key', provider_id: 'key', provider_type: 'api_key' },
  { id: 'p-ac', name: 'GitHub', provider_id: 'github', provider_type: 'oauth2_authorization_code' },
];

function renderEditor(config: Record<string, unknown>) {
  const updateField = jest.fn();
  const updateFields = jest.fn();
  render(
    <MemoryRouter>
      <ManagedAgentAuthFullscreen
        {...({
          node: { id: 'target', type: 'target', label: '', configured: true, config },
          config,
          updateField,
          updateFields,
        } as any)}
      />
    </MemoryRouter>
  );
  return { updateField, updateFields };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockHasPermission.mockReturnValue(true);
  mockGet.mockResolvedValue({ data: [] });
  mockFetch.mockResolvedValue({ ok: true, json: async () => providers });
});

const credentialProviderConfig = {
  target_auth_enabled: true,
  target_auth_type: 'credential_provider',
  target_auth_credential_provider_id: 'p-jwt',
  target_auth_scopes: 'cloud-platform',
  target_auth_inject_as: 'bearer_header',
  target_auth_fallback: 'reject',
};

describe('Managed Agent Target Authentication, credential provider', () => {
  it('offers the credential provider type and switches to it', () => {
    const { updateFields } = renderEditor({
      target_auth_enabled: true,
      target_auth_type: 'bearer',
    });
    fireEvent.change(screen.getByTestId('target-auth-type'), {
      target: { value: 'credential_provider' },
    });
    expect(updateFields).toHaveBeenCalledWith({
      target_auth_enabled: true,
      target_auth_type: 'credential_provider',
      target_auth_fallback: 'reject',
    });
  });

  it('lists only providers allowed for Target Authentication', async () => {
    renderEditor(credentialProviderConfig);
    const select = screen.getByTestId('target-auth-credential-provider-select');
    await waitFor(() => expect(select).not.toBeDisabled());
    const labels = within(select)
      .getAllByRole('option')
      .map(o => o.textContent);
    expect(labels).toEqual([
      '-- Select a credential provider --',
      'Foundry (Client Credentials)',
      'Vertex (JWT Bearer)',
      'Static key (API Key)',
    ]);
    expect(select).toHaveValue('p-jwt');
  });

  it('writes the chosen provider id into the config', async () => {
    const { updateField } = renderEditor({
      ...credentialProviderConfig,
      target_auth_credential_provider_id: '',
    });
    const select = screen.getByTestId('target-auth-credential-provider-select');
    await waitFor(() => expect(select).not.toBeDisabled());
    fireEvent.change(select, { target: { value: 'p-cc' } });
    expect(updateField).toHaveBeenCalledWith('target_auth_credential_provider_id', 'p-cc');
  });

  it('flags a saved Authorization Code provider as unusable', async () => {
    renderEditor({ ...credentialProviderConfig, target_auth_credential_provider_id: 'p-ac' });
    expect(
      await screen.findByTestId('target-auth-credential-provider-select-unusable')
    ).toHaveTextContent(
      'The Authorization Code provider cannot be used for Target Authentication.'
    );
  });

  it('flags a saved provider that no longer exists', async () => {
    renderEditor({ ...credentialProviderConfig, target_auth_credential_provider_id: 'gone' });
    expect(
      await screen.findByTestId('target-auth-credential-provider-select-unusable')
    ).toHaveTextContent('The selected provider no longer exists.');
  });

  it('shows the scope field and header shape, and a custom header form on demand', () => {
    const { updateField } = renderEditor({
      ...credentialProviderConfig,
      target_auth_inject_as: 'custom_header',
      target_auth_inject_name: 'X-Token',
      target_auth_inject_format: '{value}',
    });
    expect(screen.getByTestId('target-auth-scopes')).toHaveValue('cloud-platform');
    expect(screen.getByTestId('target-auth-inject-name')).toHaveValue('X-Token');
    expect(screen.getByTestId('target-auth-header-note')).toHaveTextContent('X-Token');
    fireEvent.change(screen.getByTestId('target-auth-inject-format'), {
      target: { value: 'tok {value}' },
    });
    expect(updateField).toHaveBeenCalledWith('target_auth_inject_format', 'tok {value}');
  });

  it('names Authorization for the bearer header shape and hides the custom fields', () => {
    renderEditor(credentialProviderConfig);
    expect(screen.getByTestId('target-auth-header-note')).toHaveTextContent('Authorization');
    expect(screen.queryByTestId('target-auth-inject-name')).not.toBeInTheDocument();
  });

  it('reports an invalid custom header format', () => {
    renderEditor({
      ...credentialProviderConfig,
      target_auth_inject_as: 'custom_header',
      target_auth_inject_name: 'X-Token',
      target_auth_inject_format: 'no placeholder',
    });
    expect(screen.getByTestId('target-auth-error')).toHaveTextContent(
      'The header format must contain {value}.'
    );
  });

  it('keeps the saved provider and skips the list call without credential_providers.view', () => {
    mockHasPermission.mockImplementation((p: string) => p !== 'credential_providers.view');
    renderEditor(credentialProviderConfig);
    expect(
      screen.getByTestId('target-auth-credential-provider-select-no-permission')
    ).toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
    expect(screen.getByDisplayValue('p-jwt')).toHaveAttribute('readonly');
  });

  it('shows a load error and not the unusable warning when the list call fails', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    renderEditor(credentialProviderConfig);
    expect(
      await screen.findByTestId('target-auth-credential-provider-select-error')
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId('target-auth-credential-provider-select-unusable')
    ).not.toBeInTheDocument();
  });

  it('tells the operator an unsupported method is kept as saved', () => {
    renderEditor({ target_auth_enabled: true, target_auth_type: 'preserved' });
    expect(screen.getByTestId('target-auth-preserved')).toHaveTextContent('saved unchanged');
    expect(screen.queryByLabelText(/Secret/)).not.toBeInTheDocument();
  });
});
