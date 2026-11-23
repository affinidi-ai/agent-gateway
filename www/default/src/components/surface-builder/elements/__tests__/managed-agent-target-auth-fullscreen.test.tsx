import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentAuthFullscreen from '../managed-agent/ManagedAgentAuthFullscreen';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { get: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../_shared/TargetAuthProviderSelect', () => (props: { errorId?: string }) => (
  <div data-testid="provider-select" data-error-id={props.errorId ?? ''} />
));
const mockSurfaceMeta = jest.fn();
jest.mock('../../SurfaceMetaContext', () => ({
  useSurfaceTenant: () => undefined,
  useOptionalSurfaceMeta: () => mockSurfaceMeta(),
}));

const renderPanel = (config: Record<string, unknown>, updateField = jest.fn()) => {
  render(
    <ManagedAgentAuthFullscreen
      node={{ id: 'target', type: 'target', label: 'T', configured: true, config } as any}
      config={config}
      updateField={updateField}
      updateFields={jest.fn()}
    />
  );
};

const base = {
  endpoint: 'https://agent.example.com',
  target_auth_enabled: true,
  target_auth_type: 'bearer',
  target_auth_header_name: 'Authorization',
  target_auth_header_format: 'Bearer {value}',
};

describe('Managed Agent Target authentication editor', () => {
  beforeEach(() => {
    mockSurfaceMeta.mockReturnValue(null);
    (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
  });

  it('offers Scopes for a credential provider and writes them to the config', () => {
    const updateField = jest.fn();
    renderPanel(
      { ...base, target_auth_source: 'provider', target_auth_provider_id: 'prov-1' },
      updateField
    );
    fireEvent.change(screen.getByTestId('managed-agent-target-auth-scopes'), {
      target: { value: 'read write' },
    });
    expect(updateField).toHaveBeenCalledWith('target_auth_scopes', 'read write');
  });

  it('offers no Scopes for a static secret', () => {
    renderPanel({ ...base, target_auth_source: 'secret', target_auth_secret_id: 's' });
    expect(screen.queryByTestId('managed-agent-target-auth-scopes')).not.toBeInTheDocument();
  });

  it('shows a blocking message next to a reserved header name and none for a valid one', () => {
    renderPanel({
      ...base,
      target_auth_source: 'secret',
      target_auth_secret_id: 's',
      target_auth_header_name: 'Host',
    });
    expect(screen.getByTestId('managed-agent-target-auth-header-name-error')).toHaveTextContent(
      'Header name must not be the reserved header Host'
    );
  });

  describe('the format field of a type other than Custom', () => {
    const bearer = { ...base, target_auth_source: 'secret', target_auth_secret_id: 's' };
    const panel = (config: Record<string, unknown>) => (
      <ManagedAgentAuthFullscreen
        node={{ id: 'target', type: 'target', label: 'T', configured: true, config } as any}
        config={config}
        updateField={jest.fn()}
        updateFields={jest.fn()}
      />
    );

    it('is hidden while the format is valid', () => {
      render(panel(bearer));
      expect(screen.queryByLabelText('Header Format')).not.toBeInTheDocument();
    });

    it('is shown with its message for a stored format problem, and stays while it is fixed', () => {
      const { rerender } = render(
        panel({ ...bearer, target_auth_header_format: 'Bearer {value}\n' })
      );
      const message = screen.getByTestId('managed-agent-target-auth-header-format-error');
      expect(message).toHaveTextContent('Header format must not contain CR, LF or NUL');
      expect(screen.getByLabelText('Header Format')).toHaveAttribute('aria-invalid', 'true');
      expect(screen.getByLabelText('Header Format')).toHaveAttribute(
        'aria-describedby',
        message.id
      );

      rerender(panel({ ...bearer, target_auth_header_format: 'Bearer {value} ' }));
      expect(screen.getByLabelText('Header Format')).toHaveAttribute('aria-invalid', 'false');
      expect(
        screen.queryByTestId('managed-agent-target-auth-header-format-error')
      ).not.toBeInTheDocument();
    });
  });

  it('shows an https advisory, not an error, for a Target that is not https', () => {
    renderPanel({
      ...base,
      endpoint: 'http://agent.example.com',
      target_auth_source: 'secret',
      target_auth_secret_id: 's',
    });
    expect(screen.queryByTestId('managed-agent-target-auth-errors')).not.toBeInTheDocument();
    expect(screen.getByTestId('managed-agent-target-auth-advisories')).toHaveTextContent(
      'Advisory: Target authentication sends a credential, so its Target must be an https URL. Save is allowed'
    );
  });

  it('ties the missing provider message to the provider select and announces it', () => {
    renderPanel({ ...base, target_auth_source: 'provider', target_auth_provider_id: '' });
    const message = screen.getByTestId('managed-agent-target-auth-provider-error');
    expect(message).toHaveTextContent('Pick the credential provider');
    expect(
      screen.getAllByRole('alert').some(region => within(region).queryByText(/Pick the credential/))
    ).toBe(true);
    expect(screen.getByTestId('provider-select')).toHaveAttribute('data-error-id', message.id);
  });

  it('ties no message to the provider select once a provider is picked', () => {
    renderPanel({ ...base, target_auth_source: 'provider', target_auth_provider_id: 'prov-1' });
    expect(
      screen.queryByTestId('managed-agent-target-auth-provider-error')
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('provider-select')).toHaveAttribute('data-error-id', '');
  });

  it('ties the missing secret message to the secret select and announces it', () => {
    renderPanel({ ...base, target_auth_source: 'secret', target_auth_secret_id: '' });
    const message = screen.getByTestId('managed-agent-target-auth-secret-error');
    expect(message).toHaveTextContent('Pick the secret');
    expect(
      screen.getAllByRole('alert').some(region => within(region).queryByText(/Pick the secret/))
    ).toBe(true);
    const select = screen.getByTestId('managed-agent-target-auth-secret');
    expect(select).toHaveAttribute('aria-invalid', 'true');
    expect(select).toHaveAttribute('aria-describedby', message.id);
  });

  it('ties no message to the secret select once a secret is picked', () => {
    renderPanel({ ...base, target_auth_source: 'secret', target_auth_secret_id: 's' });
    expect(screen.queryByTestId('managed-agent-target-auth-secret-error')).not.toBeInTheDocument();
    const select = screen.getByTestId('managed-agent-target-auth-secret');
    expect(select).not.toHaveAttribute('aria-invalid');
    expect(select).not.toHaveAttribute('aria-describedby');
  });

  it('advises when the Access Point checks no caller, and not when it does', () => {
    const config = { ...base, target_auth_source: 'secret', target_auth_secret_id: 's' };
    mockSurfaceMeta.mockReturnValue({ accessPointChecksCallers: false });
    renderPanel(config);
    expect(screen.getByTestId('managed-agent-target-auth-advisories')).toHaveTextContent(
      'it needs source authentication on the Access Point'
    );
  });

  it('shows no caller advice when the Access Point checks its callers', () => {
    mockSurfaceMeta.mockReturnValue({ accessPointChecksCallers: true });
    renderPanel({ ...base, target_auth_source: 'secret', target_auth_secret_id: 's' });
    expect(screen.queryByTestId('managed-agent-target-auth-advisories')).not.toBeInTheDocument();
  });

  it('advises on a passthrough fallback and keeps the live regions mounted', () => {
    renderPanel({
      ...base,
      target_auth_source: 'secret',
      target_auth_secret_id: 's',
      target_auth_fallback: 'passthrough',
    });
    const advisories = screen.getByTestId('managed-agent-target-auth-advisories');
    expect(advisories).toHaveTextContent('passes a request through without the credential');
    expect(
      within(screen.getByRole('status')).getByTestId('managed-agent-target-auth-advisories')
    ).toBe(advisories);
  });
});
