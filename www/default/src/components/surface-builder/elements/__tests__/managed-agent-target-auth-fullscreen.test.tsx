import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentAuthFullscreen from '../managed-agent/ManagedAgentAuthFullscreen';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { get: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../_shared/TargetAuthProviderSelect', () => () => <div />);
jest.mock('../../SurfaceMetaContext', () => ({ useSurfaceTenant: () => undefined }));

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

  it('shows an https advisory, not an error, for a Target that is not https', () => {
    renderPanel({
      ...base,
      endpoint: 'http://agent.example.com',
      target_auth_source: 'secret',
      target_auth_secret_id: 's',
    });
    expect(screen.queryByTestId('managed-agent-target-auth-errors')).not.toBeInTheDocument();
    expect(screen.getByTestId('managed-agent-target-auth-advisories')).toHaveTextContent(
      'its Target must be an https URL. Save is allowed'
    );
  });
});
