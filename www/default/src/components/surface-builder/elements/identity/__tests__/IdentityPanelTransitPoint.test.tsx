import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import IdentityPanel from '../IdentityPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { CanvasNode } from '../../types';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const fetchMock = apiClient.fetch as jest.Mock;

const transitPoint = (sourceAuth?: Record<string, unknown>): CanvasNode => ({
  id: 'tp-1',
  type: 'transit-point-a2a',
  label: '',
  configured: true,
  config: {
    alias: 'tr1',
    target_endpoint: 'https://delta.example.com',
    ...(sourceAuth ? { source_auth: sourceAuth } : {}),
  },
});

const mountPanel = (sourceAuth: Record<string, unknown> | undefined, config = {}) => {
  const updateField = jest.fn();
  const node: CanvasNode = {
    id: 'identity-tp-1-request',
    type: 'identity',
    label: '',
    configured: true,
    parentId: 'tp-1',
    slotId: 'request:identity-managed_identity',
    config,
  };
  render(
    <MemoryRouter>
      <SurfaceMetaProvider value={{ surfaceId: 'surface-1' } as SurfaceMetaValue}>
        <IdentityPanel
          node={node}
          config={config}
          updateField={updateField}
          updateFields={jest.fn()}
          protocol="a2a"
          allNodes={[transitPoint(sourceAuth), node]}
        />
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
  return updateField;
};

const typeSelect = () => screen.getByLabelText('Identity Extraction Type');
const option = (label: string) => within(typeSelect()).getByRole('option', { name: label });

const apiKeyCaller = {
  type: 'api_key',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  secret_id: 'agents',
};
const providerCaller = {
  type: 'api_key_provider',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  agent_id: 'surface-1',
};
const jwtCaller = { type: 'jwt_bearer', jwt_verification_strategy_id: 's', audiences: ['tr1'] };

describe('IdentityPanel on a Transit Point', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({ ok: true, json: async () => [] });
  });

  it.each([
    ['an API key', apiKeyCaller],
    ['an API Key Provider', providerCaller],
  ])('offers From API Key while callers authenticate with %s', (_name, sourceAuth) => {
    mountPanel(sourceAuth);
    expect(option('From API Key')).toBeEnabled();
    expect(screen.queryByTestId('identity-panel-transit-api-key-unavailable')).toBeNull();
  });

  it.each([
    ['JWT Bearer', jwtCaller],
    ['no caller authentication', undefined],
  ])('disables From API Key with %s and says why', (_name, sourceAuth) => {
    mountPanel(sourceAuth);
    expect(option('From API Key')).toBeDisabled();
    expect(screen.getByTestId('identity-panel-transit-api-key-unavailable')).toHaveTextContent(
      "From API Key needs this Transit Point's caller authentication to be an API key."
    );
  });

  it('keeps JWT Claims and mTLS disabled behind an API key caller', () => {
    mountPanel(apiKeyCaller);
    expect(option('From JWT Claims')).toBeDisabled();
    expect(option('From mTLS certificate')).toBeDisabled();
    expect(option('From Payload (identity metadata)')).toBeEnabled();
  });

  it('writes the type only when From API Key is picked', () => {
    const updateField = mountPanel(apiKeyCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_api_key' } });
    expect(updateField).toHaveBeenCalledTimes(1);
    expect(updateField).toHaveBeenCalledWith('type', 'from_api_key');
  });

  it('does not write From API Key behind a JWT Bearer caller', () => {
    const updateField = mountPanel(jwtCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_api_key' } });
    expect(updateField).not.toHaveBeenCalled();
  });

  it('shows the per-caller line and no key picker', () => {
    mountPanel(apiKeyCaller, { type: 'from_api_key' });
    expect(screen.getByTestId('identity-panel-transit-api-key-note')).toHaveTextContent(
      'Each caller is identified by the API key it presents to this Transit Point.'
    );
    expect(screen.queryByTestId('identity-panel-api-key-select')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps showing a stored API key set through the API', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => [
        { key_id: 'atgk_agent', agent_id: 'surface-1', client_id: 'agent', status: 'active' },
      ],
    });
    mountPanel(jwtCaller, { type: 'from_api_key', api_key_id: 'atgk_agent' });
    const select = screen.getByTestId('identity-panel-api-key-select');
    await within(select).findByRole('option', { name: 'agent' });
    expect(select).toHaveValue('atgk_agent');
    expect(screen.queryByTestId('identity-panel-transit-api-key-note')).toBeNull();
  });

  it('describes what each option needs on a Transit Point', () => {
    mountPanel(jwtCaller);
    const help = screen.getByTestId('identity-panel-transit-type-help');
    expect(help).toHaveTextContent(
      "Any caller can copy that DID, so policy sees it as unverified; the options below bind it to the caller's credential."
    );
    expect(help).toHaveTextContent('Needs JWT Bearer caller authentication on this Transit Point.');
    expect(help).toHaveTextContent(
      'Needs mTLS caller authentication on this Transit Point, set through the API.'
    );
  });
});

const mtlsCaller = { type: 'mtls', trust: { type: 'pinned', certificate_ids: ['c'] } };

describe('IdentityPanel From JWT Claims on a Transit Point', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({ ok: true, json: async () => [] });
  });

  it('offers From JWT Claims while callers authenticate with JWT Bearer', () => {
    mountPanel(jwtCaller);
    expect(option('From JWT Claims')).toBeEnabled();
    expect(screen.queryByTestId('identity-panel-transit-jwt-claim-unavailable')).toBeNull();
  });

  it.each([
    ['an API key', apiKeyCaller],
    ['mTLS', mtlsCaller],
    ['no caller authentication', undefined],
  ])('disables From JWT Claims with %s and says why', (_name, sourceAuth) => {
    mountPanel(sourceAuth);
    expect(option('From JWT Claims')).toBeDisabled();
    expect(screen.getByTestId('identity-panel-transit-jwt-claim-unavailable')).toHaveTextContent(
      "From JWT Claims needs this Transit Point's caller authentication to be JWT Bearer."
    );
  });

  it('writes the type when From JWT Claims is picked', () => {
    const updateField = mountPanel(jwtCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_jwt_claim' } });
    expect(updateField).toHaveBeenCalledWith('type', 'from_jwt_claim');
  });

  it('does not write From JWT Claims behind an API key caller', () => {
    const updateField = mountPanel(apiKeyCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_jwt_claim' } });
    expect(updateField).not.toHaveBeenCalled();
  });

  it('edits the claim and namespace claims', () => {
    const updateField = mountPanel(jwtCaller, { type: 'from_jwt_claim' });
    expect(
      screen.getByText('Requires JWT Bearer caller authentication on this Transit Point.')
    ).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('oid'), { target: { value: 'sub' } });
    fireEvent.change(screen.getByPlaceholderText('iss, tid'), { target: { value: 'iss, tid' } });
    expect(updateField).toHaveBeenCalledWith('claim', 'sub');
    expect(updateField).toHaveBeenCalledWith('namespace_claims', ['iss', 'tid']);
  });
});

describe('IdentityPanel From mTLS certificate on a Transit Point', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => [{ id: 'cert-1', name: 'agent cert', active: true, kind: 'client_leaf' }],
    });
  });

  it('offers From mTLS certificate while callers authenticate with mTLS', () => {
    mountPanel(mtlsCaller);
    expect(option('From mTLS certificate')).toBeEnabled();
    expect(option('From API Key')).toBeDisabled();
    expect(option('From JWT Claims')).toBeDisabled();
    expect(option('Static DID')).toBeDisabled();
    expect(screen.queryByTestId('identity-panel-transit-mtls-unavailable')).toBeNull();
  });

  it.each([
    ['an API key', apiKeyCaller],
    ['JWT Bearer', jwtCaller],
    ['no caller authentication', undefined],
  ])('disables From mTLS certificate with %s and says why', (_name, sourceAuth) => {
    mountPanel(sourceAuth);
    expect(option('From mTLS certificate')).toBeDisabled();
    expect(screen.getByTestId('identity-panel-transit-mtls-unavailable')).toHaveTextContent(
      "From mTLS certificate needs this Transit Point's caller authentication to be mTLS, set through the API."
    );
  });

  it('writes the type when From mTLS certificate is picked', () => {
    const updateField = mountPanel(mtlsCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_mtls' } });
    expect(updateField).toHaveBeenCalledTimes(1);
    expect(updateField).toHaveBeenCalledWith('type', 'from_mtls');
  });

  it('does not write From mTLS certificate behind a JWT Bearer caller', () => {
    const updateField = mountPanel(jwtCaller);
    fireEvent.change(typeSelect(), { target: { value: 'from_mtls' } });
    expect(updateField).not.toHaveBeenCalled();
  });

  it('shows the per-caller line and no certificate picker', () => {
    mountPanel(mtlsCaller, { type: 'from_mtls' });
    expect(screen.getByTestId('identity-panel-transit-mtls-note')).toHaveTextContent(
      'Each caller is identified by the client certificate it presents to this Transit Point.'
    );
    expect(screen.queryByText('Client Certificate')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps showing a stored certificate set through the API', async () => {
    mountPanel(jwtCaller, { type: 'from_mtls', certificate_id: 'cert-1' });
    await screen.findByRole('option', { name: 'agent cert' });
    expect(screen.getByDisplayValue('agent cert')).toBeInTheDocument();
    expect(screen.queryByTestId('identity-panel-transit-mtls-note')).toBeNull();
  });
});
