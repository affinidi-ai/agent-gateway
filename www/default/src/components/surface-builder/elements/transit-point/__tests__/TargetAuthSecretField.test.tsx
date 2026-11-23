import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import TargetAuthSecretField from '../TargetAuthSecretField';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import { ApiError, apiClient } from '../../../../../api';

jest.mock('../../../../../api', () => {
  class MockApiError extends Error {
    readonly status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  }
  return { apiClient: { get: jest.fn() }, ApiError: MockApiError };
});

const get = apiClient.get as jest.Mock;

const secrets = [
  {
    id: '1',
    name: 'Choose mission MCP key',
    secret_id: 'choose_mission_mcp_key',
    tenant_id: 'acme',
  },
  { id: '2', name: 'Partner billing token', secret_id: 'partner_billing_token', tenant_id: 'acme' },
  { id: '3', name: 'Wide key', secret_id: 'wide_key' },
  { id: '4', name: 'Other key', secret_id: 'other_key', tenant_id: 'other' },
];

function setupField(
  props: { value?: string; error?: string } = {},
  tenantId: string | null = 'acme'
) {
  const onChange = jest.fn();
  render(
    <SurfaceMetaProvider value={{ tenantId } as unknown as SurfaceMetaValue}>
      <TargetAuthSecretField value={props.value ?? ''} onChange={onChange} error={props.error} />
    </SurfaceMetaProvider>
  );
  return onChange;
}

const optionTexts = () =>
  within(screen.getByTestId('transit-point-target-auth-secret'))
    .getAllByRole('option')
    .map(option => option.textContent);

beforeEach(() => {
  get.mockReset();
});

describe('TargetAuthSecretField', () => {
  it('lists the surface tenant secrets by name and id and saves the secret id', async () => {
    get.mockResolvedValue({ data: secrets });
    const onChange = setupField();
    await screen.findByText('Choose mission MCP key (choose_mission_mcp_key)');
    expect(get).toHaveBeenCalledWith('/secrets/');
    expect(optionTexts()).toEqual([
      '-- Select a secret --',
      'Choose mission MCP key (choose_mission_mcp_key)',
      'Partner billing token (partner_billing_token)',
    ]);
    fireEvent.change(screen.getByTestId('transit-point-target-auth-secret'), {
      target: { value: 'partner_billing_token' },
    });
    expect(onChange).toHaveBeenCalledWith('partner_billing_token');
    expect(screen.getByText(/Don’t see the one you need\?/)).toBeInTheDocument();
    expect(screen.getByTestId('transit-point-target-auth-secret-add-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });

  it('shows the loading state until the list arrives', async () => {
    let resolve: (value: { data: typeof secrets }) => void = () => {};
    get.mockReturnValue(new Promise(r => (resolve = r)));
    setupField();
    const select = screen.getByTestId('transit-point-target-auth-secret');
    expect(select).toBeDisabled();
    expect(optionTexts()).toEqual(['-- Loading secrets... --']);
    expect(screen.queryByTestId('transit-point-target-auth-secret-refresh')).toBeNull();
    resolve({ data: secrets });
    await waitFor(() => expect(select).not.toBeDisabled());
  });

  it('offers the add link when no secrets exist yet', async () => {
    get.mockResolvedValue({ data: [] });
    setupField();
    expect(await screen.findByText(/No secrets configured yet\./)).toBeInTheDocument();
    expect(screen.getByTestId('transit-point-target-auth-secret-add-link')).toHaveTextContent(
      'Add secret'
    );
    expect(screen.getByTestId('transit-point-target-auth-secret-refresh')).toBeInTheDocument();
  });

  it('reloads the list when refreshed, keeping the field usable', async () => {
    get.mockResolvedValueOnce({ data: secrets.slice(1) });
    setupField();
    const refresh = await screen.findByTestId('transit-point-target-auth-secret-refresh');
    expect(optionTexts()).not.toContain('Choose mission MCP key (choose_mission_mcp_key)');
    get.mockResolvedValueOnce({ data: secrets });
    fireEvent.click(refresh);
    expect(
      await screen.findByText('Choose mission MCP key (choose_mission_mcp_key)')
    ).toBeInTheDocument();
    expect(get).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('transit-point-target-auth-secret')).not.toBeDisabled();
  });

  it('keeps a deleted stored secret visible as not found, with a warning', async () => {
    get.mockResolvedValue({ data: secrets.slice(1) });
    setupField({ value: 'choose_mission_mcp_key' });
    expect(await screen.findByText('choose_mission_mcp_key (not found)')).toBeInTheDocument();
    expect(screen.getByTestId('transit-point-target-auth-secret')).toHaveValue(
      'choose_mission_mcp_key'
    );
    expect(screen.getByTestId('transit-point-target-auth-secret-missing')).toHaveTextContent(
      'This secret no longer exists. Pick another one; saving will fail until you do.'
    );
  });

  it('labels a stored appliance-wide secret and explains it in full below the field', async () => {
    get.mockResolvedValue({ data: secrets });
    setupField({ value: 'wide_key' });
    expect(
      await screen.findByText('Wide key (wide_key, appliance-wide, stops working when enforced)')
    ).toBeInTheDocument();
    expect(screen.getByTestId('transit-point-target-auth-secret-outside-tenant')).toHaveTextContent(
      'This secret is appliance-wide. It stops working when tenant isolation is enforced; pick one from this surface’s tenant.'
    );
    expect(screen.queryByTestId('transit-point-target-auth-secret-missing')).toBeNull();
  });

  it('explains a stored secret from another tenant', async () => {
    get.mockResolvedValue({ data: secrets });
    setupField({ value: 'other_key' });
    expect(
      await screen.findByTestId('transit-point-target-auth-secret-outside-tenant')
    ).toHaveTextContent('This secret belongs to another tenant, so the gateway refuses it.');
  });

  it('says the list failed to load and lets the user try again', async () => {
    get.mockRejectedValueOnce(new ApiError('Server error', 500));
    setupField({ value: 'choose_mission_mcp_key' });
    expect(
      await screen.findByTestId('transit-point-target-auth-secret-load-error')
    ).toHaveTextContent('Couldn’t load secrets.');
    expect(screen.getByTestId('transit-point-target-auth-secret')).toHaveValue(
      'choose_mission_mcp_key'
    );
    expect(screen.queryByTestId('transit-point-target-auth-secret-refresh')).toBeNull();
    expect(screen.queryByText(/No secrets configured yet/)).toBeNull();
    get.mockResolvedValueOnce({ data: secrets });
    fireEvent.click(screen.getByTestId('transit-point-target-auth-secret-retry'));
    expect(
      await screen.findByTestId('transit-point-target-auth-secret-refresh')
    ).toBeInTheDocument();
    expect(screen.queryByTestId('transit-point-target-auth-secret-load-error')).toBeNull();
  });

  it('says who can help when the user may not view secrets', async () => {
    get.mockRejectedValue(new ApiError('Forbidden', 403));
    setupField({ value: 'choose_mission_mcp_key' });
    expect(await screen.findByTestId('transit-point-target-auth-secret-denied')).toHaveTextContent(
      'You don’t have access to secrets. Ask an administrator.'
    );
    expect(screen.getByTestId('transit-point-target-auth-secret')).toHaveValue(
      'choose_mission_mcp_key'
    );
    expect(screen.queryByTestId('transit-point-target-auth-secret-refresh')).toBeNull();
    expect(screen.queryByTestId('transit-point-target-auth-secret-retry')).toBeNull();
  });

  it('shows the save error it is given', async () => {
    get.mockResolvedValue({ data: secrets });
    setupField({ error: 'Pick the secret whose value authenticates this Transit Point.' });
    expect(await screen.findByTestId('transit-point-target-auth-secret-error')).toHaveTextContent(
      'Pick the secret whose value authenticates this Transit Point.'
    );
    expect(screen.getByTestId('transit-point-target-auth-secret')).toHaveClass('is-invalid');
  });
});
