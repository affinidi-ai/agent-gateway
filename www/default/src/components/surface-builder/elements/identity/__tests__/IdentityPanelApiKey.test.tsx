import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import IdentityPanel from '../IdentityPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { CanvasNode } from '../../types';
import { apiKeyStatusMap, type ApiKeyStatuses } from '../apiKeyStatus';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const fetchMock = apiClient.fetch as jest.Mock;

const renderPanel = (
  placement: Pick<CanvasNode, 'id' | 'slotId'>,
  {
    surfaceId,
    apiKeyId,
    isCreate,
    apiKeyStatuses,
  }: {
    surfaceId?: string;
    apiKeyId?: string;
    isCreate?: boolean;
    apiKeyStatuses?: ApiKeyStatuses;
  } = {
    surfaceId: 'surface-1',
  }
) => {
  const config: Record<string, unknown> = { type: 'from_api_key' };
  if (apiKeyId) config.api_key_id = apiKeyId;
  const node: CanvasNode = { ...placement, type: 'identity', label: '', configured: true, config };
  return render(
    <MemoryRouter>
      <SurfaceMetaProvider value={{ surfaceId, isCreate, apiKeyStatuses } as SurfaceMetaValue}>
        <IdentityPanel
          node={node}
          config={config}
          updateField={jest.fn()}
          updateFields={jest.fn()}
          protocol="a2a"
          allNodes={[node]}
        />
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
};

const protectedSlot = { id: 'identity-protected', slotId: 'response:identity-protected' };

describe('IdentityPanel From API Key', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => [
        { key_id: 'atgk_own', agent_id: 'surface-1', client_id: 'client-1', status: 'active' },
        { key_id: 'atgk_revoked', agent_id: 'surface-1', client_id: 'client-2', status: 'revoked' },
      ],
    });
  });

  it('shows the per-caller line and no key picker on the inbound node', () => {
    renderPanel({ id: 'identity-inbound', slotId: 'request:identity-inbound' });
    expect(screen.getByTestId('identity-panel-inbound-api-key-note')).toHaveTextContent(
      'Each caller is identified by the API key it presents.'
    );
    expect(screen.queryByTestId('identity-panel-api-key-select')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("lists only the surface's own active keys on the protected node", async () => {
    renderPanel(protectedSlot);
    expect(screen.queryByTestId('identity-panel-inbound-api-key-note')).toBeNull();
    const select = screen.getByTestId('identity-panel-api-key-select');
    expect(await within(select).findByRole('option', { name: 'client-1' })).toHaveValue('atgk_own');
    expect(within(select).queryByRole('option', { name: 'client-2' })).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/api-keys/surface-1');
  });

  it('keeps a stored key of another surface visible and selected', async () => {
    renderPanel(protectedSlot, { surfaceId: 'surface-1', apiKeyId: 'atgk_other' });
    const select = screen.getByTestId('identity-panel-api-key-select');
    await within(select).findByRole('option', { name: 'client-1' });
    const stored = within(select).getByRole('option', {
      name: 'atgk_other (not an active key of this surface)',
    });
    expect(stored).toHaveValue('atgk_other');
    expect(stored).toBeDisabled();
    expect(select).toHaveValue('atgk_other');
    expect(screen.queryByTestId('identity-api-key-revoked-warning')).toBeNull();
  });

  it.each([
    [
      'revoked',
      'client-2 (revoked)',
      'The API key this Identity uses was revoked. Select an active API key of this surface.',
    ],
    [
      'missing',
      'atgk_revoked (deleted)',
      'The API key this Identity uses was deleted. Select an active API key of this surface.',
    ],
    [
      'unavailable',
      'atgk_revoked (belongs to another surface)',
      'The API key this Identity uses belongs to another surface. Select an active API key of this surface.',
    ],
  ] as const)('names a blocking %s stored key and warns', async (status, label, warning) => {
    renderPanel(protectedSlot, {
      surfaceId: 'surface-1',
      apiKeyId: 'atgk_revoked',
      apiKeyStatuses: apiKeyStatusMap([{ key_id: 'atgk_revoked', status, blocking: true }]),
    });
    const select = screen.getByTestId('identity-panel-api-key-select');
    await within(select).findByRole('option', { name: 'client-1' });
    const stored = within(select).getByRole('option', { name: label });
    expect(stored).toHaveValue('atgk_revoked');
    expect(stored).toBeDisabled();
    expect(select).toHaveValue('atgk_revoked');
    expect(screen.getByTestId('identity-api-key-revoked-warning')).toHaveTextContent(warning);
    expect(screen.queryByTestId('identity-api-key-other-surface-notice')).toBeNull();
  });

  it('notes a non-blocking stored key of another surface without the blocking warning', async () => {
    renderPanel(protectedSlot, {
      surfaceId: 'surface-1',
      apiKeyId: 'atgk_other',
      apiKeyStatuses: apiKeyStatusMap([
        { key_id: 'atgk_other', status: 'unavailable', blocking: false },
      ]),
    });
    const select = screen.getByTestId('identity-panel-api-key-select');
    await within(select).findByRole('option', { name: 'client-1' });
    expect(
      within(select).getByRole('option', { name: 'atgk_other (belongs to another surface)' })
    ).toBeDisabled();
    expect(select).toHaveValue('atgk_other');
    expect(screen.queryByTestId('identity-api-key-revoked-warning')).toBeNull();
    const notice = screen.getByTestId('identity-api-key-other-surface-notice');
    expect(notice).toHaveTextContent(
      'The API key this Identity uses belongs to another surface. Select an active API key of this surface.'
    );
    expect(notice).toHaveClass('text-warning');
    expect(notice).toHaveAttribute('role', 'status');
  });

  it('shows no warning for an active stored key', async () => {
    renderPanel(protectedSlot, {
      surfaceId: 'surface-1',
      apiKeyId: 'atgk_own',
      apiKeyStatuses: apiKeyStatusMap([{ key_id: 'atgk_own', status: 'active', blocking: false }]),
    });
    const select = screen.getByTestId('identity-panel-api-key-select');
    await within(select).findByRole('option', { name: 'client-1' });
    expect(select).toHaveValue('atgk_own');
    expect(screen.queryByTestId('identity-api-key-revoked-warning')).toBeNull();
    expect(screen.queryByTestId('identity-api-key-other-surface-notice')).toBeNull();
  });

  it('lists no keys on the create page, which already has a surface id', () => {
    renderPanel(protectedSlot, { surfaceId: 'new-surface-uuid', isCreate: true });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByTestId('identity-panel-api-key-unsaved')).toHaveTextContent(
      'A new surface has no API keys yet. Remove this Identity or choose another type, save the surface, add an API key, then come back and select it.'
    );
    expect(
      within(screen.getByTestId('identity-panel-api-key-select')).getAllByRole('option')
    ).toHaveLength(1);
    expect(screen.queryByTestId('identity-panel-add-api-key-link')).toBeNull();
  });
});
