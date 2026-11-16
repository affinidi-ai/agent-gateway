import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import IdentityPanel from '../IdentityPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { CanvasNode } from '../../types';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const JWT = {
  id: 'users-jwt',
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'idp',
  jwt_token_header: 'Authorization',
};
const SECOND_JWT = {
  id: 'service-jwt',
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'other',
  jwt_token_header: 'X-Service-Token',
};
const API_KEY = {
  id: 'partner-key',
  method_type: 'api_key',
  extraction_source: 'http_header',
  extraction_field: 'X-API-Key',
  api_key_secret_id: 'keys',
};

const inbound = { id: 'identity-inbound', slotId: 'request:identity-inbound' };
const protectedSlot = { id: 'identity-protected', slotId: 'response:identity-protected' };

function renderPanel(
  methods: unknown[],
  config: Record<string, unknown>,
  placement: Pick<CanvasNode, 'id' | 'slotId'> = inbound
) {
  const node: CanvasNode = { ...placement, type: 'identity', label: '', configured: true, config };
  const callerAuth: CanvasNode = {
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config: { methods },
  };
  const updateField = jest.fn();
  const updateFields = jest.fn();
  render(
    <MemoryRouter>
      <SurfaceMetaProvider value={{ surfaceId: 'surface-1' } as SurfaceMetaValue}>
        <IdentityPanel
          node={node}
          config={config}
          updateField={updateField}
          updateFields={updateFields}
          protocol="a2a"
          allNodes={[node, callerAuth]}
        />
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
  return { updateField, updateFields };
}

const select = () => screen.queryByTestId('identity-panel-source-method-select');
const typeSelect = () => screen.getByLabelText('Identity Extraction Type');

describe('Identity source method selector', () => {
  it('lists only the methods of the kind the identity reads, with where each reads', () => {
    renderPanel([JWT, API_KEY, SECOND_JWT], {
      type: 'from_jwt_claim',
      source_method: 'users-jwt',
    });
    const options = within(select()!)
      .getAllByRole('option')
      .map(option => option.textContent);
    expect(options).toEqual([
      "Method 1: JWT, reads the 'authorization' header",
      "Method 3: JWT, reads the 'x-service-token' header",
    ]);
    expect(select()).toHaveValue('users-jwt');
  });

  it('lists the API key methods for an inbound From API Key identity', () => {
    renderPanel([JWT, API_KEY], { type: 'from_api_key', source_method: 'partner-key' });
    const options = within(select()!)
      .getAllByRole('option')
      .map(option => option.textContent);
    expect(options).toEqual(["Method 2: API Key, reads the 'x-api-key' header"]);
  });

  it('saves the method the admin picks', () => {
    const { updateFields } = renderPanel([JWT, SECOND_JWT, API_KEY], {
      type: 'from_jwt_claim',
      source_method: 'users-jwt',
    });
    fireEvent.change(select()!, { target: { value: 'service-jwt' } });
    expect(updateFields).toHaveBeenCalledWith({ source_method: 'service-jwt' });
  });

  it('shows no selector with a single method', () => {
    renderPanel([JWT], { type: 'from_jwt_claim' });
    expect(select()).toBeNull();
  });

  it('shows no selector for an identity that does not read the caller credential', () => {
    renderPanel([JWT, API_KEY], { type: 'from_payload' });
    expect(select()).toBeNull();
  });

  it('shows no selector on the protected identity', () => {
    renderPanel([JWT, API_KEY], { type: 'from_jwt_claim' }, protectedSlot);
    expect(select()).toBeNull();
  });

  it('shows the first JWT method as selected beside an API key method, with no Any option', () => {
    renderPanel([API_KEY, JWT, SECOND_JWT], { type: 'from_jwt_claim' });
    expect(select()).toHaveValue('users-jwt');
    expect(
      within(select()!)
        .getAllByRole('option')
        .map(option => option.textContent)
    ).not.toContain('Any JWT Bearer method');
  });

  it('shows the first API key method as selected beside a JWT method', () => {
    renderPanel([JWT, API_KEY], { type: 'from_api_key' });
    expect(select()).toHaveValue('partner-key');
  });

  it('offers Any JWT Bearer method, selected, while every method is a JWT method', () => {
    const { updateFields } = renderPanel([JWT, SECOND_JWT], { type: 'from_jwt_claim' });
    expect(select()).toHaveValue('');
    expect(
      within(select()!)
        .getAllByRole('option')
        .map(option => option.textContent)
    ).toEqual([
      'Any JWT Bearer method',
      "Method 1: JWT, reads the 'authorization' header",
      "Method 2: JWT, reads the 'x-service-token' header",
    ]);
    fireEvent.change(select()!, { target: { value: 'users-jwt' } });
    expect(updateFields).toHaveBeenCalledWith({ source_method: 'users-jwt' });
  });

  it('goes back to Any when a method was picked and every method is a JWT method', () => {
    const { updateFields } = renderPanel([JWT, SECOND_JWT], {
      type: 'from_jwt_claim',
      source_method: 'users-jwt',
    });
    fireEvent.change(select()!, { target: { value: '' } });
    expect(updateFields).toHaveBeenCalledWith({ source_method: undefined });
  });

  it('offers Any API key method while every method is an API key method', () => {
    renderPanel([API_KEY, { ...API_KEY, id: 'other-key', extraction_field: 'X-Other' }], {
      type: 'from_api_key',
    });
    expect(select()).toHaveValue('');
    expect(screen.getByRole('option', { name: 'Any API key method' })).toBeInTheDocument();
  });

  it('says a stored method is now another kind when it was retyped', () => {
    renderPanel([JWT, API_KEY], { type: 'from_jwt_claim', source_method: 'partner-key' });
    expect(screen.getByRole('option', { name: 'Method 2 is now API Key' })).toBeDisabled();
  });

  it('clears the type change so a stale method cannot return', () => {
    const { updateFields } = renderPanel([JWT, API_KEY], {
      type: 'from_payload',
      source_method: 'gone',
    });
    fireEvent.change(typeSelect(), { target: { value: 'from_jwt_claim' } });
    expect(updateFields).toHaveBeenCalledWith({ type: 'from_jwt_claim', source_method: undefined });
  });

  it('forgets the method when another extraction type is chosen', () => {
    const { updateFields } = renderPanel([JWT, API_KEY], {
      type: 'from_jwt_claim',
      source_method: 'users-jwt',
    });
    fireEvent.change(typeSelect(), { target: { value: 'from_payload' } });
    expect(updateFields).toHaveBeenCalledWith({ type: 'from_payload', source_method: undefined });
  });

  it('selects nothing and says why when no method can supply the identity', () => {
    const { updateFields } = renderPanel([API_KEY, { ...API_KEY, id: 'other-key' }], {
      type: 'from_payload',
    });
    fireEvent.change(typeSelect(), { target: { value: 'from_jwt_claim' } });
    expect(updateFields).toHaveBeenCalledWith({ type: 'from_jwt_claim', source_method: undefined });
  });

  it('warns when no method can supply the identity', () => {
    renderPanel([API_KEY, { ...API_KEY, id: 'other-key', extraction_field: 'X-Other' }], {
      type: 'from_jwt_claim',
    });
    expect(screen.getByTestId('identity-panel-source-method-none')).toHaveTextContent(
      'No Caller Context method can supply this identity. Add a JWT Bearer method, or choose another extraction type.'
    );
  });

  it('shows no selector for a single method that still holds a stale selection', () => {
    renderPanel([JWT], { type: 'from_jwt_claim', source_method: 'gone' });
    expect(select()).toBeNull();
  });

  it('keeps a non-inbound identity on the plain type update', () => {
    const { updateField, updateFields } = renderPanel(
      [JWT, API_KEY],
      { type: 'from_payload' },
      protectedSlot
    );
    fireEvent.change(typeSelect(), { target: { value: 'from_jwt_claim' } });
    expect(updateField).toHaveBeenCalledWith('type', 'from_jwt_claim');
    expect(updateFields).not.toHaveBeenCalled();
  });
});
