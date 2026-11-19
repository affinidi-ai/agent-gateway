import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
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
  const updateNodeFields = jest.fn();
  render(
    <MemoryRouter>
      <SurfaceMetaProvider value={{ surfaceId: 'surface-1' } as SurfaceMetaValue}>
        <IdentityPanel
          node={node}
          config={config}
          updateField={updateField}
          updateFields={jest.fn()}
          updateNodeFields={updateNodeFields}
          protocol="a2a"
          allNodes={[node, callerAuth]}
        />
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
  return { updateField, updateNodeFields };
}

const row = (position: number) => `identity-panel-method-identity-${position}`;
const list = () => screen.queryByTestId('identity-panel-method-identities');

describe('Identity caller identity per method', () => {
  it('lists every Caller Context method with where it reads its credential', () => {
    renderPanel([JWT, API_KEY], { type: 'from_jwt_claim' });
    expect(screen.getByText("Method 1: JWT, reads the 'authorization' header")).toBeInTheDocument();
    expect(screen.getByText("Method 2: API Key, reads the 'x-api-key' header")).toBeInTheDocument();
  });

  it('says the callers of a method this Identity cannot read are refused', () => {
    renderPanel([JWT, API_KEY], { type: 'from_jwt_claim' });
    expect(screen.getByTestId(`${row(0)}-status`)).toHaveTextContent('Uses this Identity');
    expect(screen.getByTestId(`${row(1)}-status`)).toHaveTextContent(
      'Callers of this method are refused'
    );
  });

  it("gives a method its own identity on the Caller Context element's method", () => {
    const { updateNodeFields } = renderPanel([JWT, API_KEY], { type: 'from_jwt_claim' });
    fireEvent.change(screen.getByTestId(`${row(1)}-select`), {
      target: { value: 'from_api_key' },
    });
    expect(updateNodeFields).toHaveBeenCalledWith('caller-auth', {
      methods: [JWT, { ...API_KEY, identity: { type: 'from_api_key' } }],
    });
  });

  it('edits the claim of a JWT method identity and shows no refusal for it', () => {
    const own = { ...JWT, identity: { type: 'from_jwt_claim', claim: 'oid' } };
    const { updateNodeFields } = renderPanel([own, API_KEY], { type: 'from_api_key' });
    expect(screen.queryByTestId(`${row(0)}-status`)).not.toBeInTheDocument();
    fireEvent.change(screen.getByTestId(`${row(0)}-claim`), { target: { value: 'sub' } });
    expect(updateNodeFields).toHaveBeenCalledWith('caller-auth', {
      methods: [{ ...JWT, identity: { type: 'from_jwt_claim', claim: 'sub' } }, API_KEY],
    });
  });

  it('clears a method identity back to this Identity', () => {
    const own = { ...API_KEY, identity: { type: 'from_api_key' } };
    const { updateNodeFields } = renderPanel([JWT, own], { type: 'from_jwt_claim' });
    fireEvent.change(screen.getByTestId(`${row(1)}-select`), { target: { value: '' } });
    expect(updateNodeFields).toHaveBeenCalledWith('caller-auth', {
      methods: [JWT, { ...API_KEY, identity: undefined }],
    });
  });

  it('is not shown with one method', () => {
    renderPanel([JWT], { type: 'from_jwt_claim' });
    expect(list()).not.toBeInTheDocument();
  });

  it('is shown with one method that identifies its own callers, so it can be cleared', () => {
    renderPanel([{ ...API_KEY, identity: { type: 'from_api_key' } }], { type: 'from_jwt_claim' });
    expect(screen.getByTestId(`${row(0)}-select`)).toHaveValue('from_api_key');
  });

  it('is shown beside From Payload only while a method identifies its own callers', () => {
    renderPanel([JWT, { ...API_KEY, identity: { type: 'from_api_key' } }], {
      type: 'from_payload',
    });
    expect(list()).toBeInTheDocument();
  });

  it('is not shown on the protected identity', () => {
    renderPanel([JWT, API_KEY], { type: 'from_payload' }, protectedSlot);
    expect(list()).not.toBeInTheDocument();
  });

  it('changes only the extraction type when it is changed', () => {
    const { updateField } = renderPanel([JWT, API_KEY], { type: 'from_jwt_claim' });
    fireEvent.change(screen.getByLabelText('Identity Extraction Type'), {
      target: { value: 'from_api_key' },
    });
    expect(updateField).toHaveBeenCalledWith('type', 'from_api_key');
  });
});
