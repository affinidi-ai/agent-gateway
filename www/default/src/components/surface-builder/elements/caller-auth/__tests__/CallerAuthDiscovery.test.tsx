import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import CallerAuthFullscreen from '../CallerAuthFullscreen';
import CallerAuthPanel from '../CallerAuthPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { CanvasNode, ConfigPanelProps, Protocol } from '../../types';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const RESOURCE = 'https://gateway.example/mcp/alpha';
const SETTING = {
  resource: RESOURCE,
  authorization_servers: ['https://idp.example/realms/agents'],
  scopes: ['tools'],
};

const jwtConfig = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'idp',
  audiences: [],
  jwt_token_header: 'Authorization',
  jwt_token_scheme: 'Bearer',
  jwt_forward_header: false,
  ...extra,
});

const accessPoint: CanvasNode = {
  id: 'access-point',
  type: 'access-point',
  label: 'Access Point',
  configured: true,
  config: { listen_address: 'https://gateway.example', route: '/mcp/alpha' },
};

interface HarnessProps {
  initial: Record<string, unknown>;
  latest: { config?: Record<string, unknown> };
  Panel?: React.FC<ConfigPanelProps>;
  protocol?: Protocol;
  meta?: Partial<SurfaceMetaValue>;
  hasAttemptedSave?: boolean;
}

/** Renders a caller-auth panel over config it keeps in state, as the builder does. */
const Harness: React.FC<HarnessProps> = ({
  initial,
  latest,
  Panel = CallerAuthFullscreen,
  protocol = 'mcp',
  meta,
  hasAttemptedSave = false,
}) => {
  const [config, setConfig] = useState(initial);
  latest.config = config;
  const updateFields = (fields: Record<string, unknown>) =>
    setConfig(prev => ({ ...prev, ...fields }));
  const node: CanvasNode = {
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config,
  };
  const body = (
    <MemoryRouter>
      <Panel
        node={node}
        config={config}
        updateField={(field, value) => updateFields({ [field]: value })}
        updateFields={updateFields}
        protocol={protocol}
        allNodes={[accessPoint, node]}
        hasAttemptedSave={hasAttemptedSave}
      />
    </MemoryRouter>
  );
  return meta ? (
    <SurfaceMetaProvider value={meta as SurfaceMetaValue}>{body}</SurfaceMetaProvider>
  ) : (
    body
  );
};

async function openEditor(props: Omit<HarnessProps, 'latest'>) {
  const latest: HarnessProps['latest'] = {};
  render(<Harness {...props} latest={latest} />);
  if ((props.Panel ?? CallerAuthFullscreen) === CallerAuthFullscreen) {
    await screen.findByRole('option', { name: 'Identity Provider' });
  }
  return latest;
}

function typeAndAdd(testId: string, value: string) {
  const input = screen.getByTestId(testId);
  fireEvent.change(input, { target: { value } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([{ id: 'idp', name: 'Identity Provider' }]),
  });
});

describe('Caller Context editor: authorization server discovery', () => {
  it('shows a stored setting and locks the JWT settings the gateway constrains', async () => {
    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

    expect(screen.getByTestId('caller-auth-discovery-switch')).toBeChecked();
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(RESOURCE);
    expect(screen.getByTestId('caller-auth-discovery-authorization-server-0')).toHaveTextContent(
      'https://idp.example/realms/agents'
    );
    expect(screen.getByTestId('caller-auth-discovery-scope-0')).toHaveTextContent('tools');
    expect(screen.queryByTestId('caller-auth-discovery-use-listener-url-button')).toBeNull();
    expect(screen.getByTestId('caller-auth-jwt-forward-header-checkbox')).toBeDisabled();
    expect(screen.getByLabelText(/Token Header/)).toBeDisabled();
    expect(screen.getByLabelText(/Scheme/)).toBeDisabled();
    expect(screen.getByPlaceholderText('e.g. https://api.example.com')).toBeDisabled();
    expect(screen.getByTestId('caller-auth-audiences-discovery-note')).toHaveTextContent(
      'the gateway accepts only tokens whose audience is the resource URL'
    );
    expect(screen.queryByTestId('caller-auth-discovery-variant-resource')).toBeNull();
  });

  it('turns discovery on with the listener URL and clears the settings it cannot keep', async () => {
    const latest = await openEditor({
      initial: jwtConfig({ audiences: ['api'], jwt_forward_header: true }),
    });
    expect(screen.getByTestId('caller-auth-discovery-switch')).not.toBeChecked();

    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));

    expect(latest.config).toMatchObject({
      protected_resource: { resource: RESOURCE, authorization_servers: [], scopes: [] },
      audiences: [],
      jwt_forward_header: false,
      jwt_token_header: 'Authorization',
      jwt_token_scheme: 'Bearer',
    });
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(RESOURCE);
  });

  it('starts the authorization servers with the issuer the selected strategy trusts', async () => {
    (apiClient.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve([
          {
            id: 'idp',
            name: 'Identity Provider',
            expected_issuer: 'https://idp.example/realms/agents',
          },
        ]),
    });
    const latest = await openEditor({ initial: jwtConfig() });

    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));

    expect(latest.config).toMatchObject({
      protected_resource: {
        resource: RESOURCE,
        authorization_servers: ['https://idp.example/realms/agents'],
      },
    });
  });

  it('edits the resource, authorization servers and scopes', async () => {
    const latest = await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

    fireEvent.change(screen.getByTestId('caller-auth-discovery-resource-input'), {
      target: { value: 'https://gateway.example/mcp/other ' },
    });
    expect(latest.config?.protected_resource).toMatchObject({
      resource: 'https://gateway.example/mcp/other',
    });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-use-listener-url-button'));

    typeAndAdd('caller-auth-discovery-authorization-server-input', 'http://idp2.example');
    expect(
      screen.getByTestId('caller-auth-discovery-authorization-server-input-error')
    ).toHaveTextContent('must be an https issuer URL');
    typeAndAdd('caller-auth-discovery-authorization-server-input', 'https://idp2.example');
    typeAndAdd('caller-auth-discovery-authorization-server-input', 'https://idp2.example');
    expect(
      screen.getByTestId('caller-auth-discovery-authorization-server-input-error')
    ).toHaveTextContent('This authorization server is already listed');
    fireEvent.click(screen.getByTestId('caller-auth-discovery-remove-scope-0-button'));
    typeAndAdd('caller-auth-discovery-scope-input', 'mcp:read');

    expect(latest.config?.protected_resource).toEqual({
      resource: RESOURCE,
      authorization_servers: ['https://idp.example/realms/agents', 'https://idp2.example'],
      scopes: ['mcp:read'],
    });
  });

  it('stops adding authorization servers at eight', async () => {
    const servers = Array.from({ length: 8 }, (_, i) => `https://idp${i}.example`);
    await openEditor({
      initial: jwtConfig({ protected_resource: { ...SETTING, authorization_servers: servers } }),
    });
    expect(screen.getByTestId('caller-auth-discovery-authorization-server-input')).toBeDisabled();
    expect(
      screen.getByTestId('caller-auth-discovery-add-authorization-server-button')
    ).toBeDisabled();
  });

  it('turns discovery off, and drops it when the method leaves JWT Bearer', async () => {
    const latest = await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(latest.config?.protected_resource).toBeNull();
    expect(screen.queryByTestId('caller-auth-discovery-resource-input')).toBeNull();
    expect(screen.getByTestId('caller-auth-jwt-forward-header-checkbox')).toBeEnabled();

    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    fireEvent.change(screen.getByLabelText('Authentication Method'), {
      target: { value: 'did_auth' },
    });
    expect(latest.config).toMatchObject({ method_type: 'did_auth', protected_resource: null });
  });

  it('shows the resource the active variant advertises', async () => {
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { activeVariantAlias: 'beta' },
    });
    expect(screen.getByTestId('caller-auth-discovery-variant-resource')).toHaveTextContent(
      `${RESOURCE}$beta`
    );
    expect(screen.queryByTestId('caller-auth-discovery-default-variant-note')).toBeNull();
  });

  it('tells that the default variant also answers on the route with the resource as written', async () => {
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { activeVariantAlias: 'beta', activeVariantIsDefault: true },
    });
    expect(screen.getByTestId('caller-auth-discovery-variant-resource')).toHaveTextContent(
      `${RESOURCE}$beta`
    );
    expect(screen.getByTestId('caller-auth-discovery-default-variant-note')).toHaveTextContent(
      "answers on the surface's route"
    );
  });

  it('shows a refused save next to the setting, and leaves other errors to the page', async () => {
    const refused =
      "variant 'beta': access_point.caller_authentication.protected_resource: requires empty JWT Bearer audiences (400)";
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: refused },
    });
    expect(screen.getByTestId('caller-auth-discovery-save-error')).toHaveTextContent(refused);
  });

  it('does not show an unrelated save error in the discovery section', async () => {
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: 'target.endpoint: invalid URL (400)' },
    });
    expect(screen.queryByTestId('caller-auth-discovery-save-error')).toBeNull();
  });

  it('flags field problems once a save was attempted', async () => {
    await openEditor({
      initial: jwtConfig({
        protected_resource: {
          ...SETTING,
          resource: 'https://gateway.example/mcp/other',
          authorization_servers: [],
        },
      }),
      hasAttemptedSave: true,
    });
    expect(screen.getByTestId('caller-auth-discovery-resource-error')).toHaveTextContent(
      'The resource path must be the Access Point route: /mcp/alpha'
    );
    expect(
      screen.getByTestId('caller-auth-discovery-authorization-servers-error')
    ).toHaveTextContent('List 1 to 8 authorization servers');
  });

  it('keeps a conflicting setting editable so it can be fixed', async () => {
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING, jwt_forward_header: true }),
      hasAttemptedSave: true,
    });
    expect(screen.getByTestId('caller-auth-discovery-rules-error')).toHaveTextContent(
      "cannot forward the caller's token"
    );
    const forward = screen.getByTestId('caller-auth-jwt-forward-header-checkbox');
    expect(forward).toBeEnabled();
    fireEvent.click(forward);
    expect(forward).toBeDisabled();
    expect(screen.queryByTestId('caller-auth-discovery-rules-error')).toBeNull();
  });

  it('offers the explicit setting on MCP only, and the required scopes on A2A too', async () => {
    await openEditor({ initial: jwtConfig(), protocol: 'a2a' });
    expect(screen.queryByTestId('caller-auth-discovery-switch')).toBeNull();
    expect(screen.getByTestId('caller-auth-scopes')).toBeInTheDocument();
    expect(screen.getByTestId('caller-auth-discovery-derived')).toHaveTextContent(
      'What the agent card declares'
    );
  });

  it('offers nothing to declare on a DIDComm surface', async () => {
    await openEditor({ initial: jwtConfig(), protocol: 'didcomm' });
    expect(screen.queryByTestId('caller-auth-discovery')).toBeNull();
    expect(screen.queryByTestId('caller-auth-scopes')).toBeNull();
  });

  it('keeps token forwarding and the token header editable on A2A without the explicit setting', async () => {
    const latest = await openEditor({
      initial: jwtConfig({ jwt_forward_header: true, required_scopes: ['agent:invoke'] }),
      protocol: 'a2a',
    });
    expect(screen.getByLabelText(/Token Header/)).toBeEnabled();
    expect(screen.getByLabelText(/Scheme/)).toBeEnabled();
    expect(screen.getByPlaceholderText('e.g. https://api.example.com')).toBeEnabled();
    expect(
      screen.getByTestId('caller-auth-discovery-derived-note-forwards_caller_token')
    ).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('caller-auth-jwt-forward-header-checkbox'));
    expect(latest.config?.jwt_forward_header).toBe(false);
    expect(
      screen.queryByTestId('caller-auth-discovery-derived-note-forwards_caller_token')
    ).toBeNull();
  });

  it('keeps required scopes beside the explicit setting on MCP', async () => {
    const latest = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING, required_scopes: ['tools.call'] }),
    });
    expect(screen.getByRole('button', { name: 'Remove scope tools.call' })).toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-discovery-derived')).toBeNull();
    typeAndAdd('caller-auth-scope-input', 'tools.list');
    expect(latest.config).toMatchObject({
      required_scopes: ['tools.call', 'tools.list'],
      protected_resource: SETTING,
    });
  });
});

describe('Caller Context sidebar: authorization server discovery', () => {
  it('shows the discovery status and a refused save', async () => {
    const refused =
      'access_point.caller_authentication.protected_resource: authorization_servers must list 1 to 8 issuers (400)';
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      Panel: CallerAuthPanel,
      meta: { saveError: refused },
    });
    expect(screen.getByTestId('caller-auth-panel-discovery-status')).toHaveTextContent(
      'Authorization server discovery: on, 1 authorization server'
    );
    expect(screen.getByTestId('caller-auth-panel-discovery-save-error')).toHaveTextContent(refused);
  });

  it('reports discovery off, and drops it when the method leaves JWT Bearer', async () => {
    const latest = await openEditor({ initial: jwtConfig(), Panel: CallerAuthPanel });
    expect(screen.getByTestId('caller-auth-panel-discovery-status')).toHaveTextContent(
      'Authorization server discovery: off'
    );

    fireEvent.change(screen.getByLabelText('Authentication Method'), {
      target: { value: 'api_key' },
    });
    expect(latest.config).toMatchObject({ method_type: 'api_key', protected_resource: null });
    expect(screen.queryByTestId('caller-auth-panel-discovery-status')).toBeNull();
    expect(screen.queryByTestId('caller-auth-panel-outcome')).toBeNull();
  });

  it('shows the declaration outcome on A2A, without the MCP discovery status', async () => {
    await openEditor({ initial: jwtConfig(), Panel: CallerAuthPanel, protocol: 'a2a' });
    expect(screen.getByTestId('caller-auth-outcome-chip')).toHaveTextContent(
      'Outcome shown after the first save'
    );
    expect(screen.getByText('Agent card:')).toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-panel-discovery-status')).toBeNull();
  });

  it('reads the saved outcome of the surface it edits', async () => {
    (apiClient.fetch as jest.Mock).mockClear();
    (apiClient.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          declarations: [
            { variant: null, outcome: 'declare', reason: null, resource: 'https://gw/a' },
          ],
          warnings: [],
        }),
    });
    await openEditor({
      initial: jwtConfig(),
      Panel: CallerAuthPanel,
      protocol: 'a2a',
      meta: { surfaceId: 's-9' },
    });
    expect(await screen.findByText('Declares OAuth')).toBeInTheDocument();
    expect((apiClient.fetch as jest.Mock).mock.calls[0][0]).toBe(
      '/api/v1/surfaces/s-9/declarations'
    );
  });
});
