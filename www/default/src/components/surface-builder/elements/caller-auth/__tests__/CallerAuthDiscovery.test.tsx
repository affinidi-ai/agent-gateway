import React, { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import CallerAuthFullscreen from '../CallerAuthFullscreen';
import CallerAuthPanel from '../CallerAuthPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { CanvasNode, ConfigPanelProps, Protocol } from '../../types';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const RESOURCE = 'https://gateway.example/mcp/alpha';
const ISSUER = 'https://idp.example/realms/agents';
const JWKS = 'https://idp.example/realms/agents/certs';
const SETTING = { resource: RESOURCE };
const LEGACY_SETTING = { resource: RESOURCE, authorization_servers: [ISSUER], scopes: ['tools'] };
const STRATEGY = { id: 'idp', name: 'Identity Provider', expected_issuer: ISSUER };
const PINNED_STRATEGY = {
  ...STRATEGY,
  jwks_source: { type: 'remote', jwks_uri: JWKS },
  authorization_server: { issuer: ISSUER, jwks_uri: JWKS },
};
const PROTOCOLS: Protocol[] = ['mcp', 'a2a'];

let strategies: unknown[];

const jwtConfig = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'idp',
  audiences: [],
  jwt_token_header: 'Authorization',
  jwt_token_scheme: 'Bearer',
  jwt_forward_header: false,
  ...extra,
});

const HTTPS_ACCESS_POINT = { listen_address: 'https://gateway.example', route: '/mcp/alpha' };

interface HarnessProps {
  initial: Record<string, unknown>;
  latest: { config?: Record<string, unknown> };
  Panel?: React.FC<ConfigPanelProps>;
  protocol?: Protocol;
  meta?: Partial<SurfaceMetaValue>;
  hasAttemptedSave?: boolean;
  accessPointConfig?: Record<string, unknown>;
}

/** Renders a caller-auth panel over config it keeps in state, as the builder does. */
const Harness: React.FC<HarnessProps> = ({
  initial,
  latest,
  Panel = CallerAuthFullscreen,
  protocol = 'mcp',
  meta,
  hasAttemptedSave = false,
  accessPointConfig = HTTPS_ACCESS_POINT,
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
  const accessPoint: CanvasNode = {
    id: 'access-point',
    type: 'access-point',
    label: 'Access Point',
    configured: true,
    config: accessPointConfig,
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
  const view = render(<Harness {...props} latest={latest} />);
  if ((props.Panel ?? CallerAuthFullscreen) === CallerAuthFullscreen) {
    await screen.findByRole('option', { name: 'Identity Provider' });
  }
  return { latest, view };
}

function typeAndAdd(testId: string, value: string) {
  const input = screen.getByTestId(testId);
  fireEvent.change(input, { target: { value } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

beforeEach(() => {
  strategies = [STRATEGY];
  (apiClient.fetch as jest.Mock).mockImplementation(async (url: string) => ({
    ok: true,
    json: () =>
      Promise.resolve(
        String(url).endsWith('/declarations') ? { declarations: [], warnings: [] } : strategies
      ),
  }));
});

describe('Caller Context editor: authorization server discovery', () => {
  it.each(PROTOCOLS)(
    'shows a stored setting and locks the JWT settings the gateway constrains on %s',
    async protocol => {
      await openEditor({ initial: jwtConfig({ protected_resource: LEGACY_SETTING }), protocol });

      expect(screen.getByTestId('caller-auth-discovery-switch')).toBeChecked();
      expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(RESOURCE);
      expect(
        screen.getByTestId('caller-auth-discovery-derived-authorization-server')
      ).toHaveTextContent(ISSUER);
      const overrides = screen.getByTestId('caller-auth-discovery-stored-overrides');
      expect(overrides).toHaveTextContent(`stores its authorization server as ${ISSUER}`);
      expect(overrides).toHaveTextContent(
        'also advertises tools, which the gateway does not enforce'
      );
      expect(screen.queryByTestId('caller-auth-discovery-use-listener-url-button')).toBeNull();
      expect(screen.getByTestId('caller-auth-jwt-forward-header-checkbox')).toBeDisabled();
      expect(screen.getByLabelText(/Token Header/)).toBeDisabled();
      expect(screen.getByLabelText(/Scheme/)).toBeDisabled();
      expect(screen.getByPlaceholderText('e.g. https://api.example.com')).toBeDisabled();
      expect(screen.getByTestId('caller-auth-audiences-discovery-note')).toHaveTextContent(
        'a token is accepted when the resource URL is one of its audiences'
      );
      expect(screen.queryByTestId('caller-auth-discovery-variant-resource')).toBeNull();
    }
  );

  it.each(PROTOCOLS)(
    'turns discovery on with the listener URL and clears the settings it cannot keep on %s',
    async protocol => {
      const { latest } = await openEditor({
        initial: jwtConfig({ audiences: ['api'], jwt_forward_header: true }),
        protocol,
      });
      expect(screen.getByTestId('caller-auth-discovery-switch')).not.toBeChecked();

      fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));

      expect(latest.config?.protected_resource).toEqual({ resource: RESOURCE });
      expect(latest.config).toMatchObject({
        audiences: [],
        jwt_forward_header: false,
        jwt_token_header: 'Authorization',
        jwt_token_scheme: 'Bearer',
      });
      expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(RESOURCE);
      expect(screen.queryByTestId('caller-auth-discovery-stored-overrides')).toBeNull();
    }
  );

  it('shows the authorization server of the selected strategy read-only, with its source', async () => {
    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

    expect(
      screen.getByTestId('caller-auth-discovery-derived-authorization-server')
    ).toHaveTextContent(ISSUER);
    expect(
      screen.getByTestId('caller-auth-discovery-derived-authorization-server-source')
    ).toHaveTextContent('From the JWT verification strategy Identity Provider');
    expect(screen.queryByTestId('caller-auth-discovery-authorization-server-input')).toBeNull();
  });

  it('asks for a strategy before it names an authorization server', async () => {
    await openEditor({ initial: jwtConfig({ jwt_strategy_id: '', protected_resource: SETTING }) });

    expect(
      screen.getByTestId('caller-auth-discovery-derived-authorization-server')
    ).toHaveTextContent('Select a JWT verification strategy.');
    expect(
      screen.queryByTestId('caller-auth-discovery-derived-authorization-server-source')
    ).toBeNull();
  });

  it('edits the resource and offers no field to type an authorization server or a scope', async () => {
    const { latest } = await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

    fireEvent.change(screen.getByTestId('caller-auth-discovery-resource-input'), {
      target: { value: 'https://gateway.example/mcp/other ' },
    });
    expect(latest.config?.protected_resource).toEqual({
      resource: 'https://gateway.example/mcp/other',
    });
    expect(screen.getByTestId('caller-auth-discovery-derived-audience')).toHaveTextContent(
      'https://gateway.example/mcp/other'
    );

    fireEvent.click(screen.getByTestId('caller-auth-discovery-use-listener-url-button'));
    expect(latest.config?.protected_resource).toEqual({ resource: RESOURCE });
    expect(screen.queryByTestId('caller-auth-discovery-authorization-server-input')).toBeNull();
    expect(screen.queryByTestId('caller-auth-discovery-scope-input')).toBeNull();
    expect(
      screen.queryByTestId('caller-auth-discovery-add-authorization-server-button')
    ).toBeNull();
  });

  it('shows stored authorization servers and extra scopes as overrides, and removes each on request', async () => {
    const { latest } = await openEditor({
      initial: jwtConfig({ protected_resource: LEGACY_SETTING, required_scopes: ['tools.call'] }),
    });
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'tools.call tools'
    );
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes-source')).toHaveTextContent(
      'From Required Scopes and stored extra scopes.'
    );

    fireEvent.click(screen.getByTestId('caller-auth-discovery-clear-authorization-servers-button'));
    expect(latest.config?.protected_resource).toEqual({ resource: RESOURCE, scopes: ['tools'] });
    expect(
      screen.queryByTestId('caller-auth-discovery-clear-authorization-servers-button')
    ).toBeNull();

    fireEvent.click(screen.getByTestId('caller-auth-discovery-clear-scopes-button'));
    expect(latest.config?.protected_resource).toEqual({ resource: RESOURCE });
    expect(screen.queryByTestId('caller-auth-discovery-stored-overrides')).toBeNull();
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'tools.call'
    );
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes-source')).toHaveTextContent(
      'From Required Scopes.'
    );
  });

  it('flags a stored authorization server that is no longer the strategy issuer', async () => {
    const stale = { ...LEGACY_SETTING, authorization_servers: ['https://old-idp.example'] };
    const { view } = await openEditor({ initial: jwtConfig({ protected_resource: stale }) });
    expect(screen.queryByTestId('caller-auth-discovery-authorization-servers-error')).toBeNull();
    view.unmount();

    await openEditor({ initial: jwtConfig({ protected_resource: stale }), hasAttemptedSave: true });
    const error = screen.getByTestId('caller-auth-discovery-authorization-servers-error');
    expect(error).toHaveTextContent('https://old-idp.example');
    expect(error).toHaveTextContent('is not the issuer the JWT verification strategy trusts');
  });

  it('shows a refused authorization server list beside the stored override', async () => {
    const refused = `access_point.caller_authentication.protected_resource: authorization_servers must be exactly ["${ISSUER}"], the issuer the JWT verification strategy trusts, or be omitted: the gateway advertises that issuer (400)`;
    await openEditor({
      initial: jwtConfig({ protected_resource: LEGACY_SETTING }),
      meta: { saveError: refused },
    });
    expect(
      screen.getByTestId('caller-auth-discovery-authorization-servers-error')
    ).toHaveTextContent('authorization_servers must be exactly');
    expect(screen.queryByTestId('caller-auth-discovery-save-error')).toBeNull();
  });

  it('shows the scopes from Required Scopes, and says none are required while failed callers are still refused', async () => {
    const { latest } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING, required_scopes: ['agent:invoke'] }),
    });
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'agent:invoke'
    );
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes-source')).not.toHaveTextContent(
      'still refused'
    );

    fireEvent.click(screen.getByRole('button', { name: 'Remove scope agent:invoke' }));

    expect(latest.config).toMatchObject({ required_scopes: [], protected_resource: SETTING });
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'None required'
    );
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes-source')).toHaveTextContent(
      'Callers without a valid token are still refused.'
    );
    expect(screen.getByTestId('caller-auth-discovery-switch')).toBeChecked();
  });

  it('moves focus to the Resource URL field when authorization server discovery is turned on', async () => {
    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).not.toHaveFocus();

    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.queryByTestId('caller-auth-discovery-resource-input')).toBeNull();
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));

    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveFocus();
  });

  it('announces the accepted audiences and token forwarding it turned off', async () => {
    const { view } = await openEditor({
      initial: jwtConfig({ audiences: ['api', 'other'], jwt_forward_header: true }),
    });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    const cleared = screen.getByTestId('caller-auth-discovery-cleared');
    expect(cleared).toHaveTextContent(
      'Removed 2 accepted audiences and turned token forwarding off: tokens must now name the resource URL.'
    );
    expect(
      screen
        .getAllByRole('status')
        .some(status => within(status).queryByTestId('caller-auth-discovery-cleared'))
    ).toBe(true);
    view.unmount();

    await openEditor({ initial: jwtConfig() });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.queryByTestId('caller-auth-discovery-cleared')).toBeNull();
  });

  it('warns, on a saved surface, that turning it off leaves failed callers to policy', async () => {
    const { view } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { surfaceId: 's-1', storedDiscoveryOn: true },
    });
    expect(screen.queryByTestId('caller-auth-discovery-off-warning')).toBeNull();
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    const warning = screen.getByTestId('caller-auth-discovery-off-warning');
    expect(warning).toHaveTextContent(
      'When saved, the gateway stops refusing failed callers on this route itself.'
    );
    expect(
      screen
        .getAllByRole('status')
        .some(status => within(status).queryByTestId('caller-auth-discovery-off-warning'))
    ).toBe(true);
    view.unmount();

    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.queryByTestId('caller-auth-discovery-off-warning')).toBeNull();
  });

  it('reads whether the setting is stored from the saved surface, not from the editor it opened with', async () => {
    const { view } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { surfaceId: 's-1', storedDiscoveryOn: false },
    });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.queryByTestId('caller-auth-discovery-off-warning')).toBeNull();
    view.unmount();

    await openEditor({
      initial: jwtConfig(),
      meta: { surfaceId: 's-1', storedDiscoveryOn: true },
    });
    expect(screen.getByTestId('caller-auth-discovery-off-warning')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.queryByTestId('caller-auth-discovery-off-warning')).toBeNull();
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(screen.getByTestId('caller-auth-discovery-off-warning')).toBeInTheDocument();
  });

  it('does not list a stored scope that Required Scopes already enforces as unenforced', async () => {
    await openEditor({
      initial: jwtConfig({
        required_scopes: ['agent.invoke'],
        protected_resource: { resource: RESOURCE, scopes: ['agent.invoke', 'extra'] },
      }),
    });
    const overrides = screen.getByTestId('caller-auth-discovery-stored-overrides');
    expect(overrides).toHaveTextContent(
      'also advertises extra, which the gateway does not enforce'
    );
    expect(overrides).not.toHaveTextContent('agent.invoke, which');
  });

  it('keeps the clear button but names no scope when every stored scope is enforced', async () => {
    await openEditor({
      initial: jwtConfig({
        required_scopes: ['agent.invoke'],
        protected_resource: { resource: RESOURCE, scopes: ['agent.invoke'] },
      }),
    });
    const overrides = screen.getByTestId('caller-auth-discovery-stored-overrides');
    expect(overrides).not.toHaveTextContent('does not enforce');
    expect(screen.getByTestId('caller-auth-discovery-clear-scopes-button')).toBeInTheDocument();
  });

  it.each([
    ['mcp' as Protocol, 'Off. No protected resource metadata is published.'],
    ['a2a' as Protocol, "Off. The agent card keeps the managed agent's own security"],
    ['ap2' as Protocol, "Off. The agent card keeps the managed agent's own security"],
  ])('shows what is published while off on %s', async (protocol, text) => {
    await openEditor({ initial: jwtConfig(), protocol });
    const summary = screen.getByTestId('caller-auth-discovery-off-summary');
    expect(summary).toHaveTextContent(text);
    expect(summary).toHaveTextContent('reaches policy as source_auth.method == "failed"');
    expect(screen.queryByTestId('caller-auth-discovery-derived')).toBeNull();
  });

  it('describes the switch for the protocol and ties the description to it', async () => {
    const { view } = await openEditor({ initial: jwtConfig(), protocol: 'a2a' });
    const help = screen.getByTestId('caller-auth-discovery-switch-help');
    expect(help).toHaveTextContent("in the agent card's security scheme");
    expect(screen.getByTestId('caller-auth-discovery-switch')).toHaveAttribute(
      'aria-describedby',
      help.id
    );
    expect(screen.getByRole('checkbox', { name: /^Authorization server discovery/ })).toBe(
      screen.getByTestId('caller-auth-discovery-switch')
    );
    view.unmount();

    await openEditor({ initial: jwtConfig(), protocol: 'mcp' });
    expect(screen.getByTestId('caller-auth-discovery-switch-help')).toHaveTextContent(
      'so MCP clients find the authorization server'
    );
  });

  it('shows, on A2A only, whether the strategy has a pinned authorization server for the card', async () => {
    strategies = [PINNED_STRATEGY];
    const { view } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      protocol: 'a2a',
    });
    expect(screen.getByTestId('caller-auth-discovery-card-pin')).toHaveTextContent(ISSUER);
    view.unmount();

    strategies = [STRATEGY];
    const { view: unpinned } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      protocol: 'a2a',
    });
    expect(screen.getByTestId('caller-auth-discovery-card-pin')).toHaveTextContent(
      'no pinned authorization server, so the agent card names no security scheme'
    );
    unpinned.unmount();

    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }), protocol: 'mcp' });
    expect(screen.queryByTestId('caller-auth-discovery-card-pin')).toBeNull();
  });

  it('hints when the listener has no https URL to suggest', async () => {
    const { latest, view } = await openEditor({
      initial: jwtConfig(),
      accessPointConfig: { listen_address: '0.0.0.0:8080', route: '/mcp/alpha' },
    });
    fireEvent.click(screen.getByTestId('caller-auth-discovery-switch'));
    expect(latest.config?.protected_resource).toEqual({ resource: '' });
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveValue('');
    expect(screen.getByTestId('caller-auth-discovery-resource-hint')).toHaveTextContent(
      "This Access Point's listener has no https URL"
    );
    expect(screen.getByTestId('caller-auth-discovery-derived-audience')).toHaveTextContent(
      'Enter the resource URL'
    );
    view.unmount();

    await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });
    expect(screen.getByTestId('caller-auth-discovery-resource-hint')).toHaveTextContent(
      'Register it as the API (audience) at the authorization server'
    );
  });

  it('refuses a variant of an Access Point at / with the reason at the Resource URL field', async () => {
    const root = { listen_address: 'https://gateway.example', route: '/' };
    const { view } = await openEditor({
      initial: jwtConfig({ protected_resource: { resource: 'https://gateway.example/' } }),
      accessPointConfig: root,
      meta: { activeVariantAlias: 'beta' },
    });
    expect(screen.getByTestId('caller-auth-discovery-resource-error')).toHaveTextContent(
      'has no resource of its own'
    );
    const input = screen.getByTestId('caller-auth-discovery-resource-input');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.getAttribute('aria-describedby')).toContain(
      'caller-auth-discovery-resource-error'
    );
    view.unmount();

    await openEditor({
      initial: jwtConfig({ protected_resource: { resource: 'https://gateway.example/' } }),
      accessPointConfig: root,
    });
    expect(screen.queryByTestId('caller-auth-discovery-resource-error')).toBeNull();
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveAttribute(
      'aria-invalid',
      'false'
    );
  });

  it('shows a refused resource next to the Resource URL field', async () => {
    const refused =
      'access_point.caller_authentication.protected_resource: MCP resource must match the configured public origin and endpoint path (400)';
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: refused },
    });
    expect(screen.getByTestId('caller-auth-discovery-resource-error')).toHaveTextContent(refused);
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveAttribute(
      'aria-invalid',
      'true'
    );
    expect(screen.queryByTestId('caller-auth-discovery-save-error')).toBeNull();
  });

  it('shows a refused rule in the section alert', async () => {
    const refused =
      "variant 'beta': access_point.caller_authentication.protected_resource: requires empty JWT Bearer audiences (400)";
    const { view } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: refused, activeVariantAlias: 'beta' },
    });
    expect(screen.getByTestId('caller-auth-discovery-save-error')).toHaveTextContent(refused);
    expect(screen.queryByTestId('caller-auth-discovery-resource-error')).toBeNull();
    view.unmount();

    const issuer = `access_point.caller_authentication.protected_resource: the JWT verification strategy's expected_issuer "did:web:idp.example" is not an issuer URL protected resource metadata can name: an https URL, or an http one for a strategy no tenant owns (400)`;
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: issuer },
    });
    expect(screen.getByTestId('caller-auth-discovery-save-error')).toHaveTextContent(
      'is not an issuer URL protected resource metadata can name'
    );
  });

  it('does not mark the base route for a refusal about a variant', async () => {
    const refused =
      "variant 'beta': access_point.caller_authentication.protected_resource: a variant of an Access Point at / has no resource of its own (400)";
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: refused },
    });
    expect(screen.queryByTestId('caller-auth-discovery-resource-error')).toBeNull();
    expect(screen.queryByTestId('caller-auth-discovery-save-error')).toBeNull();
    expect(screen.getByTestId('caller-auth-discovery-resource-input')).toHaveAttribute(
      'aria-invalid',
      'false'
    );
  });

  it('does not show an unrelated save error in the discovery section', async () => {
    await openEditor({
      initial: jwtConfig({ protected_resource: SETTING }),
      meta: { saveError: 'target.endpoint: invalid URL (400)' },
    });
    expect(screen.queryByTestId('caller-auth-discovery-save-error')).toBeNull();
    expect(screen.queryByTestId('caller-auth-discovery-resource-error')).toBeNull();
  });

  it('flags field problems once a save was attempted', async () => {
    const setting = {
      resource: 'https://gateway.example/mcp/other',
      authorization_servers: [],
    };
    const { view } = await openEditor({ initial: jwtConfig({ protected_resource: setting }) });
    expect(screen.queryByTestId('caller-auth-discovery-resource-error')).toBeNull();
    expect(screen.queryByTestId('caller-auth-discovery-authorization-servers-error')).toBeNull();
    view.unmount();

    await openEditor({
      initial: jwtConfig({ protected_resource: setting }),
      hasAttemptedSave: true,
    });
    expect(screen.getByTestId('caller-auth-discovery-resource-error')).toHaveTextContent(
      'The resource path must be the Access Point route: /mcp/alpha'
    );
    expect(
      screen.getByTestId('caller-auth-discovery-authorization-servers-error')
    ).toHaveTextContent(/authorization server/i);
    expect(screen.getByTestId('caller-auth-discovery-stored-overrides')).toHaveTextContent(
      'stores its authorization server as an empty list'
    );
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

  it('turns discovery off, and drops it when the method leaves JWT Bearer', async () => {
    const { latest } = await openEditor({ initial: jwtConfig({ protected_resource: SETTING }) });

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
    expect(screen.getByTestId('caller-auth-discovery-derived-audience')).toHaveTextContent(
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

  it.each(['a2a', 'ap2', 'mcp'] as Protocol[])(
    'offers authorization server discovery and Required Scopes on %s',
    async protocol => {
      await openEditor({ initial: jwtConfig(), protocol });
      expect(screen.getByTestId('caller-auth-discovery-switch')).not.toBeChecked();
      expect(screen.getByTestId('caller-auth-scopes')).toBeInTheDocument();
      expect(screen.queryByTestId('caller-auth-discovery-derived-off')).toBeNull();
      expect(screen.queryByTestId('caller-auth-discovery-add-audience-button')).toBeNull();
    }
  );

  it('offers nothing to declare on a DIDComm surface', async () => {
    await openEditor({ initial: jwtConfig(), protocol: 'didcomm' });
    expect(screen.queryByTestId('caller-auth-discovery')).toBeNull();
    expect(screen.queryByTestId('caller-auth-scopes')).toBeNull();
  });

  it('keeps token forwarding and the token header editable while authorization server discovery is off', async () => {
    const { latest } = await openEditor({
      initial: jwtConfig({ jwt_forward_header: true, required_scopes: ['agent:invoke'] }),
      protocol: 'a2a',
    });
    expect(screen.getByTestId('caller-auth-discovery-switch')).not.toBeChecked();
    expect(screen.getByLabelText(/Token Header/)).toBeEnabled();
    expect(screen.getByLabelText(/Scheme/)).toBeEnabled();
    expect(screen.getByPlaceholderText('e.g. https://api.example.com')).toBeEnabled();
    fireEvent.click(screen.getByTestId('caller-auth-jwt-forward-header-checkbox'));
    expect(latest.config?.jwt_forward_header).toBe(false);
    expect(latest.config?.protected_resource).toBeUndefined();
  });

  it('keeps required scopes beside the explicit setting on MCP', async () => {
    const { latest } = await openEditor({
      initial: jwtConfig({ protected_resource: SETTING, required_scopes: ['tools.call'] }),
    });
    expect(screen.getByRole('button', { name: 'Remove scope tools.call' })).toBeInTheDocument();
    typeAndAdd('caller-auth-scope-input', 'tools.list');
    expect(latest.config).toMatchObject({
      required_scopes: ['tools.call', 'tools.list'],
      protected_resource: SETTING,
    });
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'tools.call tools.list'
    );
  });
});

describe('Caller Context sidebar: authorization server discovery', () => {
  it.each(PROTOCOLS)(
    'shows Authorization server discovery on or off and a refused save on %s',
    async protocol => {
      const refused =
        "access_point.caller_authentication.protected_resource: authorization_servers must list 1 to 8 issuers, or be omitted to advertise the JWT verification strategy's issuer (400)";
      await openEditor({
        initial: jwtConfig({ protected_resource: SETTING }),
        Panel: CallerAuthPanel,
        protocol,
        meta: { saveError: refused },
      });
      expect(screen.getByTestId('caller-auth-panel-discovery-status')).toHaveTextContent(
        'Authorization server discovery: on'
      );
      expect(screen.getByTestId('caller-auth-panel-discovery-save-error')).toHaveTextContent(
        refused
      );
    }
  );

  it('reports discovery off, and drops it when the method leaves JWT Bearer', async () => {
    const { latest } = await openEditor({ initial: jwtConfig(), Panel: CallerAuthPanel });
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

  it('shows the declaration outcome and the authorization server discovery status on A2A', async () => {
    await openEditor({ initial: jwtConfig(), Panel: CallerAuthPanel, protocol: 'a2a' });
    expect(screen.getByTestId('caller-auth-outcome-chip')).toHaveTextContent(
      'Outcome shown after the first save'
    );
    expect(screen.getByText('Agent card:')).toBeInTheDocument();
    expect(screen.getByTestId('caller-auth-panel-discovery-status')).toHaveTextContent(
      'Authorization server discovery: off'
    );
  });

  it('shows no discovery status on a DIDComm surface', async () => {
    await openEditor({ initial: jwtConfig(), Panel: CallerAuthPanel, protocol: 'didcomm' });
    expect(screen.queryByTestId('caller-auth-panel-discovery-status')).toBeNull();
    expect(screen.queryByTestId('caller-auth-panel-outcome')).toBeNull();
  });

  it('says only the metadata names the authorization server when the card carries no scheme', async () => {
    (apiClient.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          declarations: [
            { variant: null, outcome: 'declare', reason: null, resource: 'https://gw/a' },
          ],
          warnings: [{ code: 'card_scheme_unavailable', message: 'm', path: null, variant: null }],
        }),
    });
    await openEditor({
      initial: jwtConfig(),
      Panel: CallerAuthPanel,
      protocol: 'a2a',
      meta: { surfaceId: 's-9' },
    });
    expect(await screen.findByText('Declares OAuth')).toBeInTheDocument();
    const detail = screen.getByTestId('caller-auth-outcome-detail');
    expect(detail).toHaveTextContent('Only the protected resource metadata names');
    expect(detail).toHaveTextContent('The agent card names no security scheme.');
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
