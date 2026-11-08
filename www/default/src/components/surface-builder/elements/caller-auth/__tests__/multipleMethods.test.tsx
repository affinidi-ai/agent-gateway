import React, { useState } from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import { registry } from '../../index';
import type { CanvasNode, ConfigPanelProps, PayloadContext } from '../../types';
import CallerAuthFullscreen from '../CallerAuthFullscreen';
import CallerAuthPanel from '../CallerAuthPanel';
import {
  LATER_JWT_BEARER_BESIDE_DISCOVERY,
  methodSelectionProblems,
  readMethods,
} from '../methods';
import { selectMethod } from '../selectedMethod';
import { identityDefinition } from '../../identity/definition';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn(), get: jest.fn() } }));

const JWT = {
  type: 'jwt_bearer',
  jwt_verification_strategy_id: 'idp',
  audiences: [],
  token_header: 'Authorization',
  token_scheme: 'Bearer',
  forward_header: false,
};
const API_KEY = {
  type: 'api_key',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  secret_id: 'partner-keys',
};
const JWT_METHOD = { method_type: 'jwt_bearer', jwt_strategy_id: 'idp' };
const API_KEY_METHOD = {
  method_type: 'api_key',
  extraction_source: 'http_header',
  extraction_field: 'X-API-Key',
  api_key_secret_id: 'partner-keys',
};

function stored(methods: unknown[], canvas?: unknown) {
  return {
    name: 'multi',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gateway.example',
      route: '/a2a/alpha',
      protocol: 'a2a',
      caller_authentication: { methods },
    },
    target: { endpoint: 'https://agent.example' },
    ...(canvas ? { canvas } : {}),
  };
}

function context(nodes: CanvasNode[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'multi', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const callerAuthNode = (nodes: CanvasNode[]) => nodes.find(n => n.type === 'caller-auth');

describe('caller-auth with several methods', () => {
  it('loads every stored method into the list and saves them in the same order', () => {
    const nodes = registry.nodesFromPayload(stored([JWT, API_KEY]));
    const config = callerAuthNode(nodes)?.config;

    expect(config?.methods).toEqual([
      expect.objectContaining({ method_type: 'jwt_bearer', jwt_strategy_id: 'idp' }),
      expect.objectContaining(API_KEY_METHOD),
    ]);
    expect(registry.buildPayload(context(nodes)).access_point.caller_authentication).toEqual({
      methods: [JWT, API_KEY],
    });
  });

  it('does not keep methods from a stale canvas copy once the surface has one method', () => {
    const canvas = {
      version: 1,
      nodes: [
        {
          id: 'caller-auth',
          type: 'caller-auth',
          parentId: 'access-point',
          config: { methods: [JWT_METHOD, { method_type: 'did_auth' }] },
        },
      ],
    };
    const nodes = registry.nodesFromPayload(stored([JWT], canvas));

    expect(readMethods(callerAuthNode(nodes)?.config)).toHaveLength(1);
    expect(registry.buildPayload(context(nodes)).access_point.caller_authentication).toEqual({
      methods: [JWT],
    });
  });

  it('still reads a config saved with the first method on the element itself', () => {
    expect(
      readMethods({ ...JWT_METHOD, protected_resource: null, additional_methods: [API_KEY_METHOD] })
    ).toEqual([JWT_METHOD, API_KEY_METHOD]);
  });

  it('reports an incomplete method by its position only when there are several', () => {
    const noSecret = { ...API_KEY_METHOD, api_key_secret_id: undefined };
    expect(registry.getFaultReason('caller-auth', { methods: [JWT_METHOD, noSecret] })).toBe(
      'Method 2: API key secret must be selected'
    );
    expect(registry.getFaultReason('caller-auth', { methods: [noSecret] })).toBe(
      'API key secret must be selected'
    );
  });

  it('rejects two methods reading the same header, ignoring case', () => {
    expect(
      methodSelectionProblems({
        methods: [
          { method_type: 'jwt_bearer', jwt_token_header: 'Authorization' },
          {
            method_type: 'api_key',
            extraction_source: 'http_header',
            extraction_field: 'authorization',
          },
        ],
      })
    ).toEqual([
      {
        field: 'methods',
        message:
          "Methods 1 and 2 both read the 'authorization' header; each method needs its own credential location",
      },
    ]);
  });

  it('rejects a second DID Auth method', () => {
    expect(
      methodSelectionProblems({
        methods: [
          {
            method_type: 'did_auth',
            extraction_source: 'http_header',
            extraction_field: 'X-Session-A',
          },
          {
            method_type: 'did_auth',
            extraction_source: 'http_header',
            extraction_field: 'X-Session-B',
          },
        ],
      })
    ).toEqual([{ field: 'methods', message: 'At most one DID Auth method' }]);
  });

  it('rejects a method reading the request body beside another method', () => {
    expect(
      methodSelectionProblems({
        methods: [
          JWT_METHOD,
          { method_type: 'api_key', extraction_source: 'mcp_meta', extraction_field: 'apiKey' },
        ],
      })
    ).toEqual([
      {
        field: 'methods',
        message:
          'Method 2 reads MCP _meta; with more than one method, each must read a header or the client certificate',
      },
    ]);
    expect(
      methodSelectionProblems({
        methods: [
          { method_type: 'api_key', extraction_source: 'mcp_meta', extraction_field: 'apiKey' },
        ],
      })
    ).toEqual([]);
  });

  it('accepts methods on distinct credential locations', () => {
    expect(methodSelectionProblems({ methods: [JWT_METHOD, API_KEY_METHOD] })).toEqual([]);
  });

  it('lets From JWT Claims identity rely only on a Caller Context whose methods are all JWT', () => {
    const dependency = identityDefinition.featureDependencies!.find(d =>
      d.description.startsWith('from_jwt_claim')
    )!;
    const withMethods = (methods: unknown[]) =>
      ({
        allNodes: [{ id: 'caller-auth', type: 'caller-auth', config: { methods } }],
      }) as never;
    expect(dependency.check({ type: 'from_jwt_claim' }, withMethods([JWT_METHOD]))).toBe(true);
    expect(
      dependency.check({ type: 'from_jwt_claim' }, withMethods([JWT_METHOD, API_KEY_METHOD]))
    ).toBe(false);
  });
});

const node = (config: Record<string, unknown>): CanvasNode => ({
  id: 'caller-auth',
  type: 'caller-auth',
  label: '',
  configured: true,
  config,
});

const Harness: React.FC<{
  initial: Record<string, unknown>;
  latest: { config?: any };
  Panel?: React.FC<ConfigPanelProps>;
  openFullscreenEditor?: () => void;
}> = ({ initial, latest, Panel = CallerAuthFullscreen, openFullscreenEditor }) => {
  const [config, setConfig] = useState(initial);
  latest.config = config;
  const updateFields = (fields: Record<string, unknown>) =>
    setConfig(prev => ({ ...prev, ...fields }));
  const current = node(config);
  return (
    <MemoryRouter>
      <Panel
        node={current}
        config={config}
        updateField={(field, value) => updateFields({ [field]: value })}
        updateFields={updateFields}
        protocol="a2a"
        allNodes={[current]}
        hasAttemptedSave={false}
        openFullscreenEditor={openFullscreenEditor}
      />
    </MemoryRouter>
  );
};

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
  act(() => selectMethod('caller-auth', 0));
});

describe('Caller Context editor: the method list', () => {
  it('lists every method and shows the settings of the one picked', () => {
    const latest: { config?: any } = {};
    render(<Harness initial={{ methods: [JWT_METHOD, API_KEY_METHOD] }} latest={latest} />);

    expect(screen.getByTestId('caller-auth-editor-method-0')).toHaveTextContent('JWT');
    expect(screen.getByTestId('caller-auth-editor-method-1')).toHaveTextContent(
      "Reads the 'x-api-key' header"
    );
    expect(screen.getByLabelText('Authentication Method')).toHaveValue('jwt_bearer');

    fireEvent.click(screen.getByTestId('caller-auth-editor-method-1-configure-button'));
    expect(screen.getByLabelText('Authentication Method')).toHaveValue('api_key');
    fireEvent.change(screen.getByLabelText('HTTP Header Name'), {
      target: { value: 'X-Partner-Key' },
    });

    expect(latest.config.methods[1].extraction_field).toBe('X-Partner-Key');
    expect(latest.config.methods[0]).toEqual(JWT_METHOD);
  });

  it('adds a method from the menu and opens its settings', () => {
    const latest: { config?: any } = {};
    render(<Harness initial={{ methods: [JWT_METHOD] }} latest={latest} />);

    fireEvent.click(screen.getByTestId('caller-auth-editor-add-method-button'));
    fireEvent.click(screen.getByTestId('caller-auth-editor-add-method-api_key'));

    expect(latest.config.methods).toEqual([
      JWT_METHOD,
      { method_type: 'api_key', extraction_source: 'http_header', extraction_field: 'X-API-Key' },
    ]);
    expect(screen.getByText('Method 2 settings')).toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-editor-add-method-menu')).toBeNull();
  });

  it('makes another method primary, keeping the order of the rest', () => {
    const latest: { config?: any } = {};
    const DID_METHOD = {
      method_type: 'did_auth',
      extraction_source: 'http_header',
      extraction_field: 'X-DID-Session',
    };
    render(
      <Harness initial={{ methods: [JWT_METHOD, API_KEY_METHOD, DID_METHOD] }} latest={latest} />
    );

    expect(screen.getByTestId('caller-auth-editor-method-0')).toHaveTextContent('Primary');
    expect(screen.queryByTestId('caller-auth-editor-method-0-make-primary-button')).toBeNull();

    fireEvent.click(screen.getByTestId('caller-auth-editor-method-2-make-primary-button'));
    expect(latest.config.methods.map((m: any) => m.method_type)).toEqual([
      'did_auth',
      'jwt_bearer',
      'api_key',
    ]);
    expect(screen.getByTestId('caller-auth-editor-method-0')).toHaveTextContent('DID Auth');
  });

  it('marks no method primary while there is only one', () => {
    render(<Harness initial={{ methods: [JWT_METHOD] }} latest={{}} />);
    expect(screen.getByTestId('caller-auth-editor-method-0')).not.toHaveTextContent('Primary');
  });

  it('removes a method but always keeps one', () => {
    const latest: { config?: any } = {};
    render(<Harness initial={{ methods: [JWT_METHOD, API_KEY_METHOD] }} latest={latest} />);

    fireEvent.click(screen.getByTestId('caller-auth-editor-method-1-remove-button'));
    expect(latest.config.methods).toEqual([JWT_METHOD]);
    expect(screen.getByTestId('caller-auth-editor-method-0-remove-button')).toBeDisabled();
  });

  it('keeps JWT Bearer primary while authorization server discovery is on', () => {
    render(
      <Harness
        initial={{
          methods: [JWT_METHOD, API_KEY_METHOD],
          protected_resource: {
            resource: 'https://gateway.example/mcp/alpha',
            authorization_servers: ['https://idp.example/realms/agents'],
          },
        }}
        latest={{}}
      />
    );

    expect(screen.getByTestId('caller-auth-editor-method-0')).toHaveTextContent('discovery');
    expect(screen.getByTestId('caller-auth-editor-method-1-make-primary-button')).toBeDisabled();
  });

  describe('a later JWT Bearer method beside discovery', () => {
    const SECOND_JWT = { ...JWT_METHOD, jwt_token_header: 'X-Internal-Token' };
    const DISCOVERY = {
      resource: 'https://gateway.example/mcp/alpha',
      authorization_servers: ['https://idp.example/realms/agents'],
    };

    it('is flagged with the gateway refusal while discovery is on', () => {
      const config = { methods: [JWT_METHOD, SECOND_JWT], protected_resource: DISCOVERY };
      render(<Harness initial={config} latest={{}} />);

      expect(screen.getByTestId('caller-auth-editor-method-1')).toHaveTextContent(
        LATER_JWT_BEARER_BESIDE_DISCOVERY
      );
      expect(methodSelectionProblems(config)).toEqual([
        { field: 'methods', message: LATER_JWT_BEARER_BESIDE_DISCOVERY },
      ]);
    });

    it('is ready while discovery is off', () => {
      const config = { methods: [JWT_METHOD, SECOND_JWT], protected_resource: null };
      render(<Harness initial={config} latest={{}} />);

      expect(screen.getByTestId('caller-auth-editor-method-1-status')).toHaveAttribute(
        'aria-label',
        'Ready'
      );
      expect(methodSelectionProblems(config)).toEqual([]);
    });
  });

  it('flags a method that reads the same header as an earlier one', () => {
    render(
      <Harness
        initial={{
          methods: [API_KEY_METHOD, { ...API_KEY_METHOD, extraction_field: 'x-api-key' }],
        }}
        latest={{}}
      />
    );

    expect(screen.getByTestId('caller-auth-editor-method-0-status')).toHaveAttribute(
      'aria-label',
      'Ready'
    );
    expect(screen.getByTestId('caller-auth-editor-method-1')).toHaveTextContent(
      "Methods 1 and 2 both read the 'x-api-key' header"
    );
  });
});

describe('Caller Context sidebar: the method list', () => {
  it('opens the editor on the method whose Configure was clicked', () => {
    const openFullscreenEditor = jest.fn();
    render(
      <Harness
        initial={{ methods: [JWT_METHOD, API_KEY_METHOD] }}
        latest={{}}
        Panel={CallerAuthPanel}
        openFullscreenEditor={openFullscreenEditor}
      />
    );
    const rows = screen.getByTestId('caller-auth-panel-methods');
    expect(within(rows).getAllByRole('listitem')).toHaveLength(2);
    expect(screen.queryByTestId('caller-auth-panel-method-0-remove-button')).toBeNull();
    expect(screen.queryByTestId('caller-auth-panel-method-1-make-primary-button')).toBeNull();

    fireEvent.click(screen.getByTestId('caller-auth-panel-method-1-configure-button'));
    expect(openFullscreenEditor).toHaveBeenCalled();

    render(<Harness initial={{ methods: [JWT_METHOD, API_KEY_METHOD] }} latest={{}} />);
    expect(screen.getByLabelText('Authentication Method')).toHaveValue('api_key');
  });
});
