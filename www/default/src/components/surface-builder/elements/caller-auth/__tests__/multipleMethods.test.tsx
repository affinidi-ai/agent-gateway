import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import { registry } from '../../index';
import type { CanvasNode, PayloadContext } from '../../types';
import CallerAuthFullscreen from '../CallerAuthFullscreen';
import { methodSelectionProblems } from '../methods';

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

function stored(methods: unknown[]) {
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
  it('loads every stored method and saves them in the same order', () => {
    const nodes = registry.nodesFromPayload(stored([JWT, API_KEY]));
    const config = callerAuthNode(nodes)?.config;

    expect(config?.method_type).toBe('jwt_bearer');
    expect(config?.additional_methods).toEqual([
      {
        method_type: 'api_key',
        extraction_source: 'http_header',
        extraction_field: 'X-API-Key',
        api_key_secret_id: 'partner-keys',
      },
    ]);
    expect(registry.buildPayload(context(nodes)).access_point.caller_authentication).toEqual({
      methods: [JWT, API_KEY],
    });
  });

  it('does not keep methods from a stale canvas copy once the surface has one method', () => {
    const nodes = registry.nodesFromPayload({
      ...stored([JWT]),
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'caller-auth',
            type: 'caller-auth',
            parentId: 'access-point',
            config: {
              method_type: 'jwt_bearer',
              jwt_strategy_id: 'idp',
              additional_methods: [{ method_type: 'did_auth' }],
            },
          },
        ],
      },
    });

    expect(callerAuthNode(nodes)?.config.additional_methods).toEqual([]);
    expect(registry.buildPayload(context(nodes)).access_point.caller_authentication).toEqual({
      methods: [JWT],
    });
  });

  it('reports an incomplete additional method by its position', () => {
    expect(
      registry.getFaultReason('caller-auth', {
        method_type: 'jwt_bearer',
        jwt_strategy_id: 'idp',
        additional_methods: [
          {
            method_type: 'api_key',
            extraction_source: 'http_header',
            extraction_field: 'X-API-Key',
          },
        ],
      })
    ).toBe('Method 2: API key secret must be selected');
  });

  it('rejects two methods reading the same header, ignoring case', () => {
    expect(
      methodSelectionProblems({
        method_type: 'jwt_bearer',
        jwt_token_header: 'Authorization',
        additional_methods: [
          {
            method_type: 'api_key',
            extraction_source: 'http_header',
            extraction_field: 'authorization',
          },
        ],
      })
    ).toEqual([
      {
        field: 'additional_methods',
        message:
          "Methods 1 and 2 both read the 'authorization' header; each method needs its own credential location",
      },
    ]);
  });

  it('rejects a second DID Auth method', () => {
    expect(
      methodSelectionProblems({
        method_type: 'did_auth',
        extraction_source: 'http_header',
        extraction_field: 'X-Session-A',
        additional_methods: [
          {
            method_type: 'did_auth',
            extraction_source: 'http_header',
            extraction_field: 'X-Session-B',
          },
        ],
      })
    ).toEqual([{ field: 'additional_methods', message: 'At most one DID Auth method' }]);
  });

  it('rejects a method reading the request body beside another method', () => {
    expect(
      methodSelectionProblems({
        method_type: 'jwt_bearer',
        additional_methods: [
          { method_type: 'api_key', extraction_source: 'mcp_meta', extraction_field: 'apiKey' },
        ],
      })
    ).toEqual([
      {
        field: 'additional_methods',
        message:
          'Method 2 reads MCP _meta; with more than one method, each must read a header or the client certificate',
      },
    ]);
    expect(
      methodSelectionProblems({
        method_type: 'api_key',
        extraction_source: 'mcp_meta',
        extraction_field: 'apiKey',
      })
    ).toEqual([]);
  });

  it('accepts methods on distinct credential locations', () => {
    expect(
      methodSelectionProblems({
        method_type: 'jwt_bearer',
        additional_methods: [
          {
            method_type: 'api_key',
            extraction_source: 'http_header',
            extraction_field: 'X-API-Key',
          },
        ],
      })
    ).toEqual([]);
  });
});

const Harness: React.FC<{ initial: Record<string, unknown>; latest: { config?: any } }> = ({
  initial,
  latest,
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
  return (
    <MemoryRouter>
      <CallerAuthFullscreen
        node={node}
        config={config}
        updateField={(field, value) => updateFields({ [field]: value })}
        updateFields={updateFields}
        protocol="a2a"
        allNodes={[node]}
        hasAttemptedSave={false}
      />
    </MemoryRouter>
  );
};

describe('Caller Context editor: additional methods', () => {
  beforeEach(() => {
    (apiClient.fetch as jest.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });
    (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
  });

  it('adds an API key method beside a JWT method, then removes it', () => {
    const latest: { config?: any } = {};
    render(
      <Harness initial={{ method_type: 'jwt_bearer', jwt_strategy_id: 'idp' }} latest={latest} />
    );

    fireEvent.click(screen.getByTestId('caller-auth-add-method-button'));
    expect(latest.config.additional_methods).toEqual([
      { method_type: 'api_key', extraction_source: 'http_header', extraction_field: 'X-API-Key' },
    ]);
    expect(screen.getByLabelText('Remove method 2')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('caller-auth-extra-0-remove-button'));
    expect(latest.config.additional_methods).toEqual([]);
  });

  it('edits an additional method without touching the first one', () => {
    const latest: { config?: any } = {};
    render(
      <Harness
        initial={{
          method_type: 'jwt_bearer',
          jwt_strategy_id: 'idp',
          additional_methods: [
            {
              method_type: 'api_key',
              extraction_source: 'http_header',
              extraction_field: 'X-API-Key',
            },
          ],
        }}
        latest={latest}
      />
    );

    fireEvent.change(screen.getByLabelText('HTTP Header Name'), {
      target: { value: 'X-Partner-Key' },
    });
    expect(latest.config.additional_methods[0].extraction_field).toBe('X-Partner-Key');
    expect(latest.config.method_type).toBe('jwt_bearer');
    expect(latest.config.jwt_strategy_id).toBe('idp');
  });

  it('reorders additional methods', () => {
    const latest: { config?: any } = {};
    render(
      <Harness
        initial={{
          method_type: 'jwt_bearer',
          jwt_strategy_id: 'idp',
          additional_methods: [
            {
              method_type: 'api_key',
              extraction_source: 'http_header',
              extraction_field: 'X-API-Key',
            },
            {
              method_type: 'did_auth',
              extraction_source: 'http_header',
              extraction_field: 'X-Session-Token',
            },
          ],
        }}
        latest={latest}
      />
    );

    fireEvent.click(screen.getByLabelText('Move method 3 up'));
    expect(latest.config.additional_methods.map((m: any) => m.method_type)).toEqual([
      'did_auth',
      'api_key',
    ]);
  });

  it('shows a conflict between methods reading the same header', () => {
    render(
      <Harness
        initial={{
          method_type: 'api_key',
          extraction_source: 'http_header',
          extraction_field: 'X-API-Key',
          additional_methods: [
            {
              method_type: 'api_key',
              extraction_source: 'http_header',
              extraction_field: 'x-api-key',
            },
          ],
        }}
        latest={{}}
      />
    );

    expect(screen.getByTestId('caller-auth-method-selection-error')).toHaveTextContent(
      "Methods 1 and 2 both read the 'x-api-key' header"
    );
  });

  it('moves method 2 into the first place, swapping it with the first method', () => {
    const latest: { config?: any } = {};
    render(
      <Harness
        initial={{
          method_type: 'jwt_bearer',
          jwt_strategy_id: 'idp',
          additional_methods: [
            {
              method_type: 'api_key',
              extraction_source: 'http_header',
              extraction_field: 'X-API-Key',
              api_key_secret_id: 'keys',
            },
          ],
        }}
        latest={latest}
      />
    );

    fireEvent.click(screen.getByTestId('caller-auth-extra-0-move-up-button'));
    expect(latest.config.method_type).toBe('api_key');
    expect(latest.config.api_key_secret_id).toBe('keys');
    expect(latest.config.additional_methods).toEqual([
      { method_type: 'jwt_bearer', jwt_strategy_id: 'idp' },
    ]);
  });

  it('keeps JWT Bearer first while authorization server discovery is on', () => {
    render(
      <Harness
        initial={{
          method_type: 'jwt_bearer',
          jwt_strategy_id: 'idp',
          protected_resource: {
            resource: 'https://gateway.example/mcp/alpha',
            authorization_servers: ['https://idp.example/realms/agents'],
          },
          additional_methods: [
            {
              method_type: 'api_key',
              extraction_source: 'http_header',
              extraction_field: 'X-API-Key',
            },
          ],
        }}
        latest={{}}
      />
    );

    expect(screen.getByTestId('caller-auth-extra-0-move-up-button')).toBeDisabled();
  });
});
