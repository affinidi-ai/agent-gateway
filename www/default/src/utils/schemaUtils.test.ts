import { extractAgentIdentitySchema } from './schemaUtils';

const A2A_IDENTITY_URI = 'https://fabric.affinidi.io/extensions/agent-identity/v1';

describe('extractAgentIdentitySchema', () => {
  it('builds A2A schemas from the identity extension payload without a meta-field wrapper', () => {
    const schema = JSON.parse(
      extractAgentIdentitySchema(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'message/send',
          params: {
            message: {
              extensions: [A2A_IDENTITY_URI],
              metadata: {
                [A2A_IDENTITY_URI]: {
                  softwareInfo: { name: 'test-agent', version: '1.0' },
                  cloudProvider: 'local',
                },
              },
            },
          },
        },
        'agentIdentity',
        'a2a'
      )
    );

    expect(schema.properties.softwareInfo.properties.name.type).toBe('string');
    expect(schema.properties.cloudProvider.type).toBe('string');
    expect(schema.properties.agentIdentity).toBeUndefined();
  });

  it('keeps MCP schemas wrapped under the configured meta field', () => {
    const schema = JSON.parse(
      extractAgentIdentitySchema(
        {
          jsonrpc: '2.0',
          method: 'tools/call',
          _meta: {
            serverIdentity: {
              softwareInfo: { name: 'server-agent' },
            },
          },
        },
        'serverIdentity',
        'mcp'
      )
    );

    expect(schema.properties.serverIdentity.properties.softwareInfo.properties.name.type).toBe(
      'string'
    );
  });

  describe('protocol auto-detection (no protocol argument)', () => {
    // `CaptureSchemaModal` declares `protocol` as optional, so these payloads
    // reach the detector rather than being labelled by the caller.
    const a2aPayload = (method: string) => ({
      jsonrpc: '2.0',
      id: 1,
      method,
      params: {
        message: {
          extensions: [A2A_IDENTITY_URI],
          metadata: {
            [A2A_IDENTITY_URI]: {
              softwareInfo: { name: 'test-agent' },
            },
          },
        },
      },
    });

    // An A2A v0.3 method name contains a slash; the payload must still be
    // classified as A2A, so the schema is not wrapped in an MCP `_meta` field.
    it('detects an A2A v0.3 payload rather than treating the slash method as MCP', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(a2aPayload('message/send'), 'agentIdentity')
      );

      expect(schema.properties.softwareInfo.properties.name.type).toBe('string');
      expect(schema.properties.agentIdentity).toBeUndefined();
    });

    it('detects an A2A v1.0 PascalCase payload', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(a2aPayload('SendMessage'), 'agentIdentity')
      );

      expect(schema.properties.softwareInfo.properties.name.type).toBe('string');
      expect(schema.properties.agentIdentity).toBeUndefined();
    });

    it('detects a v1.0-only method such as ListTasks as A2A', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(a2aPayload('ListTasks'), 'agentIdentity')
      );

      expect(schema.properties.softwareInfo.properties.name.type).toBe('string');
    });

    it('still detects MCP and keeps its meta-field wrapper', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(
          {
            jsonrpc: '2.0',
            method: 'tools/call',
            _meta: { serverIdentity: { softwareInfo: { name: 'server-agent' } } },
          },
          'serverIdentity'
        )
      );

      expect(schema.properties.serverIdentity.properties.softwareInfo.properties.name.type).toBe(
        'string'
      );
    });

    // MCP's opt-in Tasks extension defines `tasks/get`, `tasks/update` and
    // `tasks/cancel`; the first and third collide with A2A v0.3. `tasks/list` is
    // A2A-only and is covered here too, because a payload carrying MCP's `_meta`
    // must be treated as MCP whatever the method looks like. The extension is
    // negotiated through `params._meta`, so that container is the tie-breaker,
    // matching how the backend runs MCP wire validation ahead of method-prefix
    // classification.
    it.each(['tasks/get', 'tasks/list', 'tasks/cancel'])(
      'keeps MCP %s with top-level _meta classified as MCP, not A2A',
      method => {
        const schema = JSON.parse(
          extractAgentIdentitySchema(
            {
              jsonrpc: '2.0',
              method,
              _meta: { serverIdentity: { softwareInfo: { name: 'mcp-agent' } } },
            },
            'serverIdentity'
          )
        );

        expect(schema.properties.serverIdentity.properties.softwareInfo.properties.name.type).toBe(
          'string'
        );
      }
    );

    it('classifies MCP canonical params._meta as MCP even on a colliding tasks method', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(
          {
            jsonrpc: '2.0',
            method: 'tasks/get',
            params: { _meta: { serverIdentity: { softwareInfo: { name: 'mcp-agent' } } } },
          },
          'serverIdentity'
        )
      );

      // The meta-field wrapper is applied only for MCP, so its presence is the
      // proof of classification. The extractor itself reads only the legacy
      // top-level `_meta`, so the wrapped schema is empty, but the payload is
      // not mislabelled as A2A (which would produce an unwrapped schema).
      expect(schema.properties.serverIdentity).toBeDefined();
      expect(schema.properties.softwareInfo).toBeUndefined();
    });

    it('detects an AP2 payload from its namespaced method', () => {
      const schema = JSON.parse(
        extractAgentIdentitySchema(
          {
            jsonrpc: '2.0',
            method: 'ap2.payment.authorize',
            params: {
              message: {
                metadata: {
                  [A2A_IDENTITY_URI]: { softwareInfo: { name: 'payer-agent' } },
                },
              },
            },
          },
          'agentIdentity'
        )
      );

      expect(schema.properties.softwareInfo.properties.name.type).toBe('string');
      expect(schema.properties.agentIdentity).toBeUndefined();
    });
  });
});
