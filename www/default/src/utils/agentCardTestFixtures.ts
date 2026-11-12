type Json = Record<string, unknown>;

export const BEFORE_CARD: Json = {
  protocolVersion: '0.3.0',
  name: 'Mock agent',
  url: 'https://agent.internal/a2a',
  capabilities: { streaming: true },
  securitySchemes: {
    agent_own_oauth: {
      type: 'oauth2',
      flows: {
        clientCredentials: {
          tokenUrl: 'https://idp.example/token',
          scopes: { 'agent.read': 'Read' },
        },
      },
    },
  },
  security: [{ agent_own_oauth: ['agent.read'] }],
  signatures: [{ protected: 'p', signature: 's' }],
  skills: [{ id: 'echo', name: 'Echo' }],
};

export const AFTER_CARD: Json = {
  protocolVersion: '0.3.0',
  name: 'Mock agent',
  url: 'https://gw.example/mock-agent',
  capabilities: { streaming: true },
  securitySchemes: {
    agent_own_oauth: {
      type: 'oauth2',
      flows: {
        clientCredentials: {
          tokenUrl: 'https://idp.example/token',
          scopes: { 'agent.read': 'Read', 'agent.write': 'Write' },
        },
      },
    },
  },
  security: [{ agent_own_oauth: ['agent.read', 'agent.write'] }],
  skills: [{ id: 'echo', name: 'Echo' }],
};

export function previewBody(overrides: Json = {}): Json {
  return {
    surface_id: 's-123',
    supported: true,
    unsupported_reason: null,
    variant: null,
    generated: false,
    served_url: 'https://gw.example/mock-agent/.well-known/agent-card.json',
    source_url: 'https://agent.internal/.well-known/agent-card.json',
    source_url_query_hidden: false,
    fetched_at: '2026-10-23T10:00:00Z',
    cached: false,
    fetch: {
      status: 'ok',
      cause: null,
      http_status: null,
      duration_ms: 182,
      identity_error: null,
      identity_slot: null,
    },
    auth: {
      kind: 'credential_provider',
      result: 'sent',
      provider_name: 'oidc-e2e jwt bearer',
      token_expires_at: '2026-10-23T10:55:00Z',
      failure: null,
    },
    before: BEFORE_CARD,
    after: AFTER_CARD,
    before_bytes: 1412,
    after_bytes: 2950,
    display_limit_bytes: 262144,
    ...overrides,
  };
}

export function failedBody(cause: string, httpStatus: number | null, auth: Json = {}): Json {
  return previewBody({
    fetch: { status: 'failed', cause, http_status: httpStatus, duration_ms: 40 },
    auth: {
      kind: 'none',
      result: 'not_configured',
      provider_name: null,
      token_expires_at: null,
      failure: null,
      ...auth,
    },
    before: null,
    after: null,
    before_bytes: null,
    after_bytes: null,
  });
}

export function unsupportedBody(reason: 'not_a2a' | 'not_running' | 'operator_only'): Json {
  return {
    surface_id: 's-123',
    supported: false,
    unsupported_reason: reason,
    variant: null,
    generated: false,
    served_url: null,
    source_url: null,
    source_url_query_hidden: false,
    fetched_at: null,
    cached: false,
    fetch: null,
    auth: null,
    before: null,
    after: null,
    before_bytes: null,
    after_bytes: null,
    display_limit_bytes: 0,
  };
}
