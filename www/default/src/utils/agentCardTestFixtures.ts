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
    agent_gateway: {
      type: 'oauth2',
      flows: {
        authorizationCode: {
          authorizationUrl: 'https://as.example/authorize',
          tokenUrl: 'https://as.example/token',
          scopes: { 'gw.invoke': 'Invoke' },
        },
      },
    },
  },
  security: [{ agent_gateway: ['gw.invoke'] }],
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
    fetch: { status: 'ok', cause: null, http_status: null, duration_ms: 182 },
    auth: {
      kind: 'credential_provider',
      result: 'sent',
      provider_name: 'oidc-e2e jwt bearer',
      token_expires_at: '2026-10-23T10:55:00Z',
      failure: null,
    },
    payment_required: false,
    outcome: {
      variant: null,
      outcome: 'declare',
      reason: null,
      resource: 'https://gw.example/mock-agent',
    },
    before: BEFORE_CARD,
    after: AFTER_CARD,
    before_bytes: 1412,
    after_bytes: 2950,
    display_limit_bytes: 262144,
    last_caller_fetch: null,
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
    outcome: { variant: null, outcome: 'pass_through', reason: null, resource: null },
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
    payment_required: false,
    outcome: null,
    before: null,
    after: null,
    before_bytes: null,
    after_bytes: null,
    display_limit_bytes: 0,
    last_caller_fetch: null,
  };
}
