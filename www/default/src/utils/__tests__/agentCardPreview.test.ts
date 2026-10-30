import {
  AUTH_FAILURE_TEXT,
  CARD_AUTH_FAILURES,
  cardNamesGatewayScheme,
  CARD_FETCH_CAUSES,
  CARD_FETCH_CAUSE_LABEL,
  CARD_FETCH_CAUSE_TEXT,
  CARD_PEER_REFUSED_TEXT,
  CARD_REJECTED_CREDENTIAL_TEXT,
  describeCardAuth,
  describeFetchCause,
  describeFetchFailure,
  fetchAgentCardPreview,
  formatRelativeTime,
  parseAgentCardPreview,
  refreshAgentCardPreview,
  safeHttpUrl,
  type CardAuthReport,
  type CardFetch,
  type SupportedAgentCardPreview,
} from '../agentCardPreview';
import {
  AFTER_CARD,
  BEFORE_CARD,
  failedBody,
  previewBody,
  unsupportedBody,
} from '../agentCardTestFixtures';

const supported = (body: unknown): SupportedAgentCardPreview => {
  const parsed = parseAgentCardPreview(body);
  if (!parsed || !parsed.supported) throw new Error('expected a supported preview');
  return parsed;
};

const auth = (over: Partial<CardAuthReport> = {}): CardAuthReport => ({
  kind: 'credential_provider',
  result: 'sent',
  provider_name: 'Foundry',
  token_expires_at: null,
  failure: null,
  ...over,
});

const failed = (cause: CardFetch['cause'], http_status: number | null = null): CardFetch => ({
  status: 'failed',
  cause,
  http_status,
  duration_ms: 1,
});

describe('parseAgentCardPreview', () => {
  it('parses a ready preview', () => {
    const p = supported(previewBody());
    expect(p.surface_id).toBe('s-123');
    expect(p.fetch).toEqual({ status: 'ok', cause: null, http_status: null, duration_ms: 182 });
    expect(p.auth.provider_name).toBe('oidc-e2e jwt bearer');
    expect(p.outcome).toEqual({
      variant: null,
      outcome: 'declare',
      reason: null,
      resource: 'https://gw.example/mock-agent',
    });
    expect(p.before).toEqual(BEFORE_CARD);
    expect(p.after).toEqual(AFTER_CARD);
    expect(p.display_limit_bytes).toBe(262144);
    expect(p.last_caller_fetch).toBeNull();
  });

  it('parses an unsupported preview', () => {
    expect(parseAgentCardPreview(unsupportedBody('not_a2a'))).toEqual({
      supported: false,
      surface_id: 's-123',
      unsupported_reason: 'not_a2a',
    });
    expect(parseAgentCardPreview(unsupportedBody('not_running'))).toMatchObject({
      unsupported_reason: 'not_running',
    });
    expect(parseAgentCardPreview(unsupportedBody('operator_only'))).toEqual({
      supported: false,
      surface_id: 's-123',
      unsupported_reason: 'operator_only',
    });
    expect(
      parseAgentCardPreview({ ...unsupportedBody('not_a2a'), unsupported_reason: 'tenant_only' })
    ).toBeNull();
  });

  it('parses the last caller fetch', () => {
    const p = supported(
      previewBody({
        last_caller_fetch: {
          status: 'failed',
          cause: 'needs_token',
          http_status: 401,
          at: '2026-10-23T09:58:12Z',
        },
      })
    );
    expect(p.last_caller_fetch).toEqual({
      status: 'failed',
      cause: 'needs_token',
      http_status: 401,
      at: '2026-10-23T09:58:12Z',
    });
  });

  it('keeps cards only when they are JSON objects', () => {
    const p = supported(previewBody({ before: ['not', 'an', 'object'], after: 'text' }));
    expect(p.before).toBeNull();
    expect(p.after).toBeNull();
  });

  it('drops an outcome with an unknown value and a caller fetch with an unknown status', () => {
    const p = supported(
      previewBody({
        outcome: { variant: null, outcome: 'maybe', reason: null, resource: null },
        last_caller_fetch: { status: 'weird', cause: null, http_status: null, at: null },
      })
    );
    expect(p.outcome).toBeNull();
    expect(p.last_caller_fetch).toBeNull();
  });

  it.each([
    ['unknown fetch status', { fetch: { status: 'maybe', cause: null, http_status: null } }],
    ['unknown cause', { fetch: { status: 'failed', cause: 'gremlins', http_status: null } }],
    ['failed without a cause', { fetch: { status: 'failed', cause: null, http_status: null } }],
    ['ok with a cause', { fetch: { status: 'ok', cause: 'timeout', http_status: null } }],
    ['unknown auth kind', { auth: { kind: 'magic', result: 'sent' } }],
    ['unknown auth result', { auth: { kind: 'none', result: 'maybe' } }],
    ['unknown auth failure', { auth: { kind: 'none', result: 'failed', failure: 'oops' } }],
    ['missing fetch', { fetch: null }],
    ['missing auth', { auth: undefined }],
    ['supported not a boolean', { supported: 'yes' }],
    ['missing surface id', { surface_id: undefined }],
  ])('rejects %s', (_name, overrides) => {
    expect(parseAgentCardPreview(previewBody(overrides))).toBeNull();
  });

  it('rejects an unknown unsupported reason and non-objects', () => {
    expect(
      parseAgentCardPreview({ surface_id: 's', supported: false, unsupported_reason: 'x' })
    ).toBeNull();
    for (const v of [null, undefined, 4, 'x', []]) expect(parseAgentCardPreview(v)).toBeNull();
  });

  it('accepts every documented cause', () => {
    for (const cause of CARD_FETCH_CAUSES) {
      const status =
        cause === 'identity_failed' || cause === 'rewrite_failed' ? 'not_served' : 'failed';
      const body = previewBody({ fetch: { status, cause, http_status: null, duration_ms: 1 } });
      expect(supported(body).fetch.cause).toBe(cause);
    }
  });
});

describe('fetchAgentCardPreview and refreshAgentCardPreview', () => {
  const reply = (status: number, body: unknown) => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });

  it('reads the preview from the surface route', async () => {
    const fetcher = jest.fn().mockResolvedValue(reply(200, previewBody()));
    const p = await fetchAgentCardPreview(fetcher, 'a/b');
    expect(fetcher).toHaveBeenCalledWith('/api/v1/surfaces/a%2Fb/agent-card');
    expect(p?.supported).toBe(true);
  });

  it('returns null for an error status, a bad body and a network failure', async () => {
    expect(
      await fetchAgentCardPreview(jest.fn().mockResolvedValue(reply(500, {})), 's')
    ).toBeNull();
    expect(
      await fetchAgentCardPreview(jest.fn().mockResolvedValue(reply(200, { nope: 1 })), 's')
    ).toBeNull();
    expect(
      await fetchAgentCardPreview(jest.fn().mockRejectedValue(new Error('x')), 's')
    ).toBeNull();
  });

  it('posts to the refresh route and returns the preview', async () => {
    const fetcher = jest.fn().mockResolvedValue(reply(200, previewBody({ cached: false })));
    const result = await refreshAgentCardPreview(fetcher, 's-1');
    expect(fetcher).toHaveBeenCalledWith('/api/v1/surfaces/s-1/agent-card/refresh', {
      method: 'POST',
    });
    expect(result).toMatchObject({ kind: 'ok', preview: { supported: true, surface_id: 's-123' } });
  });

  it.each([
    [429, 'rate_limited'],
    [403, 'forbidden'],
    [404, 'error'],
    [500, 'error'],
  ])('maps status %i to %s', async (status, kind) => {
    const fetcher = jest.fn().mockResolvedValue(reply(status, {}));
    expect(await refreshAgentCardPreview(fetcher, 's')).toEqual({ kind });
  });

  it('reports an error for a malformed 200 and a network failure', async () => {
    expect(
      await refreshAgentCardPreview(jest.fn().mockResolvedValue(reply(200, { x: 1 })), 's')
    ).toEqual({ kind: 'error' });
    expect(await refreshAgentCardPreview(jest.fn().mockRejectedValue(new Error('x')), 's')).toEqual(
      {
        kind: 'error',
      }
    );
  });
});

describe('cardNamesGatewayScheme', () => {
  it('is true for a card that carries the gateway scheme', () => {
    expect(cardNamesGatewayScheme(AFTER_CARD)).toBe(true);
    expect(cardNamesGatewayScheme({ securitySchemes: { agent_gateway: {} } })).toBe(true);
  });

  it.each([
    ['no card', null],
    ['no securitySchemes', { name: 'a' }],
    ['only an upstream scheme', BEFORE_CARD],
    ['a non-object securitySchemes', { securitySchemes: ['agent_gateway'] }],
    ['a string securitySchemes', { securitySchemes: 'agent_gateway' }],
  ])('is false for %s', (_name, card) => {
    expect(cardNamesGatewayScheme(card as Record<string, unknown> | null)).toBe(false);
  });
});

describe('safeHttpUrl', () => {
  it('accepts http and https', () => {
    expect(safeHttpUrl('https://gw.example/a/b?x=1')).toBe('https://gw.example/a/b?x=1');
    expect(safeHttpUrl('http://localhost:8080/x')).toBe('http://localhost:8080/x');
  });

  it.each([
    ['javascript', 'alert(1)'].join(':'),
    ['JaVaScRiPt', 'alert(1)'].join(':'),
    'data:text/html,<script>alert(1)</script>',
    'vbscript:x',
    'file:///etc/passwd',
    '/relative/path',
    '//gw.example/x',
    'gw.example/x',
    'https://user:pw@gw.example/x',
    '',
    '   ',
    null,
    undefined,
    42,
    {},
  ])('refuses %p', value => {
    expect(safeHttpUrl(value)).toBeNull();
  });
});

describe('describeFetchCause', () => {
  it('has text for every cause and every auth failure', () => {
    for (const cause of CARD_FETCH_CAUSES) expect(CARD_FETCH_CAUSE_TEXT[cause]).toBeTruthy();
    for (const failure of CARD_AUTH_FAILURES) expect(AUTH_FAILURE_TEXT[failure]).toBeTruthy();
  });

  it('fills in the HTTP status', () => {
    expect(describeFetchCause(failed('not_found', 404), auth())).toBe(
      'The agent has no card at this URL (HTTP 404). Check the agent card location.'
    );
    expect(describeFetchCause(failed('upstream_error', 503), auth())).toBe(
      'The agent answered HTTP 503. Check the agent logs, then Refresh.'
    );
    expect(describeFetchCause(failed('upstream_error'), auth())).toBe(
      'The agent answered with an error status. Check the agent logs, then Refresh.'
    );
    expect(describeFetchCause(failed('not_found'), auth())).toBe(
      'The agent has no card at this URL. Check the agent card location.'
    );
  });

  it('tells a missing credential from a rejected one', () => {
    expect(describeFetchCause(failed('needs_token', 401), auth({ result: 'not_sent' }))).toBe(
      'The agent asked for a token (HTTP 401) and the gateway sent none. Set Target Authentication on the Managed Agent.'
    );
    expect(describeFetchCause(failed('auth_failed', 401), auth({ result: 'sent' }))).toBe(
      CARD_REJECTED_CREDENTIAL_TEXT
    );
    expect(
      describeFetchCause(
        failed('auth_failed'),
        auth({ result: 'failed', failure: 'secret_unavailable' })
      )
    ).toBe(
      'The gateway could not get its credential, so it did not ask the agent. A secret the credential needs is missing. Check Target Authentication on the Managed Agent.'
    );
    expect(describeFetchCause(failed('auth_failed'), auth({ result: 'failed' }))).toBe(
      'The gateway could not get its credential, so it did not ask the agent. Check Target Authentication on the Managed Agent.'
    );
  });

  it("names a remote gateway's refusal of this gateway's authorization", () => {
    const remote = auth({ kind: 'remote_gateway', result: 'not_configured' });
    expect(describeFetchCause(failed('auth_failed', 401), remote)).toBe(
      "The remote gateway refused this gateway's authorization (HTTP 401). Check the sign-in settings of the remote surface."
    );
    expect(describeFetchCause(failed('auth_failed', 403), remote)).toBe(
      CARD_PEER_REFUSED_TEXT.replace('{s}', '403')
    );
    expect(describeFetchCause(failed('auth_failed', 401), auth({ result: 'sent' }))).toBe(
      CARD_REJECTED_CREDENTIAL_TEXT
    );
  });

  it.each([
    ['timeout', 'Check that the agent is running, then Refresh.'],
    ['too_large', 'Shrink the agent card.'],
    ['invalid_card', 'Check the agent card location.'],
    [
      'blocked_by_egress',
      'Check the endpoint host name and DNS from the gateway host, then Refresh.',
    ],
    ['redirected', 'Set the agent card location to the final URL.'],
    ['identity_failed', 'Check the gateway logs, then Refresh.'],
    ['rewrite_failed', 'Check the gateway logs, then Refresh.'],
  ] as const)('tells the operator what to do about %s', (cause, action) => {
    const text = describeFetchCause(failed(cause), auth());
    expect(text.endsWith(action)).toBe(true);
    expect(text.length).toBeGreaterThan(action.length + 1);
  });

  it('names DNS and cloud metadata, not an egress allow setting, for a blocked card address', () => {
    expect(CARD_FETCH_CAUSE_LABEL.blocked_by_egress).toBe('Address not resolvable or not allowed');
    const text = describeFetchCause(failed('blocked_by_egress'), auth());
    expect(text).toContain("could not resolve the agent's host name");
    expect(text).toContain('cloud metadata address');
    expect(text).not.toContain('Allow the address');
  });

  it('returns nothing for a fetch that worked', () => {
    expect(
      describeFetchCause({ status: 'ok', cause: null, http_status: null, duration_ms: 1 }, auth())
    ).toBe('');
  });
});

describe('describeCardAuth', () => {
  it('names the provider and the expiry', () => {
    const expires = new Date('2026-10-23T10:55:00Z').toLocaleString();
    expect(describeCardAuth(auth({ token_expires_at: '2026-10-23T10:55:00Z' }))).toBe(
      `Foundry, token valid until ${expires}`
    );
    expect(describeCardAuth(auth())).toBe('Foundry');
    expect(describeCardAuth(auth({ provider_name: null }))).toBe('Credential provider');
  });

  it('describes the other methods', () => {
    expect(describeCardAuth(auth({ kind: 'static_secret' }))).toBe('Static secret');
    expect(describeCardAuth(auth({ kind: 'none', result: 'not_configured' }))).toBe(
      'No Target Authentication'
    );
    expect(describeCardAuth(auth({ kind: 'remote_gateway', result: 'not_configured' }))).toBe(
      'The remote gateway signs in'
    );
    expect(describeCardAuth(auth({ result: 'not_sent' }))).toBe('No credential sent');
    expect(describeCardAuth(auth({ result: 'failed' }))).toBe('Credential not obtained');
  });
});

describe('formatRelativeTime', () => {
  const now = Date.parse('2026-10-23T10:00:00Z');
  it('rounds to a readable unit', () => {
    expect(formatRelativeTime('2026-10-23T09:59:58Z', now)).toBe('just now');
    expect(formatRelativeTime('2026-10-23T09:59:30Z', now)).toBe('30 seconds ago');
    expect(formatRelativeTime('2026-10-23T09:59:00Z', now)).toBe('1 minute ago');
    expect(formatRelativeTime('2026-10-23T09:55:00Z', now)).toBe('5 minutes ago');
    expect(formatRelativeTime('2026-10-23T08:00:00Z', now)).toBe('2 hours ago');
    expect(formatRelativeTime('2026-10-21T10:00:00Z', now)).toBe('2 days ago');
  });

  it('returns null for a missing or invalid time', () => {
    expect(formatRelativeTime(null, now)).toBeNull();
    expect(formatRelativeTime('yesterday', now)).toBeNull();
  });
});

describe('failed fixture', () => {
  it('parses a failed fetch with no cards', () => {
    const p = supported(failedBody('needs_token', 401));
    expect(p.fetch).toMatchObject({ status: 'failed', cause: 'needs_token', http_status: 401 });
    expect(p.before).toBeNull();
  });
});

describe('describeFetchFailure', () => {
  it('names the cause with the HTTP status', () => {
    expect(describeFetchFailure(failed('auth_failed', 401))).toBe('Sign-in failed — HTTP 401');
    expect(describeFetchFailure(failed('needs_token', 401))).toBe('Needs a token — HTTP 401');
    expect(describeFetchFailure(failed('upstream_error', 503))).toBe('Agent error — HTTP 503');
  });

  it('names the cause alone when there is no HTTP status', () => {
    expect(describeFetchFailure(failed('timeout'))).toBe('Timed out');
  });

  it('has a label for every cause', () => {
    for (const cause of CARD_FETCH_CAUSES) {
      expect(describeFetchFailure(failed(cause))).toBeTruthy();
    }
  });

  it('returns nothing for a fetch that worked', () => {
    expect(describeFetchFailure({ cause: null, http_status: null })).toBeNull();
    expect(describeFetchFailure({ cause: null, http_status: 200 })).toBeNull();
  });
});
