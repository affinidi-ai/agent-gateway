import {
  apiKeyReferenceCanvasReason,
  apiKeyReferenceWarning,
  apiKeyStatusMap,
  firstUnusableApiKeyIdentity,
  storedApiKeyProblem,
  unlistedApiKeyLabel,
} from '../apiKeyStatus';

const protectedNode = (config: Record<string, unknown>) => ({
  id: 'identity-protected',
  slotId: 'response:identity-protected',
  type: 'identity',
  config,
});

const statuses = apiKeyStatusMap([
  { key_id: 'atgk_active', status: 'active', blocking: false },
  { key_id: 'atgk_revoked', status: 'revoked', blocking: true },
  { key_id: 'atgk_missing', status: 'missing', blocking: true },
  { key_id: 'atgk_other', status: 'unavailable', blocking: true },
  { key_id: 'atgk_other_warn', status: 'unavailable', blocking: false },
  { key_id: 'atgk_unknown', status: 'unknown', blocking: false },
]);

describe('apiKeyReferenceWarning', () => {
  it.each([
    [
      'atgk_revoked',
      'The API key this Identity uses was revoked. Select an active API key of this surface.',
    ],
    [
      'atgk_missing',
      'The API key this Identity uses was deleted. Select an active API key of this surface.',
    ],
    [
      'atgk_other',
      'The API key this Identity uses belongs to another surface. Select an active API key of this surface.',
    ],
  ])('warns for %s', (keyId, warning) => {
    expect(
      apiKeyReferenceWarning(protectedNode({ type: 'from_api_key', api_key_id: keyId }), statuses)
    ).toBe(warning);
  });

  it.each(['atgk_active', 'atgk_other_warn', 'atgk_unknown', 'atgk_unlisted'])(
    'does not warn for %s',
    keyId => {
      expect(
        apiKeyReferenceWarning(protectedNode({ type: 'from_api_key', api_key_id: keyId }), statuses)
      ).toBeNull();
    }
  );

  it('reads a Transit Point Identity too', () => {
    const node = {
      id: 'identity-tp',
      slotId: 'request:identity-managed_identity',
      type: 'identity',
      config: { type: 'from_api_key', api_key_id: 'atgk_revoked' },
    };
    expect(apiKeyReferenceWarning(node, statuses)).toMatch(/was revoked/);
  });

  it('does not warn for the inbound Identity, another type or another element', () => {
    const revoked = { type: 'from_api_key', api_key_id: 'atgk_revoked' };
    expect(
      apiKeyReferenceWarning(
        {
          id: 'identity-inbound',
          slotId: 'request:identity-inbound',
          type: 'identity',
          config: revoked,
        },
        statuses
      )
    ).toBeNull();
    expect(
      apiKeyReferenceWarning(
        protectedNode({ type: 'from_payload', api_key_id: 'atgk_revoked' }),
        statuses
      )
    ).toBeNull();
    expect(
      apiKeyReferenceWarning({ ...protectedNode(revoked), type: 'managed-agent' }, statuses)
    ).toBeNull();
    expect(apiKeyReferenceWarning(protectedNode({ type: 'from_api_key' }), statuses)).toBeNull();
    expect(apiKeyReferenceWarning(protectedNode(revoked), undefined)).toBeNull();
  });
});

describe('apiKeyReferenceCanvasReason', () => {
  it.each([
    ['atgk_revoked', 'API key revoked'],
    ['atgk_missing', 'API key deleted'],
    ['atgk_other', 'API key of another surface'],
    ['atgk_other_warn', null],
    ['atgk_active', null],
    ['atgk_unknown', null],
  ])('gives %s a short reason that tells the states apart', (keyId, reason) => {
    expect(
      apiKeyReferenceCanvasReason(
        protectedNode({ type: 'from_api_key', api_key_id: keyId }),
        statuses
      )
    ).toBe(reason);
  });
});

describe('firstUnusableApiKeyIdentity', () => {
  it('returns the first Identity whose key is revoked or deleted, with its warning', () => {
    const active = protectedNode({ type: 'from_api_key', api_key_id: 'atgk_active' });
    const missing = {
      ...protectedNode({ type: 'from_api_key', api_key_id: 'atgk_missing' }),
      id: 'identity-external',
      slotId: 'response:identity-external',
    };
    const revoked = protectedNode({ type: 'from_api_key', api_key_id: 'atgk_revoked' });
    expect(firstUnusableApiKeyIdentity([active, missing, revoked], statuses)).toEqual({
      node: missing,
      warning:
        'The API key this Identity uses was deleted. Select an active API key of this surface.',
    });
  });

  it('returns null when every key is usable or statuses are unknown', () => {
    const active = protectedNode({ type: 'from_api_key', api_key_id: 'atgk_active' });
    const revoked = protectedNode({ type: 'from_api_key', api_key_id: 'atgk_revoked' });
    const otherWarn = protectedNode({ type: 'from_api_key', api_key_id: 'atgk_other_warn' });
    expect(firstUnusableApiKeyIdentity([active, otherWarn], statuses)).toBeNull();
    expect(firstUnusableApiKeyIdentity([revoked], undefined)).toBeNull();
    expect(firstUnusableApiKeyIdentity([], statuses)).toBeNull();
  });
});

describe('storedApiKeyProblem', () => {
  it.each([
    ['atgk_revoked', { status: 'revoked', blocking: true }],
    ['atgk_missing', { status: 'missing', blocking: true }],
    ['atgk_other', { status: 'unavailable', blocking: true }],
    ['atgk_other_warn', { status: 'unavailable', blocking: false }],
    ['atgk_active', null],
    ['atgk_unknown', null],
    ['atgk_unlisted', null],
  ])('reports %s by its status and blocking', (keyId, problem) => {
    expect(storedApiKeyProblem(keyId, statuses)).toEqual(problem);
  });

  it('reports nothing without a key id or statuses', () => {
    expect(storedApiKeyProblem('', statuses)).toBeNull();
    expect(storedApiKeyProblem('atgk_revoked', undefined)).toBeNull();
  });
});

describe('apiKeyStatusMap', () => {
  it('is empty without references', () => {
    expect(apiKeyStatusMap(undefined).size).toBe(0);
  });
});

describe('unlistedApiKeyLabel', () => {
  it('names the known status or falls back to the generic label', () => {
    expect(unlistedApiKeyLabel('atgk_a', 'revoked')).toBe('atgk_a (revoked)');
    expect(unlistedApiKeyLabel('atgk_a', 'missing')).toBe('atgk_a (deleted)');
    expect(unlistedApiKeyLabel('atgk_a', null)).toBe('atgk_a (not an active key of this surface)');
  });
});
