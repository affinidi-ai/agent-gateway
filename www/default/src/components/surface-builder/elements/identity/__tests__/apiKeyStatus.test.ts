import {
  apiKeyReferenceCanvasReason,
  apiKeyReferenceWarning,
  apiKeyStatusMap,
  unlistedApiKeyLabel,
} from '../apiKeyStatus';

const protectedNode = (config: Record<string, unknown>) => ({
  id: 'identity-protected',
  slotId: 'response:identity-protected',
  type: 'identity',
  config,
});

const statuses = apiKeyStatusMap([
  { key_id: 'atgk_active', status: 'active' },
  { key_id: 'atgk_revoked', status: 'revoked' },
  { key_id: 'atgk_missing', status: 'missing' },
  { key_id: 'atgk_other', status: 'unavailable' },
  { key_id: 'atgk_unknown', status: 'unknown' },
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
    ['atgk_other', 'The API key this Identity uses belongs to another surface.'],
  ])('warns for %s', (keyId, warning) => {
    expect(
      apiKeyReferenceWarning(protectedNode({ type: 'from_api_key', api_key_id: keyId }), statuses)
    ).toBe(warning);
  });

  it.each(['atgk_active', 'atgk_unknown', 'atgk_unlisted'])('does not warn for %s', keyId => {
    expect(
      apiKeyReferenceWarning(protectedNode({ type: 'from_api_key', api_key_id: keyId }), statuses)
    ).toBeNull();
  });

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
