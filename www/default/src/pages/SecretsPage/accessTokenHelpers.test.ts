import {
  accessTokenExpiryBounds,
  canonicalResourceTarget,
  evaluateScopePreview,
  inferTenantSelection,
  toLocalDateTimeInput,
  validateAccessTokenExpiry,
  validateScopeConfig,
} from './accessTokenHelpers';

/* eslint-disable no-template-curly-in-string */

const header = { name: 'x-external-account', pattern: '\\d{12}' };

describe('access-token tenant scope helpers', () => {
  it('distinguishes appliance-wide, one-header, and ambiguous patterns', () => {
    expect(inferTenantSelection('')).toEqual({ mode: 'appliance' });
    expect(inferTenantSelection('gateways:.*')).toEqual({ mode: 'invalid', headerNames: [] });
    expect(inferTenantSelection('TENANT:${Account}:gateways:.*')).toEqual({
      mode: 'tenant',
      headerName: 'account',
    });
    expect(inferTenantSelection('TENANT:${account}:${region}:.*')).toEqual({
      mode: 'invalid',
      headerNames: ['account', 'region'],
    });
    expect(inferTenantSelection('TENANT:${Account}:${account}:secrets:.*')).toEqual({
      mode: 'invalid',
      headerNames: ['account'],
    });
  });

  it('rejects undeclared and multiple tenant selectors', () => {
    expect(validateScopeConfig('TENANT:${missing}:.*', [])).toContain(
      'Resource pattern references undeclared header(s): missing.'
    );
    expect(
      validateScopeConfig('TENANT:${x-external-account}:${region}:.*', [
        header,
        { name: 'region', pattern: '[a-z]+' },
      ])
    ).toContain('Resource pattern may select a tenant from only one distinct header.');
  });

  it('accepts bounded resource selectors and rejects unconstrained patterns', () => {
    expect(
      validateScopeConfig('TENANT:${x-external-account}:(?:secrets:demo-.*|sts-clients:.*)', [
        header,
      ])
    ).toEqual([]);

    for (const pattern of [
      '.*',
      'TENANT:.*',
      'TENANT:${x-external-account}:.*',
      'prod-.*',
      'TENANT:${x-external-account}:unknown-kind:.*',
      'TENANT:${x-external-account}:(?:secrets:.*|.*)',
      'TENANT:${x-external-account}:secrets:.*|sts-clients:.*',
    ]) {
      expect(validateScopeConfig(pattern, [header]).length).toBeGreaterThan(0);
    }
  });

  it('builds and matches the canonical UUID resource target', () => {
    const preview = evaluateScopePreview(
      'TENANT:${x-external-account}:gateways:.*',
      [header],
      { 'x-external-account': '123456789012' },
      'gateways',
      '550e8400-e29b-41d4-a716-446655440000'
    );

    expect(preview.allowed).toBe(true);
    expect(preview.target).toBe(
      canonicalResourceTarget('123456789012', 'gateways', '550e8400-e29b-41d4-a716-446655440000')
    );
  });

  it('matches validation patterns against the entire header value', () => {
    const pattern = 'TENANT:${account}:gateways:.*';
    const sampleHeaders = { account: '1234' };

    expect(
      evaluateScopePreview(
        pattern,
        [{ name: 'account', pattern: '\\d' }],
        sampleHeaders,
        'gateways',
        'gateway-1'
      ).allowed
    ).toBe(false);
    expect(
      evaluateScopePreview(
        pattern,
        [{ name: 'account', pattern: '\\d{4}' }],
        sampleHeaders,
        'gateways',
        'gateway-1'
      ).allowed
    ).toBe(true);
  });

  it('denies another resource family and escapes regex metacharacters', () => {
    const denied = evaluateScopePreview(
      'TENANT:${account}:gateways:.*',
      [{ name: 'account', pattern: '.+' }],
      { account: '.*' },
      'surfaces',
      'surface-1'
    );

    expect(denied.target).toBe('TENANT:.*:surfaces:surface-1');
    expect(denied.effectivePattern).toBe('TENANT:\\.\\*:gateways:.*');
    expect(denied.allowed).toBe(false);
  });

  it('rejects a static pattern and leaves blank scope appliance-wide', () => {
    const preview = evaluateScopePreview('prod-.*', [], {}, 'secrets', 'prod-api-key');
    expect(preview.target).toBe('prod-api-key');
    expect(preview.allowed).toBe(false);

    const applianceWide = evaluateScopePreview('', [], {}, 'secrets', 'prod-api-key');
    expect(applianceWide.target).toBe('prod-api-key');
    expect(applianceWide.allowed).toBe(true);
  });
});

describe('access-token expiration helpers', () => {
  const now = new Date('2026-09-09T12:00:00.000Z');

  it('serializes a future local date-time as an exact UTC timestamp', () => {
    const future = new Date(now.getTime() + 6 * 60 * 60 * 1000);
    const localValue = toLocalDateTimeInput(future);

    expect(validateAccessTokenExpiry(false, localValue, now)).toEqual({
      expiresAt: future.toISOString(),
    });
  });

  it('allows never and rejects missing, past, and over-limit dates', () => {
    expect(validateAccessTokenExpiry(true, '', now)).toEqual({});
    expect(validateAccessTokenExpiry(false, '', now).error).toBe(
      'Choose an expiration date and time.'
    );
    expect(
      validateAccessTokenExpiry(false, toLocalDateTimeInput(new Date(now.getTime() - 60_000)), now)
        .error
    ).toBe('Expiration must be in the future.');
    expect(
      validateAccessTokenExpiry(
        false,
        toLocalDateTimeInput(new Date(now.getTime() + 3651 * 24 * 60 * 60 * 1000)),
        now
      ).error
    ).toBe('Expiration must be within 3650 days.');
  });

  it('builds local input bounds from the same reference time', () => {
    const bounds = accessTokenExpiryBounds(now);

    expect(bounds.min).toBe(toLocalDateTimeInput(now));
    expect(new Date(bounds.max).getTime()).toBe(now.getTime() + 3650 * 24 * 60 * 60 * 1000);
  });
});
