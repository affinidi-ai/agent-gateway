import { applyPlaceholders, findPlaceholders, PLACEHOLDER_TOKENS } from '../placeholders';

describe('placeholders: applyPlaceholders', () => {
  it('substitutes known tokens with context values', () => {
    const { value, missing } = applyPlaceholders(
      {
        listen_address: '$HOST',
        route: '$ROUTE',
        target_endpoint: '$TARGET_ENDPOINT',
      },
      {
        host: '127.0.0.1:8443',
        route: '/agent',
        targetEndpoint: 'fabric://gw2/c1',
      }
    );
    expect(value).toEqual({
      listen_address: '127.0.0.1:8443',
      route: '/agent',
      target_endpoint: 'fabric://gw2/c1',
    });
    expect(missing).toEqual([]);
  });

  it('supports substring substitution (token embedded in larger string)', () => {
    const { value, missing } = applyPlaceholders(
      { url: 'https://$HOST/admin' },
      { host: 'example.com' }
    );
    expect(value).toEqual({ url: 'https://example.com/admin' });
    expect(missing).toEqual([]);
  });

  it('leaves unknown tokens untouched and reports them as missing', () => {
    const { value, missing } = applyPlaceholders(
      { a: '$HOST', b: '$ROUTE', c: '$NAME' },
      { host: 'h' }
    );
    expect(value).toEqual({ a: 'h', b: '$ROUTE', c: '$NAME' });
    expect(missing).toEqual(['$NAME', '$ROUTE']);
  });

  it('treats empty-string and null context values as missing', () => {
    const { value, missing } = applyPlaceholders(
      { a: '$HOST', b: '$NAME' },
      { host: '', name: undefined }
    );
    expect(value).toEqual({ a: '$HOST', b: '$NAME' });
    expect(missing.sort()).toEqual(['$HOST', '$NAME']);
  });

  it('walks nested arrays and objects (e.g. virtual_channels variants)', () => {
    const { value, missing } = applyPlaceholders(
      {
        listen_address: '$HOST',
        virtual_channels: [
          { alias: '$SLUG-v1', target_endpoint: '$TARGET_ENDPOINT' },
          { alias: 'static' },
        ],
      },
      {
        host: '0.0.0.0:9000',
        slug: 'demo',
        targetEndpoint: 'fabric://gw/x',
      }
    );
    expect(value).toEqual({
      listen_address: '0.0.0.0:9000',
      virtual_channels: [
        { alias: 'demo-v1', target_endpoint: 'fabric://gw/x' },
        { alias: 'static' },
      ],
    });
    expect(missing).toEqual([]);
  });

  it('does not mutate the input payload', () => {
    const input = { listen_address: '$HOST' };
    applyPlaceholders(input, { host: 'h' });
    expect(input).toEqual({ listen_address: '$HOST' });
  });

  it('ignores unknown $-prefixed words (e.g. $HOSTNAME) so they are not partially matched', () => {
    const { value, missing } = applyPlaceholders({ a: '$HOSTNAME', b: '$HOST' }, { host: 'h' });
    // $HOSTNAME is one token (regex matches greedily up to whitespace),
    // not "$HOST" + "NAME", so it stays untouched and is not reported
    // as missing (it isn't a known placeholder at all).
    expect(value).toEqual({ a: '$HOSTNAME', b: 'h' });
    expect(missing).toEqual([]);
  });

  it('handles primitive and null payloads without crashing', () => {
    expect(applyPlaceholders('$HOST', { host: 'h' }).value).toBe('h');
    expect(applyPlaceholders(42, {}).value).toBe(42);
    expect(applyPlaceholders(null, {}).value).toBeNull();
  });
});

describe('placeholders: findPlaceholders', () => {
  it('returns the sorted set of tokens present in the payload', () => {
    const tokens = findPlaceholders({
      a: '$HOST',
      nested: { b: '$ROUTE', list: ['$NAME', '$HOST'] },
    });
    expect(tokens).toEqual(['$HOST', '$NAME', '$ROUTE']);
  });

  it('returns an empty array when no tokens are present', () => {
    expect(findPlaceholders({ a: 'static', b: 1, c: null })).toEqual([]);
  });

  it('ignores unknown $-prefixed words', () => {
    expect(findPlaceholders({ a: '$UNKNOWN', b: '$HOST' })).toEqual(['$HOST']);
  });
});

describe('placeholders: vocabulary', () => {
  it('exposes the agreed-upon placeholder set', () => {
    expect([...PLACEHOLDER_TOKENS].sort()).toEqual([
      '$HOST',
      '$NAME',
      '$ROUTE',
      '$SLUG',
      '$TARGET_ENDPOINT',
    ]);
  });
});
