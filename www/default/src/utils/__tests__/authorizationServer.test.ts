import {
  DISCOVERY_FAILED_MESSAGE,
  discoverAuthorizationServer,
  discoverMetadataValue,
  parseAuthorizationServer,
} from '../authorizationServer';

const SERVER = {
  issuer: 'https://idp.example.com',
  metadata_url: 'https://idp.example.com/.well-known/oauth-authorization-server',
  token_endpoint: 'https://idp.example.com/token',
  jwks_uri: 'https://idp.example.com/jwks.json',
};

const reply = (ok: boolean, body: unknown) =>
  jest.fn().mockResolvedValue({ ok, json: async () => body });

describe('discoverMetadataValue', () => {
  it('maps the modes to true, false and omitted', () => {
    expect(discoverMetadataValue('discover')).toBe(true);
    expect(discoverMetadataValue('clear')).toBe(false);
    expect(discoverMetadataValue('keep')).toBeUndefined();
  });
});

describe('parseAuthorizationServer', () => {
  it('reads the four fields', () => {
    expect(parseAuthorizationServer(SERVER)).toEqual(SERVER);
  });
  it('rejects values without an issuer and metadata url', () => {
    expect(parseAuthorizationServer(null)).toBeNull();
    expect(parseAuthorizationServer({ issuer: 'x' })).toBeNull();
    expect(parseAuthorizationServer('x')).toBeNull();
  });
});

describe('discoverAuthorizationServer', () => {
  it('posts the issuer and returns the pinned server', async () => {
    const fetcher = reply(true, SERVER);
    const result = await discoverAuthorizationServer(fetcher, 'https://idp.example.com');
    expect(result).toEqual({ ok: true, server: SERVER });
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/jwt-verification-strategies/discover',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ issuer: 'https://idp.example.com' }),
      })
    );
  });
  it('rejects a server object nested under another key', async () => {
    const result = await discoverAuthorizationServer(
      reply(true, { authorization_server: SERVER }),
      'https://idp.example.com'
    );
    expect(result).toEqual({ ok: false, message: DISCOVERY_FAILED_MESSAGE });
  });
  it('returns a generic message when the gateway refuses', async () => {
    const result = await discoverAuthorizationServer(
      reply(false, { error: 'resolved 10.0.0.1' }),
      'https://idp.example.com'
    );
    expect(result).toEqual({ ok: false, message: DISCOVERY_FAILED_MESSAGE });
  });
  it('returns a generic message when the request throws or the body is unusable', async () => {
    const thrown = jest.fn().mockRejectedValue(new Error('boom'));
    expect(await discoverAuthorizationServer(thrown, 'x')).toEqual({
      ok: false,
      message: DISCOVERY_FAILED_MESSAGE,
    });
    expect(await discoverAuthorizationServer(reply(true, {}), 'x')).toEqual({
      ok: false,
      message: DISCOVERY_FAILED_MESSAGE,
    });
  });
});
