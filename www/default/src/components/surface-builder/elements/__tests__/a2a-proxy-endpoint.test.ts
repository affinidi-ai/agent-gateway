import {
  a2aProxyEndpoint,
  a2aProxyIdFromEndpoint,
  isA2aProxyEndpoint,
} from '../_shared/a2aProxyEndpoint';

describe('A2A proxy endpoint helpers', () => {
  it('builds an a2a-proxy endpoint and reads the id back', () => {
    const endpoint = a2aProxyEndpoint('travel-agent');
    expect(endpoint).toBe('a2a-proxy://travel-agent');
    expect(isA2aProxyEndpoint(endpoint)).toBe(true);
    expect(a2aProxyIdFromEndpoint(endpoint)).toBe('travel-agent');
  });

  it.each([
    'https://agent.example.com',
    'fabric://did:example:123',
    'proxy://a2a-proxy://x',
    'A2A-PROXY://x',
    '',
    undefined,
    null,
    42,
  ])('does not treat %p as an A2A proxy endpoint', endpoint => {
    expect(isA2aProxyEndpoint(endpoint)).toBe(false);
    expect(a2aProxyIdFromEndpoint(endpoint)).toBeUndefined();
  });
});
