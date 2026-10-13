/** Mirrors `A2A_PROXY_ENDPOINT_PREFIX` in `src/config/agent_surface.rs`. */
export const A2A_PROXY_ENDPOINT_PREFIX = 'a2a-proxy://';

export const isA2aProxyEndpoint = (endpoint: unknown): endpoint is string =>
  typeof endpoint === 'string' && endpoint.startsWith(A2A_PROXY_ENDPOINT_PREFIX);

export const a2aProxyEndpoint = (proxyId: string): string =>
  `${A2A_PROXY_ENDPOINT_PREFIX}${proxyId}`;

export const a2aProxyIdFromEndpoint = (endpoint: unknown): string | undefined =>
  isA2aProxyEndpoint(endpoint) ? endpoint.slice(A2A_PROXY_ENDPOINT_PREFIX.length) : undefined;
