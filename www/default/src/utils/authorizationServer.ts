export interface AuthorizationServer {
  issuer: string;
  metadata_url: string;
  token_endpoint: string;
  jwks_uri: string;
}

export type DiscoverMode = 'keep' | 'discover' | 'clear';

export function discoverMetadataValue(mode: DiscoverMode): boolean | undefined {
  if (mode === 'discover') return true;
  if (mode === 'clear') return false;
  return undefined;
}

export function parseAuthorizationServer(value: unknown): AuthorizationServer | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  const pick = (key: string) => (typeof v[key] === 'string' ? (v[key] as string) : '');
  const server = {
    issuer: pick('issuer'),
    metadata_url: pick('metadata_url'),
    token_endpoint: pick('token_endpoint'),
    jwks_uri: pick('jwks_uri'),
  };
  return server.issuer && server.metadata_url ? server : null;
}

export function parseScopeClaims(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\s,]+/)) {
    if (part) seen.add(part);
  }
  return Array.from(seen);
}

export const DEFAULT_SCOPE_CLAIMS = ['scope', 'scp'];

export const DISCOVERY_FAILED_MESSAGE =
  'Discovery failed. Check the issuer URL and that the authorization server publishes its metadata over https.';

export type DiscoverResult =
  | { ok: true; server: AuthorizationServer }
  | { ok: false; message: string };

export async function discoverAuthorizationServer(
  fetcher: (url: string, init?: RequestInit) => Promise<Response>,
  issuer: string
): Promise<DiscoverResult> {
  try {
    const response = await fetcher('/api/v1/jwt-verification-strategies/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer }),
    });
    if (!response.ok) return { ok: false, message: DISCOVERY_FAILED_MESSAGE };
    const server = parseAuthorizationServer(await response.json());
    return server ? { ok: true, server } : { ok: false, message: DISCOVERY_FAILED_MESSAGE };
  } catch {
    return { ok: false, message: DISCOVERY_FAILED_MESSAGE };
  }
}
