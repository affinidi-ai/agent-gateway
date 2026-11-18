import { apiClient } from '../../api';

/** An answer of the gateway, as `apiClient.fetch` resolves with it. */
export const answer = (body: unknown = {}, status = 200, statusText = 'OK') => ({
  ok: status < 400,
  status,
  statusText,
  json: () => Promise.resolve(body),
  text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
});

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

export const ALICE = 'a'.repeat(64);
export const BOB = 'b'.repeat(64);

/** A delegation of ALICE to GitHub as the vault lists it, changed by `extra`. */
export const delegation = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  agent_did: 'did:web:agent.example.com',
  user_identity_hash: ALICE,
  credential_provider_id: 'cp-github',
  provider_id: 'github',
  token_type: 'bearer',
  scopes: ['repo'],
  expires_at: fromNow(HOUR),
  consent_granted_at: fromNow(-HOUR),
  last_used_at: null,
  created_at: fromNow(-HOUR),
  updated_at: fromNow(-HOUR),
  is_expired: false,
  can_refresh: true,
  ...extra,
});

export const GITHUB = {
  id: 'cp-github',
  name: 'GitHub',
  provider_type: 'oauth2_authorization_code',
  token_refresh_enabled: true,
};

/** A provider a person consents to and one nobody does. */
export const PROVIDERS = [
  GITHUB,
  { id: 'cp-service', name: 'Billing API', provider_type: 'oauth2_client_credentials' },
];

const fetchMock = () => apiClient.fetch as jest.Mock;

/** Answers the two lists the tabs read, and every other request with `change`. */
export const gatewayHolds = (
  tokens: unknown[],
  providers: unknown = PROVIDERS,
  change: () => unknown = () => answer()
) =>
  fetchMock().mockImplementation((url: string, options?: { method?: string }) =>
    Promise.resolve(
      options?.method
        ? change()
        : answer(url === '/api/v1/credential-providers' ? providers : tokens)
    )
  );

/** The requests sent with `method` (`undefined` for a read), to `url` when one is given. */
export const requests = (method: string | undefined, url?: string) =>
  fetchMock().mock.calls.filter(
    ([asked, options]) => options?.method === method && (url === undefined || asked === url)
  );

export const vaultReads = () => requests(undefined, '/api/v1/delegation-vault');
