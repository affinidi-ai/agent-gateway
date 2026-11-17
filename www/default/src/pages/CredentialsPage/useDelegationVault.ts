import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { extractErrorMessage, formatApiError } from '../../utils/apiError';
import { DelegationToken, ProviderSummary } from './delegatedAccess';

/**
 * The vault's agent-keyed tokens, the credential providers by id, and the changes the
 * Credentials page makes to the tokens. The page loads it once and hands it to both delegation
 * tabs, so a change made on one is the list the other shows.
 */
export interface DelegationVault {
  tokens: DelegationToken[];
  /** Empty while the providers cannot be read, so the tokens still show without them. */
  providers: Record<string, ProviderSummary>;
  loading: boolean;
  /** Why the vault could not be read. The tokens are then unknown, not none. */
  vaultError: string | null;
  reload: () => void;
  /** Revokes one delegation and drops it from the list. Rejects with why the gateway refused. */
  revoke: (id: string) => Promise<void>;
  /** Revokes every delegation of a user and drops them from the list. */
  revokeUser: (userHash: string) => Promise<void>;
  /**
   * Limits one consent to `limitSecs` after it was given, and resolves with its new end once the
   * list shows it. Rejects with why the gateway refused.
   */
  limitConsent: (id: string, limitSecs: number) => Promise<string>;
}

const UNREACHABLE = 'The gateway could not be reached.';

/** `apiClient.fetch`, rejecting in words for a user when the request never got an answer. */
async function send(url: string, init?: RequestInit): Promise<Response> {
  try {
    return await apiClient.fetch(url, init);
  } catch {
    throw new Error(UNREACHABLE);
  }
}

/** Why the gateway refused a request: in its own words where it gave any, else by its status. */
async function refusalOf(response: Response): Promise<string> {
  let body = '';
  try {
    body = await response.text();
  } catch {
    body = '';
  }
  return extractErrorMessage(body) ?? formatApiError(response.status, null, response.statusText);
}

async function readVault(): Promise<DelegationToken[] | { refused: string }> {
  try {
    const response = await apiClient.fetch('/api/v1/delegation-vault');
    if (!response.ok) return { refused: await refusalOf(response) };
    const listed: unknown = await response.json();
    return Array.isArray(listed) ? listed : { refused: 'The gateway sent no list of delegations.' };
  } catch {
    return { refused: UNREACHABLE };
  }
}

async function readProviders(): Promise<Record<string, ProviderSummary>> {
  try {
    const response = await apiClient.fetch('/api/v1/credential-providers');
    const listed: unknown = response.ok ? await response.json() : [];
    return Array.isArray(listed)
      ? Object.fromEntries(listed.map((provider: ProviderSummary) => [provider.id, provider]))
      : {};
  } catch {
    return {};
  }
}

export function useDelegationVault(): DelegationVault {
  const [tokens, setTokens] = useState<DelegationToken[]>([]);
  const [providers, setProviders] = useState<Record<string, ProviderSummary>>({});
  const [loading, setLoading] = useState(true);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [reads, setReads] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    Promise.all([readVault(), readProviders()]).then(([vault, known]) => {
      if (!alive) return;
      const refused = Array.isArray(vault) ? null : vault.refused;
      setVaultError(refused);
      setTokens(Array.isArray(vault) ? vault : []);
      setProviders(known);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, [reads]);

  const reload = useCallback(() => setReads(count => count + 1), []);

  const remove = useCallback(async (url: string, kept: (token: DelegationToken) => boolean) => {
    const response = await send(url, { method: 'DELETE' });
    if (!response.ok) throw new Error(await refusalOf(response));
    setTokens(held => held.filter(kept));
  }, []);

  const revoke = useCallback(
    (id: string) =>
      remove(`/api/v1/delegation-vault/${encodeURIComponent(id)}`, token => token.id !== id),
    [remove]
  );

  const revokeUser = useCallback(
    (userHash: string) =>
      remove(
        `/api/v1/delegation-vault/by-user/${encodeURIComponent(userHash)}`,
        token => token.user_identity_hash !== userHash
      ),
    [remove]
  );

  const limitConsent = useCallback(async (id: string, limitSecs: number) => {
    const response = await send(
      `/api/v1/delegation-vault/${encodeURIComponent(id)}/consent-limit`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_consent_age_secs: limitSecs }),
      }
    );
    if (!response.ok) throw new Error(await refusalOf(response));
    const limited: { consent_expires_at?: unknown } | null = await response
      .json()
      .catch(() => null);
    const end = limited?.consent_expires_at;
    if (typeof end !== 'string') {
      throw new Error('The gateway saved the limit but did not say when the consent now ends.');
    }
    setTokens(held =>
      held.map(token => (token.id === id ? { ...token, consent_expires_at: end } : token))
    );
    return end;
  }, []);

  return { tokens, providers, loading, vaultError, reload, revoke, revokeUser, limitConsent };
}
