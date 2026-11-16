import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { DelegationToken, ProviderSummary } from './delegatedAccess';

async function listOf<T>(url: string): Promise<T[]> {
  try {
    const response = await apiClient.fetch(url);
    const data = response.ok ? await response.json() : [];
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

/**
 * The vault's agent-keyed tokens and the credential providers by id, loaded once. Either list is
 * empty when it cannot be read, so the tokens still show without their providers.
 */
export function useDelegationVault() {
  const [tokens, setTokens] = useState<DelegationToken[]>([]);
  const [providers, setProviders] = useState<Record<string, ProviderSummary>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    Promise.all([
      listOf<DelegationToken>('/api/v1/delegation-vault'),
      listOf<ProviderSummary>('/api/v1/credential-providers'),
    ]).then(([vault, known]) => {
      if (!alive) return;
      setTokens(vault);
      setProviders(Object.fromEntries(known.map(provider => [provider.id, provider])));
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  return { tokens, setTokens, providers, loading };
}
