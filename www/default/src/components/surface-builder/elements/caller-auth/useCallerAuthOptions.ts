import { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';

export interface JwtVerificationStrategyOption {
  id: string;
  name: string;
  expected_issuer?: string;
  tenant_id?: string | null;
}

export type JwtStrategiesStatus = 'idle' | 'loading' | 'loaded' | 'failed';

/**
 * The JWT verification strategies, loaded while `enabled`, and whether the list loaded or could
 * not be read; a refused request is `failed`, never an empty list.
 */
export function useJwtStrategyList(enabled = true): {
  strategies: JwtVerificationStrategyOption[];
  status: JwtStrategiesStatus;
} {
  const [strategies, setStrategies] = useState<JwtVerificationStrategyOption[]>([]);
  const [status, setStatus] = useState<JwtStrategiesStatus>('idle');
  useEffect(() => {
    if (!enabled) return;
    let current = true;
    setStatus('loading');
    apiClient
      .fetch('/api/v1/jwt-verification-strategies')
      .then(async r => {
        if (!r.ok) throw new Error(`${r.status}`);
        const data: unknown = await r.json();
        if (!current) return;
        setStrategies(Array.isArray(data) ? data : []);
        setStatus('loaded');
      })
      .catch(() => {
        if (!current) return;
        setStrategies([]);
        setStatus('failed');
      });
    return () => {
      current = false;
    };
  }, [enabled]);
  return { strategies, status };
}

/** The JWT verification strategies a caller authentication method can name, loaded while `enabled`. */
export function useJwtStrategies(enabled = true): JwtVerificationStrategyOption[] {
  return useJwtStrategyList(enabled).strategies;
}

const apiKeyTypeFirst = (a: ApiKeySecretOption, b: ApiKeySecretOption): number =>
  Number(b.secret_type === 'ApiKey') - Number(a.secret_type === 'ApiKey');

/**
 * The secrets that can hold accepted API keys, loaded while `enabled`. The gateway reads the
 * secret whatever its type, so every secret is offered, those of type `ApiKey` first.
 */
export function useApiKeySecrets(enabled: boolean): {
  secrets: ApiKeySecretOption[];
  loading: boolean;
} {
  const [secrets, setSecrets] = useState<ApiKeySecretOption[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    apiClient
      .get<ApiKeySecretOption[]>('/secrets/')
      .then(res => {
        const list: ApiKeySecretOption[] = Array.isArray(res.data) ? res.data : [];
        setSecrets([...list].sort(apiKeyTypeFirst));
      })
      .catch(() => setSecrets([]))
      .finally(() => setLoading(false));
  }, [enabled]);
  return { secrets, loading };
}
