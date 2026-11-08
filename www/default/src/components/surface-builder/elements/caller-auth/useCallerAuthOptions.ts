import { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';

export interface JwtVerificationStrategyOption {
  id: string;
  name: string;
  expected_issuer?: string;
}

export interface ApiKeySecretOption {
  id: string;
  name: string;
  secret_id?: string;
  secret_type?: string;
}

/** The JWT verification strategies a caller authentication method can name, loaded while `enabled`. */
export function useJwtStrategies(enabled = true): JwtVerificationStrategyOption[] {
  const [strategies, setStrategies] = useState<JwtVerificationStrategyOption[]>([]);
  useEffect(() => {
    if (!enabled) return;
    apiClient
      .fetch('/api/v1/jwt-verification-strategies')
      .then(r => (r.ok ? r.json() : []))
      .then((data: JwtVerificationStrategyOption[]) =>
        setStrategies(Array.isArray(data) ? data : [])
      )
      .catch(() => setStrategies([]));
  }, [enabled]);
  return strategies;
}

/** The secrets that can hold accepted API keys, loaded while `enabled`. */
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
        setSecrets(list.filter(secret => !secret.secret_type || secret.secret_type === 'ApiKey'));
      })
      .catch(() => setSecrets([]))
      .finally(() => setLoading(false));
  }, [enabled]);
  return { secrets, loading };
}
