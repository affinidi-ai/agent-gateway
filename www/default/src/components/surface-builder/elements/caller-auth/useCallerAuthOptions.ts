import { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import type { CertificateKind } from '../../../../types';

export interface JwtVerificationStrategyOption {
  id: string;
  name: string;
  expected_issuer?: string;
  tenant_id?: string | null;
}

export interface ApiKeySecretOption {
  id: string;
  name: string;
  secret_id?: string;
  secret_type?: string;
}

export interface CertificateOption {
  id: string;
  name: string;
  kind?: CertificateKind;
  active: boolean;
  expires_at?: string;
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

/**
 * The active certificates in the certificate store, loaded while `enabled`. `loaded` and `failed`
 * stay set once a read answered, so a stored id can be shown as missing only after a read.
 */
export function useCertificates(enabled: boolean): {
  certificates: CertificateOption[];
  loading: boolean;
  loaded: boolean;
  failed: boolean;
} {
  const [certificates, setCertificates] = useState<CertificateOption[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let current = true;
    setLoading(true);
    apiClient
      .get<CertificateOption[]>('/certificates')
      .then(res => {
        if (!current) return;
        setCertificates((Array.isArray(res.data) ? res.data : []).filter(c => c.active));
        setFailed(false);
        setLoaded(true);
        setLoading(false);
      })
      .catch(() => {
        if (!current) return;
        setCertificates([]);
        setFailed(true);
        setLoaded(true);
        setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [enabled]);
  return { certificates, loading, loaded, failed };
}
