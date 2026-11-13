import { useCallback, useEffect, useState } from 'react';
import { ApiError, apiClient } from '../../../../api';
import type { SecretOption } from '../../../shared/SecretOptions';

export type SecretListStatus = 'loading' | 'ready' | 'failed' | 'denied';

/**
 * The secrets a Transit Point's target authentication can name. `reload` fetches the list
 * again, keeping the current one on screen while `refreshing`; a refused request reports
 * `denied`, any other failure `failed`.
 */
export function useTargetAuthSecrets(): {
  secrets: SecretOption[];
  status: SecretListStatus;
  refreshing: boolean;
  reload: () => void;
} {
  const [secrets, setSecrets] = useState<SecretOption[]>([]);
  const [status, setStatus] = useState<SecretListStatus>('loading');
  const [refreshing, setRefreshing] = useState(false);
  const [requests, setRequests] = useState(0);

  useEffect(() => {
    let current = true;
    if (requests === 0) setStatus('loading');
    else setRefreshing(true);
    apiClient
      .get<SecretOption[]>('/secrets/')
      .then(res => {
        if (!current) return;
        setSecrets(Array.isArray(res.data) ? res.data : []);
        setStatus('ready');
      })
      .catch(error => {
        if (!current) return;
        setStatus(error instanceof ApiError && error.status === 403 ? 'denied' : 'failed');
      })
      .finally(() => {
        if (current) setRefreshing(false);
      });
    return () => {
      current = false;
    };
  }, [requests]);

  const reload = useCallback(() => setRequests(count => count + 1), []);
  return { secrets, status, refreshing, reload };
}
