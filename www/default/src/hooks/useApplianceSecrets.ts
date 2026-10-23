import { useEffect, useState } from 'react';
import { apiClient } from '../api';

export interface SecretOption {
  id: string;
  name: string;
}

interface SecretMeta {
  secret_id: string;
  name: string;
  tenant_id?: string | null;
}

/**
 * The appliance-wide secrets a `$SECRET:<secret_id>` reference can name; tenant-owned secrets
 * never resolve for appliance-wide definitions. Empty when the secrets cannot be listed.
 */
export function useApplianceSecrets(): SecretOption[] {
  const [secrets, setSecrets] = useState<SecretOption[]>([]);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get<SecretMeta[]>('/secrets/')
      .then(({ data }) => {
        if (cancelled) return;
        setSecrets(
          (data || [])
            .filter(secret => !secret.tenant_id)
            .map(secret => ({ id: secret.secret_id, name: secret.name }))
        );
      })
      .catch(() => {
        // Without secrets.view the picker offers nothing; values can still be typed.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return secrets;
}
