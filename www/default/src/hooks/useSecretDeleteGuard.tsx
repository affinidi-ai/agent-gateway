import React, { useCallback, useState } from 'react';
import { apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { usePermissions } from '../context/PermissionsContext';
import { providersUsingSecret, type ProvidersUsingSecret } from '../utils/credentialProviders';

interface GuardedSecret {
  secret_id: string;
  name: string;
}

interface PendingDelete {
  secret: GuardedSecret;
  providers: ProvidersUsingSecret;
  remove: () => Promise<void>;
}

/**
 * Warns before a secret that credential providers reference is deleted. The delete still goes
 * through after the operator confirms; the gateway does not block it. Call `guardDelete` from the
 * delete action and render `warningNode` once. Without `credential_providers.view` the providers
 * cannot be read, so the delete runs without a warning.
 */
export function useSecretDeleteGuard() {
  const { hasPermission } = usePermissions();
  const canViewProviders = hasPermission('credential_providers.view');
  const [pending, setPending] = useState<PendingDelete | null>(null);
  const [removing, setRemoving] = useState(false);

  const guardDelete = useCallback(
    async (secret: GuardedSecret, remove: () => Promise<void>) => {
      if (!canViewProviders) {
        await remove();
        return;
      }
      const providers = await providersUsingSecret(url => apiClient.fetch(url), secret.secret_id);
      if (providers.ok && providers.names.length === 0) {
        await remove();
        return;
      }
      setPending({ secret, providers, remove });
    },
    [canViewProviders]
  );

  const confirm = async () => {
    if (!pending) return;
    setRemoving(true);
    try {
      await pending.remove();
    } finally {
      setRemoving(false);
      setPending(null);
    }
  };

  const warningNode = pending ? (
    <div
      className="alert alert-warning"
      role="alertdialog"
      aria-labelledby="secret-delete-warning-title"
      data-testid="secret-delete-warning"
    >
      <strong id="secret-delete-warning-title">
        Delete secret &quot;{pending.secret.name}&quot;?
      </strong>
      {pending.providers.ok ? (
        <>
          <p className="mb-1 mt-2">
            {pending.providers.names.length === 1
              ? 'This credential provider references it and will lose its credential:'
              : 'These credential providers reference it and will lose their credential:'}
          </p>
          <ul className="mb-2">
            {pending.providers.names.map((name, index) => (
              <li key={`${index}-${name}`} data-testid="secret-delete-warning-provider">
                {name}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="mb-2 mt-2" data-testid="secret-delete-warning-unknown">
          Could not check which credential providers reference it. A provider that does will lose
          its credential.
        </p>
      )}
      <AppButton
        variant="danger"
        size="sm"
        className="me-2"
        data-testid="secret-delete-warning-confirm-button"
        onClick={confirm}
        loading={removing}
        loadingLabel="Deleting"
      >
        Delete secret anyway
      </AppButton>
      <AppButton
        variant="secondary"
        size="sm"
        data-testid="secret-delete-warning-cancel-button"
        onClick={() => setPending(null)}
        disabled={removing}
      >
        Cancel
      </AppButton>
    </div>
  ) : null;

  return { guardDelete, warningNode };
}
