import React, { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import { usePermissions } from '../../../../context/PermissionsContext';
import { deepLinks } from '../../../../utils/deepLinks';
import {
  filterProvidersForUse,
  providerPermits,
  providerTypeLabel,
  type ProviderUse,
} from '../../../../utils/credentialProviders';
import AddResourceLink from '../../../shared/AddResourceLink';

export const CREDENTIAL_PROVIDERS_VIEW_PERMISSION = 'credential_providers.view';

interface ProviderOption {
  id: string;
  name: string;
  provider_id: string;
  provider_type?: string;
}

interface Props {
  id: string;
  value: string;
  onChange: (credentialProviderId: string) => void;
  use: ProviderUse;
  testId: string;
}

const CredentialProviderPicker: React.FC<Props> = ({ id, value, onChange, use, testId }) => {
  const { hasPermission } = usePermissions();
  const canView = hasPermission(CREDENTIAL_PROVIDERS_VIEW_PERMISSION);
  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [loading, setLoading] = useState(canView);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!canView) {
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    setFailed(false);
    apiClient
      .fetch('/api/v1/credential-providers')
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((data: ProviderOption[]) => {
        if (alive) setProviders(Array.isArray(data) ? data : []);
      })
      .catch(() => {
        if (alive) {
          setProviders([]);
          setFailed(true);
        }
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [canView]);

  if (!canView) {
    return (
      <div data-testid={`${testId}-no-permission`}>
        <input
          id={id}
          type="text"
          className="form-control"
          value={value}
          readOnly
          aria-describedby={`${id}-help`}
        />
        <small id={`${id}-help`} className="form-text text-muted">
          Your role cannot list credential providers, so the selection cannot be changed here. The
          saved provider is kept.
        </small>
      </div>
    );
  }

  const eligible = filterProvidersForUse(providers, use);
  const current = providers.find(p => p.id === value);
  const currentUnusable =
    !loading &&
    !failed &&
    !!value &&
    (!current || !providerPermits(current.provider_type ?? '', use));

  return (
    <>
      <select
        className="form-control dropdown-styling"
        id={id}
        data-testid={testId}
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={loading}
      >
        <option value="">
          {loading ? '-- Loading providers... --' : '-- Select a credential provider --'}
        </option>
        {value && !eligible.some(p => p.id === value) && (
          <option value={value}>
            {current
              ? `${current.name} (${providerTypeLabel(current.provider_type ?? '')})`
              : value}
          </option>
        )}
        {eligible.map(p => (
          <option key={p.id} value={p.id}>
            {p.name} ({providerTypeLabel(p.provider_type ?? '')})
          </option>
        ))}
      </select>
      {failed && (
        <div className="form-text text-danger" role="alert" data-testid={`${testId}-error`}>
          Could not load credential providers.
        </div>
      )}
      {currentUnusable && (
        <div className="form-text text-danger" role="alert" data-testid={`${testId}-unusable`}>
          {current
            ? `The ${providerTypeLabel(current.provider_type ?? '')} provider cannot be used for Target Authentication.`
            : 'The selected provider no longer exists.'}{' '}
          The gateway rejects it when you save, so pick another provider.
        </div>
      )}
      {!loading && !failed && (
        <div className="form-text">
          {eligible.length === 0
            ? 'No usable credential providers yet. '
            : "Don't see the one you need? "}
          <AddResourceLink to={deepLinks.credentialProvider} testid={`${testId}-add-link`}>
            Add credential provider
          </AddResourceLink>
        </div>
      )}
    </>
  );
};

export default CredentialProviderPicker;
