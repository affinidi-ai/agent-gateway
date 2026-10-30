import React, { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import { isTargetAuthProviderType } from './providerTargetAuth';

interface ProviderOption {
  id: string;
  name: string;
  provider_type?: string;
}

interface TargetAuthProviderSelectProps {
  id: string;
  testId: string;
  value: string;
  onChange: (providerId: string) => void;
  small?: boolean;
}

/**
 * Picks the credential provider whose token authenticates the gateway to a target. Only
 * types that issue a token without a user are listed; the gateway refuses the others.
 */
const TargetAuthProviderSelect: React.FC<TargetAuthProviderSelectProps> = ({
  id,
  testId,
  value,
  onChange,
  small,
}) => {
  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    apiClient
      .fetch('/api/v1/credential-providers')
      .then(response => (response.ok ? response.json() : []))
      .then(data => {
        if (alive) {
          setProviders(
            (Array.isArray(data) ? data : []).filter((provider: ProviderOption) =>
              isTargetAuthProviderType(provider.provider_type)
            )
          );
        }
      })
      .catch(() => {})
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <>
      <select
        id={id}
        data-testid={testId}
        className={`form-control dropdown-styling${small ? ' form-control-sm' : ''}`}
        value={value}
        onChange={event => onChange(event.target.value)}
        disabled={loading}
      >
        <option value="">
          {loading ? '-- Loading providers... --' : '-- Select a credential provider --'}
        </option>
        {providers.map(provider => (
          <option key={provider.id} value={provider.id}>
            {provider.name}
          </option>
        ))}
      </select>
      {!loading && providers.length === 0 && (
        <div className="form-text">
          No Client Credentials, JWT Bearer, Client Credentials JWT or API Key provider yet.{' '}
          <AddResourceLink to={deepLinks.credentialProvider} testid={`${testId}-add-link`}>
            Add credential provider
          </AddResourceLink>
        </div>
      )}
    </>
  );
};

export default TargetAuthProviderSelect;
