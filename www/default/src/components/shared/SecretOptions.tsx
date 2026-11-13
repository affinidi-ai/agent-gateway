import React from 'react';
import { outOfTenantLabel, splitByTenant, type OwnerTenant } from '../../utils/tenantScope';

export interface SecretOption {
  id: string;
  name: string;
  secret_id: string;
  tenant_id?: string | null;
}

interface SecretOptionsProps {
  secrets: SecretOption[];
  ownerTenant: OwnerTenant;
  value: string;
}

/**
 * The options of a secret picker: the secrets of the owner's tenant, plus the stored choice
 * when it lies outside that tenant, labelled so it can be replaced before it stops working.
 */
export const SecretOptions: React.FC<SecretOptionsProps> = ({ secrets, ownerTenant, value }) => {
  const { offered, outside } = splitByTenant(secrets, ownerTenant);
  return (
    <>
      {offered.map(secret => (
        <option key={secret.id} value={secret.secret_id}>
          {secret.name} ({secret.secret_id})
        </option>
      ))}
      {outside
        .filter(secret => secret.secret_id === value)
        .map(secret => (
          <option key={secret.id} value={secret.secret_id}>
            {secret.name} ({secret.secret_id}, {outOfTenantLabel(secret)})
          </option>
        ))}
    </>
  );
};
