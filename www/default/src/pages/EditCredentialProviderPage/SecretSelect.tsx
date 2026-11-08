import React from 'react';
import AddResourceLink from '../../components/shared/AddResourceLink';
import FieldHelp from '../../components/shared/FieldHelp';
import { deepLinks } from '../../utils/deepLinks';
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
 * The options of a secret picker: the secrets of the provider's tenant, plus the stored choice
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

interface SecretSelectProps {
  id: string;
  label: string;
  required?: boolean;
  help?: React.ReactNode;
  hint: React.ReactNode;
  value: string;
  secrets: SecretOption[];
  ownerTenant: OwnerTenant;
  loading: boolean;
  onChange: (event: React.ChangeEvent<HTMLSelectElement>) => void;
}

/** A picker over the secrets store; the form keeps only the chosen secret's id. */
const SecretSelect: React.FC<SecretSelectProps> = ({
  id,
  label,
  required,
  help,
  hint,
  value,
  secrets,
  ownerTenant,
  loading,
  onChange,
}) => (
  <div className="mb-3">
    <div className="field-label-with-help">
      <label htmlFor={id} className="mb-0">
        {label} {required && <span className="text-danger">*</span>}
      </label>
      {help && (
        <FieldHelp ariaLabel={`About ${label}`} testId={`field-help-${id}`}>
          {help}
        </FieldHelp>
      )}
    </div>
    <select
      id={id}
      name={id}
      data-testid={`credential-provider-${id}-select`}
      className="form-control dropdown-styling"
      value={value}
      onChange={onChange}
      required={required}
      disabled={loading}
    >
      <option value="">{loading ? '-- Loading secrets... --' : '-- Select a secret --'}</option>
      <SecretOptions secrets={secrets} ownerTenant={ownerTenant} value={value} />
    </select>
    <small className="form-text text-muted">{hint}</small>
    {!loading && (
      <div className="form-text">
        {splitByTenant(secrets, ownerTenant).offered.length === 0
          ? 'No secrets configured yet. '
          : "Don't see the one you need? "}
        <AddResourceLink to={deepLinks.secret} testid={`credential-provider-add-${id}-link`}>
          Add secret
        </AddResourceLink>
      </div>
    )}
  </div>
);

export default SecretSelect;
