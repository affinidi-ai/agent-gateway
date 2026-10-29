import React from 'react';
import AddResourceLink from '../../components/shared/AddResourceLink';
import FieldHelp from '../../components/shared/FieldHelp';
import { deepLinks } from '../../utils/deepLinks';

export interface SecretOption {
  id: string;
  name: string;
  secret_id: string;
}

interface SecretSelectProps {
  id: string;
  label: string;
  required?: boolean;
  help?: React.ReactNode;
  hint: React.ReactNode;
  value: string;
  secrets: SecretOption[];
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
      {secrets.map(secret => (
        <option key={secret.id} value={secret.secret_id}>
          {secret.name} ({secret.secret_id})
        </option>
      ))}
    </select>
    <small className="form-text text-muted">{hint}</small>
    {!loading && (
      <div className="form-text">
        {secrets.length === 0 ? 'No secrets configured yet. ' : "Don't see the one you need? "}
        <AddResourceLink to={deepLinks.secret} testid={`credential-provider-add-${id}-link`}>
          Add secret
        </AddResourceLink>
      </div>
    )}
  </div>
);

export default SecretSelect;
