import React from 'react';

export interface Secret {
  id: string;
  name: string;
  secret_type?: string;
}

interface SecretSelectorProps {
  secrets: Secret[];
  selectedSecretId: string;
  onChange: (secretId: string) => void;
  label?: string;
  required?: boolean;
  helpText?: string;
  /** Text for the empty/no-selection option (e.g. when a filter hides all secrets). */
  placeholder?: string;
}

const SecretSelector: React.FC<SecretSelectorProps> = ({
  secrets,
  selectedSecretId,
  onChange,
  label = 'API Key Secret',
  required = false,
  helpText = 'API key secret for authentication with the LLM provider',
  placeholder = 'Select a secret...',
}) => {
  return (
    <div className="mb-3">
      <label>
        {label}
        {required && ' *'}
      </label>
      <select
        className="form-control dropdown-styling"
        value={selectedSecretId}
        onChange={e => onChange(e.target.value)}
        required={required}
      >
        <option value="">{placeholder}</option>
        {secrets.map(secret => (
          <option key={secret.id} value={secret.id}>
            {secret.name}
          </option>
        ))}
      </select>
      {helpText && <small className="form-text text-muted">{helpText}</small>}
    </div>
  );
};

export default SecretSelector;
