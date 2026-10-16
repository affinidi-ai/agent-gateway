import React from 'react';
import SecretInput from '../../components/integrations/SecretInput';
import { SecretOption } from '../../hooks/useApplianceSecrets';
import { EndpointType } from '../../integrationsApi';
import { EndpointForm, FieldSpec, SecretEdit, visibleFields } from './endpointFields';

interface EndpointConfigFieldsProps {
  type: EndpointType;
  form: EndpointForm;
  /** The secret fields the gateway holds a value for. */
  storedSecrets: string[];
  /** Stored secrets a secret field may reference. */
  secretOptions: SecretOption[];
  disabled?: boolean;
  onValue: (name: string, value: string | boolean) => void;
  onSecret: (name: string, edit: SecretEdit) => void;
}

const inputId = (field: FieldSpec) => `endpoint-${field.name}`;

/** The configuration fields of one endpoint type, shown for the form's current values. */
const EndpointConfigFields: React.FC<EndpointConfigFieldsProps> = ({
  type,
  form,
  storedSecrets,
  secretOptions,
  disabled = false,
  onValue,
  onSecret,
}) => (
  <>
    {visibleFields(type, form.values).map(field => {
      const id = inputId(field);
      if (field.secret) {
        return (
          <SecretInput
            key={field.name}
            id={id}
            label={field.label}
            edit={form.secrets[field.name] ?? { state: 'set', value: '' }}
            stored={storedSecrets.includes(field.name)}
            required={field.required}
            multiline={field.kind === 'secret-json'}
            placeholder={field.placeholder}
            help={field.help}
            disabled={disabled}
            // A reference resolves as a whole value; header values are referenced one by one.
            secretOptions={field.kind === 'secret' ? secretOptions : undefined}
            onChange={edit => onSecret(field.name, edit)}
          />
        );
      }

      const value = form.values[field.name];
      const label = (
        <>
          {field.label}
          {field.required && <span className="text-danger"> *</span>}
        </>
      );
      const help = field.help && <div className="form-text">{field.help}</div>;

      if (field.kind === 'switch') {
        return (
          <div className="form-check form-switch mb-3" key={field.name}>
            <input
              id={id}
              data-testid={`${id}-input`}
              className="form-check-input"
              type="checkbox"
              checked={value === true}
              disabled={disabled}
              onChange={event => onValue(field.name, event.target.checked)}
            />
            <label htmlFor={id} className="form-check-label">
              {label}
            </label>
            {help}
          </div>
        );
      }

      return (
        <div className="mb-3" key={field.name}>
          <label htmlFor={id} className="form-label">
            {label}
          </label>
          {field.kind === 'select' ? (
            <select
              id={id}
              data-testid={`${id}-input`}
              className="form-select"
              value={String(value ?? '')}
              disabled={disabled}
              onChange={event => onValue(field.name, event.target.value)}
            >
              {field.options?.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          ) : field.kind === 'list' ? (
            <textarea
              id={id}
              data-testid={`${id}-input`}
              className="form-control"
              rows={2}
              value={String(value ?? '')}
              placeholder={field.placeholder}
              disabled={disabled}
              onChange={event => onValue(field.name, event.target.value)}
            />
          ) : (
            <input
              id={id}
              data-testid={`${id}-input`}
              className="form-control"
              type={field.kind === 'number' ? 'number' : 'text'}
              value={String(value ?? '')}
              placeholder={field.placeholder}
              disabled={disabled}
              onChange={event => onValue(field.name, event.target.value)}
            />
          )}
          {help}
        </div>
      );
    })}
  </>
);

export default EndpointConfigFields;
