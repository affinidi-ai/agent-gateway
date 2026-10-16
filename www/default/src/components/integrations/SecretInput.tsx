import React from 'react';
import { AppButton } from '../shared/AppButton';
import { SecretOption } from '../../hooks/useApplianceSecrets';
import { SecretEdit } from '../../pages/EndpointEditorPage/endpointFields';

const REFERENCE_PREFIX = '$SECRET:';

interface SecretInputProps {
  id: string;
  label: string;
  edit: SecretEdit;
  /** Whether the gateway holds a value for this field. */
  stored: boolean;
  required?: boolean;
  multiline?: boolean;
  placeholder?: string;
  help?: string;
  disabled?: boolean;
  /** Stored secrets the field may reference instead of holding a value; no picker without. */
  secretOptions?: SecretOption[];
  onChange: (edit: SecretEdit) => void;
}

/**
 * A write-only field: a stored value is never shown, only kept, replaced or cleared. A
 * `$SECRET:<id>` reference names a secret in Secrets, so it is shown as written.
 */
const SecretInput: React.FC<SecretInputProps> = ({
  id,
  label,
  edit,
  stored,
  required = false,
  multiline = false,
  placeholder,
  help,
  disabled = false,
  secretOptions,
  onChange,
}) => {
  const heading = (
    <span className="form-label d-block">
      {label}
      {required && <span className="text-danger"> *</span>}
    </span>
  );

  if (edit.state === 'keep') {
    return (
      <div className="mb-3">
        {heading}
        <div className="d-flex align-items-center gap-2">
          <span className="text-muted small">
            <i className="fas fa-lock me-1" aria-hidden="true"></i>A value is stored. It is never
            shown.
          </span>
          <AppButton
            variant="outline-secondary"
            size="sm"
            disabled={disabled}
            onClick={() => onChange({ state: 'set', value: '' })}
            aria-label={`Replace ${label}`}
            data-testid={`${id}-replace-button`}
          >
            Replace
          </AppButton>
          {!required && (
            <AppButton
              variant="outline-danger"
              size="sm"
              disabled={disabled}
              onClick={() => onChange({ state: 'clear' })}
              aria-label={`Clear ${label}`}
              data-testid={`${id}-clear-button`}
            >
              Clear
            </AppButton>
          )}
        </div>
        {help && <div className="form-text">{help}</div>}
      </div>
    );
  }

  if (edit.state === 'clear') {
    return (
      <div className="mb-3">
        {heading}
        <div className="d-flex align-items-center gap-2">
          <span className="text-danger small">The stored value is removed when you save.</span>
          <AppButton
            variant="outline-secondary"
            size="sm"
            disabled={disabled}
            onClick={() => onChange({ state: 'keep' })}
            aria-label={`Undo clearing ${label}`}
            data-testid={`${id}-undo-button`}
          >
            Undo
          </AppButton>
        </div>
      </div>
    );
  }

  const reference = edit.value.startsWith(REFERENCE_PREFIX)
    ? edit.value.slice(REFERENCE_PREFIX.length)
    : null;
  const referenced = secretOptions?.find(option => option.id === reference);
  const inputProps = {
    id,
    'data-testid': `${id}-input`,
    className: 'form-control',
    value: edit.value,
    placeholder,
    disabled,
    autoComplete: 'off',
    onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      onChange({ state: 'set', value: event.target.value }),
  };

  return (
    <div className="mb-3">
      <label htmlFor={id} className="form-label">
        {label}
        {required && <span className="text-danger"> *</span>}
      </label>
      <div className="d-flex align-items-start gap-2">
        {multiline ? (
          <textarea {...inputProps} rows={4} spellCheck={false} />
        ) : (
          <input {...inputProps} type={reference !== null ? 'text' : 'password'} />
        )}
        {stored && (
          <AppButton
            variant="outline-secondary"
            size="sm"
            disabled={disabled}
            onClick={() => onChange({ state: 'keep' })}
            data-testid={`${id}-keep-button`}
          >
            Keep stored value
          </AppButton>
        )}
      </div>
      {secretOptions && (
        <div className="mt-2">
          <label htmlFor={`${id}-stored-secret`} className="form-label small mb-1">
            Use a stored secret
          </label>
          <select
            id={`${id}-stored-secret`}
            data-testid={`${id}-stored-secret-select`}
            className="form-select form-select-sm"
            value={reference ?? ''}
            disabled={disabled}
            onChange={event =>
              onChange({
                state: 'set',
                value: event.target.value ? `${REFERENCE_PREFIX}${event.target.value}` : '',
              })
            }
          >
            <option value="">None, type a value</option>
            {reference && !referenced && (
              <option value={reference}>{`${reference} (not listed)`}</option>
            )}
            {secretOptions.map(option => (
              <option key={option.id} value={option.id}>
                {option.name}
              </option>
            ))}
          </select>
        </div>
      )}
      {reference !== null && (
        <div className="form-text">
          Uses the stored secret {referenced?.name ?? reference} from Secrets.
        </div>
      )}
      {help && <div className="form-text">{help}</div>}
    </div>
  );
};

export default SecretInput;
