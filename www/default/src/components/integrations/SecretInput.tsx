import React from 'react';
import { AppButton } from '../shared/AppButton';
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
  const inputProps = {
    id,
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
          >
            Keep stored value
          </AppButton>
        )}
      </div>
      {reference !== null && (
        <div className="form-text">Uses the stored secret {reference} from Secrets.</div>
      )}
      {help && <div className="form-text">{help}</div>}
    </div>
  );
};

export default SecretInput;
