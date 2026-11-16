import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import {
  ANY_API_KEY_METHOD,
  ANY_JWT_METHOD,
  NO_SOURCE_METHOD,
  NO_SOURCE_METHOD_API_KEY,
  type SourceMethodChoice,
} from './sourceMethods';

interface Props {
  identityType: 'from_jwt_claim' | 'from_api_key';
  choices: SourceMethodChoice[];
  value: string;
  /** Every method is one the identity can read, so it may read any of them. */
  anyMethod: boolean;
  /** What a stored id that is no longer a choice shows as. */
  unlistedLabel: string;
  onChange: (id: string) => void;
}

/**
 * Which Caller Context method an inbound identity is derived from, shown only
 * while the surface has several. A request authenticated by any other method
 * is refused.
 */
const IdentitySourceMethodSelect: React.FC<Props> = ({
  identityType,
  choices,
  value,
  anyMethod,
  unlistedLabel,
  onChange,
}) => {
  if (choices.length === 0) {
    return (
      <div className="config-section">
        <Form.Text className="d-block text-danger" data-testid="identity-panel-source-method-none">
          {identityType === 'from_jwt_claim' ? NO_SOURCE_METHOD : NO_SOURCE_METHOD_API_KEY}
        </Form.Text>
      </div>
    );
  }
  const listed = choices.some(choice => choice.id === value);
  return (
    <div className="config-section">
      <label
        className="d-flex align-items-center gap-1"
        htmlFor="identity-panel-source-method-select"
      >
        Identity source method
        <FieldHelp
          testId="field-help-identity-source-method"
          ariaLabel="About the identity source method"
        >
          The Caller Context method this identity is derived from. A caller who authenticates with
          another method is refused. While every method is one this identity can read, Any serves
          the callers of all of them.
        </FieldHelp>
      </label>
      <Form.Select
        id="identity-panel-source-method-select"
        size="sm"
        className="dropdown-styling"
        data-testid="identity-panel-source-method-select"
        value={value}
        onChange={e => onChange(e.target.value)}
      >
        {anyMethod ? (
          <option value="">
            {identityType === 'from_jwt_claim' ? ANY_JWT_METHOD : ANY_API_KEY_METHOD}
          </option>
        ) : (
          !value && <option value="">Select a method</option>
        )}
        {value && !listed && (
          <option value={value} disabled>
            {unlistedLabel}
          </option>
        )}
        {choices.map(choice => (
          <option key={choice.id} value={choice.id}>
            {choice.label}
          </option>
        ))}
      </Form.Select>
    </div>
  );
};

export default IdentitySourceMethodSelect;
