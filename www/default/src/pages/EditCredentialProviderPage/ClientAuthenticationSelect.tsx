import React from 'react';
import FieldHelp from '../../components/shared/FieldHelp';
import { CLIENT_AUTHENTICATION_LABELS, ClientAuthentication } from './credentialProviderForm';

interface ClientAuthenticationSelectProps {
  value: ClientAuthentication;
  onChange: (event: React.ChangeEvent<HTMLSelectElement>) => void;
}

const OPTIONS: { value: ClientAuthentication; label: string }[] = [
  { value: '', label: 'Not sent (default)' },
  { value: 'none', label: `${CLIENT_AUTHENTICATION_LABELS.none} (public client)` },
  { value: 'client_secret_basic', label: CLIENT_AUTHENTICATION_LABELS.client_secret_basic },
  { value: 'client_secret_post', label: CLIENT_AUTHENTICATION_LABELS.client_secret_post },
];

/** How a JWT Bearer provider's OAuth client identifies itself with the grant. */
const ClientAuthenticationSelect: React.FC<ClientAuthenticationSelectProps> = ({
  value,
  onChange,
}) => (
  <div className="mb-3" data-testid="credential-provider-client-authentication">
    <hr />
    <div className="field-label-with-help">
      <label htmlFor="client_authentication" className="mb-0">
        Client authentication
      </label>
      <FieldHelp ariaLabel="About Client authentication" testId="field-help-client-authentication">
        Leave Not sent unless the token server needs its client identified. Client ID only sends the
        client ID with no secret. HTTP Basic sends the client ID and secret in the Authorization
        header. Form body sends them as form fields. Any choice shows the client pickers below.
      </FieldHelp>
    </div>
    <select
      id="client_authentication"
      name="client_authentication"
      data-testid="credential-provider-client-authentication-select"
      className="form-control dropdown-styling"
      value={value}
      onChange={onChange}
    >
      {OPTIONS.map(option => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  </div>
);

export default ClientAuthenticationSelect;
