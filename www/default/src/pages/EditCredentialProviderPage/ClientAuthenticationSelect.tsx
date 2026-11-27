import React from 'react';
import FieldHelp from '../../components/shared/FieldHelp';
import {
  CLIENT_AUTHENTICATION_LABELS,
  ClientAuthentication,
  CredentialProviderType,
} from './credentialProviderForm';

interface ClientAuthenticationSelectProps {
  providerType: CredentialProviderType;
  value: ClientAuthentication;
  onChange: (event: React.ChangeEvent<HTMLSelectElement>) => void;
}

const GRANT_OPTIONS: { value: ClientAuthentication; label: string }[] = [
  { value: '', label: 'Not sent (default)' },
  { value: 'none', label: `${CLIENT_AUTHENTICATION_LABELS.none} (public client)` },
  { value: 'client_secret_basic', label: CLIENT_AUTHENTICATION_LABELS.client_secret_basic },
  { value: 'client_secret_post', label: CLIENT_AUTHENTICATION_LABELS.client_secret_post },
];

const CLIENT_SECRET_OPTIONS: { value: ClientAuthentication; label: string }[] = [
  { value: '', label: `${CLIENT_AUTHENTICATION_LABELS.client_secret_post} (default)` },
  { value: 'client_secret_basic', label: CLIENT_AUTHENTICATION_LABELS.client_secret_basic },
];

/**
 * How a provider's OAuth client identifies itself to the token endpoint. A JWT Bearer grant
 * may send no client identity; a Client Credentials or Authorization Code provider always sends
 * its client secret, in the form body (a stored `client_secret_post` shows as the default) or by
 * HTTP Basic.
 */
const ClientAuthenticationSelect: React.FC<ClientAuthenticationSelectProps> = ({
  providerType,
  value,
  onChange,
}) => {
  const grant = providerType === 'oauth2_jwt_bearer';
  const options = grant ? GRANT_OPTIONS : CLIENT_SECRET_OPTIONS;
  const shown = grant || value === 'client_secret_basic' ? value : '';
  return (
    <div className="mb-3" data-testid="credential-provider-client-authentication">
      <hr />
      <div className="field-label-with-help">
        <label htmlFor="client_authentication" className="mb-0">
          Client authentication
        </label>
        <FieldHelp
          ariaLabel="About Client authentication"
          testId="field-help-client-authentication"
        >
          {grant
            ? 'Leave Not sent unless the token server needs its client identified. Client ID only ' +
              'sends the client ID with no secret. HTTP Basic sends the client ID and secret in the ' +
              'Authorization header. Form body sends them as form fields. Any choice shows the ' +
              'client pickers below.'
            : 'Form body sends the client ID and secret as form fields. HTTP Basic sends them in ' +
              'the Authorization header: choose it when the token server answers invalid_client ' +
              'to the form body, or names client_secret_basic. It applies to every token request, ' +
              'code exchange and refresh.'}
        </FieldHelp>
      </div>
      <select
        id="client_authentication"
        name="client_authentication"
        data-testid="credential-provider-client-authentication-select"
        className="form-control dropdown-styling"
        value={shown}
        onChange={onChange}
      >
        {options.map(option => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
};

export default ClientAuthenticationSelect;
