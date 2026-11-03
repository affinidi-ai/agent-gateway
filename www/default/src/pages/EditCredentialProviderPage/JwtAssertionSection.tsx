import React from 'react';
import FieldHelp from '../../components/shared/FieldHelp';
import SecretSelect, { SecretOption } from './SecretSelect';
import type { OwnerTenant } from '../../utils/tenantScope';
import {
  CredentialProviderType,
  JWT_ALGORITHMS,
  JwtFormFields,
  jwtKeyUnidentified,
  providerTypeFields,
} from './credentialProviderForm';

interface JwtAssertionSectionProps {
  providerType: CredentialProviderType;
  form: JwtFormFields;
  secrets: SecretOption[];
  ownerTenant: OwnerTenant;
  loadingSecrets: boolean;
  onChange: (
    event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => void;
}

/**
 * The signed-JWT settings of a JWT Bearer or Client Credentials JWT provider. Key and
 * certificate are secrets created on the Secrets page with the PEM pasted as the value.
 */
const JwtAssertionSection: React.FC<JwtAssertionSectionProps> = ({
  providerType,
  form,
  secrets,
  ownerTenant,
  loadingSecrets,
  onChange,
}) => {
  const fields = providerTypeFields(providerType);
  const algorithms = JWT_ALGORITHMS[providerType] ?? [];
  if (!fields.jwt) return null;
  return (
    <div data-testid="credential-provider-jwt-section">
      <hr />
      <h6 className="font-weight-bold text-primary mb-3">
        <i className="fas fa-file-signature me-2"></i>Signed JWT
      </h6>

      {fields.jwtIssuer && (
        <div className="mb-3">
          <div className="field-label-with-help">
            <label htmlFor="jwt_issuer" className="mb-0">
              Issuer <span className="text-danger">*</span>
            </label>
            <FieldHelp ariaLabel="About Issuer" testId="field-help-jwt-issuer">
              The <code>iss</code> claim of the grant. For a Google service account, the{' '}
              <code>client_email</code> of its JSON key file.
            </FieldHelp>
          </div>
          <input
            id="jwt_issuer"
            name="jwt_issuer"
            data-testid="credential-provider-jwt-issuer-input"
            type="text"
            className="form-control"
            value={form.jwt_issuer}
            onChange={onChange}
            required
          />
        </div>
      )}

      <SecretSelect
        id="jwt_signing_key_secret_ref"
        label="Signing Key"
        required
        help="Create the secret on the Secrets page and paste either the PEM private key, with its BEGIN and END lines, or the whole JSON key file of a Google service account, as its value. The key file is at most 16 KiB."
        hint="Secret holding a PEM private key (PKCS#1 or PKCS#8 for RSA, PKCS#8 for EC) or a Google service account JSON key file."
        value={form.jwt_signing_key_secret_ref}
        secrets={secrets}
        ownerTenant={ownerTenant}
        loading={loadingSecrets}
        onChange={onChange}
      />

      {fields.jwtCertificate && (
        <SecretSelect
          id="jwt_certificate_secret_ref"
          label="Certificate"
          help="Optional. Needed for Entra (Microsoft identity platform): Entra matches the assertion to a certificate uploaded to the app registration by its SHA-256 thumbprint, sent as the x5t#S256 header. Issuers that find the key by Key ID, such as Ory, do not need it."
          hint="Secret holding the PEM certificate (BEGIN CERTIFICATE) of the signing key."
          value={form.jwt_certificate_secret_ref}
          secrets={secrets}
          ownerTenant={ownerTenant}
          loading={loadingSecrets}
          onChange={onChange}
        />
      )}

      <div className="mb-3">
        <div className="field-label-with-help">
          <label htmlFor="jwt_key_id" className="mb-0">
            Key ID
          </label>
          <FieldHelp ariaLabel="About Key ID" testId="field-help-jwt-key-id">
            Optional <code>kid</code> header: the ID of the public key registered with the OAuth
            server, such as the <code>kid</code> of a key in an Ory client&apos;s JWKS. For a Google
            service account JSON key file, leave it empty to send the file&apos;s{' '}
            <code>private_key_id</code>; a value here overrides it.
          </FieldHelp>
        </div>
        <input
          id="jwt_key_id"
          name="jwt_key_id"
          data-testid="credential-provider-jwt-key-id-input"
          type="text"
          className="form-control"
          value={form.jwt_key_id}
          onChange={onChange}
        />
      </div>

      {jwtKeyUnidentified({ ...form, provider_type: providerType }) && (
        <div
          className="alert alert-warning py-2"
          role="status"
          data-testid="credential-provider-jwt-key-unidentified-warning"
        >
          <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
          {fields.jwtCertificate
            ? 'Neither a certificate nor a key ID is set. '
            : 'No key ID is set. '}
          The OAuth server may not be able to identify the correct public key to verify the signed
          JWT.
        </div>
      )}

      <div className="row mb-3">
        <div className="col-md-6">
          <label htmlFor="jwt_signing_algorithm">Signing Algorithm</label>
          <select
            id="jwt_signing_algorithm"
            name="jwt_signing_algorithm"
            data-testid="credential-provider-jwt-algorithm-select"
            className="form-control dropdown-styling"
            value={form.jwt_signing_algorithm || algorithms[0]}
            onChange={onChange}
          >
            {algorithms.map(algorithm => (
              <option key={algorithm} value={algorithm}>
                {algorithm}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="row mb-3">
        <div className={fields.jwtIssuer ? 'col-md-6' : 'col-12'}>
          <div className="field-label-with-help">
            <label htmlFor="jwt_audience" className="mb-0">
              Audience
            </label>
            <FieldHelp ariaLabel="About Audience" testId="field-help-jwt-audience">
              The <code>aud</code> claim. Leave empty to use the token endpoint, which is what
              Google and Entra expect.
            </FieldHelp>
          </div>
          <input
            id="jwt_audience"
            name="jwt_audience"
            data-testid="credential-provider-jwt-audience-input"
            type="url"
            className="form-control"
            value={form.jwt_audience}
            onChange={onChange}
            placeholder="The token endpoint"
          />
        </div>
        {fields.jwtIssuer && (
          <div className="col-md-6">
            <div className="field-label-with-help">
              <label htmlFor="jwt_subject" className="mb-0">
                Subject <span className="text-danger">*</span>
              </label>
              <FieldHelp ariaLabel="About Subject" testId="field-help-jwt-subject">
                The <code>sub</code> claim: the user the assertion is for, such as the user a Google
                service account acts for with domain-wide delegation.
              </FieldHelp>
            </div>
            <input
              id="jwt_subject"
              name="jwt_subject"
              data-testid="credential-provider-jwt-subject-input"
              type="text"
              className="form-control"
              value={form.jwt_subject}
              onChange={onChange}
              required
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default JwtAssertionSection;
