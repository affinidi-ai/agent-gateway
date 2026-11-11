import React from 'react';
import AddResourceLink from '../../components/shared/AddResourceLink';
import { CopyButton } from '../../components/shared/CopyButton';
import FieldHelp from '../../components/shared/FieldHelp';
import { useJwtStrategyList } from '../../components/surface-builder/elements/caller-auth/useCallerAuthOptions';
import { deepLinks } from '../../utils/deepLinks';
import { OTHER_TENANT_LABEL, splitByTenant, type OwnerTenant } from '../../utils/tenantScope';
import SecretSelect, { SecretOption } from './SecretSelect';
import type { ConsentConfirmationFormFields } from './credentialProviderForm';

interface ConsentConfirmationSectionProps {
  form: ConsentConfirmationFormFields;
  /** The confirmation redirect URI, empty until the provider's Callback URL is known. */
  redirectUri: string;
  secrets: SecretOption[];
  ownerTenant: OwnerTenant;
  loadingSecrets: boolean;
  onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => void;
}

/**
 * The consent confirmation setting of a legacy consent provider: the login client the gateway
 * signs the person in with at the callers' identity provider before sending them to the vendor.
 */
const ConsentConfirmationSection: React.FC<ConsentConfirmationSectionProps> = ({
  form,
  redirectUri,
  secrets,
  ownerTenant,
  loadingSecrets,
  onChange,
}) => {
  const { strategies, status } = useJwtStrategyList(form.consent_confirmation_enabled);
  // A tenant provider may name its own tenant's strategies or appliance-wide ones, as the gateway allows.
  const { offered, outside } = splitByTenant(strategies, ownerTenant, () => true);
  const storedId = form.cc_jwt_verification_strategy_id;
  const storedOffered = offered.some(strategy => strategy.id === storedId);
  const storedOutside = outside.find(strategy => strategy.id === storedId);
  let storedLabel: string | null = null;
  if (storedId && !storedOffered) {
    if (status !== 'loaded') storedLabel = storedId;
    else if (storedOutside) storedLabel = `${storedOutside.name} (${OTHER_TENANT_LABEL})`;
    else storedLabel = `${storedId} (not found)`;
  }
  return (
    <div data-testid="credential-provider-consent-confirmation-section">
      <hr />
      <h6 className="font-weight-bold text-primary mb-3">
        <i className="fas fa-user-check me-2"></i>Consent confirmation
      </h6>
      <div className="mb-3">
        <div className="field-label-with-help">
          <div className="form-check form-switch mb-0">
            <input
              id="consent_confirmation_enabled"
              name="consent_confirmation_enabled"
              data-testid="credential-provider-consent-confirmation-switch"
              className="form-check-input"
              type="checkbox"
              role="switch"
              checked={form.consent_confirmation_enabled}
              onChange={onChange}
            />
            <label htmlFor="consent_confirmation_enabled" className="form-check-label">
              Confirm the caller at their identity provider before the vendor
            </label>
          </div>
          <FieldHelp
            ariaLabel="About Consent confirmation"
            testId="field-help-consent-confirmation"
          >
            The person who opens a consent link first signs in at the callers&apos; identity
            provider with a login client. The gateway checks that the ID token names the caller the
            link was issued to, and refuses anyone else before the vendor. Needs{' '}
            <code>AG_IDENTITY_HASH_PEPPER</code> to be set on the gateway.
          </FieldHelp>
        </div>
      </div>

      {form.consent_confirmation_enabled && (
        <>
          <SecretSelect
            id="cc_client_id_secret_ref"
            label="Login Client ID"
            required
            help="The value itself is never shown or copied into this form, only a reference to where it's stored."
            hint="Pick the secret holding the client ID of the gateway's login client at the callers' identity provider."
            value={form.cc_client_id_secret_ref}
            secrets={secrets}
            ownerTenant={ownerTenant}
            loading={loadingSecrets}
            onChange={onChange}
          />

          <SecretSelect
            id="cc_client_secret_secret_ref"
            label="Login Client Secret"
            required
            help={
              <>
                The value itself is never shown or copied into this form, only a reference to where
                it&apos;s stored. Register the login client with <code>client_secret_post</code>:
                the gateway sends this secret in the form body.
              </>
            }
            hint="Pick the secret holding the login client's secret."
            value={form.cc_client_secret_secret_ref}
            secrets={secrets}
            ownerTenant={ownerTenant}
            loading={loadingSecrets}
            onChange={onChange}
          />

          <div className="row mb-3">
            <div className="col-md-6">
              <div className="field-label-with-help">
                <label htmlFor="cc_authorization_endpoint" className="mb-0">
                  Login Authorization Endpoint <span className="text-danger">*</span>
                </label>
                <FieldHelp
                  ariaLabel="About Login Authorization Endpoint"
                  testId="field-help-cc-authorization-endpoint"
                >
                  The identity provider&apos;s authorization endpoint, an https URL with no query or
                  fragment.
                </FieldHelp>
              </div>
              <input
                id="cc_authorization_endpoint"
                name="cc_authorization_endpoint"
                data-testid="credential-provider-consent-confirmation-authorization-endpoint-input"
                type="url"
                className="form-control"
                value={form.cc_authorization_endpoint}
                onChange={onChange}
                required
              />
            </div>
            <div className="col-md-6">
              <div className="field-label-with-help">
                <label htmlFor="cc_token_endpoint" className="mb-0">
                  Login Token Endpoint <span className="text-danger">*</span>
                </label>
                <FieldHelp
                  ariaLabel="About Login Token Endpoint"
                  testId="field-help-cc-token-endpoint"
                >
                  The identity provider&apos;s token endpoint, where the gateway trades the sign-in
                  code for the ID token.
                </FieldHelp>
              </div>
              <input
                id="cc_token_endpoint"
                name="cc_token_endpoint"
                data-testid="credential-provider-consent-confirmation-token-endpoint-input"
                type="url"
                className="form-control"
                value={form.cc_token_endpoint}
                onChange={onChange}
                required
              />
            </div>
          </div>

          <div className="mb-3">
            <div className="field-label-with-help">
              <label htmlFor="cc_jwt_verification_strategy_id" className="mb-0">
                JWT verification strategy <span className="text-danger">*</span>
              </label>
              <FieldHelp
                ariaLabel="About JWT verification strategy"
                testId="field-help-cc-strategy"
              >
                The strategy that verifies the ID token. Its expected issuer and principal claim
                decide which callers are confirmed: pick the one that verifies the callers of the
                surfaces using this provider.
              </FieldHelp>
            </div>
            <select
              id="cc_jwt_verification_strategy_id"
              name="cc_jwt_verification_strategy_id"
              data-testid="credential-provider-consent-confirmation-strategy-select"
              className="form-control dropdown-styling"
              value={form.cc_jwt_verification_strategy_id}
              onChange={onChange}
              required
            >
              <option value="">-- Select a strategy --</option>
              {offered.map(strategy => (
                <option key={strategy.id} value={strategy.id}>
                  {strategy.name}
                </option>
              ))}
              {storedLabel && <option value={storedId}>{storedLabel}</option>}
            </select>
            {status === 'failed' && (
              <div
                className="form-text text-danger"
                data-testid="credential-provider-consent-confirmation-strategies-failed"
              >
                Strategies could not be loaded
              </div>
            )}
            <div className="form-text">
              {"Don't see the one you need? "}
              <AddResourceLink
                to={deepLinks.jwtVerificationStrategy}
                testid="credential-provider-add-consent-confirmation-strategy-link"
              >
                Add strategy
              </AddResourceLink>
            </div>
          </div>

          <div className="mb-3">
            <div className="field-label-with-help">
              <label htmlFor="cc_id_token_principal_claim" className="mb-0">
                ID-token principal claim
              </label>
              <FieldHelp
                ariaLabel="About ID-token principal claim"
                testId="field-help-cc-principal-claim"
              >
                Optional. The ID-token claim that holds the caller&apos;s value, when it is not the
                strategy&apos;s principal claim. Use an immutable claim the identity provider
                assigns, such as <code>sub</code> or <code>oid</code>.
              </FieldHelp>
            </div>
            <input
              id="cc_id_token_principal_claim"
              name="cc_id_token_principal_claim"
              data-testid="credential-provider-consent-confirmation-principal-claim-input"
              type="text"
              className="form-control"
              value={form.cc_id_token_principal_claim}
              onChange={onChange}
              placeholder="The strategy's principal claim"
            />
          </div>

          <div className="mb-3">
            <div className="field-label-with-help">
              <label htmlFor="cc_redirect_uri" className="mb-0">
                Confirmation redirect URI
              </label>
              <FieldHelp
                ariaLabel="About Confirmation redirect URI"
                testId="field-help-cc-redirect-uri"
              >
                Register this URI as a redirect URI on the login client at the identity provider. It
                is the Callback URL followed by <code>/confirm</code>, so it can&apos;t be edited on
                its own: change the Callback URL to change it, then register the new URI.
              </FieldHelp>
            </div>
            {redirectUri ? (
              <div className="input-group">
                <input
                  id="cc_redirect_uri"
                  data-testid="credential-provider-consent-confirmation-redirect-uri"
                  type="text"
                  className="form-control"
                  value={redirectUri}
                  readOnly
                />
                <CopyButton
                  text={redirectUri}
                  variant="outline-primary"
                  title="Copy to clipboard"
                  data-testid="credential-provider-consent-confirmation-redirect-uri-copy"
                />
              </div>
            ) : null}
            {redirectUri && (
              <div
                className="form-text"
                data-testid="credential-provider-consent-confirmation-redirect-uri-where"
              >
                Add this URI to the allowed redirect URIs of the login client
                {form.cc_client_id_secret_ref ? (
                  <>
                    {' '}
                    whose ID is in secret <code>{form.cc_client_id_secret_ref}</code>
                  </>
                ) : null}{' '}
                at your identity provider. Don&apos;t add it at the vendor: the vendor&apos;s OAuth
                app keeps the Callback URL above. This URI follows the Callback URL, so register it
                again whenever the Callback URL changes.
              </div>
            )}
            {redirectUri ? null : (
              <div
                className="alert alert-info mt-2 mb-0"
                style={{ fontSize: '14px' }}
                data-testid="credential-provider-consent-confirmation-redirect-uri-after-create"
              >
                <i className="fas fa-info-circle me-2"></i>
                The Confirmation redirect URI is shown once the provider has a Callback URL, since
                it is the Callback URL followed by <code>/confirm</code>.
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default ConsentConfirmationSection;
