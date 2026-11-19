import React from 'react';
import FieldHelp from '../../components/shared/FieldHelp';
import { CONSENT_LIMIT_RANGE, consentLimitUnitsFor } from '../../utils/consentLimit';
import {
  CONSENT_LIMIT_FIELD_MESSAGE,
  ConsentLimitFields,
  CredentialProviderType,
  consentImpactMessage,
  consentLimitSeconds,
} from './credentialProviderForm';
import { useConsentImpact } from './useConsentImpact';

interface ConsentLimitSectionProps {
  form: ConsentLimitFields & { provider_type: CredentialProviderType };
  /** The stored provider's id; `undefined` for a new one, whose limit ends no consent. */
  providerId: string | undefined;
  /** The provider as the warning names it. */
  providerName: string;
  /** The limit the provider is stored with, in seconds; `undefined` for none. */
  storedSecs: number | undefined;
  /** Whether the last save refused the limit. */
  refused: boolean;
  inputRef: React.Ref<HTMLInputElement>;
  onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => void;
}

/**
 * The consent time limit of a provider a person consents to: its amount and unit, why a save
 * refused it, and how many active consents saving a shorter one would end.
 */
const ConsentLimitSection: React.FC<ConsentLimitSectionProps> = ({
  form,
  providerId,
  providerName,
  storedSecs,
  refused,
  inputRef,
  onChange,
}) => {
  const endingConsents = useConsentImpact(providerId, consentLimitSeconds(form), storedSecs);
  const impact = consentImpactMessage(endingConsents, providerName);

  return (
    <div className="mb-3">
      <div className="field-label-with-help">
        <label htmlFor="consent_limit_amount" className="mb-0">
          Consent time limit
        </label>
        <FieldHelp ariaLabel="About Consent time limit" testId="field-help-consent-limit">
          How long an agent may use a person's consent. At the end the gateway removes the stored
          credential and asks the person to consent again. A shorter limit also ends consents given
          earlier; a longer one never extends them.
        </FieldHelp>
      </div>
      <div className="input-group" style={{ maxWidth: '22rem' }}>
        <input
          ref={inputRef}
          id="consent_limit_amount"
          name="consent_limit_amount"
          type="number"
          min={1}
          step={1}
          className={`form-control${refused ? ' is-invalid' : ''}`}
          placeholder="Not set"
          value={form.consent_limit_amount}
          onChange={onChange}
          aria-invalid={refused || undefined}
          aria-describedby={
            refused ? 'consent_limit_error consent_limit_help' : 'consent_limit_help'
          }
          data-testid="credential-provider-consent-limit-input"
        />
        <select
          name="consent_limit_unit"
          aria-label="Consent time limit unit"
          className="form-select"
          value={form.consent_limit_unit}
          onChange={onChange}
          data-testid="credential-provider-consent-limit-unit-select"
        >
          {consentLimitUnitsFor(storedSecs).map(unit => (
            <option key={unit} value={unit}>
              {unit}
            </option>
          ))}
        </select>
      </div>
      {refused && (
        <div
          id="consent_limit_error"
          className="invalid-feedback d-block"
          data-testid="credential-provider-consent-limit-error"
        >
          {CONSENT_LIMIT_FIELD_MESSAGE}
        </div>
      )}
      <small id="consent_limit_help" className="form-text text-muted">
        Leave empty to set no limit on this provider. A default or a ceiling in the gateway's
        configuration still applies.
        {!refused && ` From ${CONSENT_LIMIT_RANGE}.`}
      </small>
      <div role="status" data-testid="credential-provider-consent-limit-impact-region">
        {impact && (
          <div
            className="alert alert-warning py-2 mt-2"
            data-testid="credential-provider-consent-limit-impact"
          >
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {impact}
          </div>
        )}
      </div>
    </div>
  );
};

export default ConsentLimitSection;
