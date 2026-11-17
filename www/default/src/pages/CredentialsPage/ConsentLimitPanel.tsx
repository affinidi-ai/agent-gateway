import React, { useState } from 'react';
import { apiClient } from '../../api';
import { formatDateTime } from '../../utils/stringUtils';
import {
  ConsentLimitUnit,
  consentLimitSecondsOf,
  consentLimitUnitsFor,
  largestWholeUnit,
} from '../../utils/consentLimit';
import {
  DelegationToken,
  LimitOutcome,
  consentLimitSecs,
  limitOutcome,
  timeLeft,
} from './delegatedAccess';

interface ConsentLimitPanelProps {
  token: DelegationToken;
  providerName: string;
  /** Called with the token as the gateway stores it once its limit is saved. */
  onSaved: (limited: DelegationToken) => void;
  onCancel: () => void;
}

/** What the panel says a limit would do, before anything is sent. */
function describeOutcome(outcome: LimitOutcome, token: DelegationToken, now: Date): string {
  switch (outcome.kind) {
    case 'invalid':
      return 'Enter a whole number from 1 minute to 365 days.';
    case 'already_older':
      return 'This consent is already older than that. Use Revoke to end it now.';
    case 'not_sooner':
      return `It already ends ${formatDateTime(outcome.end, true)}. A limit only brings the end forward.`;
    case 'ends':
      return `Consent given ${formatDateTime(token.consent_granted_at, true)}. With this limit it ends ${formatDateTime(outcome.end, true)} (${timeLeft(outcome.end, now)}).`;
  }
}

/**
 * Sets a time limit on one delegation: it then ends that long after its consent was given. It
 * opens in place under the delegation's row, never as a modal or a browser dialog, and offers
 * Save only for a limit that brings the end forward.
 */
const ConsentLimitPanel: React.FC<ConsentLimitPanelProps> = ({
  token,
  providerName,
  onSaved,
  onCancel,
}) => {
  const currentSecs = consentLimitSecs(token);
  const current = currentSecs === null ? null : largestWholeUnit(currentSecs);
  const [amount, setAmount] = useState(current ? String(current.count) : '');
  const [unit, setUnit] = useState<ConsentLimitUnit>(current?.unit ?? 'hours');
  const [refusal, setRefusal] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const now = new Date();
  const limitSecs = consentLimitSecondsOf(amount, unit);
  const outcome = limitOutcome(token, limitSecs, now);
  const id = token.id;

  const save = async () => {
    if (outcome.kind !== 'ends' || limitSecs === null) return;
    setSaving(true);
    setRefusal(null);
    let answer: unknown = null;
    let saved = false;
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/${encodeURIComponent(id)}/consent-limit`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ max_consent_age_secs: limitSecs }),
        }
      );
      answer = await response.json().catch(() => null);
      saved = response.ok && !!answer && typeof answer === 'object';
      if (!saved) {
        const said = (answer as { error?: unknown } | null)?.error;
        setRefusal(typeof said === 'string' ? said : 'The gateway did not save the limit.');
      }
    } catch {
      setRefusal('The gateway could not be reached, so the limit was not saved.');
    }
    if (saved) {
      onSaved(answer as DelegationToken);
    } else {
      setSaving(false);
    }
  };

  return (
    <div className="px-4 py-3" data-testid={`credential-token-limit-panel-${id}`}>
      <div className="fw-semibold mb-2">Limit duration · {providerName}</div>
      <div className="d-flex flex-wrap align-items-center gap-2">
        <label className="mb-0" htmlFor={`credential-token-limit-input-${id}`}>
          The agent may act for this person for at most
        </label>
        <input
          id={`credential-token-limit-input-${id}`}
          type="number"
          min={1}
          step={1}
          className={`form-control form-control-sm${refusal ? ' is-invalid' : ''}`}
          style={{ width: '6rem' }}
          value={amount}
          aria-invalid={refusal ? true : undefined}
          aria-describedby={`credential-token-limit-preview-${id}`}
          data-testid={`credential-token-limit-input-${id}`}
          onChange={e => {
            setAmount(e.target.value);
            setRefusal(null);
          }}
        />
        <select
          className="form-select form-select-sm"
          style={{ width: 'auto' }}
          aria-label="Unit of the limit"
          value={unit}
          data-testid={`credential-token-limit-unit-${id}`}
          onChange={e => {
            setUnit(e.target.value as ConsentLimitUnit);
            setRefusal(null);
          }}
        >
          {consentLimitUnitsFor(currentSecs ?? undefined).map(name => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <span>after consent.</span>
      </div>
      <div
        className="small text-muted mt-2"
        aria-live="polite"
        id={`credential-token-limit-preview-${id}`}
        data-testid={`credential-token-limit-preview-${id}`}
      >
        {describeOutcome(outcome, token, now)}
      </div>
      {refusal && (
        <div
          className="small text-danger mt-1"
          role="alert"
          data-testid={`credential-token-limit-error-${id}`}
        >
          {refusal}
        </div>
      )}
      <div className="d-flex gap-2 mt-3">
        <button
          type="button"
          className="btn btn-primary btn-sm"
          disabled={saving || outcome.kind !== 'ends'}
          data-testid={`credential-token-limit-save-${id}`}
          onClick={save}
        >
          Save limit
        </button>
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          disabled={saving}
          data-testid={`credential-token-limit-cancel-${id}`}
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default ConsentLimitPanel;
