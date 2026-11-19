import React, { useEffect, useRef, useState } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { getErrorMessage } from '../../utils/apiError';
import {
  ConsentLimitUnit,
  consentLimitSecondsOf,
  consentLimitUnitsFor,
  limitFieldsOf,
} from '../../utils/consentLimit';
import {
  DelegationToken,
  consentLimitSecs,
  limitOutcome,
  limitOutcomeText,
} from './delegatedAccess';

interface ConsentLimitPanelProps {
  token: DelegationToken;
  providerName: string;
  /** Saves the limit, in seconds after the consent was given. Rejects with why it was refused. */
  onSave: (limitSecs: number) => Promise<void>;
  /** Asks for the panel to be closed: on Cancel, and after a save while it is still shown. */
  onClose: () => void;
}

/**
 * Sets a time limit on one delegation: it then ends that long after its consent was given. It
 * opens in place under the delegation's row, never as a modal or a browser dialog, takes the
 * focus, and offers Save only for a limit that brings the end forward.
 */
const ConsentLimitPanel: React.FC<ConsentLimitPanelProps> = ({
  token,
  providerName,
  onSave,
  onClose,
}) => {
  const currentSecs = consentLimitSecs(token);
  const [fields, setFields] = useState(() => limitFieldsOf(currentSecs));
  const [refusal, setRefusal] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const shown = useRef(true);

  useEffect(() => {
    shown.current = true;
    inputRef.current?.focus();
    return () => {
      shown.current = false;
    };
  }, []);

  const now = new Date();
  const limitSecs = consentLimitSecondsOf(fields.amount, fields.unit);
  const outcome = limitOutcome(token, limitSecs, now);
  const id = token.id;
  const previewId = `credential-token-limit-preview-${id}`;
  const errorId = `credential-token-limit-error-${id}`;
  const titleId = `credential-token-limit-title-${id}`;

  const change = (changed: Partial<typeof fields>) => {
    setFields(held => ({ ...held, ...changed }));
    setRefusal(null);
  };

  const save = async () => {
    if (outcome.kind !== 'ends' || limitSecs === null) return;
    setSaving(true);
    setRefusal(null);
    try {
      await onSave(limitSecs);
    } catch (error) {
      if (shown.current) {
        setRefusal(getErrorMessage(error, 'The gateway did not save the limit.'));
        setSaving(false);
      }
      return;
    }
    if (shown.current) onClose();
  };

  return (
    <div
      className="px-4 py-3"
      id={`credential-token-limit-panel-${id}`}
      role="group"
      aria-labelledby={titleId}
      data-testid={`credential-token-limit-panel-${id}`}
    >
      <div className="fw-semibold mb-2" id={titleId}>
        Limit duration · {providerName}
      </div>
      <div className="d-flex flex-wrap align-items-center gap-2">
        <label className="mb-0" htmlFor={`credential-token-limit-input-${id}`}>
          The agent may act for this person for at most
        </label>
        <input
          ref={inputRef}
          id={`credential-token-limit-input-${id}`}
          type="number"
          min={1}
          step={1}
          className={`form-control form-control-sm${refusal ? ' is-invalid' : ''}`}
          style={{ width: '6rem' }}
          value={fields.amount}
          aria-invalid={refusal ? true : undefined}
          aria-describedby={refusal ? `${previewId} ${errorId}` : previewId}
          data-testid={`credential-token-limit-input-${id}`}
          onChange={e => change({ amount: e.target.value })}
        />
        <select
          className="form-select form-select-sm w-auto"
          aria-label="Unit of the limit"
          value={fields.unit}
          data-testid={`credential-token-limit-unit-${id}`}
          onChange={e => change({ unit: e.target.value as ConsentLimitUnit })}
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
        id={previewId}
        data-testid={previewId}
      >
        {limitOutcomeText(outcome, token.consent_granted_at, now)}
      </div>
      {refusal && (
        <div className="small text-danger mt-1" role="alert" id={errorId} data-testid={errorId}>
          {refusal}
        </div>
      )}
      <div className="d-flex gap-2 mt-3">
        <AppButton
          variant="primary"
          size="sm"
          loading={saving}
          disabled={outcome.kind !== 'ends'}
          data-testid={`credential-token-limit-save-${id}`}
          onClick={save}
        >
          Save limit
        </AppButton>
        <AppButton
          variant="outline-secondary"
          size="sm"
          disabled={saving}
          data-testid={`credential-token-limit-cancel-${id}`}
          onClick={onClose}
        >
          Cancel
        </AppButton>
      </div>
    </div>
  );
};

export default ConsentLimitPanel;
