import React from 'react';
import { auditLimitError, type AuditDeliveryLimits } from '../../utils/auditIntegrations';

interface AuditDeliveryLimitsSectionProps {
  limits: AuditDeliveryLimits;
  onChange: (limits: AuditDeliveryLimits) => void;
  disabled?: boolean;
}

interface LimitField {
  key: keyof AuditDeliveryLimits;
  testId: string;
  label: string;
  unit: string;
  hint: string;
}

const FIELDS: LimitField[] = [
  {
    key: 'maxAttempts',
    testId: 'integration-audit-max-attempts',
    label: 'Give up on a record after',
    unit: 'attempts',
    hint: 'Empty retries a record until it is delivered. While the destination is down, records are skipped too once they reach the limit.',
  },
  {
    key: 'dropAfterSecs',
    testId: 'integration-audit-drop-after',
    label: 'Skip records older than',
    unit: 'seconds',
    hint: 'Empty never skips a record for its age.',
  },
];

/** When a Governance Audit integration stops retrying a record and skips it. */
const AuditDeliveryLimitsSection: React.FC<AuditDeliveryLimitsSectionProps> = ({
  limits,
  onChange,
  disabled = false,
}) => (
  <div className="mb-3" data-testid="integration-audit-limits">
    <label className="form-label fw-bold mb-1">Delivery limits</label>
    <div className="row g-3">
      {FIELDS.map(field => {
        const error = auditLimitError(limits[field.key]);
        return (
          <div className="col-md-6" key={field.key}>
            <label htmlFor={field.testId} className="form-label small mb-1">
              {field.label}
            </label>
            <div className="input-group input-group-sm has-validation">
              <input
                id={field.testId}
                type="number"
                min={1}
                step={1}
                className={`form-control${error ? ' is-invalid' : ''}`}
                placeholder="Never"
                value={limits[field.key]}
                onChange={e => onChange({ ...limits, [field.key]: e.target.value })}
                disabled={disabled}
                data-testid={`${field.testId}-input`}
              />
              <span className="input-group-text">{field.unit}</span>
              {error && (
                <div className="invalid-feedback" data-testid={`${field.testId}-error`}>
                  {error}
                </div>
              )}
            </div>
            <small className="form-text text-muted">{field.hint}</small>
          </div>
        );
      })}
    </div>
  </div>
);

export default AuditDeliveryLimitsSection;
