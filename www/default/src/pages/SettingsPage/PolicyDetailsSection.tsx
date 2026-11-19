import React from 'react';
import { CopyButton } from '../../components/shared/CopyButton';
import FieldHelp from '../../components/shared/FieldHelp';
import PolicySectionTitle from './policyTemplates/PolicySectionTitle';
import { POLICY_TYPE_NAMES, type PolicyType } from './policyTemplates/types';

interface PolicyDetailsSectionProps {
  isCreateMode: boolean;
  /** False when the Define button that opened the create page already set the Type. */
  showType: boolean;
  readOnly: boolean;
  name: string;
  description: string;
  policyType: PolicyType;
  enabled: boolean;
  /** Edit mode only. */
  policyId?: string;
  contentHash?: string;
  onNameChange: (name: string) => void;
  onDescriptionChange: (description: string) => void;
  onEnabledChange: (enabled: boolean) => void;
}

const ReadOnlyValue: React.FC<{ label: string; value: string; help: string; testId: string }> = ({
  label,
  value,
  help,
  testId,
}) => (
  <div className="policy-details__readonly" data-testid={testId}>
    <span className="small text-muted text-nowrap">
      {label}{' '}
      <FieldHelp testId={`field-help-${testId}`} ariaLabel={`About ${label}`}>
        {help}
      </FieldHelp>
    </span>
    <code className="policy-details__readonly-value" title={value}>
      {value}
    </code>
    <CopyButton text={value} title={`Copy ${label}`} data-testid={`${testId}-copy-button`} />
  </div>
);

/** Name, description, type and status of a policy, plus its id and hash once saved. */
const PolicyDetailsSection: React.FC<PolicyDetailsSectionProps> = ({
  isCreateMode,
  showType,
  readOnly,
  name,
  description,
  policyType,
  enabled,
  policyId,
  contentHash,
  onNameChange,
  onDescriptionChange,
  onEnabledChange,
}) => (
  <section className="policy-section" data-testid="policy-details-section">
    <PolicySectionTitle title="Details" icon="fa-info-circle" />
    <div className="row">
      <div className="col-12 mb-3">
        <div className="field-label-with-help">
          <label htmlFor="policy-name-input" className="mb-0">
            Name <span className="text-danger">*</span>
          </label>
          <FieldHelp testId="field-help-policy-definition-name" ariaLabel="About Name">
            A short, memorable label, this is what you&apos;ll see in the policy list and in
            audit-log entries when this policy makes a decision.
          </FieldHelp>
        </div>
        <input
          id="policy-name-input"
          type="text"
          className="form-control"
          value={name}
          readOnly={readOnly}
          onChange={e => onNameChange(e.target.value)}
          placeholder="e.g. Require Authentication"
          data-testid="policy-definition-name-input"
        />
      </div>
      <div className="col-12 mb-3">
        <div className="field-label-with-help">
          <label htmlFor="policy-description-input" className="mb-0">
            Description
          </label>
          <FieldHelp
            testId="field-help-policy-definition-description"
            ariaLabel="About Description"
          >
            Shown in the policy list and version history, use it to note what this policy enforces
            and why, for whoever looks at this later.
          </FieldHelp>
        </div>
        <textarea
          id="policy-description-input"
          rows={2}
          className="form-control"
          value={description}
          readOnly={readOnly}
          onChange={e => onDescriptionChange(e.target.value)}
          placeholder="What does this policy do?"
          data-testid="policy-definition-description-input"
        />
      </div>
    </div>
    <div className="row">
      {showType && (
        <div className="col-md-6 mb-3">
          <div className="field-label-with-help">
            <label htmlFor="policy-type-select" className="mb-0">
              Type
            </label>
            <FieldHelp testId="field-help-policy-definition-type" ariaLabel="About Type">
              Gateway policies attach to a gateway connection (your own appliance, or one remote
              peer) and can also be enforced appliance-wide from the policy list. Agent Surface
              policies apply only to one specific agent surface&apos;s traffic.
            </FieldHelp>
          </div>
          <select
            id="policy-type-select"
            className="form-control dropdown-styling"
            value={policyType}
            disabled
            title={
              isCreateMode
                ? 'Set by the Define button that opens this page.'
                : "A policy's type is fixed once created."
            }
            data-testid="policy-definition-type-select"
          >
            {(Object.keys(POLICY_TYPE_NAMES) as PolicyType[]).map(type => (
              <option key={type} value={type}>
                {POLICY_TYPE_NAMES[type].label}
              </option>
            ))}
          </select>
          <small className="form-text text-muted">
            <i className="fas fa-lock me-1" aria-hidden="true" />
            {isCreateMode
              ? "Set by the Define button that opens this page. It can't be changed here."
              : "A policy's type is fixed once created."}
          </small>
        </div>
      )}
      <div className="col-md-6 mb-3">
        <div className="field-label-with-help">
          <span>Status</span>
          <FieldHelp testId="field-help-policy-definition-status" ariaLabel="About Status">
            When off, this policy is never evaluated. If this policy is also enforced Globally on
            the list page, turning it off will make every request in that plane fail closed (denied)
            until it&apos;s re-enabled or removed from Global enforcement. Global assignments set to
            Monitor only are unaffected: they just stop logging this policy&apos;s decisions.
          </FieldHelp>
        </div>
        <div className="form-check form-switch">
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id="policy-enabled"
            checked={enabled}
            disabled={readOnly}
            onChange={e => onEnabledChange(e.target.checked)}
            data-testid="policy-definition-enabled-switch"
          />
          <label className="form-check-label" htmlFor="policy-enabled">
            Enabled
          </label>
        </div>
      </div>
    </div>
    {!isCreateMode && (policyId || contentHash) && (
      <div className="policy-details__ids">
        {policyId && (
          <ReadOnlyValue
            label="Policy ID"
            value={policyId}
            help="Referenced by surfaces and gateways and shown in the Audit Log. It can't be changed."
            testId="policy-definition-id"
          />
        )}
        {contentHash && (
          <ReadOnlyValue
            label="SHA"
            value={contentHash}
            help="Content hash of the currently enforced revision."
            testId="policy-definition-sha"
          />
        )}
      </div>
    )}
  </section>
);

export default PolicyDetailsSection;
