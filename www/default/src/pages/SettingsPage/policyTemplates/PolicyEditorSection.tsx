import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import FieldHelp from '../../../components/shared/FieldHelp';
import PolicyRulesList from './PolicyRulesList';
import PolicySectionTitle from './PolicySectionTitle';
import RegoReference from './RegoReference';
import { groupUse, parsePolicyRules, ruleUse, type PolicyRule, type RuleGroup } from './regoRules';
import { DecisionBadge } from './TemplateBadges';
import type { PolicyType } from './types';
import './PolicyTemplates.css';

export type PolicyView = 'rules' | 'rego';

interface PolicyEditorSectionProps {
  step?: number;
  policy: string;
  policyType: PolicyType;
  onPolicyChange: (policy: string) => void;
  view: PolicyView;
  onViewChange: (view: PolicyView) => void;
  regoRef: React.RefObject<HTMLTextAreaElement>;
  canEdit: boolean;
  isValidating: boolean;
  policyValid: boolean;
  policyErrors: string[];
  packageMismatch: string | null;
  onFixPackage: () => void;
  justAdded: string | null;
  /** Per rule group, the other Type its template was written for. */
  otherTypeGroups?: (PolicyType | null)[];
  /** The template a new policy's own rules started from, while they still follow it. */
  startedFrom?: string | null;
  onAdd: () => void;
  onRemoveGroup: (group: RuleGroup) => void;
  onRemoveRule: (rule: PolicyRule) => void;
  onSetDefaultDeny: () => void;
  /** Selects a rule's lines in the Rego textarea. */
  onShowRule: (rule: PolicyRule) => void;
}

/** The policy itself: a Rules view of the Rego, and the Rego editor. */
const PolicyEditorSection: React.FC<PolicyEditorSectionProps> = ({
  step,
  policy,
  policyType,
  onPolicyChange,
  view,
  onViewChange,
  regoRef,
  canEdit,
  isValidating,
  policyValid,
  policyErrors,
  packageMismatch,
  onFixPackage,
  justAdded,
  otherTypeGroups,
  startedFrom = null,
  onAdd,
  onRemoveGroup,
  onRemoveRule,
  onSetDefaultDeny,
  onShowRule,
}) => {
  const parsed = useMemo(() => parsePolicyRules(policy), [policy]);
  const ruleCount = parsed.ok ? parsed.groups.reduce((n, g) => n + g.rules.length, 0) : 0;
  const valid = policyValid && !packageMismatch;
  // The gateway treats an empty policy as allowing every request.
  const empty = !policy.trim();
  const [pendingRule, setPendingRule] = useState<PolicyRule | null>(null);
  const gutterRef = useRef<HTMLPreElement>(null);
  const lineCount = Math.max(1, policy.split('\n').length);

  // The textarea can take the selection only once the Rego view is shown.
  useEffect(() => {
    if (view !== 'rego' || !pendingRule) return;
    onShowRule(pendingRule);
    setPendingRule(null);
  }, [view, pendingRule, onShowRule]);

  const showRule = (rule: PolicyRule) => {
    setPendingRule(rule);
    onViewChange('rego');
  };

  const syncGutter = () => {
    if (gutterRef.current && regoRef.current) {
      gutterRef.current.scrollTop = regoRef.current.scrollTop;
    }
  };

  return (
    <section className="policy-section" data-testid="policy-editor-section">
      <PolicySectionTitle step={step} title="Policy">
        <div className="btn-group btn-group-sm" role="group" aria-label="Policy view">
          {(
            [
              ['rules', 'Rules', 'fa-list-check'],
              ['rego', 'Rego', 'fa-code'],
            ] as const
          ).map(([key, label, icon]) => (
            <AppButton
              key={key}
              variant={view === key ? 'primary' : 'outline-secondary'}
              aria-pressed={view === key}
              onClick={() => onViewChange(key)}
              iconStart={<i className={`fas ${icon}`} aria-hidden="true" />}
              data-testid={`policy-view-${key}`}
            >
              {label}
            </AppButton>
          ))}
        </div>
      </PolicySectionTitle>

      <div className="policy-editor__status">
        {parsed.ok && (
          <>
            <span className="text-muted small" data-testid="policy-rules-count">
              {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'}
            </span>
            <DecisionBadge decision={empty ? 'allow' : (parsed.defaultDecision ?? 'deny')} />
          </>
        )}
        {isValidating && (
          <span className="text-muted small" data-testid="policy-compile-status">
            <i className="fas fa-spinner fa-spin" aria-hidden="true" /> Compiling...
          </span>
        )}
        {!isValidating && policy.trim() && valid && (
          <span className="text-success small" data-testid="policy-compile-status">
            <i className="fas fa-check-circle" aria-hidden="true" /> Valid
          </span>
        )}
        {!isValidating && policy.trim() && !valid && (
          <span className="text-danger small" data-testid="policy-compile-status">
            <i className="fas fa-circle-exclamation" aria-hidden="true" /> Invalid
          </span>
        )}
        {canEdit && (
          <AppButton
            variant="outline-primary"
            className="ms-auto"
            onClick={onAdd}
            iconStart={<i className="fas fa-plus" aria-hidden="true" />}
            data-testid="policy-templates-insert-button"
          >
            Add rules from a template
          </AppButton>
        )}
      </div>

      <div className={view === 'rules' ? '' : 'd-none'} data-testid="policy-view-rules-panel">
        <PolicyRulesList
          parsed={parsed}
          canEdit={canEdit}
          valid={valid || isValidating}
          packageMismatch={!!packageMismatch}
          empty={empty}
          justAdded={justAdded}
          otherTypeGroups={otherTypeGroups}
          onAdd={onAdd}
          onWriteRego={() => onViewChange('rego')}
          onRemoveGroup={onRemoveGroup}
          onRemoveRule={onRemoveRule}
          ruleUse={rule => ruleUse(parsed, rule)}
          groupUse={group => groupUse(parsed, group)}
          startedFrom={startedFrom}
          onSetDefaultDeny={onSetDefaultDeny}
          onShowRule={showRule}
        />
      </div>

      <div className={view === 'rego' ? '' : 'd-none'} data-testid="policy-view-rego-panel">
        <RegoReference policyType={policyType} />
        <label className="font-weight-bold" htmlFor="policy-rego-input">
          Policy Content (Rego){' '}
          <FieldHelp testId="field-help-policy-definition-content" ariaLabel="About Policy Content">
            Rego is the policy language OPA (Open Policy Agent) uses to evaluate these rules. See
            the Rego reference above for the input fields and examples.
          </FieldHelp>
        </label>
        <div className={`policy-rego-editor${valid ? '' : ' is-invalid'}`}>
          <pre className="policy-rego-gutter" ref={gutterRef} aria-hidden="true">
            {Array.from({ length: lineCount }, (_, i) => i + 1).join('\n')}
          </pre>
          <textarea
            id="policy-rego-input"
            ref={regoRef}
            className={`form-control font-monospace policy-rego-textarea ${valid ? '' : 'is-invalid'}`}
            rows={18}
            wrap="off"
            spellCheck={false}
            value={policy}
            readOnly={!canEdit}
            onChange={e => onPolicyChange(e.target.value)}
            onScroll={syncGutter}
            placeholder="...add policy here..."
            data-testid="policy-rego-textarea"
          />
        </div>
        <small className="form-text text-muted">
          Leave empty to allow all traffic. Changing the Rego creates a new version each time you
          save.
        </small>
        {policyErrors.length > 0 && (
          <div className="alert alert-danger compile-error-alert py-2 px-3 mt-2 mb-0">
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {policyErrors.map((err, idx) => (
              <span key={idx} className="policy-error-text">
                {err}
              </span>
            ))}
          </div>
        )}
        {packageMismatch && (
          <div className="alert alert-danger policy-package-mismatch py-2 px-3 mt-2 mb-0 d-flex align-items-start">
            <i className="fas fa-exclamation-triangle me-2 mt-1 flex-shrink-0" aria-hidden="true" />
            <div>
              <strong>Package mismatch:</strong> {packageMismatch}
              {canEdit && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger ml-2 py-0 px-2 policy-fix-package-button"
                  onClick={onFixPackage}
                >
                  Fix it
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};

export default PolicyEditorSection;
