import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import FieldHelp from '../../../components/shared/FieldHelp';
import PolicyRulesList from './PolicyRulesList';
import PolicySectionTitle from './PolicySectionTitle';
import RegoReference from './RegoReference';
import { parsePolicyRules, ruleInUse, type PolicyRule, type RuleGroup } from './regoRules';
import { DecisionBadge } from './TemplateBadges';
import type { PolicyType } from './types';
import './PolicyTemplates.css';

export type PolicyView = 'rules' | 'rego';

const monoError: React.CSSProperties = {
  whiteSpace: 'pre-wrap',
  fontFamily: 'Monaco, Consolas, "Courier New", monospace',
  fontSize: '0.8rem',
};

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
            <DecisionBadge
              decision={empty ? 'allow' : (parsed.defaultDecision ?? 'deny')}
              prefix="Default"
            />
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
          <button
            type="button"
            className="btn btn-sm btn-outline-primary ms-auto"
            onClick={onAdd}
            data-testid="policy-templates-insert-button"
          >
            <i className="fas fa-plus me-1" aria-hidden="true" />
            Add rules from a template
          </button>
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
          onAdd={onAdd}
          onWriteRego={() => onViewChange('rego')}
          onRemoveGroup={onRemoveGroup}
          onRemoveRule={onRemoveRule}
          isRuleInUse={rule => ruleInUse(policy, parsed, rule)}
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
              <span key={idx} style={monoError}>
                {err}
              </span>
            ))}
          </div>
        )}
        {packageMismatch && (
          <div
            className="alert alert-danger py-2 px-3 mt-2 mb-0 d-flex align-items-start"
            style={{ fontSize: '0.85rem' }}
          >
            <i className="fas fa-exclamation-triangle me-2 mt-1 flex-shrink-0" aria-hidden="true" />
            <div>
              <strong>Package mismatch:</strong> {packageMismatch}
              <button
                type="button"
                className="btn btn-sm btn-danger ms-2 py-0 px-2"
                style={{ fontSize: '0.8rem' }}
                onClick={onFixPackage}
              >
                Fix it
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};

export default PolicyEditorSection;
