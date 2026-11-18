import React from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import InfoBanner from '../../../components/shared/InfoBanner';
import type { ParsedPolicy, PolicyRule, RuleGroup, RuleKind } from './regoRules';

interface PolicyRulesListProps {
  parsed: ParsedPolicy;
  /** Shows Add rules, Remove and Deny by default. */
  canEdit: boolean;
  /** False while the Rego doesn't compile. */
  valid: boolean;
  /** The package doesn't match the Type, which the banner names instead of a compile error. */
  packageMismatch: boolean;
  /** An empty policy, which the gateway treats as allowing every request. */
  empty: boolean;
  /** The template whose rules were added last, marked "Just added". */
  justAdded: string | null;
  onAdd: () => void;
  onWriteRego: () => void;
  onRemoveGroup: (group: RuleGroup) => void;
  onRemoveRule: (rule: PolicyRule) => void;
  /** A rule `allow` still reads through other rules, which Remove refuses. */
  isRuleInUse: (rule: PolicyRule) => boolean;
  /** A template group whose rules `allow` still reads from outside it, which Remove refuses. */
  isGroupInUse: (group: RuleGroup) => boolean;
  onSetDefaultDeny: () => void;
  onShowRule: (rule: PolicyRule) => void;
}

const KIND_LABEL: Record<RuleKind, string> = {
  allow: 'Allows',
  deny: 'Deny reason',
  helper: 'Helper',
};

const KIND_TITLE: Record<RuleKind, string> = {
  allow: 'Allows the request when its conditions match',
  deny: 'Gives the reason a request was denied; does not decide it',
  helper: 'Read by other rules; decides nothing on its own',
};

const RULE_IN_USE = 'Another rule uses this; remove that rule first';
const GROUP_IN_USE = 'A rule outside this template uses its rules; remove that rule first';

const lineLabel = (rule: PolicyRule) =>
  rule.startLine === rule.endLine
    ? `Line ${rule.startLine}`
    : `Lines ${rule.startLine}–${rule.endLine}`;

/** The Rules view of the policy: the rules in the Rego, grouped by the template they came from. */
const PolicyRulesList: React.FC<PolicyRulesListProps> = ({
  parsed,
  canEdit,
  valid,
  packageMismatch,
  empty,
  justAdded,
  onAdd,
  onWriteRego,
  onRemoveGroup,
  onRemoveRule,
  isRuleInUse,
  isGroupInUse,
  onSetDefaultDeny,
  onShowRule,
}) => {
  if (!parsed.ok) {
    return (
      <div data-testid="policy-rules-unparsed">
        <InfoBanner
          variant="warning"
          icon="fa-exclamation-triangle"
          collapsible={false}
          className="mb-2"
          summary="The rules can't be listed until every bracket in the Rego is closed."
        >
          <AppButton
            variant="outline-primary"
            onClick={onWriteRego}
            data-testid="policy-rules-open-rego-button"
          >
            Open Rego
          </AppButton>
        </InfoBanner>
      </div>
    );
  }

  const allowRules = parsed.groups.some(g => g.rules.some(r => r.kind === 'allow'));
  const lastJustAdded = parsed.groups.reduce<RuleGroup | null>(
    (last, g) => (g.source.kind === 'template' && g.source.name === justAdded ? g : last),
    null
  );

  return (
    <div className="policy-rules" data-testid="policy-rules-list">
      {!valid && (
        <div data-testid="policy-rules-invalid-banner">
          <InfoBanner
            variant="danger"
            icon="fa-circle-exclamation"
            collapsible={false}
            className="mb-2"
            summary={
              packageMismatch
                ? "The package doesn't match the policy Type, so the policy can't be saved."
                : "The Rego doesn't compile, so the policy can't be saved."
            }
          >
            <AppButton
              variant="outline-primary"
              onClick={onWriteRego}
              data-testid="policy-rules-invalid-open-rego-button"
            >
              Open Rego
            </AppButton>
          </InfoBanner>
        </div>
      )}

      {parsed.defaultDecision === 'allow' && allowRules && (
        <div data-testid="policy-rules-allow-default-warning">
          <InfoBanner
            variant="warning"
            icon="fa-exclamation-triangle"
            collapsible={false}
            className="mb-2"
            summary="Every request is allowed by default, so the allow rules below change nothing."
          >
            {canEdit && (
              <AppButton
                variant="outline-primary"
                onClick={onSetDefaultDeny}
                data-testid="policy-rules-set-default-deny-button"
              >
                Deny by default
              </AppButton>
            )}
          </InfoBanner>
        </div>
      )}

      {parsed.groups.length === 0 && (
        <div className="policy-rules__empty" data-testid="policy-rules-empty">
          <i className="fas fa-list-check fa-lg text-muted" aria-hidden="true" />
          <div className="fw-bold mt-2">No rules yet</div>
          <div className="small text-muted mb-2">
            {empty
              ? 'An empty policy allows every request.'
              : `The default decision (${parsed.defaultDecision === 'allow' ? 'allow' : 'deny'}) applies to every request.`}
          </div>
          {canEdit && (
            <div className="d-flex justify-content-center flex-wrap gap-2">
              <AppButton
                onClick={onAdd}
                iconStart={<i className="fas fa-plus" aria-hidden="true" />}
                data-testid="policy-rules-add-button"
              >
                Add rules from a template
              </AppButton>
              <AppButton
                variant="outline-primary"
                onClick={onWriteRego}
                iconStart={<i className="fas fa-code" aria-hidden="true" />}
                data-testid="policy-rules-write-rego-button"
              >
                Write Rego
              </AppButton>
            </div>
          )}
        </div>
      )}

      {parsed.groups.map((group, index) => {
        const isTemplate = group.source.kind === 'template';
        const testId = `policy-rules-group-${index}`;
        const groupInUse = isTemplate && canEdit && isGroupInUse(group);
        return (
          <div
            className="policy-rules__group"
            key={`${group.startLine}-${index}`}
            data-testid={testId}
          >
            <div className="policy-rules__group-header">
              <span className="small text-muted">
                {group.source.kind === 'template' ? (
                  <>
                    <i className="fas fa-layer-group me-1" aria-hidden="true" />
                    From template <strong>{group.source.name}</strong>
                  </>
                ) : (
                  <>
                    <i className="fas fa-pen me-1" aria-hidden="true" />
                    Written in the editor
                  </>
                )}
              </span>
              {group === lastJustAdded && (
                <Badge tone="success" value="Just added" data-testid="policy-rules-just-added" />
              )}
              {isTemplate && canEdit && (
                <AppButton
                  variant="link"
                  className="text-danger p-0 ms-auto"
                  disabled={groupInUse}
                  onClick={() => onRemoveGroup(group)}
                  aria-label={`Remove the rules from ${group.source.kind === 'template' ? group.source.name : 'the editor'}`}
                  aria-describedby={groupInUse ? `${testId}-in-use` : undefined}
                  data-testid={`${testId}-remove-button`}
                >
                  Remove
                </AppButton>
              )}
            </div>
            {groupInUse && (
              <div
                className="small text-muted ps-2 mb-1"
                id={`${testId}-in-use`}
                data-testid={`${testId}-in-use`}
              >
                {GROUP_IN_USE}
              </div>
            )}
            {group.rules.length === 0 && (
              <div className="small text-muted ps-2">No rules left from this template.</div>
            )}
            <ul className="list-unstyled mb-0">
              {group.rules.map((rule, ruleIndex) => {
                const ruleTestId = `${testId}-rule-${ruleIndex}`;
                const inUse = canEdit && isRuleInUse(rule);
                return (
                  <li
                    key={rule.startLine}
                    className={`policy-rules__rule${inUse ? ' policy-rules__rule--in-use' : ''}`}
                    data-testid={ruleTestId}
                  >
                    <span className="badge policy-rules__kind" title={KIND_TITLE[rule.kind]}>
                      {KIND_LABEL[rule.kind]}
                    </span>
                    <code className="policy-rules__summary" title={rule.summary}>
                      {rule.summary}
                    </code>
                    <AppButton
                      variant="link"
                      className="p-0 text-nowrap"
                      onClick={() => onShowRule(rule)}
                      aria-label={`Show ${rule.head} in the Rego`}
                      data-testid={`${ruleTestId}-show-button`}
                    >
                      {lineLabel(rule)}
                    </AppButton>
                    {canEdit && (
                      <AppButton
                        variant="link"
                        className="text-danger p-0 text-nowrap"
                        disabled={inUse}
                        title={inUse ? RULE_IN_USE : undefined}
                        onClick={() => onRemoveRule(rule)}
                        aria-label={`Remove the rule ${rule.head}`}
                        aria-describedby={inUse ? `${ruleTestId}-in-use` : undefined}
                        data-testid={`${ruleTestId}-remove-button`}
                      >
                        Remove
                      </AppButton>
                    )}
                    {inUse && (
                      <span
                        className="policy-rules__in-use small text-muted"
                        id={`${ruleTestId}-in-use`}
                        data-testid={`${ruleTestId}-in-use`}
                      >
                        {RULE_IN_USE}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </div>
  );
};

export default PolicyRulesList;
