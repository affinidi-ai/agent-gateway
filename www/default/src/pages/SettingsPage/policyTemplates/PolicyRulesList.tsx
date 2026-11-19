import React from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import InfoBanner from '../../../components/shared/InfoBanner';
import type {
  DecisionSummary,
  ParsedPolicy,
  PolicyRule,
  RuleGroup,
  RuleRole,
  RuleUse,
} from './regoRules';
import { POLICY_TYPE_NAMES, type PolicyType } from './types';

interface PolicyRulesListProps {
  parsed: ParsedPolicy;
  /** What the policy decides (`summarizeDecision`), or null when there is nothing to summarise. */
  summary: DecisionSummary | null;
  /** Each rule's part in the decision (`ruleRoles`). */
  ruleRole: (rule: PolicyRule) => RuleRole;
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
  /** Per group, the other Type its template was written for (`groupsForOtherType`). */
  otherTypeGroups?: (PolicyType | null)[];
  onAdd: () => void;
  onWriteRego: () => void;
  onRemoveGroup: (group: RuleGroup) => void;
  onRemoveRule: (rule: PolicyRule) => void;
  /** Why Remove refuses a rule `allow` still reads through other rules; null when it doesn't. */
  ruleUse: (rule: PolicyRule) => RuleUse | null;
  /** Why Remove refuses a template group whose rules `allow` reads from outside it. */
  groupUse: (group: RuleGroup) => RuleUse | null;
  /** The template a new policy's own rules started from, while they still follow it. */
  startedFrom: string | null;
  onSetDefaultDeny: () => void;
  onShowRule: (rule: PolicyRule) => void;
}

const ROLE_LABEL: Record<RuleRole, string> = {
  allow: 'Allows',
  'deny-reason': 'Deny reason',
  'used-by-allow': 'Used by allow',
  'not-used-by-allow': 'Not used by allow',
};

const ROLE_TITLE: Record<RuleRole, string> = {
  allow: 'Allows the request when its conditions match',
  'deny-reason': 'Gives the reason a request was denied; does not decide it',
  'used-by-allow':
    'allow reads this rule, directly or through other rules, so it changes what the policy decides',
  'not-used-by-allow':
    "allow doesn't read this rule, so it doesn't change whether a request is allowed",
};

const DecisionSummaryText: React.FC<{ summary: DecisionSummary }> = ({ summary }) => {
  switch (summary.kind) {
    case 'unsummarised':
      return <>The Rules view can&apos;t summarise how this policy sets allow. Read the Rego.</>;
    case 'allows-all':
      return summary.reason === 'default' ? (
        <>This policy allows every request: the default is ALLOW.</>
      ) : (
        <>This policy allows every request: an allow rule has no conditions.</>
      );
    case 'any-allow':
      return (
        <>
          This policy allows a request when {summary.allowRules === 1 ? 'its' : 'any'} allow rule
          matches. Otherwise:{' '}
          <span
            className="audit-decision audit-decision--deny"
            data-testid="policy-rules-summary-otherwise"
          >
            <i className="fas fa-xmark" aria-hidden="true" />
            DENY
          </span>
          {!summary.hasDefault && ' (no default is set)'}
        </>
      );
    case 'denies-all':
      return summary.hasDefault ? (
        <>This policy denies every request: no rule allows one.</>
      ) : (
        <>This policy denies every request: no rule allows one and no default is set.</>
      );
  }
};

const DOCUMENT_READ =
  'The Rego reads the policy as a whole document; remove rules in the Rego view.';

const readerText = (use: RuleUse) =>
  use.kind === 'reader' ? ` (${use.name}, line ${use.line})` : '';

const ruleInUseText = (use: RuleUse) =>
  use.kind === 'document'
    ? DOCUMENT_READ
    : `Another rule uses this${readerText(use)}; remove that rule first.`;

const groupInUseText = (use: RuleUse) =>
  use.kind === 'document'
    ? DOCUMENT_READ
    : `A rule outside this template uses its rules${readerText(use)}; remove that rule first.`;

const otherTypeOf = (type: PolicyType): PolicyType =>
  type === 'gateway' ? 'agent_surface' : 'gateway';

const Misfit: React.FC<{ testId: string; children: React.ReactNode }> = ({ testId, children }) => (
  <div className="policy-rules__misfit small" data-testid={testId}>
    <i className="fas fa-exclamation-triangle" aria-hidden="true" />
    <span>{children}</span>
  </div>
);

const lineRange = (rule: PolicyRule) =>
  rule.startLine === rule.endLine ? `${rule.startLine}` : `${rule.startLine}–${rule.endLine}`;

const lineLabel = (rule: PolicyRule) =>
  `${rule.startLine === rule.endLine ? 'Line' : 'Lines'} ${lineRange(rule)}`;

/** The Rules view of the policy: the rules in the Rego, grouped by the template they came from. */
const PolicyRulesList: React.FC<PolicyRulesListProps> = ({
  parsed,
  summary,
  ruleRole,
  canEdit,
  valid,
  packageMismatch,
  empty,
  justAdded,
  otherTypeGroups = [],
  onAdd,
  onWriteRego,
  onRemoveGroup,
  onRemoveRule,
  ruleUse,
  groupUse,
  startedFrom,
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
          summary="The rules can't be listed: a bracket is open, or a statement doesn't start with a rule name."
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

  const allows = (g: RuleGroup) => g.rules.some(r => r.kind === 'allow');
  const allowRules = parsed.groups.some(allows);
  // Default ALLOW makes allow rules moot only while every allow definition is plain.
  const allowByDefault = parsed.defaultDecision === 'allow' && summary?.kind !== 'unsummarised';
  const misfitType = otherTypeGroups.find((t): t is PolicyType => t !== null);
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

      {misfitType && (
        <div data-testid="policy-rules-other-type-banner">
          <InfoBanner
            variant="warning"
            icon="fa-exclamation-triangle"
            collapsible={false}
            className="mb-2"
            summary={`Remove the rules written for ${POLICY_TYPE_NAMES[misfitType].name} policies to create this policy.`}
          />
        </div>
      )}

      {allowByDefault && allowRules && (
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

      {valid && summary && (
        <p className="text-muted small mb-2" data-testid="policy-rules-summary">
          <i className="fas fa-info-circle me-1" aria-hidden="true" />
          <DecisionSummaryText summary={summary} />
        </p>
      )}

      {parsed.groups.length === 0 && (
        <div className="policy-rules__empty" data-testid="policy-rules-empty">
          <i className="fas fa-list-check fa-lg text-muted" aria-hidden="true" />
          <div className="fw-bold mt-2">No rules yet</div>
          <div className="small text-muted mb-2">
            {empty
              ? 'An empty policy allows every request.'
              : parsed.defaultDecision === null
                ? 'No default is set, so every request is denied.'
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
        const groupReason = isTemplate && canEdit ? groupUse(group) : null;
        const groupInUse = groupReason !== null;
        const writtenFor = otherTypeGroups[index] ?? null;
        const noEffect = allowByDefault && allows(group);
        const ruleCount = group.rules.length;
        return (
          <div className="card mb-2" key={`${group.startLine}-${index}`} data-testid={testId}>
            <div className="card-header py-2 policy-rules__group-header">
              <span className="small text-muted">
                {group.source.kind === 'template' ? (
                  <>
                    <i className="fas fa-layer-group me-1" aria-hidden="true" />
                    From template: <strong>{group.source.name}</strong>
                  </>
                ) : (
                  <>
                    <i className="fas fa-pen me-1" aria-hidden="true" />
                    <strong>Your rules</strong>
                    {startedFrom && ` · started from ${startedFrom}`}
                  </>
                )}
              </span>
              <span className="small text-muted" data-testid={`${testId}-count`}>
                {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'}
              </span>
              {group === lastJustAdded && (
                <Badge tone="success" value="Just added" data-testid="policy-rules-just-added" />
              )}
              {isTemplate && canEdit && (
                <AppButton
                  variant="outline-danger"
                  className="ms-auto"
                  disabled={groupInUse}
                  onClick={() => onRemoveGroup(group)}
                  aria-label={`Remove the rules from ${group.source.kind === 'template' ? group.source.name : 'the editor'}`}
                  aria-describedby={groupInUse ? `${testId}-in-use` : undefined}
                  data-testid={`${testId}-remove-button`}
                >
                  Remove group
                </AppButton>
              )}
            </div>
            {(groupReason || writtenFor || noEffect || ruleCount === 0) && (
              <div className="card-body py-2 policy-rules__notes">
                {groupReason && (
                  <div
                    className="small text-muted mb-1"
                    id={`${testId}-in-use`}
                    data-testid={`${testId}-in-use`}
                  >
                    {groupInUseText(groupReason)}
                  </div>
                )}
                {writtenFor && (
                  <Misfit testId={`${testId}-other-type`}>
                    Written for {POLICY_TYPE_NAMES[writtenFor].name} policies. It reads input{' '}
                    {POLICY_TYPE_NAMES[otherTypeOf(writtenFor)].name} policies don&apos;t get.
                    Remove it to create this policy.
                  </Misfit>
                )}
                {noEffect && (
                  <Misfit testId={`${testId}-no-effect`}>
                    No effect while the default is ALLOW.
                  </Misfit>
                )}
                {ruleCount === 0 && (
                  <div className="small text-muted">No rules left from this template.</div>
                )}
              </div>
            )}
            {ruleCount > 0 && (
              <table className="table table-sm align-middle mb-0 policy-rules__table">
                <thead className="thead-light">
                  <tr>
                    <th className="policy-rules__col-kind">Kind</th>
                    <th>Rule</th>
                    <th className="policy-rules__col-line">Line</th>
                    {canEdit && (
                      <th className="policy-rules__col-actions">
                        <span className="visually-hidden">Actions</span>
                      </th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {group.rules.map((rule, ruleIndex) => {
                    const ruleTestId = `${testId}-rule-${ruleIndex}`;
                    const reason = canEdit ? ruleUse(rule) : null;
                    const inUse = reason !== null;
                    const role = ruleRole(rule);
                    return (
                      <tr key={rule.startLine} data-testid={ruleTestId}>
                        <td>
                          <span
                            className="badge policy-rules__kind"
                            title={ROLE_TITLE[role]}
                            data-testid={`${ruleTestId}-kind`}
                          >
                            {ROLE_LABEL[role]}
                          </span>
                        </td>
                        <td>
                          <code className="policy-rules__summary" title={rule.summary}>
                            {rule.summary}
                          </code>
                          {reason && (
                            <div
                              className="small text-muted mt-1"
                              id={`${ruleTestId}-in-use`}
                              data-testid={`${ruleTestId}-in-use`}
                            >
                              {ruleInUseText(reason)}
                            </div>
                          )}
                        </td>
                        <td>
                          <AppButton
                            variant="outline-secondary"
                            size="sm"
                            className="text-nowrap font-monospace"
                            iconStart={<i className="fas fa-code" aria-hidden="true" />}
                            onClick={() => onShowRule(rule)}
                            title="Show in the Rego"
                            aria-label={`Show ${rule.head} in the Rego, ${lineLabel(rule).toLowerCase()}`}
                            data-testid={`${ruleTestId}-show-button`}
                          >
                            {lineRange(rule)}
                          </AppButton>
                        </td>
                        {canEdit && (
                          <td className="text-end">
                            <AppButton
                              variant="outline-danger"
                              size="sm"
                              disabled={inUse}
                              title={reason ? ruleInUseText(reason) : 'Remove'}
                              onClick={() => onRemoveRule(rule)}
                              aria-label={`Remove the rule ${rule.head}`}
                              aria-describedby={inUse ? `${ruleTestId}-in-use` : undefined}
                              data-testid={`${ruleTestId}-remove-button`}
                            >
                              <i className="fas fa-trash" aria-hidden="true" />
                            </AppButton>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default PolicyRulesList;
