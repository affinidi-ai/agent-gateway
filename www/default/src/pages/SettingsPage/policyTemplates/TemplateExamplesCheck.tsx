import React, { useEffect, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import { usePolicyTemplateServices } from './policyTemplateServices';
import { defaultDecision } from './regoTemplate';
import type { PolicyDecision, PolicyTemplate, PolicyType } from './types';

interface TemplateExamplesCheckProps {
  policyId: string;
  policyType: PolicyType;
  /** The editor's current Rego, so unsaved edits are checked. */
  draftPolicy: string;
  template: PolicyTemplate;
  /** False when the template was inserted with a setting changed from its default. */
  usesDefaultSettings: boolean;
  onDismiss: () => void;
  /** Opens an example's input in Test (dry-run). */
  onLoadInTest?: (name: string, input: Record<string, unknown>) => void;
}

type Outcome = { decision: PolicyDecision; reason?: string } | { error: string } | null;

/** Why an example's decision differs from the one the template expects. */
function differsBecause(
  expected: PolicyDecision,
  allowsByDefault: boolean,
  reason?: string
): string {
  if (expected === 'deny' && allowsByDefault) {
    return 'This policy allows every request by default, so its allow rules change nothing. Use Deny by default in the Rules view.';
  }
  if (expected === 'deny') {
    return 'Another allow rule in this policy lets this request through. Allow rules combine with OR, so the template adds nothing here until that rule is narrowed or removed.';
  }
  return `This policy denies it, though the template expects it to be allowed. Load it in Test to see the decision.${reason ? ` Reason: ${reason}` : ''}`;
}

/**
 * Runs an inserted template's examples against the draft policy and shows each expected
 * decision beside the one the draft gives, so a rule elsewhere in the policy that
 * overrides the template shows before saving.
 */
const TemplateExamplesCheck: React.FC<TemplateExamplesCheckProps> = ({
  policyId,
  policyType,
  draftPolicy,
  template,
  usesDefaultSettings,
  onDismiss,
  onLoadInTest,
}) => {
  const { simulate } = usePolicyTemplateServices();
  const [outcomes, setOutcomes] = useState<Outcome[]>(() => template.examples.map(() => null));

  useEffect(() => {
    let cancelled = false;
    // Earlier decisions were for an earlier draft; show the rows as running until these return.
    setOutcomes(template.examples.map(() => null));
    const timer = setTimeout(async () => {
      const results = await Promise.all(
        template.examples.map(async (ex): Promise<Outcome> => {
          try {
            const r = await simulate(policyId, policyType, draftPolicy, ex.input);
            return { decision: r.allow ? 'allow' : 'deny', reason: r.reason };
          } catch (e) {
            return { error: e instanceof Error ? e.message : 'Dry-run failed' };
          }
        })
      );
      if (!cancelled) setOutcomes(results);
    }, 500);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [policyId, policyType, draftPolicy, template, simulate]);

  // The examples were written for the default settings, so a different decision after a
  // setting changed says nothing about the rest of the policy.
  const isMismatch = (o: Outcome, i: number) =>
    usesDefaultSettings && !!o && 'decision' in o && o.decision !== template.examples[i].expected;
  const mismatches = outcomes.filter(isMismatch).length;
  const allowsByDefault = defaultDecision(draftPolicy) === 'allow';

  return (
    <div
      className="card shadow-sm mb-4 border-left-primary"
      data-testid="policy-template-examples-card"
    >
      <div className="card-body py-3 px-3">
        <div className="d-flex justify-content-between align-items-center mb-2">
          <h6 className="font-weight-bold text-primary mb-0">
            <i className="fas fa-layer-group me-2" aria-hidden="true" />
            Template examples
          </h6>
          <button
            type="button"
            className="btn-close"
            aria-label="Hide template examples"
            onClick={onDismiss}
            data-testid="policy-template-examples-close-button"
          />
        </div>
        <p className="text-muted small mb-2">
          {template.name} · run through Test (dry-run) against this draft, saved or not.
        </p>
        {!usesDefaultSettings && (
          <p
            className="text-muted small mb-2"
            data-testid="policy-template-examples-changed-settings"
          >
            <i className="fas fa-info-circle me-1" aria-hidden="true" />
            The examples assume the template&apos;s default settings, and you changed one, so a
            different decision is expected and not highlighted.
          </p>
        )}
        <div className="table-responsive">
          <table className="table table-sm mb-2">
            <thead className="thead-light">
              <tr>
                <th>Example</th>
                <th>Expected</th>
                <th>This policy</th>
                <th>Result</th>
                {onLoadInTest && (
                  <th>
                    <span className="visually-hidden">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {template.examples.map((ex, i) => {
                const o = outcomes[i];
                const mismatch = isMismatch(o, i);
                return (
                  <tr
                    key={`${i}-${ex.name}`}
                    className={mismatch ? 'table-warning' : undefined}
                    data-testid={`policy-template-example-row-${i}`}
                  >
                    <td>
                      {ex.name}
                      {mismatch && o && 'decision' in o && (
                        <div
                          className="small text-muted"
                          data-testid={`policy-template-example-row-${i}-why`}
                        >
                          {differsBecause(ex.expected, allowsByDefault, o.reason)}
                        </div>
                      )}
                    </td>
                    <td>
                      <Badge
                        tone={ex.expected === 'allow' ? 'success' : 'danger'}
                        value={ex.expected.toUpperCase()}
                      />
                    </td>
                    <td>
                      {o === null ? (
                        <span
                          className="spinner-border spinner-border-sm text-primary"
                          role="status"
                        />
                      ) : 'error' in o ? (
                        <span className="text-danger small">{o.error}</span>
                      ) : (
                        <Badge
                          tone={o.decision === 'allow' ? 'success' : 'danger'}
                          value={o.decision.toUpperCase()}
                        />
                      )}
                    </td>
                    <td>
                      {usesDefaultSettings && o && 'decision' in o && (
                        <Badge
                          tone={mismatch ? 'danger' : 'success'}
                          value={mismatch ? 'Differs' : 'Matches'}
                        />
                      )}
                    </td>
                    {onLoadInTest && (
                      <td>
                        <AppButton
                          variant="link"
                          className="p-0 text-nowrap"
                          onClick={() => onLoadInTest(ex.name, ex.input)}
                          aria-label={`Load ${ex.name} in Test (dry-run)`}
                          data-testid={`policy-template-example-row-${i}-load-button`}
                        >
                          Load in Test
                        </AppButton>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {mismatches > 0 && (
          <div className="small text-muted" data-testid="policy-template-examples-mismatch">
            <i className="fas fa-info-circle me-1" aria-hidden="true" />
            {mismatches === 1 ? 'One example gets' : `${mismatches} examples get`} a different
            decision from this policy. Another rule may allow or deny it; any rule that allows lets
            the request through.
          </div>
        )}
      </div>
    </div>
  );
};

export default TemplateExamplesCheck;
