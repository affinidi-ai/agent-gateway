import React, { useEffect, useState } from 'react';
import { Badge } from '../../../components/shared/Badge';
import { simulatePolicy } from '../simulatePolicy';
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
}

type Outcome = { decision: PolicyDecision } | { error: string } | null;

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
}) => {
  const [outcomes, setOutcomes] = useState<Outcome[]>(() => template.examples.map(() => null));

  useEffect(() => {
    let cancelled = false;
    // Earlier decisions were for an earlier draft; show the rows as running until these return.
    setOutcomes(template.examples.map(() => null));
    const timer = setTimeout(async () => {
      const results = await Promise.all(
        template.examples.map(async (ex): Promise<Outcome> => {
          try {
            const r = await simulatePolicy(policyId, policyType, draftPolicy, ex.input);
            return { decision: r.allow ? 'allow' : 'deny' };
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
  }, [policyId, policyType, draftPolicy, template]);

  // The examples were written for the default settings, so a different decision after a
  // setting changed says nothing about the rest of the policy.
  const isMismatch = (o: Outcome, i: number) =>
    usesDefaultSettings && !!o && 'decision' in o && o.decision !== template.examples[i].expected;
  const mismatches = outcomes.filter(isMismatch).length;

  return (
    <div
      className="card shadow-sm mb-4 border-left-primary"
      data-testid="policy-template-examples-card"
    >
      <div className="card-body py-3 px-3">
        <div className="d-flex justify-content-between align-items-center mb-2">
          <h6 className="font-weight-bold text-primary mb-0">
            <i className="fas fa-layer-group me-2" aria-hidden="true" />
            Template examples{' '}
            <span className="text-muted fw-normal small">from {template.name}</span>
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
          Each example runs against the Rego in the editor (unsaved), as the Test (dry-run) card
          does.
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
                <th>Draft gives</th>
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
                    <td>{ex.name}</td>
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
