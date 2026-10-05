/**
 * TemplateConflictModal — resolves per-item placement conflicts
 * before the engine commits.
 *
 * Shown only when `planTemplate()` finds singleton-cardinality items
 * that already exist on the canvas. Clean items and unsupported
 * items are listed read-only for context.
 */

import React, { useState, useMemo } from 'react';
import type { PlacementDecision, TemplatePlan } from './types';

interface TemplateConflictModalProps {
  plan: TemplatePlan;
  onCancel: () => void;
  onConfirm: (decisions: Record<number, PlacementDecision>) => void;
}

const DECISION_OPTIONS: { value: PlacementDecision; label: string; hint: string }[] = [
  { value: 'merge', label: 'Merge', hint: 'Fill empty fields only' },
  { value: 'overwrite', label: 'Overwrite', hint: 'Replace existing config' },
  { value: 'place', label: 'Add anyway', hint: 'Create a second instance' },
  { value: 'skip', label: 'Skip', hint: 'Leave existing untouched' },
];

const TemplateConflictModal: React.FC<TemplateConflictModalProps> = ({
  plan,
  onCancel,
  onConfirm,
}) => {
  const initial = useMemo(() => {
    const d: Record<number, PlacementDecision> = {};
    plan.conflicts.forEach(c => {
      d[c.itemIndex] = c.suggested;
    });
    return d;
  }, [plan]);
  const [decisions, setDecisions] = useState<Record<number, PlacementDecision>>(initial);

  const setAll = (value: PlacementDecision) => {
    const next: Record<number, PlacementDecision> = {};
    plan.conflicts.forEach(c => {
      next[c.itemIndex] = value;
    });
    setDecisions(next);
  };

  return (
    <>
      <div className="modal fade show" style={{ display: 'block' }} tabIndex={-1}>
        <div className="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">
                <i className="fas fa-triangle-exclamation me-2 text-warning" />
                Resolve template conflicts
              </h5>
              <button type="button" className="btn-close" onClick={onCancel} aria-label="Close" />
            </div>
            <div className="modal-body">
              <p className="text-muted small mb-3">
                Applying <strong>{plan.template.name}</strong> would touch nodes that already exist.
                Choose how each conflicting item should be applied.
              </p>

              <div className="d-flex align-items-center gap-2 mb-3">
                <span className="small text-muted">Apply to all:</span>
                {DECISION_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => setAll(opt.value)}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <div className="border rounded mb-3">
                <table className="table table-sm mb-0 align-middle">
                  <thead className="table-light">
                    <tr>
                      <th style={{ width: '40%' }}>Item</th>
                      <th>Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.conflicts.map(c => (
                      <tr key={c.itemIndex}>
                        <td>
                          <div>
                            <code>{c.item.kind}</code>{' '}
                            <span className="text-muted small">({c.item.scope})</span>
                          </div>
                          <div className="small text-muted">
                            Existing node: <code className="small">{c.existingNode.id}</code>
                          </div>
                        </td>
                        <td>
                          <select
                            className="form-select form-select-sm"
                            value={decisions[c.itemIndex] ?? c.suggested}
                            onChange={e =>
                              setDecisions(prev => ({
                                ...prev,
                                [c.itemIndex]: e.target.value as PlacementDecision,
                              }))
                            }
                          >
                            {DECISION_OPTIONS.map(opt => (
                              <option key={opt.value} value={opt.value}>
                                {opt.label} — {opt.hint}
                              </option>
                            ))}
                          </select>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {plan.clean.length > 0 && (
                <details className="mb-2">
                  <summary className="small text-muted">
                    {plan.clean.length} item{plan.clean.length === 1 ? '' : 's'} will be added
                    cleanly
                  </summary>
                  <ul className="small text-muted mt-2 ps-3 mb-0">
                    {plan.clean.map(({ itemIndex, item }) => (
                      <li key={itemIndex}>
                        <code>{item.kind}</code> <span className="text-muted">({item.scope})</span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}

              {plan.unsupported.length > 0 && (
                <details>
                  <summary className="small text-muted">
                    {plan.unsupported.length} item
                    {plan.unsupported.length === 1 ? '' : 's'} cannot be placed
                  </summary>
                  <ul className="small text-muted mt-2 ps-3 mb-0">
                    {plan.unsupported.map(({ itemIndex, item, reason }) => (
                      <li key={itemIndex}>
                        <code>{item.kind}</code> — {reason}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onConfirm(decisions)}
              >
                <i className="fas fa-check me-1" />
                Apply
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show" />
    </>
  );
};

export default TemplateConflictModal;
