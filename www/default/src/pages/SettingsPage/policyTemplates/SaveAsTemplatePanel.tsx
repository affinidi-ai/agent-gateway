import React, { useState } from 'react';
import FormSelect from '../../../components/shared/FormSelect';
import FieldHelp from '../../../components/shared/FieldHelp';
import { simulatePolicy } from '../simulatePolicy';
import { defaultDecision } from './regoTemplate';
import { savePolicyTemplate } from './policyTemplateStore';
import { DecisionBadge } from './TemplateBadges';
import {
  CATEGORY_LABELS,
  type PolicyTemplate,
  type PolicyTemplateCategory,
  type PolicyTemplateExample,
  type PolicyType,
} from './types';
import './PolicyTemplates.css';

interface SaveAsTemplatePanelProps {
  policyId: string;
  policyType: PolicyType;
  /** The saved version's Rego; unsaved edits are never copied. */
  savedPolicy: string;
  defaultName: string;
  defaultSummary: string;
  /** The Test (dry-run) card's sample input JSON. */
  sampleInput: string;
  onSaved: (template: PolicyTemplate) => void;
  onClose: () => void;
}

const CATEGORY_OPTIONS = (Object.keys(CATEGORY_LABELS) as PolicyTemplateCategory[]).map(c => ({
  value: c,
  label: CATEGORY_LABELS[c],
}));

/** Input paths a module reads, such as `jwt.sub`, shown as tags on the template. */
export function readsFromRego(rego: string): string[] {
  const paths = Array.from(rego.matchAll(/\binput\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)/g), m => m[1]);
  return Array.from(new Set(paths)).slice(0, 6);
}

/** One past the highest "Example N" name, so a removed example's number isn't reused. */
function nextExampleNumber(examples: PolicyTemplateExample[]): number {
  const numbers = examples.map(ex => Number(/^Example (\d+)$/.exec(ex.name)?.[1] ?? 0));
  return Math.max(examples.length, ...numbers) + 1;
}

const SaveAsTemplatePanel: React.FC<SaveAsTemplatePanelProps> = ({
  policyId,
  policyType,
  savedPolicy,
  defaultName,
  defaultSummary,
  sampleInput,
  onSaved,
  onClose,
}) => {
  const [name, setName] = useState(defaultName);
  const [summary, setSummary] = useState(defaultSummary);
  const [category, setCategory] = useState<PolicyTemplateCategory>('authentication');
  const [examples, setExamples] = useState<PolicyTemplateExample[]>([]);
  const [adding, setAdding] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reads = readsFromRego(savedPolicy);

  const addCurrentSample = async () => {
    let input: unknown;
    try {
      input = JSON.parse(sampleInput);
    } catch {
      setError('The sample input in the Test (dry-run) card is not valid JSON.');
      return;
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      setError('The sample input must be a JSON object.');
      return;
    }
    setAdding(true);
    setError(null);
    try {
      const result = await simulatePolicy(policyId, policyType, savedPolicy, input);
      setExamples(prev => [
        ...prev,
        {
          name: `Example ${nextExampleNumber(prev)}`,
          input: input as Record<string, unknown>,
          expected: result.allow ? 'allow' : 'deny',
        },
      ]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Dry-run failed');
    } finally {
      setAdding(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const template = await savePolicyTemplate({
        name,
        summary,
        category,
        policy_type: policyType,
        rego: savedPolicy,
        reads,
        examples: examples.map(ex => ({ ...ex, name: ex.name.trim() || 'Example' })),
      });
      onSaved(template);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save the template');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="card shadow-sm mb-4 policy-templates-panel"
      data-testid="policy-templates-save-panel"
    >
      <div className="card-header py-3 d-flex justify-content-between align-items-start">
        <div>
          <div className="small text-muted">
            <i className="fas fa-copy me-1 text-primary" aria-hidden="true" />
            Templates · Your organization
          </div>
          <h6 className="m-0 mt-1 font-weight-bold text-primary">Save as template</h6>
          <div className="small text-muted">
            Copies the saved version. Later edits to this policy don&apos;t change the template.
          </div>
        </div>
        <button
          type="button"
          className="btn-close"
          aria-label="Close save as template"
          onClick={onClose}
          data-testid="policy-templates-save-close-button"
        />
      </div>
      <div className="card-body">
        {error && (
          <div
            className="alert alert-danger py-2 px-3 small"
            data-testid="policy-templates-save-error"
          >
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {error}
          </div>
        )}
        <div className="mb-3">
          <label className="font-weight-bold" htmlFor="policy-template-save-name">
            Template name
          </label>
          <input
            id="policy-template-save-name"
            type="text"
            className="form-control form-control-sm"
            value={name}
            onChange={e => setName(e.target.value)}
            data-testid="policy-templates-save-name-input"
          />
        </div>
        <div className="mb-3">
          <label className="font-weight-bold" htmlFor="policy-template-save-summary">
            Summary{' '}
            <FieldHelp testId="field-help-policy-template-summary" ariaLabel="About Summary">
              One line, shown in the Template field and the template list.
            </FieldHelp>
          </label>
          <input
            id="policy-template-save-summary"
            type="text"
            className="form-control form-control-sm"
            value={summary}
            onChange={e => setSummary(e.target.value)}
            data-testid="policy-templates-save-summary-input"
          />
        </div>
        <div className="mb-3">
          <span className="font-weight-bold d-block">Category</span>
          <FormSelect
            value={category}
            options={CATEGORY_OPTIONS}
            onChange={setCategory}
            ariaLabel="Category"
            testid="policy-templates-save-category"
          />
        </div>
        <div className="d-flex flex-wrap gap-2 mb-3">
          <DecisionBadge decision={defaultDecision(savedPolicy)} prefix="Default" />
          {reads.map(r => (
            <span key={r} className="badge policy-template-reads">
              reads {r}
            </span>
          ))}
        </div>
        <div className="mb-3">
          <span className="font-weight-bold d-block mb-1">How it decides</span>
          {examples.length === 0 && <div className="text-muted small mb-1">No examples yet.</div>}
          <ul className="list-unstyled mb-1">
            {examples.map((ex, i) => (
              <li key={i} className="policy-template-example">
                <input
                  type="text"
                  className="form-control form-control-sm"
                  aria-label={`Example ${i + 1} name`}
                  value={ex.name}
                  onChange={e =>
                    setExamples(prev =>
                      prev.map((p, j) => (j === i ? { ...p, name: e.target.value } : p))
                    )
                  }
                  data-testid={`policy-templates-save-example-name-${i}`}
                />
                <span
                  className={`badge ${ex.expected === 'allow' ? 'text-bg-success' : 'text-bg-danger'}`}
                >
                  {ex.expected.toUpperCase()}
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-link text-danger p-0"
                  aria-label={`Remove example ${i + 1}`}
                  onClick={() => setExamples(prev => prev.filter((_, j) => j !== i))}
                  data-testid={`policy-templates-save-example-remove-button-${i}`}
                >
                  <i className="fas fa-trash" aria-hidden="true" />
                </button>
              </li>
            ))}
          </ul>
          <button
            type="button"
            className="btn btn-sm btn-link px-0"
            onClick={() => void addCurrentSample()}
            disabled={adding}
            data-testid="policy-templates-save-add-example-button"
          >
            <i
              className={`fas ${adding ? 'fa-spinner fa-spin' : 'fa-plus'} me-1`}
              aria-hidden="true"
            />
            Add current sample input
          </button>
          <div className="small text-muted">
            Takes the JSON from the Test (dry-run) card and records the decision the saved version
            gives.
          </div>
        </div>
        <div className="small text-muted mb-3">
          Kept in this browser tab until it is closed, and listed under{' '}
          <strong>Your organization</strong>.
        </div>
        <div className="d-flex justify-content-end gap-2">
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={onClose}
            data-testid="policy-templates-save-cancel-button"
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => void save()}
            disabled={saving || !name.trim()}
            data-testid="policy-templates-save-button"
          >
            <i
              className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'} me-1`}
              aria-hidden="true"
            />
            Save template
          </button>
        </div>
      </div>
    </div>
  );
};

export default SaveAsTemplatePanel;
