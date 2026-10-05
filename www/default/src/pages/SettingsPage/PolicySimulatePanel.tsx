import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';

interface SimulateResult {
  allow: boolean;
  reason?: string;
  policy_type: string;
  version?: number;
  content_hash: string;
  query: string;
}

interface PolicySimulatePanelProps {
  policyId: string;
  /** The policy type currently selected in the editor (may be unsaved). */
  policyType: 'gateway' | 'agent_surface';
  /** The current editor Rego — evaluated as a draft so unsaved edits are tested. */
  draftPolicy: string;
  /** Saved sample input, owned by the editor form so it persists on save. */
  sampleInput: string;
  onSampleInputChange: (value: string) => void;
  /** Whether the draft Rego above currently compiles (live-validated by the editor). */
  policyValid: boolean;
}

export const POLICY_SIMULATE_DEFAULT_INPUT = `{
  "jwt": { "sub": "user@example.com", "role": "admin" },
  "http": { "method": "POST", "path": "/", "headers": {} },
  "gateway": { "direction": "inbound" }
}`;

/** Pull the `error` field out of a JSON error body; falls back to the raw text. */
const extractErrorMessage = (body: string): string => {
  try {
    const parsed = JSON.parse(body) as { error?: string };
    return parsed.error ?? body;
  } catch {
    return body;
  }
};

/**
 * Dry-run the policy currently in the editor against a sample input, without
 * touching any runtime engine or live traffic. Evaluates the unsaved draft body
 * via `POST /policy-definitions/{id}/simulate`.
 */
const PolicySimulatePanel: React.FC<PolicySimulatePanelProps> = ({
  policyId,
  policyType,
  draftPolicy,
  sampleInput,
  onSampleInputChange,
  policyValid,
}) => {
  const [result, setResult] = useState<SimulateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [autoRun, setAutoRun] = useState(false);

  const sampleInputError = useMemo(() => {
    try {
      JSON.parse(sampleInput);
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : 'Sample input must be valid JSON.';
    }
  }, [sampleInput]);

  const tooltipReason = !policyValid
    ? 'Fix the policy compile error above before running'
    : sampleInputError
      ? 'Fix the sample input JSON below before running'
      : null;
  const canRun = policyValid && !sampleInputError;
  const disabled = running || !canRun;

  const run = async () => {
    let input: unknown;
    try {
      input = JSON.parse(sampleInput);
    } catch {
      setError('Sample input must be valid JSON.');
      setResult(null);
      return;
    }
    try {
      setRunning(true);
      const resp = await apiClient.fetch(
        `/api/v1/policy-definitions/${encodeURIComponent(policyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input, policy: draftPolicy, policy_type: policyType }),
        }
      );
      if (!resp.ok) {
        const detail = await resp.text().catch(() => '');
        throw new Error(extractErrorMessage(detail) || `Dry-run failed: ${resp.statusText}`);
      }
      setResult((await resp.json()) as SimulateResult);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Dry-run failed');
      setResult(null);
    } finally {
      setRunning(false);
    }
  };

  // Auto-run: re-simulate on every policy/sample-input change, debounced.
  useEffect(() => {
    if (!autoRun || !canRun) return;
    const timer = setTimeout(() => {
      run();
    }, 500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRun, draftPolicy, sampleInput, canRun]);

  // The last dry-run outcome is stale once the policy or sample input becomes
  // invalid — clear it rather than showing an ALLOW/DENY that no longer applies.
  useEffect(() => {
    if (canRun) return;
    setResult(null);
    setError(null);
  }, [canRun]);

  return (
    <div className="card shadow-sm mb-4 border-left-primary" data-testid="policy-simulate-panel">
      <div className="card-body py-3 px-3">
        <div className="d-flex justify-content-between align-items-center mb-2">
          <h6 className="font-weight-bold text-primary mb-0">
            <i className="fas fa-flask me-2"></i>
            Test (dry-run)
          </h6>
          <div className="d-flex align-items-center">
            <div className="d-flex align-items-center me-3">
              <input
                className="form-check-input mt-0 me-1"
                type="checkbox"
                id="policy-simulate-autorun"
                checked={autoRun}
                onChange={e => setAutoRun(e.target.checked)}
                data-testid="policy-simulate-autorun"
              />
              <label className="mb-0 small" htmlFor="policy-simulate-autorun">
                Auto-run
              </label>
            </div>
            <span title={tooltipReason ?? undefined}>
              <button
                type="button"
                className="btn btn-sm btn-outline-primary"
                style={{
                  width: '13rem',
                  whiteSpace: 'nowrap',
                  pointerEvents: disabled || autoRun ? 'none' : undefined,
                }}
                onClick={run}
                disabled={disabled || autoRun}
                data-testid="policy-simulate-run"
              >
                <i className={`fas ${running ? 'fa-spinner fa-spin' : 'fa-play'} me-1`}></i>
                Run against the draft above
              </button>
            </span>
          </div>
        </div>
        <p className="text-muted small mb-2">
          Evaluates the Rego currently in the editor (unsaved) against the sample <code>input</code>{' '}
          below. Nothing is enforced — no engine or live traffic is touched.
        </p>
        <label className="font-weight-bold">
          Sample input JSON
          {sampleInput.trim() && !sampleInputError && (
            <span className="ms-2 text-success small">
              <i className="fas fa-check-circle"></i> Valid
            </span>
          )}
          {sampleInput.trim() && sampleInputError && (
            <span className="ms-2 text-danger small">
              <i className="fas fa-circle-exclamation"></i> Invalid
            </span>
          )}
        </label>
        <textarea
          className={`form-control font-monospace small ${sampleInputError ? 'is-invalid' : ''}`}
          rows={8}
          style={{ fontSize: '0.8rem' }}
          value={sampleInput}
          onChange={e => onSampleInputChange(e.target.value)}
          data-testid="policy-simulate-input"
        />
        {sampleInputError && (
          <div
            className="alert alert-danger compile-error-alert py-2 px-3 mt-2 mb-0"
            data-testid="policy-simulate-input-error"
          >
            <i className="fas fa-exclamation-triangle me-2"></i>
            <span
              style={{
                whiteSpace: 'pre-wrap',
                fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                fontSize: '0.8rem',
              }}
            >
              {`Sample input is not valid JSON: ${sampleInputError}`}
            </span>
          </div>
        )}
        {error && (
          <div className="alert alert-danger compile-error-alert py-2 px-3 mb-0">
            <i className="fas fa-exclamation-triangle me-2"></i>
            <span
              style={{
                whiteSpace: 'pre-wrap',
                fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                fontSize: '0.8rem',
              }}
            >
              {error}
            </span>
          </div>
        )}
        {result && (
          <div
            className="policy-preview-block rounded py-2 px-3 mb-0"
            data-testid="policy-simulate-result"
          >
            <div className="d-flex align-items-center mb-1">
              <span className={`badge ${result.allow ? 'text-bg-success' : 'text-bg-danger'} me-2`}>
                {result.allow ? 'ALLOW' : 'DENY'}
              </span>
              {result.reason && <span className="small">{result.reason}</span>}
            </div>
            <div className="small text-muted">
              <code>{result.query}</code>
              {typeof result.version === 'number' ? ` · v${result.version}` : ' · draft'} ·{' '}
              {result.content_hash}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PolicySimulatePanel;
