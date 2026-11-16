import React, { useState } from 'react';
import type { AgentSurface } from '../../../../api';
import { formatTime } from '../../../../utils/stringUtils';
import PolicyInputCaptureControl from '../PolicyInputCaptureControl';
import {
  CapturedPolicy,
  CapturedPolicyInput,
  MAX_POLICY_INPUTS,
} from './usePolicyInputCaptureStream';

interface PolicyInputCaptureCardProps {
  captures: CapturedPolicyInput[];
  /** Whether the surface has a policy of its own; without one it has nothing to capture. */
  hasPolicy?: boolean;
}

/** Whether `surface` has an Access Point, Target, response or Transit Point policy. */
export const surfaceHasPolicy = (surface: AgentSurface): boolean =>
  Boolean(
    surface.access_point?.inbound_policy ||
    surface.target?.policy ||
    surface.target?.response_policy ||
    surface.transit?.points?.some(point => point.policy)
  );

const decisionBadge = (decision: string) => {
  if (decision === 'allow') {
    return (
      <span className="badge text-bg-success">
        <i className="fas fa-check-circle"></i> Allow
      </span>
    );
  }
  if (decision === 'deny') {
    return (
      <span className="badge text-bg-danger">
        <i className="fas fa-ban"></i> Deny
      </span>
    );
  }
  return (
    <span className="badge text-bg-warning">
      <i className="fas fa-exclamation-triangle"></i> Error
    </span>
  );
};

/** The name a captured policy is shown by: its name, else its id, else "inline policy". */
export const policyLabel = (policy: CapturedPolicy): string =>
  policy.name || policy.id || 'inline policy';

const PolicyNames: React.FC<{ capture: CapturedPolicyInput }> = ({ capture }) => {
  if (capture.policies.length === 0) return null;
  return (
    <div className="small text-muted">
      {capture.policies.map((policy, index) => {
        const denied = capture.decidedBy !== undefined && capture.decidedBy === policy.id;
        return (
          <span
            key={`${policy.id ?? 'inline'}-${index}`}
            className={`me-2 ${denied ? 'text-danger fw-semibold' : ''}`}
            title={policy.id}
            data-testid="policy-input-capture-policy"
          >
            <i className="fas fa-file-code me-1"></i>
            {policyLabel(policy)}
            {policy.version !== undefined && ` v${policy.version}`}
            {denied && ' (denied)'}
          </span>
        );
      })}
    </div>
  );
};

const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    console.error('Failed to copy to clipboard:', e);
  }
};

const PolicyInputCaptureCard: React.FC<PolicyInputCaptureCardProps> = ({
  captures,
  hasPolicy = true,
}) => {
  const [openId, setOpenId] = useState<number | null>(null);
  const [slot, setSlot] = useState<string>('');
  const slots = Array.from(new Set(captures.map(capture => capture.slot))).sort();
  const shown = slot ? captures.filter(capture => capture.slot === slot) : captures;

  return (
    <div className="card shadow mb-4" data-testid="policy-input-capture-card">
      <div className="card-header py-3 d-flex align-items-center justify-content-between flex-wrap gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-gavel"></i> Policy Input
          {captures.length > 0 && (
            <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
              {captures.length}/{MAX_POLICY_INPUTS}
            </span>
          )}
        </h6>
        <PolicyInputCaptureControl />
      </div>
      <div className="card-body">
        {!hasPolicy && (
          <div className="alert alert-info small py-2" data-testid="policy-input-capture-no-policy">
            This surface has no policy yet, so its requests have no policy evaluation to capture.
            Only a gateway or appliance-wide policy, if one applies, shows here. To see the input of
            each request, add a request policy to the surface; one that allows everything is enough.
          </div>
        )}
        {captures.length === 0 ? (
          <p className="text-muted small mb-0" data-testid="policy-input-capture-empty">
            Listen to policy input, then send a request to this surface. The input and the decision
            of each policy evaluation show here, live. On an appliance with several nodes, only
            requests served by the node this dashboard is connected to show.
          </p>
        ) : (
          <div className="table-responsive">
            <div className="d-flex align-items-center flex-wrap gap-2 mb-2 small text-muted">
              <span data-testid="policy-input-capture-kept">
                The last {MAX_POLICY_INPUTS} policy evaluations are kept; one request can run
                several policies.
              </span>
              <select
                className="form-select form-select-sm w-auto ms-auto"
                aria-label="Show the evaluations of one policy slot"
                data-testid="policy-input-capture-slot-filter"
                value={slot}
                onChange={e => setSlot(e.target.value)}
              >
                <option value="">All policy slots</option>
                {slots.map(name => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </div>
            <table className="table table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Policy</th>
                  <th>Decision</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {shown.map(capture => {
                  const input = JSON.stringify(capture.input, null, 2);
                  const open = openId === capture.id;
                  return (
                    <React.Fragment key={capture.id}>
                      <tr data-testid="policy-input-capture-row">
                        <td className="text-nowrap">{formatTime(capture.timestamp)}</td>
                        <td>
                          {capture.slot}
                          {capture.surfaceVariant && capture.surfaceVariant !== '_base_' && (
                            <span className="badge text-bg-secondary ms-2">
                              {capture.surfaceVariant}
                            </span>
                          )}
                          <PolicyNames capture={capture} />
                        </td>
                        <td>
                          {decisionBadge(capture.decision)}
                          {capture.reason && (
                            <small
                              className="text-muted ms-2"
                              data-testid="policy-input-capture-reason"
                            >
                              {capture.reason}
                            </small>
                          )}
                        </td>
                        <td className="text-end text-nowrap">
                          <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary"
                            data-testid="policy-input-capture-toggle"
                            onClick={() => setOpenId(open ? null : capture.id)}
                          >
                            {open ? 'Hide input' : 'Show input'}
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary ms-2"
                            title="Copy the input, to try it in the policy Test panel"
                            data-testid="policy-input-capture-copy"
                            onClick={() => copyText(input)}
                          >
                            <i className="fas fa-copy"></i>
                          </button>
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={4}>
                            <pre
                              className="mb-0 small"
                              style={{ maxHeight: 400, overflow: 'auto' }}
                              data-testid="policy-input-capture-input"
                            >
                              {input}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default PolicyInputCaptureCard;
