import React, { useState } from 'react';
import type { AgentSurface } from '../../../../api';
import { formatDateTime } from '../../../../utils/stringUtils';
import { showToast } from '../../../../utils/toaster';
import { CopyButton } from '../../../shared/CopyButton';
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
  /** How many evaluations the gateway dropped for this dashboard because it fell behind. */
  skipped?: number;
}

/**
 * Whether `surface` has a policy the gateway captures: on the Access Point, Target or its
 * response, the shared Transit Point policy, a Transit Point or its response, or a
 * variant's Access Point or Target.
 */
export const surfaceHasPolicy = (surface: AgentSurface): boolean =>
  Boolean(
    surface.access_point?.inbound_policy ||
    surface.target?.policy ||
    surface.target?.response_policy ||
    surface.transit?.opa_policy_definition_id ||
    surface.transit?.points?.some(point => point.policy || point.response_policy) ||
    surface.variants?.some(
      variant =>
        variant.overrides?.access_point?.inbound_policy || variant.overrides?.target?.policy
    )
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

const PolicyInputCaptureCard: React.FC<PolicyInputCaptureCardProps> = ({
  captures,
  hasPolicy = true,
  skipped = 0,
}) => {
  const [openId, setOpenId] = useState<number | null>(null);
  const [slot, setSlot] = useState<string>('');
  const slots = Array.from(new Set(captures.map(capture => capture.slot))).sort();
  // A chosen slot that has left the list (cleared or rolled off) shows every slot again.
  const activeSlot = slots.includes(slot) ? slot : '';
  const shown = activeSlot ? captures.filter(capture => capture.slot === activeSlot) : captures;

  return (
    <div className="card shadow mb-4" data-testid="policy-input-capture-card">
      <div className="card-header py-3 d-flex align-items-center justify-content-between flex-wrap gap-2">
        <div>
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-gavel"></i> Policy Input
            {captures.length > 0 && (
              <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
                {captures.length}/{MAX_POLICY_INPUTS}
              </span>
            )}
          </h6>
          <small className="d-block text-warning mt-1" data-testid="policy-input-capture-warning">
            <i className="fas fa-exclamation-triangle me-1"></i>
            For developing and testing policies only
          </small>
          <small className="d-block text-muted" data-testid="policy-input-capture-kept">
            The last {MAX_POLICY_INPUTS} policy evaluations are kept; one request can add several
            rows
          </small>
        </div>
        <PolicyInputCaptureControl />
      </div>
      <div className="card-body">
        {skipped > 0 && (
          <div
            className="alert alert-warning mb-3"
            style={{ fontSize: '14px' }}
            data-testid="policy-input-capture-skipped"
          >
            <i className="fas fa-exclamation-triangle me-2"></i>
            {skipped} policy {skipped === 1 ? 'evaluation was' : 'evaluations were'} not shown: the
            surface sent them faster than this dashboard could receive them.
          </div>
        )}
        {!hasPolicy && (
          <div
            className="alert alert-info mb-3"
            style={{ fontSize: '14px' }}
            data-testid="policy-input-capture-no-policy"
          >
            <i className="fas fa-info-circle me-2"></i>
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
          <>
            <div className="d-flex justify-content-end mb-2">
              <select
                className="form-select form-select-sm w-auto"
                aria-label="Show the evaluations of one policy slot"
                data-testid="policy-input-capture-slot-filter"
                value={activeSlot}
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
            <div className="table-responsive">
              <table className="table table-hover table-sm">
                <thead>
                  <tr>
                    <th>Timestamp</th>
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
                          <td className="text-nowrap timestamp-cell">
                            {formatDateTime(capture.timestamp, true)}
                          </td>
                          <td>
                            <span className="badge text-bg-secondary">{capture.slot}</span>
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
                            <CopyButton
                              text={input}
                              title="Copy the input"
                              onCopyError={() =>
                                showToast('error', 'Could not copy to the clipboard')
                              }
                              data-testid="policy-input-capture-copy"
                            />
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
          </>
        )}
      </div>
    </div>
  );
};

export default PolicyInputCaptureCard;
