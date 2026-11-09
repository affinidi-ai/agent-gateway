import React, { useEffect, useRef, useState } from 'react';
import { apiClient, type ApiError } from '../../api';
import GatewayStatusCell from '../../components/gateways/GatewayStatusCell';
import { AppButton } from '../../components/shared/AppButton';
import type { GatewayListItem } from '../../utils/gateways';

export const APPROVAL_POLL_MS = 3000;

const STATUS_TEXT: Record<string, string> = {
  pending: 'Waiting for agent-pay to answer the connection request.',
  'awaiting-approval':
    "agent-pay received the connection request. Its administrator must approve it in agent-pay's dashboard.",
  disabled: 'This payment gateway is disabled. Enable it on its page to finish setting it up.',
  failed: 'The connection is failing. It is retried automatically.',
};

interface AwaitApprovalStepProps {
  gatewayId: string;
  onApproved: (gateway: GatewayListItem) => void;
  onLeave: () => void;
}

/** Polls the new payment gateway until agent-pay's administrator approves it. */
const AwaitApprovalStep: React.FC<AwaitApprovalStepProps> = ({
  gatewayId,
  onApproved,
  onLeave,
}) => {
  const [gateway, setGateway] = useState<GatewayListItem | null>(null);
  const [problem, setProblem] = useState<'missing' | 'failed' | null>(null);
  const onApprovedRef = useRef(onApproved);
  onApprovedRef.current = onApproved;

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const check = async () => {
      try {
        const { data } = await apiClient.get<GatewayListItem>(
          `/payment-gateways/${encodeURIComponent(gatewayId)}`
        );
        if (cancelled) return;
        setGateway(data);
        setProblem(null);
        if (data.status === 'active') {
          onApprovedRef.current(data);
          return;
        }
      } catch (err) {
        if (cancelled) return;
        if ((err as Partial<ApiError> | null)?.status === 404) {
          setProblem('missing');
          return;
        }
        setProblem('failed');
      }
      timer = setTimeout(check, APPROVAL_POLL_MS);
    };
    check();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [gatewayId]);

  return (
    <div className="card shadow" data-testid="wizard-step-approval">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-user-check me-2" aria-hidden="true"></i> Awaiting Approval
        </h6>
      </div>
      <div className="card-body">
        {problem === 'missing' ? (
          <div
            className="alert alert-danger"
            role="alert"
            data-testid="payment-gateway-approval-error"
          >
            <i className="fas fa-exclamation-circle me-2" aria-hidden="true"></i>
            This payment gateway no longer exists. It may have been deleted. Start again from
            Connections → Payment Gateways.
          </div>
        ) : (
          <>
            <div className="d-flex align-items-center gap-3 mb-3">
              {gateway ? (
                <div data-testid="payment-gateway-approval-status">
                  <GatewayStatusCell gateway={gateway} />
                </div>
              ) : (
                <div className="spinner-border spinner-border-sm text-primary" role="status">
                  <span className="visually-hidden">Checking</span>
                </div>
              )}
              <span className="text-muted">
                {gateway
                  ? (STATUS_TEXT[gateway.status] ?? 'Checking the connection…')
                  : 'Checking the connection…'}
              </span>
            </div>
            {problem === 'failed' && (
              <div
                className="alert alert-warning"
                role="alert"
                data-testid="payment-gateway-approval-error"
              >
                <i className="fas fa-triangle-exclamation me-2" aria-hidden="true"></i>
                Could not check the connection. Trying again…
              </div>
            )}
            <div className="alert alert-info" role="note">
              <i className="fas fa-info-circle me-2" aria-hidden="true"></i>
              <strong>agent-pay must approve this connection.</strong>
              <p className="mb-0 mt-2">
                agent-pay always asks its administrator to approve a new gateway. Ask them to
                approve it; this page moves on by itself once they do. You can leave meanwhile: the
                payment gateway stays in Connections → Payment Gateways, and its Verify action
                brings you back here.
              </p>
            </div>
          </>
        )}
        <div className="d-flex justify-content-start mt-4">
          <AppButton
            type="button"
            variant="secondary"
            size="md"
            onClick={onLeave}
            iconStart={<i className="fas fa-arrow-left" aria-hidden="true"></i>}
            data-testid="wizard-cancel"
          >
            Back to Connections
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default AwaitApprovalStep;
