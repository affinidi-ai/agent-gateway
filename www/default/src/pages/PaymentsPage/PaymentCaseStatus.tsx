import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { formatDateTime } from '../../utils/stringUtils';
import type { PaymentCaseStatus as CaseStatus, PaymentCaseStatusReport } from '../../types';

type Tone = 'success' | 'info' | 'warning' | 'danger' | 'secondary';

const CASE_STATUS_META: Record<CaseStatus, { label: string; tone: Tone; text: string }> = {
  held: {
    label: 'Held',
    tone: 'warning',
    text: 'Waiting for a reviewer to approve or reject this payment.',
  },
  approved: {
    label: 'Approved',
    tone: 'info',
    text: 'A reviewer approved this payment; the capture is not confirmed yet.',
  },
  captured: {
    label: 'Captured',
    tone: 'success',
    text: 'A reviewer approved this payment and agent-pay captured it.',
  },
  rejected: {
    label: 'Rejected',
    tone: 'danger',
    text: 'A reviewer rejected this payment. Nothing was taken.',
  },
  voided: {
    label: 'Voided',
    tone: 'secondary',
    text: 'An operator voided this case. Nothing was taken.',
  },
  capture_failed: {
    label: 'Capture failed',
    tone: 'danger',
    text: 'Payment capture failed or is unconfirmed - reconcile before asking the payer to pay again.',
  },
};

const meta = (status: string) =>
  Object.prototype.hasOwnProperty.call(CASE_STATUS_META, status)
    ? CASE_STATUS_META[status as CaseStatus]
    : {
        label: status,
        tone: 'secondary' as Tone,
        text: 'agent-pay reported a status this page does not know.',
      };

const checkedAt = (value: string): string => {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : formatDateTime(d, true);
};

interface Props {
  report?: PaymentCaseStatusReport;
  refreshing: boolean;
  onRefresh: () => void;
}

/** What agent-pay says about a held payment now, with a button to ask again. */
const PaymentCaseStatus: React.FC<Props> = ({ report, refreshing, onRefresh }) => {
  const status = report ? meta(report.status) : null;
  return (
    <div data-testid="payments-detail-case-status">
      {status && report ? (
        <>
          <Badge value={status.label} tone={status.tone} size="sm" />{' '}
          <span data-testid="payments-detail-case-status-text">{status.text}</span>
          <div className="small text-muted">Checked {checkedAt(report.checked_at)}</div>
        </>
      ) : (
        <span className="text-muted" data-testid="payments-detail-case-status-text">
          Not available: agent-pay may not be connected or may not have answered in time, may no
          longer know this case, or the status was not requested for this row. Use Refresh status to
          ask again.
        </span>
      )}
      <div className="mt-1">
        <AppButton
          variant="outline-secondary"
          size="sm"
          onClick={onRefresh}
          loading={refreshing}
          loadingLabel="Refreshing..."
          disabled={refreshing}
          data-testid="payments-detail-refresh-button"
          iconStart={<i className="fas fa-sync-alt fa-sm me-1" aria-hidden="true" />}
        >
          Refresh status
        </AppButton>
      </div>
    </div>
  );
};

export default PaymentCaseStatus;
