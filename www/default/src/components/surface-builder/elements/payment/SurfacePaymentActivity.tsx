import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '../../../../api';
import { Badge } from '../../../shared/Badge';
import { AppButton } from '../../../shared/AppButton';
import { OUTCOME_META, formatLedgerAmount, rowDate } from '../../../../pages/PaymentsPage/ledger';
import {
  PAYMENT_OUTCOMES,
  type PaymentBreaker,
  type PaymentLedgerRow,
  type PaymentSummary,
} from '../../../../types';

export const RECENT_ROWS = 5;

const BREAKER_META: Record<
  PaymentBreaker['state'],
  { label: string; tone: 'success' | 'warning' | 'danger' }
> = {
  closed: { label: 'Closed', tone: 'success' },
  half_open: { label: 'Half-open', tone: 'warning' },
  open: { label: 'Open', tone: 'danger' },
};

interface Props {
  surfaceId: string;
  paymentGatewayId: string;
}

interface Activity {
  summary: PaymentSummary;
  recent: PaymentLedgerRow[];
  breaker: PaymentBreaker | null;
}

/**
 * The last 24 hours of an agent_pay surface's payments: counts by outcome, the
 * newest rows and its payment gateway's circuit breaker.
 */
const SurfacePaymentActivity: React.FC<Props> = ({ surfaceId, paymentGatewayId }) => {
  const [activity, setActivity] = useState<Activity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const latest = useRef(0);

  const load = useCallback(async () => {
    const request = ++latest.current;
    setError(null);
    try {
      const [summary, page, breaker] = await Promise.all([
        apiClient.getPaymentSummary(surfaceId, 24),
        apiClient.listPayments({ surface_id: surfaceId, limit: RECENT_ROWS }),
        apiClient.getPaymentBreaker(paymentGatewayId).catch(() => null),
      ]);
      if (request === latest.current) setActivity({ summary, recent: page.payments, breaker });
    } catch (err) {
      if (request === latest.current) {
        setError(err instanceof Error ? err.message : 'Failed to load payments');
      }
    }
  }, [surfaceId, paymentGatewayId]);

  useEffect(() => {
    load();
    return () => {
      latest.current += 1;
    };
  }, [load]);

  const paymentsHref = `/payments?surface_id=${encodeURIComponent(surfaceId)}`;
  const counted = PAYMENT_OUTCOMES.filter(o => (activity?.summary.counts[o] ?? 0) > 0);

  return (
    <div
      className="alert alert-light border py-2 px-3 mb-2 small"
      data-testid="surface-payment-activity"
    >
      <div className="d-flex flex-wrap align-items-center gap-2">
        <strong>
          <i className="fas fa-money-bill-wave me-1" aria-hidden="true" />
          Payments, last 24 h
        </strong>
        {error ? (
          <span className="text-danger" data-testid="surface-payment-activity-error">
            {error}
          </span>
        ) : !activity ? (
          <span className="text-muted">Loading…</span>
        ) : counted.length === 0 ? (
          <span className="text-muted" data-testid="surface-payment-activity-empty">
            No payments
          </span>
        ) : (
          counted.map(o => (
            <span key={o} data-testid={`surface-payment-count-${o}`}>
              <Badge value={OUTCOME_META[o].label} tone={OUTCOME_META[o].tone} size="sm" />{' '}
              {activity.summary.counts[o]}
            </span>
          ))
        )}
        {activity?.breaker && (
          <span
            className="ms-2"
            title={`${activity.breaker.consecutive_failures} consecutive failure(s); opens after ${activity.breaker.failures_to_open}`}
            data-testid="surface-payment-breaker"
          >
            Gateway breaker{' '}
            <Badge
              value={BREAKER_META[activity.breaker.state].label}
              tone={BREAKER_META[activity.breaker.state].tone}
              size="sm"
            />
            {activity.breaker.retry_after_secs !== undefined &&
              ` retry in ${activity.breaker.retry_after_secs}s`}
          </span>
        )}
        <span className="ms-auto d-flex gap-2">
          {activity && activity.recent.length > 0 && (
            <AppButton
              variant="link"
              size="sm"
              className="p-0"
              onClick={() => setExpanded(e => !e)}
              aria-expanded={expanded}
              data-testid="surface-payment-recent-toggle"
            >
              {expanded ? 'Hide recent' : 'Recent'}
            </AppButton>
          )}
          <Link to={paymentsHref} data-testid="surface-payment-activity-link">
            View payments
          </Link>
        </span>
      </div>
      {expanded && activity && (
        <ul className="list-unstyled mb-0 mt-2" data-testid="surface-payment-recent">
          {activity.recent.map(row => {
            const meta = OUTCOME_META[row.outcome] ?? OUTCOME_META.unavailable;
            return (
              <li key={row.id} data-testid={`surface-payment-recent-${row.id}`}>
                <Badge value={meta.label} tone={meta.tone} size="sm" />{' '}
                {rowDate(row)?.toLocaleString() ?? '—'} · {formatLedgerAmount(row)}
                {row.resource && (
                  <>
                    {' '}
                    · <code>{row.resource}</code>
                  </>
                )}
                {row.reason && <span className="text-muted"> · {row.reason}</span>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};

export default SurfacePaymentActivity;
