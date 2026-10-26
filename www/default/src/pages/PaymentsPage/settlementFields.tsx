import React from 'react';
import type { PaymentLedgerRow } from '../../types';
import { Badge } from '../../components/shared/Badge';
import { formatLedgerAmount } from './ledger';

type Field = [string, React.ReactNode];

const INTENT_LABEL: Record<NonNullable<PaymentLedgerRow['settle_intent']>, string> = {
  capture: 'Capture',
  void: 'Void',
};

/** Where a held payment's capture or void stands, as the ledger row records it. */
export function settlementStatus(row: PaymentLedgerRow): string {
  if (row.reconcile_failed) return 'Reconciliation gave up';
  if (row.superseded_by) return 'Superseded';
  if (row.outcome === 'authorized') {
    return row.settle_intent ? `${INTENT_LABEL[row.settle_intent]} pending` : 'Awaiting delivery';
  }
  if (row.outcome === 'unconfirmed') return 'Unconfirmed, reconciling';
  return 'Settled';
}

/** The settlement rows of the payment detail; only those the row has a value for. */
export function settlementFields(row: PaymentLedgerRow): Field[] {
  const fields: Field[] = [];
  const held = Boolean(row.authorization_id || row.settle_intent || row.reconcile_failed);
  if (row.authorization_id) {
    fields.push([
      'Authorization id',
      <code key="auth" data-testid="payments-detail-authorization-id">
        {row.authorization_id}
      </code>,
    ]);
  }
  if (row.capture_deadline) {
    fields.push([
      'Capture deadline',
      <span key="deadline" data-testid="payments-detail-capture-deadline">
        {new Date(row.capture_deadline).toLocaleString()}
      </span>,
    ]);
  }
  if (row.settle_intent) {
    fields.push([
      'Intent',
      <span key="intent" data-testid="payments-detail-settle-intent">
        {INTENT_LABEL[row.settle_intent]}
        {row.settle_attempts
          ? ` (${row.settle_attempts} attempt${row.settle_attempts === 1 ? '' : 's'})`
          : ''}
      </span>,
    ]);
  }
  if (held) {
    fields.push([
      'Settlement status',
      <span key="settlement" data-testid="payments-detail-settlement-status">
        {settlementStatus(row)}
      </span>,
    ]);
  }
  if (row.price_mismatch) {
    const quoted = row.quoted_amount
      ? formatLedgerAmount({ amount: row.quoted_amount, currency: row.quoted_currency })
      : '—';
    fields.push([
      'Charged vs quoted',
      <span key="price" data-testid="payments-detail-price-mismatch">
        {formatLedgerAmount(row)} charged, {quoted} quoted{' '}
        <Badge value="Price mismatch" tone="warning" size="sm" />
      </span>,
    ]);
  }
  if (row.superseded_by) {
    fields.push([
      'Superseded by',
      <code key="superseded" data-testid="payments-detail-superseded-by">
        {row.superseded_by}
      </code>,
    ]);
  }
  if (row.reconcile_failed) {
    fields.push([
      'Reconciliation',
      <span key="reconcile" data-testid="payments-detail-reconcile-failed">
        <Badge value="Reconcile failed" tone="danger" size="sm" /> settle it with agent-pay by hand
      </span>,
    ]);
  }
  return fields;
}
