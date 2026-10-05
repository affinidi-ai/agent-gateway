import React, { useCallback, useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title as ChartTitle,
  Tooltip,
  Legend,
  ChartOptions,
} from 'chart.js';
import {
  formatDateTime,
  formatDuration,
  formatTime,
  timeAgo,
  topAndTail,
} from '../utils/stringUtils';
import { Link } from 'react-router-dom';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { DeleteButton } from '../components/shared/DeleteButton';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import FieldHelp from '../components/shared/FieldHelp';
import InfoBanner from '../components/shared/InfoBanner';
import { DOCS_URL } from '../config/docs';
import { apiClient } from '../api';
import { usePermissions } from '../context/PermissionsContext';

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, BarElement, ChartTitle, Tooltip, Legend);

interface PaymentTransaction {
  tx_hash: string;
  channel_id: string;
  channel_name: string;
  resource_path?: string;
  network?: string;
  network_name?: string;
  amount?: string;
  decimals?: number;
  asset?: string;
  recipient?: string;
  recipient_name?: string;
  tx_explorer_url?: string;
  address_explorer_url?: string;
  correlation_id?: string;

  // Verification stage
  verification_id?: string;
  verification_status?: string;
  verification_created_at?: number;
  verification_completed_at?: number;
  verification_error?: string;
  verification_is_local?: boolean;
  verification_mode?: string;

  // Settlement stage
  settlement_id?: string;
  settlement_status?: string;
  settlement_mode?: string;
  settlement_method?: string;
  settlement_verified_at?: number;
  settlement_completed_at?: number;
  settlement_attempts?: number;
  settlement_error?: string;
  settlement_is_local?: boolean;
  sync_status?: string;

  // Combined timestamps
  created_at: number;
  first_seen: number;
  last_updated: number;

  // MPP-specific (protocol discriminant; x402 rows omit this)
  protocol?: 'x402' | 'mpp';
  payment_method?: string;
  currency?: string;
  payer?: string;
}

interface MppTransactionSummary {
  id: string;
  surface_id: string;
  channel_name: string;
  resource_url: string;
  payment_method: string;
  status: string;
  reference: string;
  error?: string;
  payer?: string;
  amount?: string;
  currency?: string;
  created_at: number;
}

interface ChartDataPoint {
  timestamp: number;
  label: string;
  count: number;
  verifications: number;
  settlements: number;
}

const PaymentsPage: React.FC = () => {
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canDeleteTransactions = !permissionsLoading && hasPermission('payments.delete');
  const [transactions, setTransactions] = useState<PaymentTransaction[]>([]);
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [filterText, setFilterText] = useState<string>('');
  const [bucketSeconds, setBucketSeconds] = useState<number>(900); // Default 15 minutes
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedTransactionDetails, setSelectedTransactionDetails] = useState<string>('');
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [transactionErrors, setTransactionErrors] = useState<{
    verificationError?: string;
    settlementError?: string;
  }>({});
  const [transactionStatus, setTransactionStatus] = useState<{
    verificationStatus?: string;
    settlementStatus?: string;
  }>({});

  // Fetch transaction details
  const handleViewDetails = async (transactionId: string, protocol: 'x402' | 'mpp' = 'x402') => {
    setLoadingDetails(true);
    setShowDetailsModal(true);
    setSelectedTransactionDetails('Loading...');
    setTransactionErrors({});
    setTransactionStatus({});

    try {
      const url =
        protocol === 'mpp'
          ? `/api/admin/mpp/transactions/${transactionId}`
          : `/api/admin/x402/transactions/${transactionId}`;
      const response = await apiClient.fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to fetch transaction details: ${response.statusText}`);
      }
      const data = await response.json();
      setSelectedTransactionDetails(JSON.stringify(data, null, 2));

      // Extract error information
      const errors: { verificationError?: string; settlementError?: string } = {};
      if (data.verification?.error) {
        errors.verificationError = data.verification.error;
      }
      if (data.settlement?.error) {
        errors.settlementError = data.settlement.error;
      }
      setTransactionErrors(errors);

      // Extract status information
      const status: { verificationStatus?: string; settlementStatus?: string } = {};
      if (data.verification?.status) {
        status.verificationStatus = data.verification.status;
      }
      if (data.settlement?.status) {
        status.settlementStatus = data.settlement.status;
      }
      setTransactionStatus(status);
    } catch (err) {
      setSelectedTransactionDetails(
        `Error: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
      setTransactionErrors({});
      setTransactionStatus({});
    } finally {
      setLoadingDetails(false);
    }
  };

  // Format currency
  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 6,
    }).format(amount);
  };

  // Calculate USD value from amount and decimals
  const calculateUsdValue = (amount: string, decimals?: number): number => {
    if (!decimals) return 0;
    const amountNum = parseFloat(amount || '0');
    if (isNaN(amountNum)) return 0;
    return amountNum / Math.pow(10, decimals);
  };

  // Format an MPP amount + ISO currency code. MPP config/store amounts are
  // already major-unit values (e.g. "1.00" or crypto base units), not minor
  // units like Stripe's API-facing cents, so no scaling is applied here.
  const formatMppAmount = (amount?: string, currency?: string): string => {
    if (!amount) return '—';
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum)) return amount;
    const code = (currency || 'usd').toUpperCase();
    try {
      return new Intl.NumberFormat('en-US', { style: 'currency', currency: code }).format(
        amountNum
      );
    } catch {
      return `${amountNum.toFixed(2)} ${code}`;
    }
  };

  // Map an MPP transaction summary onto the shared table row shape
  const mppToRow = (mpp: MppTransactionSummary): PaymentTransaction => {
    const status = mpp.status.toLowerCase();
    const paidAt = status === 'verified' ? mpp.created_at : undefined;
    return {
      tx_hash: '',
      channel_id: mpp.surface_id,
      channel_name: mpp.channel_name,
      resource_path: mpp.resource_url,
      recipient_name: mpp.payer || 'Stripe',
      correlation_id: mpp.id,
      verification_status: status,
      verification_mode: mpp.payment_method || 'mpp',
      verification_error: mpp.error,
      verification_completed_at: paidAt,
      settlement_status: status,
      settlement_completed_at: paidAt,
      created_at: mpp.created_at,
      first_seen: mpp.created_at,
      last_updated: mpp.created_at,
      protocol: 'mpp',
      payment_method: mpp.payment_method,
      currency: mpp.currency,
      payer: mpp.payer,
      amount: mpp.amount,
    };
  };

  // Duration formatting now handled by shared utility in stringUtils

  // Delete transaction handler
  const handleDeleteTransaction = async (id: string) => {
    try {
      const url = `/api/admin/x402/transactions/${id}`;

      const response = await apiClient.fetch(url, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Failed to delete: ${response.status}`);
      }

      setSuccess('Transaction deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      fetchData();
    } catch (error: any) {
      setError(error.message || 'Failed to delete transaction');
    }
  };

  // Fetch unified payments data
  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true);

      const buildUrl = (path: string) => {
        const base = path.includes('?') ? path + '&' : path + '?';
        return `${base}bucket_seconds=${bucketSeconds}`;
      };

      const response = await apiClient.fetch(buildUrl('/api/admin/x402/payments/all?limit=200'));
      const data = await response.json();

      let mppRows: PaymentTransaction[] = [];
      try {
        const mppResponse = await apiClient.fetch('/api/admin/mpp/transactions?limit=200');
        if (mppResponse.ok) {
          const mppData = await mppResponse.json();
          mppRows = (mppData.transactions || []).map((t: MppTransactionSummary) => mppToRow(t));
        }
      } catch (mppError) {
        console.error('Failed to fetch MPP transactions:', mppError);
      }

      // Group payments by tx_hash to combine verification + settlement
      // Use correlation_id as primary key if available, fallback to tx_hash
      const txMap = new Map<string, any>();

      (data.payments || []).forEach((p: any) => {
        // Use correlation_id as primary linkage if available, otherwise tx_hash
        const linkKey = p.correlation_id || p.tx_hash || `no-key-${p.id}`;

        if (!txMap.has(linkKey)) {
          txMap.set(linkKey, {
            tx_hash: p.tx_hash || '',
            channel_id: p.channel_id,
            channel_name: p.channel_name,
            network: p.network,
            network_name: p.network_name,
            amount: p.amount,
            decimals: p.decimals,
            asset: p.asset,
            recipient: p.recipient,
            recipient_name: p.recipient_name,
            tx_explorer_url: p.tx_explorer_url,
            address_explorer_url: p.address_explorer_url,
            correlation_id: p.correlation_id,
            created_at: p.created_at,
          });
        }

        const tx = txMap.get(linkKey);

        // Preserve fields if they come from this payment record
        if (p.tx_hash && !tx.tx_hash) tx.tx_hash = p.tx_hash;
        if (p.tx_explorer_url && !tx.tx_explorer_url) tx.tx_explorer_url = p.tx_explorer_url;
        if (p.address_explorer_url && !tx.address_explorer_url)
          tx.address_explorer_url = p.address_explorer_url;
        if (p.recipient_name && !tx.recipient_name) tx.recipient_name = p.recipient_name;
        if (p.created_at && !tx.created_at) tx.created_at = p.created_at;

        if (p.type === 'verification') {
          tx.verification_id = p.id;
          tx.verification_status = p.status;
          tx.verification_created_at = p.created_at;
          tx.verification_completed_at = p.completed_at;
          tx.verification_error = p.error;
          tx.resource_path = p.resource_path;
          tx.verification_mode = p.verification_mode;
          // Verification is local if verification_mode is 'Local', 'Signature', or 'Mock'
          // Remote if 'FabricGateway' or 'ExternalFacilitator'
          tx.verification_is_local =
            p.verification_mode &&
            (p.verification_mode.toLowerCase() === 'local' ||
              p.verification_mode.toLowerCase() === 'signature' ||
              p.verification_mode.toLowerCase() === 'mock');
        } else if (p.type === 'settlement') {
          tx.settlement_id = p.id;
          tx.settlement_status = p.status;
          tx.settlement_mode = p.settlement_mode;
          tx.settlement_method = p.settlement_method;
          tx.settlement_verified_at = p.verified_at;
          tx.settlement_completed_at = p.settlement_completed_at;
          tx.settlement_attempts = p.settlement_attempts;
          tx.settlement_error = p.error;
          tx.sync_status = p.sync_status;
          // Settlement is local if sync_status is 'local', remote otherwise
          tx.settlement_is_local = p.sync_status === 'local';
        }

        // Update timestamps
        const timestamps = [
          p.created_at,
          p.completed_at,
          p.verified_at,
          p.settlement_completed_at,
        ].filter(t => t);

        if (timestamps.length > 0) {
          tx.first_seen = tx.first_seen
            ? Math.min(tx.first_seen, ...timestamps)
            : Math.min(...timestamps);
          tx.last_updated = tx.last_updated
            ? Math.max(tx.last_updated, ...timestamps)
            : Math.max(...timestamps);
        }
      });

      // Convert map to array and sort by most recent first
      const allTransactions: PaymentTransaction[] = [
        ...Array.from(txMap.values()),
        ...mppRows,
      ].sort((a, b) => (b.last_updated || 0) - (a.last_updated || 0));

      setTransactions(allTransactions);
      setChartData(data.chart_data || []);
    } catch (error) {
      console.error('Failed to fetch payments data:', error);
    } finally {
      setRefreshing(false);
    }
  }, [bucketSeconds]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Filter function for transactions
  const filterTransaction = (tx: PaymentTransaction): boolean => {
    if (!filterText.trim()) return true;

    const searchLower = filterText.toLowerCase();

    // Check all searchable fields
    const searchableFields = [
      tx.channel_name || '',
      tx.resource_path || '',
      tx.network || '',
      tx.network_name || '',
      tx.tx_hash || '',
      tx.amount || '',
      tx.verification_status || '',
      tx.settlement_status || '',
      tx.payment_method || '',
      tx.payer || '',
      tx.currency || '',
    ];

    return searchableFields.some(field => field && field.toLowerCase().includes(searchLower));
  };

  // Apply filters
  const filteredTransactions = transactions.filter(filterTransaction);

  // Prepare chart data with local timezone labels
  const paymentsChartData = {
    labels: chartData.map(d => {
      // Convert Unix timestamp to local timezone time string
      const date = new Date(d.timestamp * 1000);
      return formatTime(date);
    }),
    datasets: [
      {
        label: 'Verifications',
        data: chartData.map(d => d.verifications),
        backgroundColor: 'rgba(75, 192, 192, 0.6)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1,
      },
      {
        label: 'Settlements',
        data: chartData.map(d => d.settlements),
        backgroundColor: 'rgba(255, 159, 64, 0.6)',
        borderColor: 'rgba(255, 159, 64, 1)',
        borderWidth: 1,
      },
    ],
  };

  const chartOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
        },
      },
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },
  };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={filterText}
            onChange={setFilterText}
            placeholder="Filter Payments..."
          />
        </div>
        <AppButton
          variant="primary"
          size="md"
          className="shadow-sm"
          onClick={fetchData}
          loading={refreshing}
          loadingLabel="Refreshing..."
          disabled={refreshing}
          iconStart={<i className="fas fa-sync-alt fa-sm me-1" aria-hidden="true" />}
        >
          Refresh
        </AppButton>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      {/* Payments Over Time Chart */}
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-chart-bar me-2"></i>
            Payments Over Time
          </h6>
          <select
            className="form-control form-control-sm dropdown-styling"
            style={{ width: 'auto' }}
            value={bucketSeconds}
            onChange={e => setBucketSeconds(parseInt(e.target.value))}
            title="Time bucket size"
          >
            <option value={30}>30 seconds</option>
            <option value={60}>1 minute</option>
            <option value={300}>5 minutes</option>
            <option value={900}>15 minutes</option>
            <option value={1800}>30 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={10800}>3 hours</option>
            <option value={21600}>6 hours</option>
          </select>
        </div>
        <div className="card-body">
          <div style={{ height: '300px' }}>
            {chartData.length > 0 ? (
              <Bar data={paymentsChartData} options={chartOptions} />
            ) : (
              <div className="d-flex justify-content-center align-items-center h-100">
                <p className="text-muted">No payment data available for chart</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* All Payments Section */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-money-bill-wave me-2"></i>
            All Payments
            <Badge
              value={filteredTransactions.length}
              className="ms-2"
              ariaLabel={`${filteredTransactions.length} payments shown`}
            />
            {filterText && transactions.length !== filteredTransactions.length && (
              <Badge
                value={transactions.length}
                tone="secondary"
                prefix="of "
                className="ms-1"
                ariaLabel={`${filteredTransactions.length} of ${transactions.length} payments shown`}
              />
            )}
          </h6>
        </div>
        <div className="card-body">
          <InfoBanner
            title="How payment processing works"
            testIdPrefix="payments-overview"
            docLink={DOCS_URL.payments}
          >
            <p className="mb-0">
              Payments use <strong>x402</strong>, a protocol where a caller pays per request instead
              of holding a subscription. Each transaction moves through two stages, shown in the
              Progress column: <strong>Verified</strong> confirms the caller's payment;{' '}
              <strong>Settled</strong> means the funds have actually moved.
            </p>
          </InfoBanner>
          {transactions.length === 0 ? (
            <EmptyState
              icon="fa-money-bill-wave"
              title="No payments yet"
              body="Payments are charges your surfaces collect from callers using x402, a protocol where a caller pays per request instead of holding a subscription. They appear here once a paywalled surface starts charging callers."
              docsHref={DOCS_URL.payments}
            />
          ) : filteredTransactions.length === 0 ? (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className="mb-0">No payments match your search.</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="table table-sm table-hover mb-0">
                <thead>
                  <tr>
                    <th>
                      Processing{' '}
                      <FieldHelp
                        ariaLabel="About Processing"
                        testId="field-help-payments-processing-mode"
                      >
                        <p>How this payment was verified and settled:</p>
                        <ul className="mb-0 ps-3">
                          <li>
                            <strong>Local</strong>: this gateway checked it directly (may still
                            confirm details on the blockchain).
                          </li>
                          <li>
                            <strong>Signature</strong>: verified using only a cryptographic
                            signature, no blockchain lookup.
                          </li>
                          <li>
                            <strong>Mock</strong>: a test/sandbox payment, no real funds moved.
                          </li>
                          <li>
                            <strong>FabricGateway</strong>: verified by another connected gateway in
                            your network of linked gateways.
                          </li>
                          <li>
                            <strong>ExternalFacilitator</strong>: verified by an outside x402
                            facilitator service.
                          </li>
                        </ul>
                      </FieldHelp>
                    </th>
                    <th style={{ width: '144px' }}>Progress</th>
                    <th>Channel, Network & Wallet</th>
                    <th>Processing milestones</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTransactions.map(txn => {
                    // Determine verification circle style
                    const verifyComplete =
                      txn.verification_status?.toLowerCase().includes('verified') ||
                      txn.verification_status?.toLowerCase().includes('completed');
                    const verifyFailed =
                      txn.verification_status?.toLowerCase().includes('failed') ||
                      txn.verification_status?.toLowerCase().includes('error');
                    const verifyCircleClass = verifyFailed
                      ? 'text-danger'
                      : verifyComplete
                        ? 'text-success'
                        : 'text-muted';
                    const verifyIcon =
                      verifyComplete || verifyFailed ? 'fas fa-circle' : 'far fa-circle';

                    // Determine settlement circle style
                    const settleComplete =
                      txn.settlement_status?.toLowerCase().includes('settled') ||
                      txn.settlement_status?.toLowerCase().includes('completed');
                    const settleFailed =
                      txn.settlement_status?.toLowerCase().includes('failed') ||
                      txn.settlement_status?.toLowerCase().includes('error');
                    const settleCircleClass = settleFailed
                      ? 'text-danger'
                      : settleComplete
                        ? 'text-success'
                        : 'text-muted';
                    const settleIcon =
                      settleComplete || settleFailed ? 'fas fa-circle' : 'far fa-circle';

                    // Calculate settlement duration if both timestamps exist (returns formatted string)
                    const settlementDuration =
                      txn.verification_created_at && txn.settlement_completed_at
                        ? formatDuration(txn.verification_created_at, txn.settlement_completed_at)
                        : null;

                    // Format date/time - use timeAgo if < 1 hour, otherwise full date
                    const now = Math.floor(Date.now() / 1000);
                    const createdTime = txn.created_at;
                    const verifyTime = txn.verification_completed_at;
                    const settleTime = txn.settlement_completed_at;

                    const formatTimestamp = (ts: number | undefined) => {
                      if (!ts) return '(In progress)';
                      const age = now - ts;
                      if (age < 3600) {
                        return timeAgo(new Date(ts * 1000));
                      }
                      return formatDateTime(new Date(ts * 1000), true);
                    };

                    // Determine transaction ID for deletion (prefer correlation_id, fallback to verification or settlement)
                    const transactionId =
                      txn.correlation_id || txn.verification_id || txn.settlement_id;

                    // Determine processing mode (from verification_mode or settlement_method)
                    const processingMode =
                      txn.verification_mode || txn.settlement_method || 'Unknown';

                    // Determine overall status (use settlement status if available, otherwise verification)
                    const overallStatus =
                      txn.settlement_status || txn.verification_status || 'Unknown';
                    const isFinalStatus = settleComplete || verifyComplete;
                    const statusBadgeClass = isFinalStatus
                      ? 'text-bg-success'
                      : settleFailed || verifyFailed
                        ? 'text-bg-danger'
                        : 'text-bg-warning';

                    return (
                      <tr key={txn.tx_hash || txn.correlation_id}>
                        <td>
                          <div className="d-flex flex-column" style={{ gap: '4px' }}>
                            <span className="badge text-bg-info" style={{ fontSize: '11px' }}>
                              {processingMode}
                            </span>
                            <span
                              className={`badge ${statusBadgeClass}`}
                              style={{ fontSize: '11px' }}
                            >
                              {overallStatus}
                            </span>
                          </div>
                        </td>
                        <td>
                          <div className="d-flex flex-column" style={{ gap: '6px' }}>
                            {/* Main progress circles */}
                            <div className="d-flex align-items-start" style={{ gap: '8px' }}>
                              {/* Verification Stage */}
                              <div className="text-center" style={{ minWidth: '80px' }}>
                                <div style={{ height: '20px', lineHeight: '20px' }}>
                                  <i
                                    className={`${verifyIcon} ${verifyCircleClass}`}
                                    style={{ fontSize: '16px' }}
                                  ></i>
                                </div>
                                <div
                                  className="small text-muted"
                                  style={{ fontSize: '11px', marginTop: '2px' }}
                                >
                                  {txn.protocol === 'mpp' ? 'Paid' : 'Verified'}
                                </div>
                              </div>

                              {txn.protocol !== 'mpp' && (
                                <>
                                  {/* Connector */}
                                  <div
                                    style={{
                                      height: '2px',
                                      width: '20px',
                                      backgroundColor: 'var(--gray-500)',
                                      flexShrink: 0,
                                      marginTop: '9px',
                                    }}
                                  ></div>

                                  {/* Settlement Stage */}
                                  <div className="text-center" style={{ minWidth: '80px' }}>
                                    <div style={{ height: '20px', lineHeight: '20px' }}>
                                      <i
                                        className={`${settleIcon} ${settleCircleClass}`}
                                        style={{ fontSize: '16px' }}
                                      ></i>
                                    </div>
                                    <div
                                      className="small text-muted"
                                      style={{ fontSize: '11px', marginTop: '2px' }}
                                    >
                                      Settled
                                    </div>
                                  </div>
                                </>
                              )}
                            </div>

                            {/* Duration */}
                            {settlementDuration !== null && (
                              <div className="text-center text-muted" style={{ fontSize: '12px' }}>
                                {settlementDuration}
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <Link
                            to={`/surfaces/${encodeURIComponent(txn.channel_id || '')}`}
                            className="text-primary"
                          >
                            {txn.channel_name || txn.channel_id || '-'}
                          </Link>
                          {(txn.recipient_name || txn.recipient) && (
                            <div className="small text-muted" title={txn.recipient}>
                              {txn.protocol === 'mpp'
                                ? formatMppAmount(txn.amount, txn.currency)
                                : txn.amount && txn.decimals
                                  ? formatCurrency(calculateUsdValue(txn.amount, txn.decimals))
                                  : '$0.00'}{' '}
                              {txn.protocol === 'mpp' ? 'paid via' : 'sent to'}{' '}
                              {txn.recipient_name || txn.recipient}
                              {txn.network_name ? ` on ${txn.network_name}` : ''}
                              {txn.tx_hash && (
                                <span className="small">
                                  {txn.tx_explorer_url ? (
                                    <a
                                      href={txn.tx_explorer_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-primary"
                                      title={txn.tx_hash}
                                    >
                                      <i
                                        className="fas fa-external-link-alt ms-1"
                                        style={{ fontSize: '12px' }}
                                      ></i>
                                    </a>
                                  ) : (
                                    <span title={txn.tx_hash} style={{ cursor: 'default' }}>
                                      {topAndTail(txn.tx_hash, 8, 8)}
                                    </span>
                                  )}
                                </span>
                              )}{' '}
                              <div className="mt-1">
                                <AppButton
                                  variant="link"
                                  size="sm"
                                  onClick={() =>
                                    handleViewDetails(transactionId || '', txn.protocol || 'x402')
                                  }
                                  className="p-0 text-primary"
                                  style={{ fontSize: '12px', textDecoration: 'none' }}
                                  disabled={!transactionId}
                                  iconStart={
                                    <i className="fas fa-file-alt me-1" aria-hidden="true"></i>
                                  }
                                >
                                  view transaction details
                                </AppButton>
                              </div>{' '}
                            </div>
                          )}
                        </td>
                        <td>
                          <div className="d-flex flex-column" style={{ gap: '2px' }}>
                            <div className="small">
                              <span
                                className={`badge ${createdTime ? 'text-bg-success' : 'text-bg-secondary'}`}
                                style={{
                                  fontSize: '11px',
                                  minWidth: '60px',
                                  display: 'inline-block',
                                  marginRight: '10px',
                                  backgroundColor: createdTime
                                    ? 'var(--success)'
                                    : 'var(--gray-500)',
                                  color: '#fff',
                                }}
                              >
                                Created
                              </span>
                              {createdTime ? formatTimestamp(createdTime) : '(In progress)'}
                            </div>
                            <div className="small">
                              <span
                                className={`badge ${verifyTime ? 'text-bg-success' : 'text-bg-secondary'}`}
                                style={{
                                  fontSize: '11px',
                                  minWidth: '60px',
                                  display: 'inline-block',
                                  marginRight: '10px',
                                  backgroundColor: verifyTime
                                    ? 'var(--success)'
                                    : 'var(--gray-500)',
                                  color: '#fff',
                                }}
                              >
                                {txn.protocol === 'mpp' ? 'Paid' : 'Verified'}
                              </span>
                              {verifyTime ? formatTimestamp(verifyTime) : '(In progress)'}
                            </div>
                            {txn.protocol !== 'mpp' && (
                              <div className="small">
                                <span
                                  className={`badge ${settleTime ? 'text-bg-success' : 'text-bg-secondary'}`}
                                  style={{
                                    fontSize: '11px',
                                    minWidth: '60px',
                                    display: 'inline-block',
                                    marginRight: '10px',
                                    backgroundColor: settleTime
                                      ? 'var(--success)'
                                      : 'var(--gray-500)',
                                    color: '#fff',
                                  }}
                                >
                                  Settled
                                </span>
                                {settleTime ? formatTimestamp(settleTime) : '(In progress)'}
                              </div>
                            )}
                          </div>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          {canDeleteTransactions && transactionId && txn.protocol !== 'mpp' && (
                            <DeleteButton
                              onDelete={() => handleDeleteTransaction(transactionId)}
                              size="sm"
                              title="Delete Transaction"
                            />
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Transaction Details Modal */}
      {showDetailsModal && (
        <div
          className="modal show d-block"
          tabIndex={-1}
          style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
        >
          <div className="modal-dialog modal-lg modal-dialog-scrollable">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Transaction Details</h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setShowDetailsModal(false)}
                  aria-label="Close"
                />
              </div>
              <div className="modal-body">
                {loadingDetails ? (
                  <div className="text-center py-4">
                    <div className="spinner-border text-primary" role="status">
                      <span className="sr-only">Loading...</span>
                    </div>
                  </div>
                ) : (
                  <>
                    <textarea
                      className="form-control"
                      rows={20}
                      readOnly
                      value={selectedTransactionDetails}
                      style={{ fontFamily: 'monospace', fontSize: '12px' }}
                    />

                    {/* Success Information */}
                    {!transactionErrors.verificationError &&
                      !transactionErrors.settlementError &&
                      (transactionStatus.verificationStatus ||
                        transactionStatus.settlementStatus) && (
                        <div className="alert alert-success mt-3 mb-0" role="alert">
                          <h6 className="alert-heading mb-2">
                            <i className="fas fa-check-circle me-2"></i>
                            Transaction Status
                          </h6>
                          {transactionStatus.verificationStatus && (
                            <div className="mb-2">
                              <strong>Verification:</strong>
                              <span
                                className="ms-2 badge text-bg-success"
                                style={{ fontSize: '12px' }}
                              >
                                {transactionStatus.verificationStatus}
                              </span>
                            </div>
                          )}
                          {transactionStatus.settlementStatus && (
                            <div className={transactionStatus.verificationStatus ? 'mt-2' : ''}>
                              <strong>Settlement:</strong>
                              <span
                                className="ms-2 badge text-bg-success"
                                style={{ fontSize: '12px' }}
                              >
                                {transactionStatus.settlementStatus}
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                    {/* Error Information */}
                    {(transactionErrors.verificationError || transactionErrors.settlementError) && (
                      <div className="alert alert-danger mt-3 mb-0" role="alert">
                        <h6 className="alert-heading mb-2">
                          <i className="fas fa-exclamation-triangle me-2"></i>
                          Error Details
                        </h6>
                        {transactionErrors.verificationError && (
                          <div className="mb-2">
                            <strong>Verification Error:</strong>
                            <div
                              className="mt-1"
                              style={{
                                fontFamily: 'monospace',
                                fontSize: '13px',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                              }}
                            >
                              {transactionErrors.verificationError}
                            </div>
                          </div>
                        )}
                        {transactionErrors.settlementError && (
                          <div className={transactionErrors.verificationError ? 'mt-3' : ''}>
                            <strong>Settlement Error:</strong>
                            <div
                              className="mt-1"
                              style={{
                                fontFamily: 'monospace',
                                fontSize: '13px',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                              }}
                            >
                              {transactionErrors.settlementError}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
              <div className="modal-footer">
                <AppButton variant="secondary" size="sm" onClick={() => setShowDetailsModal(false)}>
                  Close
                </AppButton>
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(selectedTransactionDetails);
                    setSuccess('Transaction details copied to clipboard');
                    setTimeout(() => setSuccess(null), 3000);
                  }}
                  disabled={loadingDetails}
                  iconStart={<i className="fas fa-copy fa-sm me-1" aria-hidden="true" />}
                >
                  Copy to Clipboard
                </AppButton>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PaymentsPage;
