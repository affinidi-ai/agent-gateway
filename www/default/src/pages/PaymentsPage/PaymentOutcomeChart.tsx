import React, { useMemo } from 'react';
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
import { formatTime } from '../../utils/stringUtils';
import { PAYMENT_OUTCOMES, type PaymentLedgerRow } from '../../types';
import { OUTCOME_META, bucketByOutcome } from './ledger';

ChartJS.register(CategoryScale, LinearScale, BarElement, ChartTitle, Tooltip, Legend);

const BUCKETS: Array<[number, string]> = [
  [60, '1 minute'],
  [300, '5 minutes'],
  [900, '15 minutes'],
  [3600, '1 hour'],
  [21600, '6 hours'],
  [86400, '1 day'],
];

const cssColor = (name: string, fallback: string) => {
  const v =
    typeof window !== 'undefined'
      ? getComputedStyle(document.documentElement).getPropertyValue(name).trim()
      : '';
  return v || fallback;
};

const options: ChartOptions<'bar'> = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: { stacked: true, grid: { display: false } },
    y: { stacked: true, beginAtZero: true, ticks: { stepSize: 1 } },
  },
  plugins: {
    legend: { display: true, position: 'top' },
    tooltip: { mode: 'index', intersect: false },
  },
};

interface Props {
  rows: PaymentLedgerRow[];
  bucketSeconds: number;
  onBucketChange: (seconds: number) => void;
}

const PaymentOutcomeChart: React.FC<Props> = ({ rows, bucketSeconds, onBucketChange }) => {
  const buckets = useMemo(() => bucketByOutcome(rows, bucketSeconds), [rows, bucketSeconds]);
  const data = useMemo(
    () => ({
      labels: buckets.map(b => formatTime(new Date(b.start))),
      datasets: PAYMENT_OUTCOMES.map(outcome => ({
        label: OUTCOME_META[outcome].label,
        data: buckets.map(b => b.counts[outcome]),
        backgroundColor: cssColor(OUTCOME_META[outcome].color, '#6b7280'),
        borderRadius: 4,
        borderSkipped: 'start' as const,
      })),
    }),
    [buckets]
  );

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-chart-bar me-2" aria-hidden="true" />
          Payments by outcome
        </h6>
        <select
          className="form-control form-control-sm dropdown-styling"
          style={{ width: 'auto' }}
          value={bucketSeconds}
          onChange={e => onBucketChange(parseInt(e.target.value, 10))}
          aria-label="Time bucket size"
          data-testid="payments-bucket-select"
        >
          {BUCKETS.map(([seconds, label]) => (
            <option key={seconds} value={seconds}>
              {label}
            </option>
          ))}
        </select>
      </div>
      <div className="card-body">
        <div style={{ height: '300px' }} data-testid="payments-outcome-chart">
          {buckets.length > 0 ? (
            <Bar data={data} options={options} />
          ) : (
            <div className="d-flex justify-content-center align-items-center h-100">
              <p className="text-muted">No payment data available for chart</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PaymentOutcomeChart;
