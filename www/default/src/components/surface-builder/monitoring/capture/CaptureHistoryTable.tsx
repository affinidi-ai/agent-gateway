import React from 'react';
import { formatDateTime } from '../../../../utils/stringUtils';
import { CapturedPayload, MAX_HISTORY } from './types';

interface CaptureHistoryTableProps {
  captured: CapturedPayload[];
  onSelectRow: (capture: CapturedPayload) => void;
}

const statusBadge = (status: string) => {
  const cls =
    status === 'success'
      ? 'text-bg-success'
      : status === 'Failed Validation'
        ? 'text-bg-danger'
        : status === 'method_not_allowed' || status === 'mcp_error'
          ? 'text-bg-warning'
          : 'text-bg-info';
  let icon: string;
  let label: string;
  if (status === 'success') {
    icon = 'fa-check-circle';
    label = 'Success';
  } else if (status === 'Failed Validation') {
    icon = 'fa-times-circle';
    label = 'Failed Validation';
  } else if (status === 'method_not_allowed') {
    icon = 'fa-exclamation-triangle';
    label = 'Method Not Allowed';
  } else if (status === 'mcp_error') {
    icon = 'fa-exclamation-circle';
    label = 'MCP Error';
  } else {
    icon = 'fa-info-circle';
    label = status;
  }
  return (
    <span className={`badge ${cls}`}>
      <i className={`fas ${icon}`}></i> {label}
    </span>
  );
};

const CaptureHistoryTable: React.FC<CaptureHistoryTableProps> = ({ captured, onSelectRow }) => {
  if (captured.length === 0) return null;
  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-info">
          <i className="fas fa-history"></i> Payload History
          <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
            {captured.length}/{MAX_HISTORY}
          </span>
          <small className="text-muted ms-2">Click any row to load into view above</small>
        </h6>
      </div>
      <div className="card-body">
        <div className="table-responsive">
          <table className="table table-hover table-sm">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Channel</th>
                <th>Validation Status</th>
                <th>Payload Preview</th>
              </tr>
            </thead>
            <tbody>
              {captured.map((capture, index) => {
                const preview = JSON.stringify(capture.payload);
                return (
                  <tr
                    key={index}
                    onClick={() => onSelectRow(capture)}
                    className="capture-row"
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="timestamp-cell">{formatDateTime(capture.timestamp, true)}</td>
                    <td>
                      <span className="badge text-bg-secondary">{capture.channel}</span>
                    </td>
                    <td>{statusBadge(capture.validation_status)}</td>
                    <td>
                      <code className="payload-preview">
                        {preview.substring(0, 100)}
                        {preview.length > 100 && '...'}
                      </code>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default CaptureHistoryTable;
