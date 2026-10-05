import React from 'react';
import { MetricsConfig } from '../types';

interface RetentionTabProps {
  config: MetricsConfig;
  updateConfig: (path: string[], value: any) => void;
}

const RetentionTab: React.FC<RetentionTabProps> = ({ config, updateConfig }) => {
  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fas fa-clock me-2"></i>
          Retention Configuration
        </h5>
        <p className="text-muted">
          Configure how long data is retained locally and in the collector.
        </p>
      </div>

      <div className="mb-4">
        <label htmlFor="localLogsHours" className="form-label">
          Local Logs Retention (hours)
        </label>
        <input
          type="number"
          className="form-control"
          id="localLogsHours"
          value={config.retention.local_logs_hours}
          onChange={e =>
            updateConfig(['retention', 'local_logs_hours'], parseInt(e.target.value) || 24)
          }
          min="1"
        />
        <div className="form-text">
          How long to keep local log files before deletion. Default is 24 hours.
        </div>
      </div>

      <div className="mb-4">
        <label htmlFor="collectorLogSize" className="form-label">
          Collector Log Size Limit (MB)
        </label>
        <input
          type="number"
          className="form-control"
          id="collectorLogSize"
          value={config.retention.collector_log_mb}
          onChange={e =>
            updateConfig(['retention', 'collector_log_mb'], parseInt(e.target.value) || 100)
          }
          min="1"
        />
        <div className="form-text">
          Maximum size for collector log files before rotation. Default is 100 MB.
        </div>
      </div>

      <div className="alert alert-warning">
        <i className="fas fa-exclamation-triangle me-2"></i>
        <strong>Warning:</strong> Lower retention values will reduce disk usage but may result in
        data loss if logs are not exported before deletion.
      </div>

      <div className="card bg-light">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-lightbulb me-2"></i>
            Retention Recommendations
          </h6>
          <ul className="mb-0">
            <li>
              <strong>Development:</strong> 24 hours is usually sufficient
            </li>
            <li>
              <strong>Staging:</strong> 48-72 hours for debugging
            </li>
            <li>
              <strong>Production:</strong> 168 hours (7 days) or more, with external storage
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default RetentionTab;
