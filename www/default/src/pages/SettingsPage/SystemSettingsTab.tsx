import React from 'react';
import { Settings } from '../../types';

interface SystemSettingsTabProps {
  formData: Settings;
  isSubmitting: boolean;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onSave: (e: React.FormEvent) => void;
  onReset: () => void;
}

const SystemSettingsTab: React.FC<SystemSettingsTabProps> = ({
  formData,
  isSubmitting,
  onInputChange,
  onSave,
  onReset,
}) => {
  return (
    <div className="card shadow mb-3">
      <div className="card-body">
        <p className="text-muted mb-3">
          These settings affect the entire system and all users. Changes here require administrator
          privileges.
        </p>
        <form onSubmit={onSave}>
          <div className="row">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Metrics Retention</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="metrics_retention">Metrics Retention Period (minutes)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="metrics_retention"
                  name="metrics_retention"
                  min="1"
                  max="10080"
                  value={formData.metrics_retention}
                  onChange={onInputChange}
                  placeholder="Enter retention period in minutes"
                />
                <small className="form-text text-muted">
                  How long to keep connection and rule validation metrics. Default: 360 minutes (6
                  hours). Range: 1 minute to 10,080 minutes (7 days)
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Task Activity Window</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="task_activity_window">Task Activity Scope (seconds)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="task_activity_window"
                  name="task_activity_window"
                  min="10"
                  max="600"
                  value={formData.task_activity_window}
                  onChange={onInputChange}
                  placeholder="Enter activity window in seconds"
                />
                <small className="form-text text-muted">
                  Time window for calculating task throughput. Recent activity resets the window.
                  Default: 60 seconds
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Onboarding Surface Settings</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="onboarding_channel_ttl_seconds">
                  Temporary Channel Timeout (seconds)
                </label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="onboarding_channel_ttl_seconds"
                  name="onboarding_channel_ttl_seconds"
                  min="10"
                  max="300"
                  value={formData.onboarding_channel_ttl_seconds}
                  onChange={onInputChange}
                  placeholder="Enter timeout in seconds"
                />
                <small className="form-text text-muted">
                  How long temporary onboarding channels remain active before automatic deletion.
                  Default: 30 seconds
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Sliding Window Scopes</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="connections_window">Total Connections Window (minutes)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="connections_window"
                  name="connections_window"
                  min="1"
                  max="1440"
                  value={formData.connections_window}
                  onChange={onInputChange}
                  placeholder="Enter connections window in minutes"
                />
                <small className="form-text text-muted">
                  Sliding window for total connections count. Default: 60 minutes
                </small>
              </div>

              <div className="mb-3 mb-3">
                <label htmlFor="latency_window">Average Latency Window (minutes)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="latency_window"
                  name="latency_window"
                  min="1"
                  max="1440"
                  value={formData.latency_window}
                  onChange={onInputChange}
                  placeholder="Enter latency window in minutes"
                />
                <small className="form-text text-muted">
                  Sliding window for average latency calculations. Default: 60 minutes
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Integrations</h6>
              <div className="mb-3">
                <label htmlFor="appliance_id">Appliance ID</label>
                <input
                  type="text"
                  className="form-control form-control-sm font-monospace"
                  id="appliance_id"
                  name="appliance_id"
                  maxLength={256}
                  value={formData.appliance_id ?? ''}
                  onChange={onInputChange}
                  placeholder="e.g. this appliance's id in Agent Watch"
                  data-testid="settings-appliance-id-input"
                />
                <small className="form-text text-muted">
                  Sent as{' '}
                  <code>
                    ${'{'}APPLIANCE_ID{'}'}
                  </code>{' '}
                  in integration payloads. While it is empty the variable is sent unfilled.
                </small>
              </div>

              <div className="d-flex">
                <button
                  type="submit"
                  className="btn btn-primary btn-sm me-2"
                  disabled={isSubmitting}
                >
                  <i className="fas fa-save"></i> Save System Settings
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={isSubmitting}
                  onClick={onReset}
                >
                  <i className="fas fa-undo"></i> Reset to Defaults
                </button>
              </div>
            </div>

            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">About Task Activity Scope</h6>
              <div className="alert alert-info py-2">
                <strong>Throughput Calculation:</strong>
                <p className="mb-0">
                  The task activity window determines how recent activity affects throughput
                  display. If no activity occurs within this window, throughput shows 0 B/s. Any new
                  activity resets the window.
                </p>
              </div>

              <h6 className="mb-2 font-weight-bold">About Metrics Retention</h6>
              <div className="alert alert-warning py-2">
                <strong>
                  <i className="fas fa-exclamation-triangle"></i> Note:
                </strong>
                <p className="mb-0">
                  Metrics older than the retention period are automatically deleted on restart.
                  Reducing this value will truncate historical data on the next restart.
                </p>
              </div>

              <h6 className="mb-2 font-weight-bold">About Sliding Windows</h6>
              <div className="alert alert-info py-2">
                <strong>Window Scopes:</strong>
                <ul className="mb-0">
                  <li>
                    <strong>Connections Window:</strong> Tracks total connections in the specified
                    time period
                  </li>
                  <li>
                    <strong>Latency Window:</strong> Calculates average latency from connections in
                    the specified time period
                  </li>
                  <li>
                    Shorter windows show more recent activity, longer windows provide broader trends
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default SystemSettingsTab;
