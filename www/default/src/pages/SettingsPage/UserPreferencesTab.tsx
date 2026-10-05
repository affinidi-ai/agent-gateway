import React from 'react';
import { Settings, UserSettingsOverrides } from '../../types';
import FieldHelp from '../../components/shared/FieldHelp';

interface UserPreferencesTabProps {
  formData: Settings;
  userSettingsOverrides: UserSettingsOverrides | null;
  isSubmitting: boolean;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onSelectChange: (e: React.ChangeEvent<HTMLSelectElement>) => void;
  onSaveUserSettings: (overrides: Partial<UserSettingsOverrides>) => void;
  onResetUserSettings: () => void;
}

const UserPreferencesTab: React.FC<UserPreferencesTabProps> = ({
  formData,
  userSettingsOverrides,
  isSubmitting,
  onInputChange,
  onSelectChange,
  onSaveUserSettings,
  onResetUserSettings,
}) => {
  const handleSaveMyPreferences = (e: React.FormEvent) => {
    e.preventDefault();
    onSaveUserSettings({
      badge_threshold_minutes: formData.badge_threshold,
      refresh_interval_seconds: formData.refresh_interval_seconds,
      log_timestamp_format: formData.log_timestamp_format,
      bucket_seconds: formData.bucket_seconds,
      payments_min_display: formData.payments_min_display,
    });
  };

  return (
    <div className="card shadow mb-3">
      <div className="card-body">
        <p className="text-muted mb-3">
          These preferences are personal to your account. They override the system defaults for your
          dashboard only.
          {userSettingsOverrides &&
            Object.keys(userSettingsOverrides).some(
              k => (userSettingsOverrides as any)[k] != null
            ) && <span className="ms-2 badge text-bg-info">Custom preferences active</span>}
        </p>
        <form onSubmit={handleSaveMyPreferences}>
          <div className="row">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Identity Badge Settings</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="badge_threshold">Badge Time Threshold (minutes)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="badge_threshold"
                  name="badge_threshold"
                  min="1"
                  max="1440"
                  value={formData.badge_threshold}
                  onChange={onInputChange}
                  placeholder="Enter threshold in minutes"
                />
                <small className="form-text text-muted">
                  Identities created or used within this time will show "new" or "active" badges.
                  Default: 5 minutes
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Dashboard Refresh Rate</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="refresh_interval_seconds">Auto-Refresh Interval (seconds)</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="refresh_interval_seconds"
                  name="refresh_interval_seconds"
                  min="1"
                  max="300"
                  value={formData.refresh_interval_seconds || 5}
                  onChange={onInputChange}
                  placeholder="Enter refresh interval in seconds"
                />
                <small className="form-text text-muted">
                  Minimum time between dashboard data refreshes. Lower = more real-time but higher
                  bandwidth. Default: 5 seconds. Range: 1-300 seconds (5 minutes)
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Log Display</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="log_timestamp_format">Log Timestamp Format</label>
                <select
                  className="form-control form-control-sm dropdown-styling"
                  id="log_timestamp_format"
                  name="log_timestamp_format"
                  value={formData.log_timestamp_format || 'local'}
                  onChange={onSelectChange}
                >
                  <option value="local">Local Time (with timezone)</option>
                  <option value="utc">UTC (ISO 8601)</option>
                  <option value="relative">Relative (e.g., "2m ago")</option>
                  <option value="compact">Compact (time only)</option>
                </select>
                <small className="form-text text-muted">
                  Format for log entry timestamps in the Logs page. Default: Local Time
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Graph Settings</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="bucket_seconds">
                  Time Series Bucket Interval{' '}
                  <FieldHelp testId="field-help-bucket-seconds" ariaLabel="About Bucket Interval">
                    A bucket groups events into one time slice on a graph. A smaller bucket (e.g. 30
                    seconds) shows more detail but a noisier line; a larger one (e.g. 1 hour)
                    smooths the trend but hides short spikes.
                  </FieldHelp>
                </label>
                <select
                  className="form-control form-control-sm dropdown-styling"
                  id="bucket_seconds"
                  name="bucket_seconds"
                  value={formData.bucket_seconds || 30}
                  onChange={onSelectChange}
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
                <small className="form-text text-muted">
                  Default bucket interval for aggregated connections time series graph. Can be
                  overridden on the dashboard. Default: 30 seconds
                </small>
              </div>

              <h6 className="mb-2 font-weight-bold">Payment Settings</h6>
              <div className="mb-3 mb-3">
                <label htmlFor="payments_min_display">Minimum Payment Items to Display</label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="payments_min_display"
                  name="payments_min_display"
                  min="1"
                  max="100"
                  value={formData.payments_min_display}
                  onChange={onInputChange}
                  placeholder="Enter minimum number of items"
                />
                <small className="form-text text-muted">
                  Minimum number of payment items to display in the Payments page. Default: 10
                </small>
              </div>

              <div className="d-flex">
                <button
                  type="submit"
                  className="btn btn-primary btn-sm me-2"
                  disabled={isSubmitting}
                >
                  <i className="fas fa-save"></i> Save My Preferences
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={isSubmitting}
                  onClick={onResetUserSettings}
                >
                  <i className="fas fa-undo"></i> Reset to System Defaults
                </button>
              </div>
            </div>

            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">About Badge Logic</h6>
              <div className="alert alert-info py-2">
                <strong>Badge Behavior:</strong>
                <ul className="mb-0">
                  <li>
                    <span className="badge text-bg-success">NEW</span> - Identity created within
                    threshold
                  </li>
                  <li>
                    <span className="badge text-bg-primary">ACTIVE</span> - Identity used within
                    threshold
                  </li>
                  <li>No badge - Identity hasn't been used recently</li>
                </ul>
              </div>

              <h6 className="mb-2 font-weight-bold">About Preferences</h6>
              <div className="alert alert-info py-2">
                <strong>Per-User Settings:</strong>
                <p className="mb-0">
                  These preferences are saved to your user account. They override the system
                  defaults for your dashboard only. Other users are not affected by your changes.
                  Resetting will revert to the system-wide defaults set by the administrator.
                </p>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default UserPreferencesTab;
