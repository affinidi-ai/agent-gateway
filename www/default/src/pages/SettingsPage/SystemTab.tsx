import React, { useRef, useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { FeatureFlags, Settings } from '../../types';

interface SystemTabProps {
  isSubmitting: boolean;
  onTruncateMetrics: () => void;
  settings: Settings | null;
  updateSettings: (settings: Partial<Settings>) => Promise<void>;
}

const SystemTab: React.FC<SystemTabProps> = ({
  isSubmitting,
  onTruncateMetrics,
  settings,
  updateSettings,
}) => {
  const [exportPubKey, setExportPubKey] = useState('');
  const [isExporting, setIsExporting] = useState(false);
  const [isBackingUp, setIsBackingUp] = useState(false);
  const [isRestoring, setIsRestoring] = useState(false);
  const [isTruncatingLogs, setIsTruncatingLogs] = useState(false);
  const restoreFileInputRef = useRef<HTMLInputElement>(null);

  const handleBackupStorage = async () => {
    setIsBackingUp(true);
    showToast('loading', 'Building full storage backup...');

    try {
      const blob = await apiClient.backupStorage();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'backup.agbak';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('success', 'Backup downloaded successfully!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Backup failed';
      showToast('error', errorMessage);
    } finally {
      setIsBackingUp(false);
    }
  };

  const handleRestoreStorage = async () => {
    restoreFileInputRef.current?.click();
  };

  const handleRestoreFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset input so same file can be re-selected
    e.target.value = '';

    if (!file.name.endsWith('.agbak') && !file.name.endsWith('.tgwbak')) {
      showToast('error', 'Please select a .agbak backup file');
      return;
    }

    if (
      !window.confirm(
        'Are you sure you want to restore from this backup?\n\n' +
          'The current storage will be backed up automatically before restore.\n' +
          'The service will restart twice to complete the restore process.'
      )
    ) {
      return;
    }

    setIsRestoring(true);
    showToast('loading', 'Uploading backup and initiating restore...');

    try {
      await apiClient.restoreStorage(file);
      showToast('success', 'Backup uploaded. The service will restart to complete the restore.');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Restore failed';
      showToast('error', errorMessage);
    } finally {
      setIsRestoring(false);
    }
  };

  const handleExportStorage = async () => {
    if (!exportPubKey.trim()) {
      showToast('error', 'Please paste an Ed25519 public key in PEM format');
      return;
    }

    setIsExporting(true);
    showToast('loading', 'Building encrypted storage export...');

    try {
      const blob = await apiClient.exportStorage(exportPubKey);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `storage-export-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')}.agx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('success', 'Storage export downloaded successfully!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Export failed';
      showToast('error', errorMessage);
    } finally {
      setIsExporting(false);
    }
  };

  const featureFlags = settings?.feature_flags || {};

  const handleTruncateOldLogs = async () => {
    setIsTruncatingLogs(true);
    showToast('loading', 'Truncating old log files...');
    try {
      const result = await apiClient.truncateOldLogs();
      const freedMB = (result.bytes_freed / (1024 * 1024)).toFixed(1);
      showToast('success', `Removed ${result.files_removed} old log file(s), freed ${freedMB} MB`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to truncate logs';
      showToast('error', errorMessage);
    } finally {
      setIsTruncatingLogs(false);
    }
  };

  return (
    <>
      <div className="card shadow mb-3">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-danger">
            <i className="fas fa-cogs"></i> System Actions
          </h6>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            These operations affect the backend system and apply changes immediately.
          </p>
          <div className="row">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Metrics Management</h6>
              <button
                type="button"
                className="btn btn-warning btn-sm"
                disabled={isSubmitting}
                onClick={onTruncateMetrics}
              >
                <i className="fas fa-cut"></i>{' '}
                {isSubmitting ? 'Processing...' : 'Truncate Old Metrics Now'}
              </button>
              <small className="form-text text-muted d-block mt-1">
                Remove metrics older than the retention period immediately without restarting.
              </small>
            </div>
          </div>
          <div className="row mt-3">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Log Management</h6>
              <button
                type="button"
                className="btn btn-warning btn-sm"
                disabled={isTruncatingLogs}
                onClick={handleTruncateOldLogs}
              >
                <i className={isTruncatingLogs ? 'fas fa-spinner fa-spin' : 'fas fa-cut'}></i>{' '}
                {isTruncatingLogs ? 'Truncating...' : 'Truncate Old Logs'}
              </button>
              <small className="form-text text-muted d-block mt-1">
                Remove old / rotated log files. The current active log file is always kept.
              </small>
            </div>
          </div>
        </div>
      </div>

      {/* Export Storage */}
      <div className="card shadow mb-3">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-info">
            <i className="fas fa-download"></i> Export Storage
          </h6>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Export Storage</h6>
              <p className="text-muted small mb-2">
                Export a PII-redacted snapshot of the storage directory, encrypted with your Ed25519
                public key. Sensitive directories (keys, secrets, credentials, avatars) are excluded
                entirely. Decrypt with:{' '}
                <code>./agent-gateway --decrypt-export export.agx --output export.zip</code>
              </p>
              <div className="mb-3 mb-2">
                <label htmlFor="exportPubKey">Ed25519 Public Key (PEM)</label>
                <textarea
                  className="form-control form-control-sm font-monospace"
                  id="exportPubKey"
                  rows={5}
                  placeholder={
                    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----'
                  }
                  value={exportPubKey}
                  onChange={e => setExportPubKey(e.target.value)}
                  style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                />
              </div>
              <button
                type="button"
                className="btn btn-outline-info btn-sm"
                disabled={isExporting || !exportPubKey.trim()}
                onClick={handleExportStorage}
              >
                <i className={isExporting ? 'fas fa-spinner fa-spin' : 'fas fa-download'}></i>{' '}
                {isExporting ? 'Exporting...' : 'Export & Download'}
              </button>
            </div>
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">About Storage Export</h6>
              <div className="alert alert-info py-2">
                <strong>Included:</strong>
                <ul className="mb-0 small">
                  <li>Channel, gateway, and mediator configurations</li>
                  <li>Integration definitions and triggers (credentials redacted)</li>
                  <li>Trust registry and connection point configs (DIDs hashed)</li>
                  <li>Metrics, notifications, and logs (IPs/emails redacted)</li>
                </ul>
              </div>
              <div className="alert alert-warning py-2">
                <strong>Not included:</strong>
                <ul className="mb-0 small">
                  <li>Private keys, secrets, API keys, certificates</li>
                  <li>Session tokens, passkey credentials</li>
                  <li>User avatars (photos)</li>
                  <li>
                    Directories: <code>identities</code>, <code>secrets</code>, <code>vc_keys</code>
                    , <code>passkeys</code>, <code>apikeys</code>, <code>certificates</code>,{' '}
                    <code>sessions</code>, <code>avatars</code>
                  </li>
                </ul>
              </div>
              <div className="alert alert-warning py-2 small">
                <i className="fas fa-shield-alt"></i> <strong>Encryption:</strong> The export is
                encrypted with your public key using hybrid encryption (X25519 ECDH + AES-256-GCM).
                Only the holder of the corresponding private key can decrypt it.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Backup / Restore */}
      <div className="card shadow mb-3">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-warning">
            <i className="fas fa-archive"></i> Backup / Restore
          </h6>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">Full Storage Backup</h6>
              <p className="text-muted small mb-2">
                Download a complete encrypted backup of the <code>_storage</code> folder. Unlike the
                Export above, this backup includes <strong>data including PIIs</strong>, private
                keys, secrets, and credentials. The file (<code>.agbak</code>) is an AES-256-GCM
                encrypted binary. Store it securely and do not share it over unencrypted channels.
              </p>
              <button
                type="button"
                className="btn btn-outline-warning btn-sm"
                disabled={isBackingUp}
                onClick={handleBackupStorage}
              >
                <i className={isBackingUp ? 'fas fa-spinner fa-spin' : 'fas fa-download'}></i>{' '}
                {isBackingUp ? 'Backing up...' : 'Backup'}
              </button>

              <hr />

              <h6 className="mb-2 font-weight-bold">Restore from Backup</h6>
              <p className="text-muted small mb-2">
                Upload a previously downloaded <code>backup.agbak</code> to restore the service. The
                current storage will be automatically backed up before the restore begins. The
                service will restart twice to complete the procedure.
              </p>
              <ol className="small text-muted mb-2">
                <li>
                  Upload triggers the service to save <code>backup.agbak</code> to{' '}
                  <code>_backup_restore/</code> and restart
                </li>
                <li>
                  On restart, the current <code>_storage</code> is archived to{' '}
                  <code>_backup_restore/local_backups/</code>
                </li>
                <li>
                  The uploaded backup is extracted as the new <code>_storage</code>
                </li>
                <li>The service restarts once more and runs normally with restored data</li>
              </ol>
              <input
                ref={restoreFileInputRef}
                type="file"
                accept=".agbak,.tgwbak"
                style={{ display: 'none' }}
                onChange={handleRestoreFileSelected}
              />
              <button
                type="button"
                className="btn btn-outline-danger btn-sm"
                disabled={isRestoring}
                onClick={handleRestoreStorage}
              >
                <i className={isRestoring ? 'fas fa-spinner fa-spin' : 'fas fa-upload'}></i>{' '}
                {isRestoring ? 'Restoring...' : 'Restore'}
              </button>
            </div>
            <div className="col-md-6">
              <h6 className="mb-2 font-weight-bold">About Backup / Restore</h6>
              <div className="alert alert-info py-2">
                <strong>Included:</strong>
                <ul className="mb-0 small">
                  <li>
                    Complete <code>_storage</code> directory with all files
                  </li>
                  <li>Private keys, secrets, API keys, certificates</li>
                  <li>All configurations, metrics, and user data</li>
                  <li>Session tokens, passkey credentials, avatars</li>
                </ul>
              </div>
              <div className="alert alert-warning py-2">
                <strong>Not included:</strong>
                <ul className="mb-0 small">
                  <li>
                    Directories: <code>logs</code> and <code>system_metrics</code> (ephemeral data,
                    regenerated at runtime)
                  </li>
                </ul>
              </div>
              <div className="alert alert-info py-2 small">
                <i className="fas fa-lock"></i> <strong>Encryption:</strong> The backup is encrypted
                with AES-256-GCM. It contains sensitive data including private keys, secrets, and
                credentials. Store it securely and never share it over unencrypted channels.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Flags */}
      <div className="card shadow mb-3">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-flag"></i> Feature Flags
          </h6>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            Enable or disable experimental features. Changes take effect immediately.
          </p>
          <div className="table-responsive">
            <table className="table table-sm mb-0">
              <thead className="thead-light">
                <tr>
                  <th style={{ whiteSpace: 'nowrap', width: '1%' }}>Flag</th>
                  <th>Description</th>
                  <th style={{ width: '80px' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                <FeatureFlagRow
                  flag="metrics"
                  // Default on when unset — explicit `false` hides the entry.
                  checked={featureFlags.metrics !== false}
                  disabled={isSubmitting}
                  description={
                    <>
                      Adds the <code>Metrics</code> entry to the sidebar. The <code>/metrics</code>{' '}
                      routes remain reachable directly even when this toggle is off.
                    </>
                  }
                  onChangeMessages={{
                    on: 'Metrics shown in sidebar.',
                    off: 'Metrics hidden from sidebar.',
                  }}
                  featureFlags={featureFlags}
                  updateSettings={updateSettings}
                />
                <FeatureFlagRow
                  flag="agent_pay_delegation"
                  // Default off when unset — must be explicit `true` to reveal.
                  checked={featureFlags.agent_pay_delegation === true}
                  disabled={isSubmitting}
                  description={
                    <>
                      Adds the <code>Agent Pay (delegate payment)</code> provider option to the{' '}
                      <code>Payment</code> element in the surface builder. UI-only: surfaces already
                      configured to delegate payment to a connected Agent-Pay gateway continue to
                      work regardless of this toggle.
                    </>
                  }
                  onChangeMessages={{
                    on: 'Agent-Pay delegation shown in the Payment element.',
                    off: 'Agent-Pay delegation hidden from the Payment element.',
                  }}
                  featureFlags={featureFlags}
                  updateSettings={updateSettings}
                />
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
};

interface FeatureFlagRowProps {
  flag: keyof FeatureFlags;
  checked: boolean;
  disabled: boolean;
  description: React.ReactNode;
  onChangeMessages: { on: string; off: string };
  featureFlags: FeatureFlags;
  updateSettings: (patch: { feature_flags: FeatureFlags }) => Promise<unknown>;
}

const FeatureFlagRow: React.FC<FeatureFlagRowProps> = ({
  flag,
  checked,
  disabled,
  description,
  onChangeMessages,
  featureFlags,
  updateSettings,
}) => {
  const inputId = `flag-${flag}`;
  const nameId = `${inputId}-name`;
  return (
    <tr>
      <td id={nameId} style={{ whiteSpace: 'nowrap' }}>
        <code>{flag}</code>
      </td>
      <td>{description}</td>
      <td className="text-center">
        <div className="custom-control custom-switch">
          <input
            type="checkbox"
            className="custom-control-input"
            id={inputId}
            role="switch"
            aria-labelledby={nameId}
            data-testid={`settings-flag-${flag}`}
            checked={checked}
            disabled={disabled}
            onChange={async e => {
              const next: FeatureFlags = {
                ...featureFlags,
                [flag]: e.target.checked,
              };
              try {
                await updateSettings({ feature_flags: next });
                showToast('success', e.target.checked ? onChangeMessages.on : onChangeMessages.off);
              } catch (err) {
                const msg = err instanceof Error ? err.message : 'Failed to update flag';
                showToast('error', msg);
              }
            }}
          />
          <label className="custom-control-label" htmlFor={inputId}></label>
        </div>
      </td>
    </tr>
  );
};

export default React.memo(
  SystemTab,
  (prev, next) => prev.isSubmitting === next.isSubmitting && prev.settings === next.settings
);
