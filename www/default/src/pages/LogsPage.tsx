import React, { useEffect, useRef, useState } from 'react';
import { useApp } from '../context/AppContext';
import { WS_NONE, WS_LOGS } from '../utils/wsSubscriptions';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { AppButton } from '../components/shared/AppButton';
import FieldHelp from '../components/shared/FieldHelp';
import LogsViewer from '../components/shared/LogsViewer';

const LogsPage: React.FC = () => {
  const { actions } = useApp();
  const hasLoadedRef = useRef(false);
  const [isDownloading, setIsDownloading] = useState(false);

  // Clear filters on mount to show all logs (unfiltered view)
  useEffect(() => {
    hasLoadedRef.current = false;
    actions.setDashboardFilters(null);
    // Subscribe to logs-only delta to reduce WS payload size
    actions.setWsSubscription(WS_LOGS);
    return () => {
      // Restore full subscription when leaving the page
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run only once on mount

  const handleDownloadLogs = async () => {
    setIsDownloading(true);
    showToast('loading', 'Downloading log files...');
    try {
      const blob = await apiClient.downloadLogs();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `logs-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      const sizeMB = (blob.size / (1024 * 1024)).toFixed(1);
      showToast('success', `Logs downloaded (${sizeMB} MB)`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Download failed';
      showToast('error', errorMessage);
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="container-fluid">
      <div className="row">
        <div className="col-12">
          <LogsViewer
            title="Gateway Logs"
            titleHelp={
              <FieldHelp testId="field-help-gateway-logs" ariaLabel="About Gateway Logs">
                Every proxy log line written by this appliance, across all surfaces and gateways,
                unfiltered by channel.
              </FieldHelp>
            }
            stripAllPrefixes={true}
            controlSize="md"
            disableControlsWhenEmpty
            showFilters
            filterStorageKey="logs-page"
            headerActions={
              <AppButton
                variant="outline-primary"
                size="md"
                loading={isDownloading}
                loadingLabel="Downloading..."
                onClick={handleDownloadLogs}
                iconStart={
                  <i
                    className={isDownloading ? 'fas fa-spinner fa-spin' : 'fas fa-download'}
                    aria-hidden="true"
                  />
                }
              >
                Download All Logs
              </AppButton>
            }
          />
        </div>
      </div>
    </div>
  );
};

export default LogsPage;
