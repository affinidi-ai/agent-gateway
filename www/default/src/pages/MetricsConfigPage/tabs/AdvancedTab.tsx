import React from 'react';
import { MetricsConfig } from '../types';

interface AdvancedTabProps {
  config: MetricsConfig;
  updateConfig: (path: string[], value: any) => void;
}

const AdvancedTab: React.FC<AdvancedTabProps> = ({ config, updateConfig }) => {
  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fas fa-cog me-2"></i>
          Advanced Configuration
        </h5>
        <p className="text-muted">Fine-tune batching, queuing, and host metrics collection.</p>
      </div>

      <h6 className="mb-3">
        <i className="fas fa-layer-group me-2"></i>
        Batching Settings
      </h6>

      <div className="mb-4">
        <label htmlFor="batchSize" className="form-label">
          Batch Size
        </label>
        <input
          type="number"
          className="form-control"
          id="batchSize"
          value={config.advanced.batch_size}
          onChange={e => updateConfig(['advanced', 'batch_size'], parseInt(e.target.value) || 512)}
          min="1"
        />
        <div className="form-text">
          Number of spans/metrics to batch before export. Higher values reduce network overhead but
          increase latency. Default is 512.
        </div>
      </div>

      <div className="mb-4">
        <label htmlFor="batchTimeout" className="form-label">
          Batch Timeout (milliseconds)
        </label>
        <input
          type="number"
          className="form-control"
          id="batchTimeout"
          value={config.advanced.batch_delay_ms}
          onChange={e =>
            updateConfig(['advanced', 'batch_delay_ms'], parseInt(e.target.value) || 5000)
          }
          min="100"
        />
        <div className="form-text">
          Maximum time to wait before exporting a partial batch. Default is 5000ms (5 seconds).
        </div>
      </div>

      <hr className="my-4" />

      <h6 className="mb-3">
        <i className="fas fa-bars me-2"></i>
        Queue Settings
      </h6>

      <div className="mb-4">
        <label htmlFor="batchQueueSize" className="form-label">
          Batch Queue Size
        </label>
        <input
          type="number"
          className="form-control"
          id="batchQueueSize"
          value={config.advanced.batch_queue_size}
          onChange={e =>
            updateConfig(['advanced', 'batch_queue_size'], parseInt(e.target.value) || 2048)
          }
          min="1"
        />
        <div className="form-text">
          Maximum number of items in the batch queue. When full, oldest items may be dropped.
          Default is 2048.
        </div>
      </div>

      <hr className="my-4" />

      <h6 className="mb-3">
        <i className="fas fa-server me-2"></i>
        Host Metrics
      </h6>

      <div className="form-check mb-4">
        <input
          className="form-check-input"
          type="checkbox"
          id="hostMetrics"
          checked={config.advanced.host_metrics.enabled}
          onChange={e => updateConfig(['advanced', 'host_metrics', 'enabled'], e.target.checked)}
        />
        <label className="form-check-label" htmlFor="hostMetrics">
          <strong>Enable Host Metrics Collection</strong>
        </label>
        <div className="form-text">
          Collect CPU, memory, disk, and network metrics from the host system
        </div>
      </div>

      {config.advanced.host_metrics.enabled && (
        <div className="alert alert-info">
          <i className="fas fa-info-circle me-2"></i>
          Host metrics include: CPU utilization, memory usage, disk I/O, network throughput, and
          process-level statistics.
        </div>
      )}

      <div className="card bg-light mt-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-wrench me-2"></i>
            Performance Tuning Tips
          </h6>
          <ul className="mb-0">
            <li>
              <strong>High Throughput:</strong> Increase batch size (1024+) and timeout (10s+)
            </li>
            <li>
              <strong>Low Latency:</strong> Decrease batch size (128-256) and timeout (1-2s)
            </li>
            <li>
              <strong>Memory Constrained:</strong> Reduce max queue size to 512-1024
            </li>
            <li>
              <strong>Host Metrics:</strong> Adds ~1-2% CPU overhead when enabled
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default AdvancedTab;
