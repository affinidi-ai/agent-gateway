import React from 'react';
import { MetricsConfig } from '../types';

interface CloudWatchTabProps {
  config: MetricsConfig;
  updateConfig: (path: string[], value: any) => void;
}

const CloudWatchTab: React.FC<CloudWatchTabProps> = ({ config, updateConfig }) => {
  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fab fa-aws me-2"></i>
          CloudWatch Configuration
        </h5>
        <p className="text-muted">Export metrics directly to AWS CloudWatch</p>
      </div>

      <div className="form-check mb-4">
        <input
          className="form-check-input"
          type="checkbox"
          id="cloudwatchEnabled"
          checked={config.cloudwatch.enabled}
          onChange={e => updateConfig(['cloudwatch', 'enabled'], e.target.checked)}
        />
        <label className="form-check-label" htmlFor="cloudwatchEnabled">
          <strong>Enable CloudWatch Metrics</strong>
        </label>
        <div className="form-text">Export metrics directly to AWS CloudWatch</div>
      </div>

      {config.cloudwatch.enabled && (
        <>
          <div className="mb-4">
            <label htmlFor="cloudwatchRegion" className="form-label">
              AWS Region
            </label>
            <input
              type="text"
              className="form-control"
              id="cloudwatchRegion"
              value={config.cloudwatch.region}
              onChange={e => updateConfig(['cloudwatch', 'region'], e.target.value)}
              placeholder="us-east-1"
            />
            <div className="form-text">
              The AWS region for CloudWatch (e.g., us-east-1, eu-west-1, ap-southeast-1)
            </div>
          </div>

          <div className="mb-4">
            <label htmlFor="cloudwatchNamespace" className="form-label">
              CloudWatch Namespace
            </label>
            <input
              type="text"
              className="form-control"
              id="cloudwatchNamespace"
              value={config.cloudwatch.namespace}
              onChange={e => updateConfig(['cloudwatch', 'namespace'], e.target.value)}
              placeholder="AgentGateway"
            />
            <div className="form-text">
              The CloudWatch namespace for metrics. All metrics will be grouped under this
              namespace.
            </div>
          </div>

          <div className="alert alert-info">
            <i className="fas fa-info-circle me-2"></i>
            <strong>Note:</strong> Ensure your AWS credentials are configured correctly. CloudWatch
            metrics may incur additional AWS costs.
          </div>
        </>
      )}
    </div>
  );
};

export default CloudWatchTab;
