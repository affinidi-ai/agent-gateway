import React from 'react';

const HelpTab: React.FC = () => {
  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fas fa-info-circle me-2"></i>
          OpenTelemetry Integration Guide
        </h5>
        <p className="text-muted">
          Understanding and deploying the Agent Gateway observability stack
        </p>
      </div>

      {/* OpenTelemetry Overview */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-chart-line me-2 text-primary"></i>
            What is OpenTelemetry?
          </h6>
          <p className="mb-3">
            OpenTelemetry (OTEL) is an open-source observability framework that provides a
            standardized way to collect and export telemetry data (traces, metrics, and logs) from
            your applications. Agent Gateway uses OpenTelemetry to provide comprehensive visibility
            into system behavior, performance, and reliability.
          </p>
          <div className="alert alert-info">
            <strong>Three Pillars of Observability:</strong>
            <ul className="mb-0 mt-2">
              <li>
                <strong>Traces:</strong> Track requests as they flow through the system, showing
                timing and dependencies
              </li>
              <li>
                <strong>Metrics:</strong> Measure system performance with counters, gauges, and
                histograms
              </li>
              <li>
                <strong>Logs:</strong> Capture detailed event information with structured context
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Infrastructure Setup */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-server me-2 text-primary"></i>
            Required Infrastructure Components
          </h6>
          <p className="mb-3">
            Agent Gateway exports telemetry over OTLP, so it works with any OpenTelemetry-compatible
            observability stack. A typical local setup runs an OpenTelemetry Collector alongside the
            backends below via Docker Compose or your existing observability platform.
          </p>

          <h6 className="mt-4 mb-3">Core Components:</h6>

          <div className="row">
            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-exchange-alt me-2 text-info"></i>OpenTelemetry Collector
                </h6>
                <p className="small text-muted mb-2">
                  <strong>Port:</strong> 4317 (gRPC), 4318 (HTTP)
                </p>
                <p className="small">
                  Receives, processes, and routes telemetry data from Agent Gateway to various
                  backends. Acts as a vendor-agnostic intermediary that enables easy switching
                  between observability platforms.
                </p>
              </div>
            </div>

            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-project-diagram me-2 text-info"></i>Jaeger
                </h6>
                <p className="small text-muted mb-2">
                  <strong>UI:</strong>{' '}
                  <a
                    href="http://localhost:16686"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary"
                  >
                    http://localhost:16686
                  </a>
                </p>
                <p className="small">
                  Distributed tracing platform for monitoring and troubleshooting
                  microservices-based architectures. Provides powerful trace visualization and
                  dependency analysis.
                </p>
              </div>
            </div>

            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-chart-area me-2 text-info"></i>Prometheus
                </h6>
                <p className="small text-muted mb-2">
                  <strong>UI:</strong>{' '}
                  <a
                    href="http://localhost:9090"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary"
                  >
                    http://localhost:9090
                  </a>
                </p>
                <p className="small">
                  Time-series database for metrics collection and storage. Industry-standard
                  solution for monitoring with powerful querying capabilities (PromQL) and built-in
                  alerting.
                </p>
              </div>
            </div>

            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-chart-line me-2 text-info"></i>Grafana
                </h6>
                <p className="small text-muted mb-2">
                  <strong>UI:</strong>{' '}
                  <a
                    href="http://localhost:3000"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary"
                  >
                    http://localhost:3000
                  </a>
                </p>
                <p className="small">
                  Visualization and analytics platform. Create comprehensive dashboards combining
                  metrics, traces, and logs for unified observability across your infrastructure.
                </p>
              </div>
            </div>

            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-database me-2 text-info"></i>Tempo
                </h6>
                <p className="small text-muted mb-2">
                  <strong>Port:</strong> 3200
                </p>
                <p className="small">
                  High-volume distributed tracing backend designed for long-term trace storage with
                  cost-effective object storage integration (S3, GCS, Azure Blob).
                </p>
              </div>
            </div>

            <div className="col-md-6 mb-3">
              <div className="border rounded p-3 h-100">
                <h6>
                  <i className="fas fa-stream me-2 text-info"></i>Kafka + Kafka UI
                </h6>
                <p className="small text-muted mb-2">
                  <strong>Kafka UI:</strong>{' '}
                  <a
                    href="http://localhost:3001"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary"
                  >
                    http://localhost:3001
                  </a>
                  <br />
                  <strong>Kafka:</strong> localhost:29092
                </p>
                <p className="small">
                  Event streaming platform for real-time data pipelines and message routing. Kafka
                  UI provides intuitive management and monitoring of topics and consumers.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Deployment Guide */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-rocket me-2 text-primary"></i>
            Deployment Guide
          </h6>

          <div className="mb-3">
            <strong>1. Setup the Infrastructure</strong>
            <p className="small text-muted mb-0 mt-2">
              Stand up an OpenTelemetry Collector and the backends listed above using your own
              Docker Compose stack or a managed observability platform. Point the Collector's OTLP
              receiver at ports 4317 (gRPC) and 4318 (HTTP).
            </p>
          </div>

          <div className="mb-3">
            <strong>2. Configure Agent Gateway</strong>
            <p className="small text-muted mb-2">
              Set the OTLP endpoint in the OpenTelemetry tab above. For Docker deployments, use the
              service name:
            </p>
            <pre className="bg-light p-3 rounded">
              <code>http://otel-collector:4317</code>
            </pre>
            <p className="small text-muted mb-0">
              For local development (Agent Gateway running outside Docker), use:
            </p>
            <pre className="bg-light p-3 rounded">
              <code>http://localhost:4317</code>
            </pre>
          </div>

          <div className="mb-3">
            <strong>3. Test the Connection</strong>
            <p className="small text-muted mb-2">
              Use the "Test Connection" button in the OpenTelemetry tab to verify connectivity to
              the OTEL Collector.
            </p>
          </div>

          <div className="mb-3">
            <strong>4. Access the Observability Tools</strong>
            <ul className="small mb-0">
              <li>
                <strong>Jaeger UI:</strong>{' '}
                <a href="http://localhost:16686" target="_blank" rel="noopener noreferrer">
                  http://localhost:16686
                </a>{' '}
                - View distributed traces
              </li>
              <li>
                <strong>Grafana:</strong>{' '}
                <a href="http://localhost:3000" target="_blank" rel="noopener noreferrer">
                  http://localhost:3000
                </a>{' '}
                - Access dashboards (default: admin/admin)
              </li>
              <li>
                <strong>Prometheus:</strong>{' '}
                <a href="http://localhost:9090" target="_blank" rel="noopener noreferrer">
                  http://localhost:9090
                </a>{' '}
                - Query metrics directly
              </li>
              <li>
                <strong>Kafka UI:</strong>{' '}
                <a href="http://localhost:3001" target="_blank" rel="noopener noreferrer">
                  http://localhost:3001
                </a>{' '}
                - Monitor message streams
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Cloud Integration */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-cloud me-2 text-primary"></i>
            Cloud Platform Integration
          </h6>
          <p className="mb-3">
            The OpenTelemetry Collector can export telemetry to any OTLP-compatible backend. Popular
            enterprise platforms include:
          </p>

          <div className="row">
            <div className="col-md-4 mb-2">
              <strong>Datadog</strong>
              <p className="small text-muted mb-0">
                Full-stack observability with APM, infrastructure monitoring, and log management
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Honeycomb</strong>
              <p className="small text-muted mb-0">
                High-cardinality observability optimized for debugging complex distributed systems
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>New Relic</strong>
              <p className="small text-muted mb-0">
                Comprehensive observability platform with AI-powered insights
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>AWS CloudWatch</strong>
              <p className="small text-muted mb-0">
                Native AWS monitoring integrated with other AWS services
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Azure Monitor</strong>
              <p className="small text-muted mb-0">
                Microsoft Azure's monitoring solution with Application Insights
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Google Cloud Operations</strong>
              <p className="small text-muted mb-0">
                Integrated monitoring, logging, and tracing for GCP
              </p>
            </div>
          </div>

          <div className="alert alert-info mt-3 mb-0">
            <i className="fas fa-lightbulb me-2"></i>
            <strong>Tip:</strong> Configure multiple exporters in the OTEL Collector to send
            telemetry to both local tools and cloud platforms simultaneously.
          </div>
        </div>
      </div>

      {/* Documentation Links */}
      <div className="card">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-book me-2 text-primary"></i>
            Additional Resources
          </h6>
          <div className="row">
            <div className="col-md-6">
              <ul className="small mb-0">
                <li>
                  <a
                    href="https://opentelemetry.io/docs/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    OpenTelemetry Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://www.jaegertracing.io/docs/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Jaeger Documentation
                  </a>
                </li>
                <li>
                  <a href="https://prometheus.io/docs/" target="_blank" rel="noopener noreferrer">
                    Prometheus Documentation
                  </a>
                </li>
              </ul>
            </div>
            <div className="col-md-6">
              <ul className="small mb-0">
                <li>
                  <a href="https://grafana.com/docs/" target="_blank" rel="noopener noreferrer">
                    Grafana Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://grafana.com/docs/tempo/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Tempo Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://kafka.apache.org/documentation/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Apache Kafka Documentation
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HelpTab;
