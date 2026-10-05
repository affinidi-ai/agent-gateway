import React, { useEffect, useRef, useState } from 'react';
import { MetricsConfig, ConnectionTestResult, OtlpAuthConfig, OtlpProtocol } from '../types';
import { apiClient } from '../../../api';
import { useApp } from '../../../context/AppContext';
import { showToast } from '../../../utils/toaster';

interface OpenTelemetryTabProps {
  config: MetricsConfig;
  updateConfig: (path: string[], value: any) => void;
}

interface SecretOption {
  id: string;
  name: string;
  secret_id: string;
}

const DEFAULT_AUTH: OtlpAuthConfig = {
  header_name: 'Authorization',
  secret_id: '',
  header_format: 'Bearer {value}',
};

/** OTLP default receiver ports by transport (OTel convention). */
const DEFAULT_PORT: Record<OtlpProtocol, string> = { grpc: '4317', http: '4318' };

/**
 * When the operator switches transport, swap the endpoint's port to the new
 * protocol's default — but only when it still carries the *other* protocol's
 * default port (i.e. the operator hasn't customised it). A custom host, port,
 * or path is left untouched. The port must sit immediately after the host and
 * be followed by the end of the string or a path/query/fragment separator.
 */
export const swapDefaultPort = (endpoint: string, newProtocol: OtlpProtocol): string => {
  const next = DEFAULT_PORT[newProtocol];
  const previous = newProtocol === 'http' ? DEFAULT_PORT.grpc : DEFAULT_PORT.http;
  return endpoint.replace(new RegExp(`(://[^/:]+):${previous}(?=$|[/?#])`), `$1:${next}`);
};

const OpenTelemetryTab: React.FC<OpenTelemetryTabProps> = ({ config, updateConfig }) => {
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<ConnectionTestResult | null>(
    null
  );
  const [secrets, setSecrets] = useState<SecretOption[]>([]);

  useEffect(() => {
    apiClient
      .get<SecretOption[]>('/secrets/')
      .then(res => setSecrets(Array.isArray(res.data) ? res.data : []))
      .catch(() => setSecrets([]));
  }, []);

  const protocol: OtlpProtocol = config.opentelemetry.protocol ?? 'grpc';
  const auth = config.opentelemetry.auth;
  const authEnabled = !!auth;
  const defaultPort = DEFAULT_PORT[protocol];

  const updateAuth = (patch: Partial<OtlpAuthConfig>) => {
    updateConfig(['opentelemetry', 'auth'], { ...DEFAULT_AUTH, ...auth, ...patch });
  };

  const toggleAuth = (enabled: boolean) => {
    updateConfig(['opentelemetry', 'auth'], enabled ? { ...DEFAULT_AUTH } : undefined);
  };

  const handleProtocolChange = (newProtocol: OtlpProtocol) => {
    updateConfig(['opentelemetry', 'protocol'], newProtocol);
    const swapped = swapDefaultPort(config.opentelemetry.endpoint, newProtocol);
    if (swapped !== config.opentelemetry.endpoint) {
      updateConfig(['opentelemetry', 'endpoint'], swapped);
    }
  };

  const handleTestConnection = async () => {
    try {
      setTestingConnection(true);
      setConnectionTestResult(null);
      const result = await apiClient.testOtlpConnection(config.opentelemetry.endpoint);
      setConnectionTestResult(result);
    } catch (err: any) {
      setConnectionTestResult({
        success: false,
        message: err.message || 'Connection test failed',
      });
    } finally {
      setTestingConnection(false);
    }
  };

  // --- Prometheus endpoint authentication ---------------------------------
  // Backed by the Settings API (settings.json), not metrics.json: this guards
  // the /v1/metrics/prometheus scrape endpoint with HTTP Basic auth. It saves
  // via its own inline button (updateSettings), independent of the metrics
  // page's main Save button.
  const { state, actions } = useApp();
  const settings = state.settings;
  const updateSettings = actions.updateSettings;

  const [promUsername, setPromUsername] = useState('');
  const [promPassword, setPromPassword] = useState('');
  const [isSavingPromAuth, setIsSavingPromAuth] = useState(false);
  const [showPromAuthForm, setShowPromAuthForm] = useState(false);

  const promAuthEnabled = settings?.prometheus_auth_enabled || false;

  // Seed the username field from settings once when auth is already enabled
  const promAuthUsernameSeeded = useRef(false);
  useEffect(() => {
    if (promAuthEnabled && !promAuthUsernameSeeded.current && settings?.prometheus_auth_username) {
      setPromUsername(settings.prometheus_auth_username);
      promAuthUsernameSeeded.current = true;
    }
  }, [promAuthEnabled, settings?.prometheus_auth_username]);

  const handleTogglePromAuth = async () => {
    if (!promAuthEnabled && !showPromAuthForm) {
      // Enabling: reveal the form and seed the username from current settings (default: "prometheus")
      setPromUsername(settings?.prometheus_auth_username || 'prometheus');
      setShowPromAuthForm(true);
      return;
    }
    if (!promAuthEnabled && showPromAuthForm) {
      // User toggled off before saving — just hide the form
      setShowPromAuthForm(false);
      setPromUsername('');
      setPromPassword('');
      return;
    }
    // Disabling: send immediately
    try {
      setIsSavingPromAuth(true);
      await updateSettings({ prometheus_auth_enabled: false } as any);
      setShowPromAuthForm(false);
      setPromUsername('');
      setPromPassword('');
      showToast('success', 'Prometheus authentication disabled');
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to disable Prometheus auth';
      showToast('error', errorMessage);
    } finally {
      setIsSavingPromAuth(false);
    }
  };

  const handleSavePromCredentials = async () => {
    if (!promUsername.trim()) {
      showToast('error', 'Username cannot be empty');
      return;
    }
    if (!promAuthEnabled && !promPassword) {
      showToast('error', 'Password is required when enabling Prometheus authentication');
      return;
    }
    try {
      const update: any = {
        prometheus_auth_enabled: true,
        prometheus_auth_username: promUsername.trim(),
      };
      if (promPassword) {
        update.prometheus_auth_password = promPassword;
      }
      setIsSavingPromAuth(true);
      await updateSettings(update);
      setPromPassword('');
      setShowPromAuthForm(false);
      showToast(
        'success',
        promAuthEnabled ? 'Prometheus credentials updated' : 'Prometheus authentication enabled'
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save credentials';
      showToast('error', errorMessage);
    } finally {
      setIsSavingPromAuth(false);
    }
  };

  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fas fa-diagram-project me-2"></i>
          OpenTelemetry Configuration
        </h5>
        <p className="text-muted">Configure OTLP endpoint and telemetry signal exports</p>
      </div>

      <div className="form-check mb-4">
        <input
          className="form-check-input"
          type="checkbox"
          id="otelEnabled"
          checked={config.opentelemetry.enabled}
          onChange={e => updateConfig(['opentelemetry', 'enabled'], e.target.checked)}
        />
        <label className="form-check-label" htmlFor="otelEnabled">
          <strong>Enable OpenTelemetry</strong>
        </label>
        <div className="form-text">
          Export traces, metrics, and logs to an OpenTelemetry Collector
        </div>
      </div>

      {config.opentelemetry.enabled && (
        <>
          <div className="mb-4">
            <label htmlFor="otelProtocol" className="form-label">
              Transport Protocol
            </label>
            <select
              className="form-select"
              id="otelProtocol"
              value={protocol}
              onChange={e => handleProtocolChange(e.target.value as OtlpProtocol)}
            >
              <option value="grpc">OTLP / gRPC</option>
              <option value="http">OTLP / HTTP</option>
            </select>
            <div className="form-text">
              The OTLP transport used to reach the collector. Changing the protocol updates the
              default endpoint port (gRPC 4317 / HTTP 4318) and is applied on save without a
              restart.
            </div>
          </div>

          <div className="mb-4">
            <label htmlFor="otelEndpoint" className="form-label">
              {protocol === 'http' ? 'OTLP Endpoint (HTTP)' : 'OTLP Endpoint (gRPC)'}
            </label>
            <div className="input-group">
              <input
                type="text"
                className="form-control"
                id="otelEndpoint"
                value={config.opentelemetry.endpoint}
                onChange={e => updateConfig(['opentelemetry', 'endpoint'], e.target.value)}
                placeholder={`http://localhost:${defaultPort}`}
              />
              <button
                className="btn btn-outline-secondary"
                type="button"
                onClick={handleTestConnection}
                disabled={testingConnection}
              >
                {testingConnection ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Testing...
                  </>
                ) : (
                  <>
                    <i className="fas fa-check-circle me-1"></i>
                    Test Connection
                  </>
                )}
              </button>
            </div>
            <div className="form-text">
              {protocol === 'http' ? (
                <>
                  The base HTTP endpoint for the OpenTelemetry Collector (default port {defaultPort}
                  ). The signal paths <code>/v1/traces</code>, <code>/v1/metrics</code>, and{' '}
                  <code>/v1/logs</code> are appended automatically.
                </>
              ) : (
                <>The gRPC endpoint for the OpenTelemetry Collector (default port {defaultPort})</>
              )}
            </div>
            {connectionTestResult && (
              <div
                className={`alert mt-2 ${connectionTestResult.success ? 'alert-success' : 'alert-warning'}`}
              >
                <i
                  className={`fas ${connectionTestResult.success ? 'fa-check-circle' : 'fa-exclamation-triangle'} me-2`}
                ></i>
                {connectionTestResult.message}
              </div>
            )}
          </div>

          <div className="mb-4">
            <h6 className="mb-3">
              <i className="fas fa-key me-2"></i>
              Authentication
            </h6>
            <div className="form-check mb-3">
              <input
                className="form-check-input"
                type="checkbox"
                id="otelAuthEnabled"
                checked={authEnabled}
                onChange={e => toggleAuth(e.target.checked)}
              />
              <label className="form-check-label" htmlFor="otelAuthEnabled">
                Authenticate to the collector
              </label>
              <div className="form-text">
                Attach an authentication header (e.g. a Bearer token or API key) to every OTLP
                export. The credential value is read from the internal secrets store and is never
                stored in this configuration.
              </div>
            </div>

            {authEnabled && (
              <>
                <div className="mb-3">
                  <label htmlFor="otelAuthHeaderName" className="form-label">
                    Header Name
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    id="otelAuthHeaderName"
                    value={auth?.header_name ?? ''}
                    onChange={e => updateAuth({ header_name: e.target.value })}
                    placeholder="Authorization"
                  />
                  <div className="form-text">
                    The header sent to the collector, e.g. <code>Authorization</code> or{' '}
                    <code>X-Api-Key</code>.
                  </div>
                </div>

                <div className="mb-3">
                  <label htmlFor="otelAuthSecret" className="form-label">
                    Secret
                  </label>
                  <select
                    className="form-select"
                    id="otelAuthSecret"
                    value={auth?.secret_id ?? ''}
                    onChange={e => updateAuth({ secret_id: e.target.value })}
                  >
                    <option value="">Select a secret…</option>
                    {secrets.map(s => (
                      <option key={s.id} value={s.secret_id}>
                        {s.name} ({s.secret_id})
                      </option>
                    ))}
                    {auth?.secret_id && !secrets.some(s => s.secret_id === auth.secret_id) && (
                      <option value={auth.secret_id}>{auth.secret_id} (not found)</option>
                    )}
                  </select>
                  <div className="form-text">
                    The credential value is taken from this secret. Manage secrets on the{' '}
                    <a href="/secrets">Secrets</a> page.
                  </div>
                </div>

                <div className="mb-3">
                  <label htmlFor="otelAuthFormat" className="form-label">
                    Header Format
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    id="otelAuthFormat"
                    value={auth?.header_format ?? ''}
                    onChange={e => updateAuth({ header_format: e.target.value })}
                    placeholder="Bearer {value}"
                  />
                  <div className="form-text">
                    Template for the header value. <code>{'{value}'}</code> is replaced with the
                    secret. Use <code>Bearer {'{value}'}</code> for a bearer token, or{' '}
                    <code>{'{value}'}</code> to send the raw value.
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="mb-4">
            <label htmlFor="serviceName" className="form-label">
              Service Name
            </label>
            <input
              type="text"
              className="form-control"
              id="serviceName"
              value={config.opentelemetry.service_name}
              onChange={e => updateConfig(['opentelemetry', 'service_name'], e.target.value)}
              placeholder="agent-gateway"
            />
            <div className="form-text">The service name used in distributed tracing</div>
          </div>

          <div className="mb-4">
            <label htmlFor="environment" className="form-label">
              Environment
            </label>
            <input
              type="text"
              className="form-control"
              id="environment"
              value={config.opentelemetry.environment}
              onChange={e => updateConfig(['opentelemetry', 'environment'], e.target.value)}
              placeholder="development"
            />
            <div className="form-text">
              The deployment environment (e.g., development, staging, production)
            </div>
          </div>

          <hr className="my-4" />

          <h6 className="mb-3">
            <i className="fas fa-project-diagram me-2"></i>
            Traces
          </h6>
          <div className="form-check mb-3">
            <input
              className="form-check-input"
              type="checkbox"
              id="tracesEnabled"
              checked={config.opentelemetry.traces.enabled}
              onChange={e => updateConfig(['opentelemetry', 'traces', 'enabled'], e.target.checked)}
            />
            <label className="form-check-label" htmlFor="tracesEnabled">
              Enable Trace Export
            </label>
          </div>

          {config.opentelemetry.traces.enabled && (
            <div className="mb-4">
              <label htmlFor="sampleRate" className="form-label">
                Sample Rate:{' '}
                <strong>{(config.opentelemetry.traces.sample_rate * 100).toFixed(0)}%</strong>
              </label>
              <input
                type="range"
                className="form-range"
                id="sampleRate"
                min="0"
                max="1"
                step="0.01"
                value={config.opentelemetry.traces.sample_rate}
                onChange={e =>
                  updateConfig(
                    ['opentelemetry', 'traces', 'sample_rate'],
                    parseFloat(e.target.value)
                  )
                }
              />
              <div className="form-text">
                Percentage of traces to sample (0% = none, 100% = all)
              </div>
            </div>
          )}

          {config.opentelemetry.traces.enabled && (
            <div className="form-check mb-4">
              <input
                className="form-check-input"
                type="checkbox"
                id="recordCallerIdentity"
                checked={config.opentelemetry.traces.record_caller_identity ?? false}
                onChange={e =>
                  updateConfig(
                    ['opentelemetry', 'traces', 'record_caller_identity'],
                    e.target.checked
                  )
                }
              />
              <label className="form-check-label" htmlFor="recordCallerIdentity">
                Record caller identity on spans
              </label>
              <div className="form-text">
                Stamp the authenticated caller&apos;s <code>caller.auth_method</code>,{' '}
                <code>caller.principal</code>, and derived <code>caller.did</code> onto the root
                request span. Subject to log redaction. Off by default.
              </div>
            </div>
          )}

          <hr className="my-4" />

          <h6 className="mb-3">
            <i className="fas fa-tachometer-alt me-2"></i>
            Metrics
          </h6>
          <div className="form-check mb-3">
            <input
              className="form-check-input"
              type="checkbox"
              id="metricsEnabled"
              checked={config.opentelemetry.metrics.enabled}
              onChange={e =>
                updateConfig(['opentelemetry', 'metrics', 'enabled'], e.target.checked)
              }
            />
            <label className="form-check-label" htmlFor="metricsEnabled">
              Enable Metrics Export
            </label>
          </div>

          {config.opentelemetry.metrics.enabled && (
            <div className="mb-4">
              <label htmlFor="exportInterval" className="form-label">
                Export Interval (seconds)
              </label>
              <input
                type="number"
                className="form-control"
                id="exportInterval"
                value={config.opentelemetry.metrics.export_interval_seconds}
                onChange={e =>
                  updateConfig(
                    ['opentelemetry', 'metrics', 'export_interval_seconds'],
                    parseInt(e.target.value) || 60
                  )
                }
                min="1"
              />
              <div className="form-text">How often to export metrics to the collector</div>
            </div>
          )}

          <hr className="my-4" />

          <h6 className="mb-3">
            <i className="fas fa-file-alt me-2"></i>
            Logs
          </h6>
          <div className="form-check mb-3">
            <input
              className="form-check-input"
              type="checkbox"
              id="logsEnabled"
              checked={config.opentelemetry.logs.enabled}
              onChange={e => updateConfig(['opentelemetry', 'logs', 'enabled'], e.target.checked)}
            />
            <label className="form-check-label" htmlFor="logsEnabled">
              Enable Log Export
            </label>
            <div className="form-text">Export application logs to the OpenTelemetry Collector</div>
          </div>
        </>
      )}

      {/* Prometheus Endpoint Authentication */}
      <hr className="my-4" />
      <div className="card shadow mb-3">
        <div className="card-header py-2 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-info">
            <i className="fas fa-shield-alt"></i> Prometheus Endpoint Authentication
          </h6>
          <div className="custom-control custom-switch">
            <input
              type="checkbox"
              className="custom-control-input"
              id="prom-auth-toggle"
              checked={promAuthEnabled || showPromAuthForm}
              disabled={isSavingPromAuth}
              onChange={handleTogglePromAuth}
            />
            <label className="custom-control-label" htmlFor="prom-auth-toggle">
              {promAuthEnabled
                ? 'Enabled'
                : showPromAuthForm
                  ? 'Pending — save credentials below'
                  : 'Disabled'}
            </label>
          </div>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            Require HTTP Basic Authentication for the <code>/v1/metrics/prometheus</code> endpoint.
            When enabled, Prometheus scrapers must provide valid credentials.
          </p>
          {(promAuthEnabled || showPromAuthForm) && (
            <div className="row">
              <div className="col-md-6">
                <div className="mb-3">
                  <label htmlFor="prom-username" className="form-label">
                    Username
                  </label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    id="prom-username"
                    placeholder="Required"
                    value={promUsername}
                    onChange={e => setPromUsername(e.target.value)}
                  />
                </div>
                <div className="mb-3">
                  <label htmlFor="prom-password" className="form-label">
                    Password
                  </label>
                  <input
                    type="password"
                    className="form-control form-control-sm"
                    id="prom-password"
                    placeholder={promAuthEnabled ? 'Leave empty to keep current' : 'Required'}
                    value={promPassword}
                    onChange={e => setPromPassword(e.target.value)}
                  />
                  <small className="form-text text-muted">
                    {promAuthEnabled
                      ? 'Leave empty to keep the current password. The password is stored as a bcrypt hash.'
                      : 'Required. The password is stored as a bcrypt hash.'}
                  </small>
                </div>
                <span
                  title={
                    !promUsername.trim()
                      ? 'Enter a username to enable saving'
                      : !promAuthEnabled && !promPassword
                        ? 'Enter a password to enable saving'
                        : ''
                  }
                >
                  <button
                    type="button"
                    className="btn btn-info btn-sm"
                    disabled={isSavingPromAuth || !promUsername.trim()}
                    style={
                      isSavingPromAuth || !promUsername.trim()
                        ? { opacity: 0.5, cursor: 'not-allowed' }
                        : {}
                    }
                    onClick={handleSavePromCredentials}
                  >
                    <i className={isSavingPromAuth ? 'fas fa-spinner fa-spin' : 'fas fa-save'}></i>{' '}
                    {isSavingPromAuth ? 'Saving...' : 'Save Credentials'}
                  </button>
                </span>
              </div>
              <div className="col-md-6">
                <div className="alert alert-info py-2 small">
                  <i className="fas fa-info-circle"></i> Configure your Prometheus scraper with
                  matching credentials:
                  <pre className="mt-2 mb-0" style={{ fontSize: '0.75rem' }}>
                    {`basic_auth:
  username: "<username>"
  password: "<password>"`}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OpenTelemetryTab;
