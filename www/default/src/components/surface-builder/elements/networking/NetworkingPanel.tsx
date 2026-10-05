import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import FieldHelp from '../../../shared/FieldHelp';

const NetworkingPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Timeouts</label>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Request timeout (seconds)</Form.Label>
          <FieldHelp
            testId="field-help-networking-request-timeout-seconds"
            ariaLabel="About Request timeout (seconds)"
          >
            How long the gateway waits for a response from the target before giving up and treating
            the request as failed.
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.timeout_secs ?? ''}
          onChange={e => updateField('timeout_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Connect timeout (seconds)</Form.Label>
          <FieldHelp
            testId="field-help-networking-connect-timeout-seconds"
            ariaLabel="About Connect timeout (seconds)"
          >
            How long the gateway waits to establish a network connection to the target before giving
            up. This is separate from how long it waits for a response once connected.
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.connect_timeout_secs ?? ''}
          onChange={e => updateField('connect_timeout_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Idle timeout (seconds)</Form.Label>
          <FieldHelp
            testId="field-help-networking-idle-timeout-seconds"
            ariaLabel="About Idle timeout (seconds)"
          >
            How long the target can pause partway through a non-streaming response before the
            gateway stops waiting and returns a timeout.
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.idle_timeout_secs ?? ''}
          onChange={e => updateField('idle_timeout_secs', e.target.value)}
        />
      </Form.Group>
    </div>

    <div className="config-section">
      <label>Retry</label>
      <Form.Check
        type="switch"
        id="retry-enable"
        label={
          <span className="d-flex align-items-center gap-1">
            Enable automatic retries
            <FieldHelp
              testId="field-help-networking-enable-automatic-retries"
              ariaLabel="About Enable automatic retries"
            >
              When on, the gateway automatically retries a failed request instead of immediately
              returning an error to the caller.
            </FieldHelp>
          </span>
        }
        checked={config.retry_enabled || false}
        onChange={e => updateField('retry_enabled', e.target.checked)}
      />
      {config.retry_enabled && (
        <>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Max attempts</Form.Label>
              <FieldHelp testId="field-help-networking-max-attempts" ariaLabel="About Max attempts">
                The number of times the gateway will retry a failed request after the original
                attempt: a value of 3 means up to 4 total sends before it gives up and returns an
                error.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              max="10"
              value={config.retry_max ?? ''}
              onChange={e => updateField('retry_max', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Backoff multiplier</Form.Label>
              <FieldHelp
                testId="field-help-networking-backoff-multiplier"
                ariaLabel="About Backoff multiplier"
              >
                How much longer the gateway waits between each retry compared to the last one: a
                multiplier of 2 doubles the wait time after every failed attempt, so retries slow
                down instead of hammering a struggling target.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              step="0.1"
              min="1"
              value={config.retry_backoff_multiplier ?? ''}
              onChange={e => updateField('retry_backoff_multiplier', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Initial backoff (ms)</Form.Label>
              <FieldHelp
                testId="field-help-networking-initial-backoff-ms"
                ariaLabel="About Initial backoff (ms)"
              >
                How long the gateway waits before the very first retry, in milliseconds. Later
                retries wait longer, based on the Backoff multiplier above.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="0"
              value={config.retry_initial_backoff_ms ?? ''}
              onChange={e => updateField('retry_initial_backoff_ms', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Max backoff (ms)</Form.Label>
              <FieldHelp
                testId="field-help-networking-max-backoff-ms"
                ariaLabel="About Max backoff (ms)"
              >
                The longest the gateway will ever wait between retries, in milliseconds. This caps
                how slow retries can get even after many failures.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="0"
              value={config.retry_max_backoff_ms ?? ''}
              onChange={e => updateField('retry_max_backoff_ms', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Retryable status codes</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.retry_status_codes ?? ''}
              onChange={e => updateField('retry_status_codes', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Comma-separated HTTP status codes (e.g. 502,503,504)
            </Form.Text>
          </Form.Group>
        </>
      )}
    </div>

    <div className="config-section">
      <label>Circuit Breaker</label>
      <Form.Check
        type="switch"
        id="cb-enable"
        label={
          <span className="d-flex align-items-center gap-1">
            Enable circuit breaker
            <FieldHelp
              testId="field-help-networking-enable-circuit-breaker"
              ariaLabel="About Enable circuit breaker"
            >
              When on, the gateway temporarily stops sending traffic to a target that's failing
              repeatedly, giving it time to recover instead of continuing to send doomed requests.
            </FieldHelp>
          </span>
        }
        checked={config.circuit_breaker_enabled || false}
        onChange={e => updateField('circuit_breaker_enabled', e.target.checked)}
      />
      {config.circuit_breaker_enabled && (
        <>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Failure threshold</Form.Label>
              <FieldHelp
                testId="field-help-networking-failure-threshold"
                ariaLabel="About Failure threshold"
              >
                How many failed requests in a row before the gateway temporarily stops sending
                traffic to this target and gives it time to recover.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_threshold ?? ''}
              onChange={e => updateField('cb_threshold', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">
                Success threshold (to close)
              </Form.Label>
              <FieldHelp
                testId="field-help-networking-success-threshold-to-close"
                ariaLabel="About Success threshold (to close)"
              >
                How many requests must succeed in a row before the gateway trusts the target again
                and resumes sending it normal traffic.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_success_threshold ?? ''}
              onChange={e => updateField('cb_success_threshold', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Recovery timeout (seconds)</Form.Label>
              <FieldHelp
                testId="field-help-networking-recovery-timeout-seconds"
                ariaLabel="About Recovery timeout (seconds)"
              >
                How long the gateway waits after stopping traffic to a failing target before it
                tries sending a test request again to see if the target has recovered.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_recovery_secs ?? ''}
              onChange={e => updateField('cb_recovery_secs', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Window size (seconds)</Form.Label>
              <FieldHelp
                testId="field-help-networking-window-size-seconds"
                ariaLabel="About Window size (seconds)"
              >
                The time window the gateway looks back over when counting failures: a 60-second
                window means only failures from the last minute count toward the Failure threshold
                above.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_window_secs ?? ''}
              onChange={e => updateField('cb_window_secs', e.target.value)}
            />
          </Form.Group>
        </>
      )}
    </div>

    <div className="config-section">
      <label>Traffic Mirroring</label>
      <Form.Check
        type="switch"
        id="mirror-enable"
        label={
          <span className="d-flex align-items-center gap-1">
            Mirror traffic to shadow endpoint
            <FieldHelp
              testId="field-help-networking-mirror-traffic-to-shadow-endpoint"
              ariaLabel="About Mirror traffic to shadow endpoint"
            >
              When on, the gateway sends a copy of live traffic to a second 'shadow' endpoint as
              well as the real target, useful for testing a new version without it affecting real
              responses.
            </FieldHelp>
          </span>
        }
        checked={config.mirror_enabled || false}
        onChange={e => updateField('mirror_enabled', e.target.checked)}
      />
      {config.mirror_enabled && (
        <>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Mirror endpoint</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.mirror_endpoint ?? ''}
              onChange={e => updateField('mirror_endpoint', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Full URL of the shadow endpoint (e.g. https://shadow.internal:3001).
            </Form.Text>
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Traffic percentage</Form.Label>
              <FieldHelp
                testId="field-help-networking-traffic-percentage"
                ariaLabel="About Traffic percentage"
              >
                What percentage of requests get mirrored to the shadow endpoint: a value of 10 means
                roughly 1 in 10 requests gets a copy sent, not all of them.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              max="100"
              value={config.mirror_percentage ?? ''}
              onChange={e => updateField('mirror_percentage', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Mirror timeout (seconds)</Form.Label>
              <FieldHelp
                testId="field-help-networking-mirror-timeout-seconds"
                ariaLabel="About Mirror timeout (seconds)"
              >
                How long the gateway waits for the shadow endpoint to respond before giving up on
                that mirrored copy. This never affects the response sent back to the real caller.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.mirror_timeout_secs ?? ''}
              onChange={e => updateField('mirror_timeout_secs', e.target.value)}
            />
          </Form.Group>
          <Form.Check
            type="switch"
            id="mirror-async"
            label={
              <span className="d-flex align-items-center gap-1">
                Fire-and-forget (async)
                <FieldHelp
                  testId="field-help-networking-fire-and-forget-async"
                  ariaLabel="About Fire-and-forget (async)"
                >
                  When on, the gateway doesn't wait for the shadow endpoint to respond at all before
                  moving on. The mirrored copy is sent and forgotten, so a slow or broken shadow
                  endpoint can never slow down or affect the real request.
                </FieldHelp>
              </span>
            }
            className="mt-2"
            checked={config.mirror_async || false}
            onChange={e => updateField('mirror_async', e.target.checked)}
          />
        </>
      )}
    </div>
  </>
);

export default NetworkingPanel;
