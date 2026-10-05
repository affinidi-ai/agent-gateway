import React, { useState, useEffect } from 'react';
import FieldHelp from '../shared/FieldHelp';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';

export interface WebhookConfiguration {
  url: string;
  method?: string;
  signing_secret?: string;
  headers?: Record<string, string>;
}

export interface WebhookContent {
  [key: string]: any;
}

interface WebhookIntegrationFormProps {
  configuration: WebhookConfiguration;
  content: WebhookContent;
  onConfigurationChange: (config: WebhookConfiguration) => void;
  onContentChange: (content: WebhookContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
}

// Generate a random UUID for the signing secret
const generateSecret = () => {
  return crypto.randomUUID();
};

const WebhookIntegrationForm: React.FC<WebhookIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
}) => {
  const [url, setUrl] = useState(configuration.url || '');
  const [method, setMethod] = useState(configuration.method || 'POST');
  const [signingSecret, setSigningSecret] = useState(
    configuration.signing_secret || generateSecret()
  );
  const [customHeaders, setCustomHeaders] = useState(
    configuration.headers ? JSON.stringify(configuration.headers, null, 2) : '{}'
  );
  const [payloadTemplate, setPayloadTemplate] = useState(JSON.stringify(content, null, 2));
  const [headersError, setHeadersError] = useState('');
  const [payloadError, setPayloadError] = useState('');

  useEffect(() => {
    // Validate and update configuration
    let headers: Record<string, string> | undefined;
    try {
      const parsed = JSON.parse(customHeaders);
      if (Object.keys(parsed).length > 0) {
        headers = parsed;
      }
      setHeadersError('');
    } catch (e) {
      setHeadersError('Invalid JSON');
    }

    onConfigurationChange({
      url,
      method: method || 'POST',
      signing_secret: signingSecret || undefined,
      headers,
    });
  }, [url, method, signingSecret, customHeaders]);

  useEffect(() => {
    // Validate and update content
    try {
      const parsed = JSON.parse(payloadTemplate);
      setPayloadError('');
      onContentChange(parsed);
    } catch (e) {
      setPayloadError('Invalid JSON');
    }
  }, [payloadTemplate]);

  return (
    <div className="webhook-notifier-form">
      <div className="mb-3">
        <label className="form-label">
          Webhook URL <span className="text-danger">*</span>
        </label>
        <input
          type="url"
          className="form-control"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://api.example.com/webhooks/notifications"
          required
        />
        <small className="form-text text-muted">
          The HTTP endpoint that will receive webhook notifications
        </small>
      </div>

      <div className="mb-3">
        <label className="form-label">HTTP Method</label>
        <select
          className="form-control dropdown-styling"
          value={method}
          onChange={e => setMethod(e.target.value)}
        >
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
        </select>
        <small className="form-text text-muted">HTTP method to use when sending the webhook</small>
      </div>

      <div className="mb-3">
        <label className="form-label">
          Signing Secret <span className="text-muted">(Optional)</span>{' '}
          <FieldHelp
            testId="field-help-webhook-signing-secret"
            ariaLabel="About the signing secret"
          >
            Every request carries <code>X-Webhook-Timestamp: &lt;unix_timestamp&gt;</code>. With a
            signing secret it also carries <code>X-Webhook-Signature-256: sha256=&lt;hex&gt;</code>,
            computed as <code>HMAC-SHA256(secret, timestamp + &quot;.&quot; + payload_json)</code>.
            Recompute it on the receiver and reject stale timestamps to block forged and replayed
            requests.
          </FieldHelp>
        </label>
        <div className="input-group">
          <input
            type="text"
            className="form-control font-monospace"
            value={signingSecret}
            onChange={e => setSigningSecret(e.target.value)}
            placeholder="Auto-generated UUID or enter your own..."
          />
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => setSigningSecret(generateSecret())}
            title="Generate new secret"
          >
            <i className="fas fa-sync-alt"></i>
          </button>
        </div>
        <small className="form-text text-muted">
          <i className="fas fa-shield-alt me-1"></i>
          Signs each request with HMAC-SHA256 so the receiver can verify it came from the gateway.
        </small>
      </div>

      <div className="mb-3">
        <label className="form-label">
          Custom Headers <span className="text-muted">(Optional)</span>
        </label>
        <textarea
          className={`form-control font-monospace ${headersError || fieldHasMissingVariables(customHeaders, validRuntimeVars) ? 'is-invalid' : ''}`}
          rows={4}
          value={customHeaders}
          onChange={e => setCustomHeaders(e.target.value)}
          placeholder={`{
  "Authorization": "Bearer your-token",
  "X-Custom-Header": "value"
}`}
          style={{ fontSize: '0.875rem' }}
        />
        {headersError && <div className="invalid-feedback">{headersError}</div>}
        <small className="form-text text-muted">
          Additional HTTP headers to include with each webhook request (JSON object)
        </small>
      </div>

      <div className="mb-3">
        <label className="form-label">
          Payload Template <span className="text-danger">*</span>
        </label>
        <textarea
          className={`form-control font-monospace ${payloadError || fieldHasMissingVariables(payloadTemplate, validRuntimeVars) ? 'is-invalid' : ''}`}
          rows={16}
          value={payloadTemplate}
          data-testid="webhook-payload-template"
          onChange={e => setPayloadTemplate(e.target.value)}
          style={{ fontSize: '0.875rem' }}
          required
        />
        {payloadError && <div className="invalid-feedback">{payloadError}</div>}
        <small className="form-text text-muted">
          <i className="fas fa-code me-1"></i>
          JSON payload template. Use variables like{' '}
          <code>
            ${'{'}CP_NAME{'}'}
          </code>{' '}
          or{' '}
          <code>
            ${'{'}CP_NAME:Label{'}'}
          </code>{' '}
          for runtime substitution.{' '}
          <FieldHelp testId="field-help-webhook-label-suffix" ariaLabel="About the :Label suffix">
            The optional <code>:Label</code> part only affects how a custom variable is displayed
            when someone fills it in by hand, it has no effect on runtime variables the system fills
            in automatically.
          </FieldHelp>
        </small>
      </div>
    </div>
  );
};

export default WebhookIntegrationForm;
