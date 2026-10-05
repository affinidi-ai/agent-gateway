import React from 'react';
import FieldHelp from '../shared/FieldHelp';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';

interface EmailConfiguration {
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password: string;
  from: string;
  to: string[];
  use_tls: boolean;
  use_starttls: boolean;
}

interface EmailContent {
  subject: string;
  body: string;
  format?: 'html' | 'plain';
}

interface EmailIntegrationFormProps {
  configuration: EmailConfiguration;
  content: EmailContent;
  onConfigurationChange: (config: EmailConfiguration) => void;
  onContentChange: (content: EmailContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
}

const EmailIntegrationForm: React.FC<EmailIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
}) => {
  const handleConfigChange = (field: keyof EmailConfiguration, value: any) => {
    onConfigurationChange({ ...configuration, [field]: value });
  };

  const handleContentChange = (field: keyof EmailContent, value: string) => {
    onContentChange({ ...content, [field]: value });
  };

  const handleToEmailsChange = (value: string) => {
    // Split by comma or newline and trim
    const emails = value
      .split(/[,\n]/)
      .map(e => e.trim())
      .filter(e => e.length > 0);
    handleConfigChange('to', emails);
  };

  return (
    <div>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-envelope me-2"></i>
            Email Content Template
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label htmlFor="subject" className="form-label">
              Subject *
            </label>
            <input
              type="text"
              id="subject"
              className={
                fieldHasMissingVariables(content.subject, validRuntimeVars)
                  ? 'form-control is-invalid'
                  : 'form-control'
              }
              value={content.subject}
              onChange={e => handleContentChange('subject', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              <i className="fas fa-info-circle me-1"></i>
              You can insert variables using this format {`\${YOUR_VARIABLE_NAME}`} and these will
              be replaced at send time.
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="format" className="form-label">
              Email Format *
            </label>
            <select
              id="format"
              className="form-control dropdown-styling"
              value={content.format || 'html'}
              onChange={e => handleContentChange('format' as keyof EmailContent, e.target.value)}
              disabled={disabled}
              required
            >
              <option value="html">HTML</option>
              <option value="plain">Plain Text</option>
            </select>
            <small className="form-text text-muted">
              <i className="fas fa-info-circle me-1"></i>
              Choose plain text for simple emails or HTML for formatted content
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="body" className="form-label">
              Body *
            </label>
            <textarea
              id="body"
              className={
                fieldHasMissingVariables(content.body, validRuntimeVars)
                  ? 'form-control font-monospace is-invalid'
                  : 'form-control font-monospace'
              }
              rows={12}
              value={content.body}
              onChange={e => handleContentChange('body', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              <i className="fas fa-info-circle me-1"></i>
              {content.format === 'html'
                ? 'HTML email body. Use HTML tags for formatting. Supports template variables.'
                : 'Plain text email body. Supports template variables.'}
            </small>
          </div>
        </div>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-server me-2"></i>
            SMTP Configuration
          </h6>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-8">
              <div className="mb-3">
                <label htmlFor="smtp_host" className="form-label">
                  SMTP Host *
                </label>
                <input
                  type="text"
                  id="smtp_host"
                  className="form-control"
                  value={configuration.smtp_host}
                  onChange={e => handleConfigChange('smtp_host', e.target.value)}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">The SMTP server hostname</small>
              </div>
            </div>
            <div className="col-md-4">
              <div className="mb-3">
                <label htmlFor="smtp_port" className="form-label">
                  Port *
                </label>
                <input
                  type="number"
                  id="smtp_port"
                  className="form-control"
                  value={configuration.smtp_port}
                  onChange={e => handleConfigChange('smtp_port', parseInt(e.target.value) || 587)}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">Usually 587 or 465</small>
              </div>
            </div>
          </div>

          <div className="mb-3">
            <label htmlFor="smtp_username" className="form-label">
              Username *
            </label>
            <input
              type="text"
              id="smtp_username"
              className="form-control"
              value={configuration.smtp_username}
              onChange={e => handleConfigChange('smtp_username', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">SMTP authentication username</small>
          </div>

          <div className="mb-3">
            <label htmlFor="smtp_password" className="form-label">
              Password *
            </label>
            <input
              type="password"
              id="smtp_password"
              className="form-control"
              value={configuration.smtp_password}
              onChange={e => handleConfigChange('smtp_password', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              For Gmail, use an{' '}
              <a
                href="https://support.google.com/accounts/answer/185833"
                target="_blank"
                rel="noopener noreferrer"
              >
                App Password
              </a>
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="from" className="form-label">
              From Address *
            </label>
            <input
              type="email"
              id="from"
              className="form-control"
              value={configuration.from}
              onChange={e => handleConfigChange('from', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">The sender email address</small>
          </div>

          <div className="mb-3">
            <label htmlFor="to" className="form-label">
              Recipient Email(s) *
            </label>
            <textarea
              id="to"
              className="form-control"
              rows={3}
              value={configuration.to.join('\n')}
              onChange={e => handleToEmailsChange(e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              Enter one email per line or separate with commas
            </small>
          </div>

          <div className="row">
            <div className="col-md-6">
              <div className="custom-control custom-checkbox mb-3">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="use_tls"
                  checked={configuration.use_tls}
                  onChange={e => handleConfigChange('use_tls', e.target.checked)}
                  disabled={disabled}
                />
                <label className="custom-control-label" htmlFor="use_tls">
                  Use TLS{' '}
                  <FieldHelp testId="field-help-email-tls" ariaLabel="About TLS vs STARTTLS">
                    TLS connects already encrypted (used with port 465). STARTTLS connects in plain
                    text then upgrades to encryption (used with port 587). Use whichever your
                    provider documents, most providers only support one.
                  </FieldHelp>
                </label>
                <small className="form-text text-muted">Enable TLS encryption (port 465)</small>
              </div>
            </div>
            <div className="col-md-6">
              <div className="custom-control custom-checkbox mb-3">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="use_starttls"
                  checked={configuration.use_starttls}
                  onChange={e => handleConfigChange('use_starttls', e.target.checked)}
                  disabled={disabled}
                />
                <label className="custom-control-label" htmlFor="use_starttls">
                  Use STARTTLS
                </label>
                <small className="form-text text-muted">Enable STARTTLS (port 587)</small>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailIntegrationForm;
