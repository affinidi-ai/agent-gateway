import React from 'react';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';

interface SlackConfiguration {
  webhook_url: string;
}

interface SlackContent {
  text: string;
  bot_name?: string;
  icon_emoji?: string;
  channel?: string;
}

interface SlackIntegrationFormProps {
  configuration: SlackConfiguration;
  content: SlackContent;
  onConfigurationChange: (config: SlackConfiguration) => void;
  onContentChange: (content: SlackContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
}

const SlackIntegrationForm: React.FC<SlackIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
}) => {
  const handleConfigChange = (field: keyof SlackConfiguration, value: string) => {
    onConfigurationChange({ ...configuration, [field]: value });
  };

  const handleContentChange = (field: keyof SlackContent, value: string) => {
    onContentChange({ ...content, [field]: value });
  };

  return (
    <div>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-comment-dots me-2"></i>
            Message Content Template
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label htmlFor="text" className="form-label">
              Message Text *
            </label>
            <textarea
              id="text"
              className={
                fieldHasMissingVariables(content.text, validRuntimeVars)
                  ? 'form-control font-monospace is-invalid'
                  : 'form-control font-monospace'
              }
              rows={6}
              value={content.text}
              onChange={e => handleContentChange('text', e.target.value)}
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              <i className="fas fa-info-circle me-1"></i>
              Use Slack's{' '}
              <a
                href="https://api.slack.com/reference/surfaces/formatting"
                target="_blank"
                rel="noopener noreferrer"
              >
                mrkdwn formatting
              </a>
              . Supports template variables.
            </small>
          </div>

          <div className="row">
            <div className="col-md-6">
              <div className="mb-3">
                <label htmlFor="bot_name" className="form-label">
                  Bot Name
                </label>
                <input
                  type="text"
                  id="bot_name"
                  className="form-control"
                  value={content.bot_name || ''}
                  onChange={e => handleContentChange('bot_name', e.target.value)}
                  disabled={disabled}
                />
                <small className="form-text text-muted">Display name for the bot (optional)</small>
              </div>
            </div>
            <div className="col-md-6">
              <div className="mb-3">
                <label htmlFor="icon_emoji" className="form-label">
                  Icon Emoji
                </label>
                <input
                  type="text"
                  id="icon_emoji"
                  className="form-control"
                  value={content.icon_emoji || ''}
                  onChange={e => handleContentChange('icon_emoji', e.target.value)}
                  disabled={disabled}
                />
                <small className="form-text text-muted">
                  Emoji icon (e.g., :bell:, :robot_face:)
                </small>
              </div>
            </div>
          </div>

          <div className="mb-3">
            <label htmlFor="channel" className="form-label">
              Channel Override
            </label>
            <input
              type="text"
              id="channel"
              className="form-control"
              value={content.channel || ''}
              onChange={e => handleContentChange('channel', e.target.value)}
              disabled={disabled}
            />
            <small className="form-text text-muted">
              Override the default channel (optional, e.g., #alerts or @username)
            </small>
          </div>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fab fa-slack me-2"></i>
            Slack Webhook Configuration
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label htmlFor="webhook_url" className="form-label">
              Webhook URL *
            </label>
            <input
              type="url"
              id="webhook_url"
              className="form-control font-monospace"
              value={configuration.webhook_url}
              onChange={e => handleConfigChange('webhook_url', e.target.value)}
              placeholder="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
              disabled={disabled}
              required
            />
            <small className="form-text text-muted">
              <i className="fas fa-info-circle me-1"></i>
              Your Slack Incoming Webhook URL. See sidebar for setup instructions.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SlackIntegrationForm;
