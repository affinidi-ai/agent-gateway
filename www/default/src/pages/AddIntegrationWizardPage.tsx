import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { getRuntimeVariablesForCategories } from '../utils/runtimeVariables';
import {
  AUDIT_INTEGRATION_CATEGORY,
  auditPayloadTemplate,
  selectableCategories,
  selectableTypes,
} from '../utils/auditIntegrations';
import { usePermissions } from '../context/PermissionsContext';
import EmailIntegrationForm from '../components/integration-forms/EmailIntegrationForm';
import SlackIntegrationForm from '../components/integration-forms/SlackIntegrationForm';
import WebhookIntegrationForm from '../components/integration-forms/WebhookIntegrationForm';
import StreamIntegrationForm from '../components/integration-forms/StreamIntegrationForm';
import { useIntegrationSamples } from '../hooks/useIntegrationSamples';
import { IntegrationContents } from '../utils/integrationSamples';
import RuntimeVariablesSidebar from '../components/RuntimeVariablesSidebar';
import AuditIntegrationCard from '../components/integrations/AuditIntegrationCard';

interface IntegrationFieldMetadata {
  name: string;
  label: string;
  type: string;
  required: boolean;
}

interface IntegrationType {
  enum_value: string;
  name: string;
  description: string;
  metadata: {
    fields?: IntegrationFieldMetadata[];
    [key: string]: any;
  };
}

interface IntegrationCategory {
  enum_value: string;
  name: string;
  description: string;
  metadata: Record<string, any>;
}

interface IntegrationConfig {
  types: IntegrationType[];
  categories: IntegrationCategory[];
}

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
  format?: 'plain' | 'html';
}

interface SlackConfiguration {
  webhook_url: string;
}

interface SlackContent {
  text: string;
  bot_name?: string;
  icon_emoji?: string;
  channel?: string;
}

interface WebhookConfiguration {
  url: string;
  method?: string;
  signing_secret?: string;
  headers?: Record<string, string>;
}

interface WebhookContent {
  [key: string]: any;
}

interface StreamConfiguration {
  platform: string;
  topic: string;
  brokers?: string;
  region?: string;
  redis_url?: string;
  auth_type?: string;
  sasl_username?: string;
  sasl_password?: string;
  access_key?: string;
  secret_key?: string;
}

interface StreamContent {
  [key: string]: any;
}

const AddIntegrationWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const requested = useRef({
    type: searchParams.get('type'),
    category: searchParams.get('category'),
  });
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canViewAudit = hasPermission('audit.view');
  // console.log('[AddIntegrationWizardPage] Component rendering');
  const [integrationConfig, setIntegrationConfig] = useState<IntegrationConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [categoryInitialised, setCategoryInitialised] = useState(false);
  const [unavailableCategory, setUnavailableCategory] = useState<string | null>(null);
  const [payloadVersion, setPayloadVersion] = useState(0);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [type, setType] = useState('email');
  const [category, setCategory] = useState('general');
  const [configuration, setConfiguration] = useState('{}');
  const [content, setContent] = useState('{}');

  // Email-specific state
  const [emailConfiguration, setEmailConfiguration] = useState<EmailConfiguration>({
    smtp_host: '',
    smtp_port: 587,
    smtp_username: '',
    smtp_password: '',
    from: '',
    to: [],
    use_tls: false,
    use_starttls: true,
  });
  const [emailContent, setEmailContent] = useState<EmailContent>({
    subject: '',
    body: '',
    format: 'plain',
  });

  // Slack-specific state
  const [slackConfiguration, setSlackConfiguration] = useState<SlackConfiguration>({
    webhook_url: '',
  });
  const [slackContent, setSlackContent] = useState<SlackContent>({
    text: '',
    bot_name: '',
    icon_emoji: '',
    channel: '',
  });

  // Webhook-specific state
  const [webhookConfiguration, setWebhookConfiguration] = useState<WebhookConfiguration>({
    url: '',
    method: 'POST',
    signing_secret: '',
  });
  const [webhookContent, setWebhookContent] = useState<WebhookContent>({});

  // Stream-specific state
  const [streamConfiguration, setStreamConfiguration] = useState<StreamConfiguration>({
    platform: 'kafka',
    topic: '',
  });
  const [streamContent, setStreamContent] = useState<StreamContent>({});

  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isModified, setIsModified] = useState(false);
  const [hasMissingVariables, setHasMissingVariables] = useState(false);
  const [validRuntimeVars, setValidRuntimeVars] = useState<Set<string>>(new Set());

  // console.log('[AddIntegrationWizardPage] Component rendering, streamConfiguration:', JSON.stringify(streamConfiguration));
  // console.log('[AddIntegrationWizardPage] hasMissingVariables:', hasMissingVariables, 'validRuntimeVars size:', validRuntimeVars.size);

  // Fetch integration configuration from backend
  useEffect(() => {
    const fetchIntegrationConfig = async () => {
      try {
        // console.log('[AddIntegrationWizardPage] Fetching integration config from /integrations/config');
        const response = await apiClient.get('/integrations/config');
        // console.log('[AddIntegrationWizardPage] Integration config response:', response);
        // console.log('[AddIntegrationWizardPage] Integration config data:', response.data);
        setIntegrationConfig(response.data);

        // Set default type to the requested type, else the first available type
        const types: IntegrationType[] = response.data.types ?? [];
        const requestedType = types.find(t => t.enum_value === requested.current.type);
        if (requestedType || types.length > 0) {
          setType((requestedType ?? types[0]).enum_value);
        }

        // console.log('[AddIntegrationWizardPage] Integration config setup complete');
      } catch (err) {
        console.error('[AddIntegrationWizardPage] Failed to fetch integration config:', err);
        console.error('[AddIntegrationWizardPage] Error details:', {
          message: (err as any).message,
          response: (err as any).response,
          data: (err as any).response?.data,
        });
        showToast('error', 'Failed to load integration configuration');
      } finally {
        setConfigLoading(false);
      }
    };

    fetchIntegrationConfig();
  }, []);

  const categories = useMemo(
    () => selectableCategories(integrationConfig?.categories ?? [], canViewAudit),
    [integrationConfig, canViewAudit]
  );
  const types = useMemo(
    () => selectableTypes(integrationConfig?.types ?? [], category),
    [integrationConfig, category]
  );

  // A category that allows fewer types (audit: Stream and Webhook) moves an
  // incompatible type onto the first one it allows.
  useEffect(() => {
    if (types.length > 0 && !types.some(t => t.enum_value === type)) {
      setType(types[0].enum_value);
    }
  }, [types, type]);

  // Untouched content follows the category's sample; the JSON payload forms
  // keep their own editor state, so they remount to show a replaced sample.
  const applySamples = useCallback((replacements: Partial<IntegrationContents>) => {
    if (replacements.email) setEmailContent(replacements.email);
    if (replacements.slack) setSlackContent(replacements.slack);
    if (replacements.webhook) setWebhookContent(replacements.webhook);
    if (replacements.stream) setStreamContent(replacements.stream);
    if (replacements.webhook || replacements.stream) {
      setPayloadVersion(version => version + 1);
    }
  }, []);
  const samples = useIntegrationSamples(
    category,
    { email: emailContent, slack: slackContent, webhook: webhookContent, stream: streamContent },
    applySamples
  );

  // Preselect the requested category (e.g. from the Audit Log) once permissions
  // are known, unless the user already picked one: this effect can run after
  // their first change and must not overwrite it.
  const categoryChosen = useRef(false);
  useEffect(() => {
    if (categoryInitialised || !integrationConfig || permissionsLoading) {
      return;
    }
    const requestedCategory = requested.current.category;
    const match = categories.find(c => c.enum_value === requestedCategory);
    if (requestedCategory && !match) {
      setUnavailableCategory(requestedCategory);
    }
    const initial = match ?? categories[0];
    if (initial && !categoryChosen.current) {
      setCategory(initial.enum_value);
    }
    setCategoryInitialised(true);
  }, [categoryInitialised, integrationConfig, permissionsLoading, categories]);

  const handleUseAuditTemplate = () => {
    if (type === 'stream') {
      setStreamContent(auditPayloadTemplate());
    } else if (type === 'webhook') {
      setWebhookContent(auditPayloadTemplate());
    }
    setPayloadVersion(version => version + 1);
    setIsModified(true);
  };

  // Fetch valid runtime variables when category changes
  useEffect(() => {
    const fetchValidRuntimeVars = async () => {
      try {
        const vars = await getRuntimeVariablesForCategories(['general', category || 'general']);
        const validNames = new Set(Object.keys(vars));
        setValidRuntimeVars(validNames);
      } catch (err) {
        console.error('[AddIntegrationWizardPage] Failed to fetch valid runtime variables:', err);
      }
    };

    fetchValidRuntimeVars();
  }, [category]);

  // Stable callback for stream configuration updates
  const handleStreamConfigurationChange = useCallback((config: StreamConfiguration) => {
    setStreamConfiguration(config);
    setIsModified(true);
  }, []);

  const handleStreamContentChange = useCallback((content: StreamContent) => {
    setStreamContent(content);
    setIsModified(true);
  }, []);

  // Stable callback for missing variables change
  const handleMissingVariablesChange = useCallback((count: number) => {
    setHasMissingVariables(count > 0);
  }, []);

  // Keyboard shortcut for saving (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (!isSubmitting) {
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSubmitting]);

  const getConfigurationPlaceholder = (notifierType: string) => {
    switch (notifierType) {
      case 'email':
        return `{
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_username": "user@gmail.com",
  "smtp_password": "app-password",
  "from": "gateway@company.com",
  "to": ["admin@company.com"],
  "use_tls": false,
  "use_starttls": true
}`;
      case 'slack':
        return `{
  "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}`;
      case 'webhook':
        return `{
  "url": "https://your-server.com/webhook",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer YOUR_TOKEN"
  }
}`;
      case 'stream':
        return `{
  "platform": "kafka",
  "topic": "agent-gateway-events",
  "brokers": "localhost:9092,localhost:9093",
  "auth_type": "sasl_plain",
  "username": "your-username",
  "password": "your-password",
  "partition_key": "\${EVENT_TYPE}"
}`;
      default:
        return '{"key": "value"}';
    }
  };

  const getContentPlaceholder = (notifierType: string) => {
    switch (notifierType) {
      case 'email':
        return `{
  "subject": "Notification from \${CP_NAME}",
  "body": "Message received at \${TIMESTAMP}\\n\\nMessage ID: \${MESSAGE_ID}"
}`;
      case 'slack':
        return `{
  "text": "🔔 Notification from *\${CP_NAME}*\\n\\nMessage ID: \`\${MESSAGE_ID}\`\\nTime: \${TIMESTAMP}",
  "bot_name": "Agent Gateway",
  "icon_emoji": ":robot_face:",
  "channel": "#notifications"
}`;
      case 'webhook':
        return `{
  "connection_point": "\${CP_NAME}",
  "message_id": "\${MESSAGE_ID}",
  "timestamp": "\${TIMESTAMP}",
  "event": "notification"
}`;
      case 'stream':
        return `{
  "event_type": "\${EVENT_TYPE}",
  "entity_id": "\${ENTITY_ID}",
  "entity_type": "\${ENTITY_TYPE}",
  "timestamp": "\${TIMESTAMP}",
  "new_state": "\${NEW_STATE}",
  "old_state": "\${OLD_STATE}"
}`;
      default:
        return '{}';
    }
  };

  const getDefaultConfiguration = (notifierType: string) => {
    switch (notifierType) {
      case 'email':
        return `{
  "smtp_host": "",
  "smtp_port": 587,
  "smtp_username": "",
  "smtp_password": "",
  "from": "",
  "to": [],
  "use_tls": false,
  "use_starttls": true
}`;
      case 'slack':
        return `{
  "webhook_url": ""
}`;
      case 'webhook':
        return `{
  "url": "",
  "method": "POST"
}`;
      case 'stream':
        return `{
  "platform": "kafka",
  "topic": "",
  "brokers": "",
  "auth_type": "none"
}`;
      default:
        return '{}';
    }
  };

  const getDefaultContent = (notifierType: string) => {
    switch (notifierType) {
      case 'email':
        return `{
  "subject": "",
  "body": ""
}`;
      case 'slack':
        return `{
  "text": ""
}`;
      case 'webhook':
        return `{}`;
      case 'stream':
        return `{
  "event_type": "\${EVENT_TYPE}",
  "timestamp": "\${TIMESTAMP}"
}`;
      default:
        return '{}';
    }
  };

  const handleTypeChange = (newType: string) => {
    setType(newType);
    setIsModified(true);
    // Only update if empty or default {}
    if (configuration.trim() === '{}' || configuration.trim() === '') {
      setConfiguration(getDefaultConfiguration(newType));
    }
    if (content.trim() === '{}' || content.trim() === '') {
      setContent(getDefaultContent(newType));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validation
    if (!name.trim()) {
      setError('Integration name is required');
      return;
    }

    let configObj: any;
    let contentObj: any;

    // Get configuration and content based on type
    if (type === 'email') {
      // Validate email fields
      if (
        !emailConfiguration.smtp_host ||
        !emailConfiguration.smtp_username ||
        !emailConfiguration.smtp_password ||
        !emailConfiguration.from ||
        emailConfiguration.to.length === 0
      ) {
        setError('Please fill in all required email configuration fields');
        return;
      }
      if (!emailContent.subject || !emailContent.body) {
        setError('Please fill in email subject and body');
        return;
      }
      configObj = emailConfiguration;
      contentObj = emailContent;
    } else if (type === 'slack') {
      // Validate slack fields
      if (!slackConfiguration.webhook_url) {
        setError('Please provide a Slack webhook URL');
        return;
      }
      if (!slackContent.text) {
        setError('Please provide message text');
        return;
      }
      configObj = slackConfiguration;
      // Filter out empty optional fields
      contentObj = {
        text: slackContent.text,
        ...(slackContent.bot_name && { bot_name: slackContent.bot_name }),
        ...(slackContent.icon_emoji && { icon_emoji: slackContent.icon_emoji }),
        ...(slackContent.channel && { channel: slackContent.channel }),
      };
    } else if (type === 'webhook') {
      // Validate webhook fields
      if (!webhookConfiguration.url) {
        setError('Please provide a webhook URL');
        return;
      }
      // Filter out empty optional fields
      configObj = {
        url: webhookConfiguration.url,
        method: webhookConfiguration.method || 'POST',
        ...(webhookConfiguration.signing_secret && {
          signing_secret: webhookConfiguration.signing_secret,
        }),
        ...(webhookConfiguration.headers &&
          Object.keys(webhookConfiguration.headers).length > 0 && {
            headers: webhookConfiguration.headers,
          }),
      };
      contentObj = webhookContent;
    } else if (type === 'stream') {
      // Validate stream fields
      // console.log('[AddIntegrationWizardPage] Stream validation - streamConfiguration:', JSON.stringify(streamConfiguration, null, 2));
      if (!streamConfiguration.platform) {
        setError('Please select a streaming platform');
        return;
      }
      if (!streamConfiguration.topic || streamConfiguration.topic.trim() === '') {
        setError('Please provide a topic/stream name');
        return;
      }
      // Platform-specific validation
      if (
        (streamConfiguration.platform === 'kafka' || streamConfiguration.platform === 'pulsar') &&
        !streamConfiguration.brokers
      ) {
        setError('Please provide broker URLs for Kafka/Pulsar');
        return;
      }
      if (streamConfiguration.platform === 'kinesis' && !streamConfiguration.region) {
        setError('Please provide AWS region for Kinesis');
        return;
      }
      if (streamConfiguration.platform === 'redis' && !streamConfiguration.redis_url) {
        setError('Please provide Redis URL');
        return;
      }

      configObj = streamConfiguration;
      contentObj = streamContent;
    } else {
      // For other types, validate JSON
      try {
        configObj = JSON.parse(configuration);
      } catch (err) {
        setError('Configuration must be valid JSON');
        return;
      }

      try {
        contentObj = JSON.parse(content);
      } catch (err) {
        setError('Content must be valid JSON');
        return;
      }
    }

    try {
      setIsSubmitting(true);

      const payload = {
        name: name.trim(),
        description: description.trim(),
        type,
        category: category || 'general',
        configuration: configObj,
        content: contentObj,
        status: 'active',
      };

      const response = await apiClient.post('/integrations', payload);
      showToast('success', `Integration "${name}" has been successfully created.`, {
        autoRemove: true,
        duration: 2000,
      });

      navigate('/integrations', { replace: true });
    } catch (err: any) {
      console.error('Failed to create integration:', err);
      setError(err.response?.data?.message || err.message || 'Failed to create integration');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    navigate('/integrations');
  };

  const handleClear = () => {
    setName('');
    setDescription('');
    setEmailConfiguration({
      smtp_host: '',
      smtp_port: 587,
      smtp_username: '',
      smtp_password: '',
      from: '',
      to: [],
      use_tls: false,
      use_starttls: true,
    });
    setEmailContent({ subject: '', body: '', format: 'plain', ...samples?.email });
    setSlackConfiguration({ webhook_url: '' });
    setSlackContent({ text: '', bot_name: '', icon_emoji: '', channel: '', ...samples?.slack });
    setWebhookConfiguration({ url: '', method: 'POST', signing_secret: '' });
    setWebhookContent(samples?.webhook ?? {});
    setStreamConfiguration({ platform: 'kafka', topic: '' });
    setStreamContent(samples?.stream ?? {});
    setPayloadVersion(version => version + 1);
    setConfiguration('{}');
    setContent('{}');
    setError('');
    setIsModified(false);
  };

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleCancel} disabled={isSubmitting}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-bell me-2"></i>
            Add integration
          </h1>
          <p className="text-muted mt-2">
            Create a new integration to send notifications about gateway events
          </p>
        </div>
      </div>

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2"></i>
                Integration Details
              </h6>
            </div>
            <div className="card-body">
              {error && (
                <div className="alert alert-danger" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  {error}
                </div>
              )}

              {configLoading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-primary" role="status">
                    <span className="sr-only">Loading...</span>
                  </div>
                  <p className="text-muted mt-2">Loading integration configuration...</p>
                </div>
              ) : !integrationConfig ? (
                <div className="alert alert-warning" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  Failed to load integration configuration
                </div>
              ) : (
                <form onSubmit={handleSubmit} data-testid="integration-form">
                  <div className="alert alert-info mb-4" data-testid="integration-intro">
                    <i className="fas fa-info-circle me-2"></i>
                    <strong>Integrations:</strong> Send a message by Email, Slack, Webhook or Stream
                    whenever an event in the chosen category happens, such as a gateway, user or
                    connection point change.
                  </div>

                  {unavailableCategory && (
                    <div
                      className="alert alert-warning mb-4"
                      role="alert"
                      data-testid="integration-category-unavailable"
                    >
                      <i className="fas fa-exclamation-triangle me-2"></i>
                      The <code>{unavailableCategory}</code> category isn&rsquo;t available to you
                      on this gateway, so another category is selected. An integration saved here
                      won&rsquo;t receive <code>{unavailableCategory}</code> events.
                      {unavailableCategory === AUDIT_INTEGRATION_CATEGORY &&
                        ' Governance Audit integrations need the audit.view permission.'}
                    </div>
                  )}

                  <div className="mb-3">
                    <label htmlFor="type" className="form-label">
                      Integration Type *
                    </label>
                    <select
                      id="type"
                      className="form-control dropdown-styling"
                      value={type}
                      onChange={e => handleTypeChange(e.target.value)}
                      disabled={isSubmitting}
                      required
                    >
                      {types.map(t => (
                        <option key={t.enum_value} value={t.enum_value} title={t.description}>
                          {t.name}
                        </option>
                      ))}
                    </select>
                    <small className="form-text text-muted">
                      <i className="fas fa-info-circle me-1"></i>
                      {integrationConfig.types.find(t => t.enum_value === type)?.description ||
                        'How notifications will be sent'}
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="category" className="form-label">
                      Category *
                    </label>
                    <select
                      id="category"
                      className="form-control dropdown-styling"
                      value={category}
                      onChange={e => {
                        categoryChosen.current = true;
                        setCategory(e.target.value);
                        setIsModified(true);
                      }}
                      disabled={isSubmitting}
                      required
                      data-testid="integration-category-select"
                    >
                      {categories.map(c => (
                        <option key={c.enum_value} value={c.enum_value} title={c.description}>
                          {c.name}
                        </option>
                      ))}
                    </select>
                    <small className="form-text text-muted">
                      <i className="fas fa-info-circle me-1"></i>
                      {categories.find(c => c.enum_value === category)?.description ||
                        'Context determines which runtime variables are available'}
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="name" className="form-label">
                      Integration Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      className="form-control"
                      value={name}
                      onChange={e => {
                        setName(e.target.value);
                        setIsModified(true);
                      }}
                      placeholder="e.g., Email integration"
                      disabled={isSubmitting}
                      required
                    />
                    <small className="form-text text-muted">
                      A friendly name to identify this integration
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="description" className="form-label">
                      Description
                    </label>
                    <input
                      id="description"
                      className="form-control"
                      value={description}
                      onChange={e => {
                        setDescription(e.target.value);
                        setIsModified(true);
                      }}
                      placeholder="Describe the purpose of this integration..."
                      disabled={isSubmitting}
                    />
                    <small className="form-text text-muted">
                      Optional description of what this integration is used for
                    </small>
                  </div>

                  {type === 'email' ? (
                    <EmailIntegrationForm
                      configuration={emailConfiguration}
                      content={emailContent}
                      onConfigurationChange={config => {
                        setEmailConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={content => {
                        setEmailContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSubmitting}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : type === 'slack' ? (
                    <SlackIntegrationForm
                      configuration={slackConfiguration}
                      content={slackContent}
                      onConfigurationChange={config => {
                        setSlackConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={content => {
                        setSlackContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSubmitting}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : type === 'webhook' ? (
                    <WebhookIntegrationForm
                      key={`webhook-${payloadVersion}`}
                      configuration={webhookConfiguration}
                      content={webhookContent}
                      onConfigurationChange={config => {
                        setWebhookConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={content => {
                        setWebhookContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSubmitting}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : type === 'stream' ? (
                    <StreamIntegrationForm
                      key={`stream-${payloadVersion}`}
                      configuration={streamConfiguration}
                      content={streamContent}
                      onConfigurationChange={handleStreamConfigurationChange}
                      onContentChange={handleStreamContentChange}
                      disabled={isSubmitting}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : (
                    <>
                      <div className="mb-3">
                        <label htmlFor="configuration" className="form-label">
                          Configuration (JSON) *
                        </label>
                        <textarea
                          id="configuration"
                          className="form-control font-monospace"
                          rows={10}
                          value={configuration}
                          onChange={e => {
                            setConfiguration(e.target.value);
                            setIsModified(true);
                          }}
                          placeholder={getConfigurationPlaceholder(type)}
                          disabled={isSubmitting}
                          required
                        />
                        <small className="form-text text-muted">
                          <i className="fas fa-info-circle me-1"></i>
                          Connection and authentication settings (e.g., SMTP host/port/credentials,
                          Slack webhook URL, etc.)
                        </small>
                      </div>

                      <div className="mb-3">
                        <label htmlFor="content" className="form-label">
                          Content Template (JSON) *
                        </label>
                        <textarea
                          id="content"
                          className="form-control font-monospace"
                          rows={10}
                          value={content}
                          onChange={e => {
                            setContent(e.target.value);
                            setIsModified(true);
                          }}
                          placeholder={getContentPlaceholder(type)}
                          disabled={isSubmitting}
                          required
                        />
                        <small className="form-text text-muted">
                          <i className="fas fa-info-circle me-1"></i>
                          Message content template with optional variables like {`\${CP_NAME}`},{' '}
                          {`\${MESSAGE_ID}`}, {`\${TIMESTAMP}`}
                        </small>
                      </div>
                    </>
                  )}

                  <div className="d-flex justify-content-between">
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={handleClear}
                      disabled={isSubmitting || !isModified}
                      title="Clear form"
                    >
                      <i className="fas fa-times me-1"></i>
                      Clear
                    </button>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={isSubmitting || hasMissingVariables}
                      title={
                        hasMissingVariables
                          ? 'Cannot create: integration has missing variables'
                          : ''
                      }
                    >
                      {isSubmitting ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                            aria-hidden="true"
                          ></span>
                          Creating...
                        </>
                      ) : (
                        <>
                          <i className="fas fa-plus me-1"></i> Create integration
                        </>
                      )}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          {category === AUDIT_INTEGRATION_CATEGORY && (
            <AuditIntegrationCard
              type={type}
              onUseTemplate={handleUseAuditTemplate}
              disabled={isSubmitting}
            />
          )}
          {type === 'email' ? (
            <>
              <div className="card shadow mb-4">
                <div className="card-header py-3">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-lightbulb me-2"></i>
                    Quick Setup Guide
                  </h6>
                </div>
                <div className="card-body">
                  <ol className="mb-0" style={{ fontSize: '0.9em', paddingLeft: '20px' }}>
                    <li>Choose SMTP provider (Gmail, SendGrid, etc.)</li>
                    <li>Get SMTP credentials</li>
                    <li>Configure host, port, and credentials</li>
                    <li>Set recipient email addresses</li>
                    <li>Write subject and body with template variables</li>
                    <li>Test the configuration</li>
                  </ol>
                </div>
              </div>

              <RuntimeVariablesSidebar
                category={category}
                configuration={emailConfiguration}
                content={emailContent}
                onMissingVariablesChange={handleMissingVariablesChange}
              />

              <a
                href="/guides/email-integration.html"
                target="_blank"
                className="btn btn-sm btn-outline-primary w-100"
              >
                <i className="fas fa-book me-2"></i>
                View Complete Guide
              </a>
            </>
          ) : type === 'slack' ? (
            <>
              <div className="card shadow mb-4">
                <div className="card-header py-3">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-lightbulb me-2"></i>
                    How to Get Webhook URL
                  </h6>
                </div>
                <div className="card-body">
                  <ol className="mb-0" style={{ fontSize: '0.9em', paddingLeft: '20px' }}>
                    <li>
                      Go to{' '}
                      <a
                        href="https://api.slack.com/apps"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        api.slack.com/apps
                      </a>
                    </li>
                    <li>Create a new app or select an existing one</li>
                    <li>Enable "Incoming Webhooks"</li>
                    <li>Click "Add New Webhook to Workspace"</li>
                    <li>Select a channel and authorize</li>
                    <li>Copy the webhook URL</li>
                  </ol>
                </div>
              </div>

              <RuntimeVariablesSidebar
                category={category}
                configuration={slackConfiguration}
                content={slackContent}
                onMissingVariablesChange={handleMissingVariablesChange}
              />

              <a
                href="/guides/slack-integration.html"
                target="_blank"
                className="btn btn-sm btn-outline-primary w-100"
              >
                <i className="fas fa-book me-2"></i>
                View Complete Guide
              </a>
            </>
          ) : type === 'webhook' ? (
            <>
              <div className="card shadow mb-4">
                <div className="card-header py-3">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-lightbulb me-2"></i>
                    Quick Setup Guide
                  </h6>
                </div>
                <div className="card-body">
                  <ol className="mb-0" style={{ fontSize: '0.9em', paddingLeft: '20px' }}>
                    <li>Prepare your webhook endpoint (POST/PUT/PATCH)</li>
                    <li>Generate a signing secret (recommended)</li>
                    <li>Configure webhook URL and method</li>
                    <li>Design JSON payload template with variables</li>
                    <li>Implement signature verification on your server</li>
                    <li>Test the webhook</li>
                  </ol>
                  <hr />
                  <p className="mb-2 mt-3">
                    <small>
                      <strong>Security:</strong>
                    </small>
                  </p>
                  <p className="mb-0" style={{ fontSize: '0.85em' }}>
                    Use HMAC-SHA256 signing to verify webhook authenticity and prevent tampering.
                    See the complete guide for implementation examples.
                  </p>
                </div>
              </div>

              <RuntimeVariablesSidebar
                category={category}
                configuration={webhookConfiguration}
                content={webhookContent}
                onMissingVariablesChange={handleMissingVariablesChange}
              />

              <a
                href="/guides/webhook-integration.html"
                target="_blank"
                className="btn btn-sm btn-outline-primary w-100"
              >
                <i className="fas fa-book me-2"></i>
                View Complete Guide
              </a>
            </>
          ) : type === 'stream' ? (
            <>
              <div className="card shadow mb-4">
                <div className="card-header py-3">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-lightbulb me-2"></i>
                    Quick Setup Guide
                  </h6>
                </div>
                <div className="card-body">
                  <ol className="mb-0" style={{ fontSize: '0.9em', paddingLeft: '20px' }}>
                    <li>Choose streaming platform (Kafka, Kinesis, Pulsar, Redis)</li>
                    <li>Configure platform-specific connection details</li>
                    <li>Set topic/stream name</li>
                    <li>Design JSON event template with variables</li>
                    <li>Test the stream integration</li>
                  </ol>
                  <hr />
                  <p className="mb-2 mt-3">
                    <small>
                      <strong>Event Format:</strong>
                    </small>
                  </p>
                  <p className="mb-0" style={{ fontSize: '0.85em' }}>
                    Events are published as JSON payloads. Use template variables to include dynamic
                    data from gateway events.
                  </p>
                </div>
              </div>

              <RuntimeVariablesSidebar
                category={category}
                configuration={streamConfiguration}
                content={streamContent}
                onMissingVariablesChange={handleMissingVariablesChange}
              />

              <a
                href="/guides/stream-integration.html"
                target="_blank"
                className="btn btn-sm btn-outline-primary w-100"
              >
                <i className="fas fa-book me-2"></i>
                View Complete Guide
              </a>
            </>
          ) : (
            <>
              <div className="card shadow mb-4">
                <div className="card-header py-3">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-info-circle me-2"></i>
                    Integration Info
                  </h6>
                </div>
                <div className="card-body">
                  <p className="mb-2">Integrations send alerts about gateway events such as:</p>
                  <ul className="mb-0">
                    <li>Surface status changes</li>
                    <li>Message delivery failures</li>
                    <li>System alerts and warnings</li>
                    <li>Configuration updates</li>
                  </ul>
                </div>
              </div>

              <RuntimeVariablesSidebar
                category={category}
                configuration={
                  type === 'email'
                    ? emailConfiguration
                    : type === 'slack'
                      ? slackConfiguration
                      : type === 'webhook'
                        ? webhookConfiguration
                        : type === 'stream'
                          ? streamConfiguration
                          : undefined
                }
                content={
                  type === 'email'
                    ? emailContent
                    : type === 'slack'
                      ? slackContent
                      : type === 'webhook'
                        ? webhookContent
                        : type === 'stream'
                          ? streamContent
                          : undefined
                }
                onMissingVariablesChange={handleMissingVariablesChange}
              />
            </>
          )}
        </div>
      </div>
      <br />
    </div>
  );
};

export default AddIntegrationWizardPage;
