import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import EmailIntegrationForm from '../components/integration-forms/EmailIntegrationForm';
import SlackIntegrationForm from '../components/integration-forms/SlackIntegrationForm';
import WebhookIntegrationForm from '../components/integration-forms/WebhookIntegrationForm';
import StreamIntegrationForm from '../components/integration-forms/StreamIntegrationForm';
import TestNotifierModal from '../components/TestNotifierModal';
import RuntimeVariablesSidebar from '../components/RuntimeVariablesSidebar';
import { DeleteButton } from '../components/shared/DeleteButton';
import {
  extractTemplateVariablesFromObject,
  createTestVariables,
  getNotifierTestSuccessMessage,
} from '../utils/templateVariables';
import { getRuntimeVariablesForCategories } from '../utils/runtimeVariables';
import {
  AUDIT_INTEGRATION_CATEGORY,
  auditPayloadTemplate,
  selectableCategories,
} from '../utils/auditIntegrations';
import { usePermissions } from '../context/PermissionsContext';
import AuditIntegrationCard from '../components/integrations/AuditIntegrationCard';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import { useIntegrationSamples } from '../hooks/useIntegrationSamples';
import { IntegrationContents } from '../utils/integrationSamples';

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

interface IntegrationFormData {
  name: string;
  description: string;
  type: string;
  category?: string;
  configuration: string;
  content: string;
  status: string;
}

const EditIntegrationPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;
  const { hasPermission } = usePermissions();
  const canViewAudit = hasPermission('audit.view');

  const [integrationConfig, setIntegrationConfig] = useState<IntegrationConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [payloadVersion, setPayloadVersion] = useState(0);
  const [formData, setFormData] = useState<IntegrationFormData>({
    name: '',
    description: '',
    type: 'email',
    category: 'general',
    configuration: '{}',
    content: '{}',
    status: 'active',
  });
  const categories = useMemo(
    () => selectableCategories(integrationConfig?.categories ?? [], canViewAudit),
    [integrationConfig, canViewAudit]
  );

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

  const [loading, setLoading] = useState(isEditMode);
  const [isSaving, setIsSaving] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');
  const [isModified, setIsModified] = useState(false);
  const [hasMissingVariables, setHasMissingVariables] = useState(false);
  const [validRuntimeVars, setValidRuntimeVars] = useState<Set<string>>(new Set());
  const [showTestModal, setShowTestModal] = useState(false);
  const [testVariables, setTestVariables] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ message: string; isSuccess: boolean } | null>(
    null
  );

  // Untouched content follows the category's sample once the integration has
  // loaded; the JSON payload forms remount to show a replaced sample.
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
    formData.category,
    { email: emailContent, slack: slackContent, webhook: webhookContent, stream: streamContent },
    applySamples,
    !loading
  );

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

  // Fetch integration configuration from backend
  useEffect(() => {
    const fetchIntegrationConfig = async () => {
      try {
        const response = await apiClient.get('/integrations/config');
        setIntegrationConfig(response.data);
      } catch (err) {
        console.error('Failed to fetch integration config:', err);
        showToast('error', 'Failed to load integration configuration');
      } finally {
        setConfigLoading(false);
      }
    };

    fetchIntegrationConfig();
  }, []);

  useEffect(() => {
    if (isEditMode && id) {
      fetchIntegration(id);
    }
  }, [id, isEditMode]);

  // Fetch valid runtime variables when category changes
  useEffect(() => {
    const fetchValidVars = async () => {
      try {
        const vars = await getRuntimeVariablesForCategories([
          'general',
          formData.category || 'general',
        ]);
        setValidRuntimeVars(new Set(Object.keys(vars)));
      } catch (err) {
        console.error('Failed to fetch runtime variables:', err);
      }
    };
    fetchValidVars();
  }, [formData.category]);

  // Keyboard shortcut for saving (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        // Only trigger save if not already saving, form is modified (or it's create mode), and no missing variables
        if (!isSaving && !isTesting && (!isEditMode || isModified) && !hasMissingVariables) {
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSaving, isTesting, isModified, isEditMode, hasMissingVariables]);

  const fetchIntegration = async (notifierId: string) => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/integrations/${notifierId}`);
      const integration = response.data;

      setFormData({
        name: integration.name || '',
        description: integration.description || '',
        type: integration.type || 'email',
        category: integration.category || 'general',
        configuration:
          typeof integration.configuration === 'string'
            ? integration.configuration
            : JSON.stringify(integration.configuration, null, 2),
        content:
          typeof integration.content === 'string'
            ? integration.content
            : JSON.stringify(integration.content, null, 2),
        status: integration.status || 'active',
      });

      // Load email-specific state if it's an email integration
      if (integration.type === 'email') {
        const config =
          typeof integration.configuration === 'object'
            ? integration.configuration
            : JSON.parse(integration.configuration);
        const content =
          typeof integration.content === 'object'
            ? integration.content
            : JSON.parse(integration.content);

        setEmailConfiguration({
          smtp_host: config.smtp_host || '',
          smtp_port: config.smtp_port || 587,
          smtp_username: config.smtp_username || '',
          smtp_password: config.smtp_password || '',
          from: config.from || '',
          to: config.to || [],
          use_tls: config.use_tls || false,
          use_starttls: config.use_starttls !== undefined ? config.use_starttls : true,
        });

        setEmailContent({
          subject: content.subject || '',
          body: content.body || '',
          format: content.format || 'plain',
        });
      } else if (integration.type === 'slack') {
        const config =
          typeof integration.configuration === 'object'
            ? integration.configuration
            : JSON.parse(integration.configuration);
        const content =
          typeof integration.content === 'object'
            ? integration.content
            : JSON.parse(integration.content);

        setSlackConfiguration({
          webhook_url: config.webhook_url || '',
        });

        setSlackContent({
          text: content.text || '',
          bot_name: content.bot_name || '',
          icon_emoji: content.icon_emoji || '',
          channel: content.channel || '',
        });
      } else if (integration.type === 'webhook') {
        const config =
          typeof integration.configuration === 'object'
            ? integration.configuration
            : JSON.parse(integration.configuration);
        const content =
          typeof integration.content === 'object'
            ? integration.content
            : JSON.parse(integration.content);

        setWebhookConfiguration({
          url: config.url || '',
          method: config.method || 'POST',
          signing_secret: config.signing_secret || '',
          headers: config.headers || undefined,
        });

        setWebhookContent(content || {});
      } else if (integration.type === 'stream') {
        const config =
          typeof integration.configuration === 'object'
            ? integration.configuration
            : JSON.parse(integration.configuration);
        const content =
          typeof integration.content === 'object'
            ? integration.content
            : JSON.parse(integration.content);

        setStreamConfiguration({
          platform: config.platform || 'kafka',
          topic: config.topic || '',
          brokers: config.brokers || '',
          region: config.region || '',
          redis_url: config.redis_url || '',
          auth_type: config.auth_type || 'none',
          sasl_username: config.sasl_username || '',
          sasl_password: config.sasl_password || '',
          access_key: config.access_key || '',
          secret_key: config.secret_key || '',
        });

        setStreamContent(content || {});
      }
    } catch (err: any) {
      console.error('Failed to fetch integration:', err);
      setError(err.response?.data?.message || err.message || 'Failed to load integration');
    } finally {
      setLoading(false);
      setIsModified(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent | React.MouseEvent) => {
    e.preventDefault();
    setError('');

    if (!formData.name.trim()) {
      setError('Integration name is required');
      return;
    }

    let configObj: any;
    let contentObj: any;

    // Get configuration and content based on type
    if (formData.type === 'email') {
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
    } else if (formData.type === 'slack') {
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
    } else if (formData.type === 'webhook') {
      // Validate webhook fields
      if (!webhookConfiguration.url) {
        setError('Please provide a webhook URL');
        return;
      }
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
    } else if (formData.type === 'stream') {
      // Validate stream fields
      if (
        !streamConfiguration.platform ||
        !streamConfiguration.topic ||
        streamConfiguration.topic.trim() === ''
      ) {
        setError('Please provide streaming platform and topic');
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
        configObj = JSON.parse(formData.configuration);
      } catch (err) {
        setError('Configuration must be valid JSON');
        return;
      }

      try {
        contentObj = JSON.parse(formData.content);
      } catch (err) {
        setError('Content must be valid JSON');
        return;
      }
    }

    try {
      setIsSaving(true);

      const payload = {
        name: formData.name.trim(),
        description: formData.description.trim(),
        type: formData.type,
        category: formData.category || 'general',
        configuration: configObj,
        content: contentObj,
        status: formData.status,
      };

      if (isEditMode && id) {
        await apiClient.put(`/integrations/${id}`, payload);
        setIsModified(false);
        showToast('success', `Integration "${formData.name}" has been successfully saved.`, {
          autoRemove: true,
          duration: 2000,
        });
        navigate('/integrations', { replace: true });
      } else {
        await apiClient.post('/integrations', payload);
        showToast('success', `Integration "${formData.name}" has been successfully created.`, {
          autoRemove: true,
          duration: 2000,
        });
        navigate('/integrations', { replace: true });
      }
    } catch (err: any) {
      console.error('Failed to save integration:', err);
      setError(
        err.response?.data?.message ||
          err.message ||
          `Failed to ${isEditMode ? 'update' : 'create'} integration`
      );
    } finally {
      setIsSaving(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target;

    if (type === 'checkbox' && name === 'enabled') {
      const checked = (e.target as HTMLInputElement).checked;
      setFormData(prev => ({ ...prev, status: checked ? 'active' : 'disabled' }));
      setIsModified(true);
      return;
    }

    setFormData(prev => ({ ...prev, [name]: value }));
    setIsModified(true);
  };

  const handleUseAuditTemplate = () => {
    if (formData.type === 'stream') {
      setStreamContent(auditPayloadTemplate());
    } else if (formData.type === 'webhook') {
      setWebhookContent(auditPayloadTemplate());
    }
    setPayloadVersion(version => version + 1);
    setIsModified(true);
  };

  const handleCancel = () => {
    navigate('/integrations');
  };

  const handleClear = () => {
    if (isEditMode && id) {
      fetchIntegration(id);
    } else {
      setFormData({
        name: '',
        description: '',
        type: 'email',
        category: 'general',
        configuration: '{}',
        content: '{}',
        status: 'active',
      });
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
      setIsModified(false);
      setError('');
    }
  };

  const handleDelete = async () => {
    if (!id) return;

    try {
      await apiClient.delete(`/integrations/${id}`);
      navigate('/integrations', { replace: true });
    } catch (err: any) {
      console.error('Failed to delete integration:', err);
      setError(err.response?.data?.message || err.message || 'Failed to delete integration');
    }
  };

  const handleTest = async () => {
    let configObj: any;
    let contentObj: any;

    // Get configuration and content based on type
    if (formData.type === 'email') {
      configObj = emailConfiguration;
      contentObj = emailContent;
    } else if (formData.type === 'slack') {
      configObj = slackConfiguration;
      // Filter out empty optional fields
      contentObj = {
        text: slackContent.text,
        ...(slackContent.bot_name && { bot_name: slackContent.bot_name }),
        ...(slackContent.icon_emoji && { icon_emoji: slackContent.icon_emoji }),
        ...(slackContent.channel && { channel: slackContent.channel }),
      };
    } else if (formData.type === 'webhook') {
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
    } else if (formData.type === 'stream') {
      configObj = streamConfiguration;
      contentObj = streamContent;
    } else {
      // Validate JSON config first
      try {
        configObj = JSON.parse(formData.configuration);
        contentObj = JSON.parse(formData.content);
      } catch (err) {
        setError('Please fix the configuration/content JSON before testing');
        return;
      }
    }

    // Extract template variables from content using same method as IntegrationsPage
    let variables = extractTemplateVariablesFromObject(contentObj);

    // For webhooks, also extract variables from headers in configuration
    if (formData.type === 'webhook' && configObj.headers) {
      const headerVariables = extractTemplateVariablesFromObject(configObj.headers);
      // Merge and deduplicate
      variables = Array.from(new Set([...variables, ...headerVariables])).sort();
    }

    // Clear any previous test results
    setTestResult(null);

    // Always show modal to allow user to see test results
    setTestVariables(createTestVariables(variables));
    setShowTestModal(true);
  };

  const sendTestNotification = async (
    configObj: any,
    contentObj: any,
    variables: Record<string, string>
  ) => {
    try {
      setIsTesting(true);
      setError('');

      const payload = {
        type: formData.type,
        configuration: configObj,
        content: contentObj,
        variables,
      };

      // Add 30 second timeout for webhook testing
      await apiClient.post('/integrations/test', payload, { timeout: 30000 });

      // Show success message based on type
      const successMessage = getNotifierTestSuccessMessage(formData.type);

      setTestResult({ message: successMessage, isSuccess: true });
    } catch (err: any) {
      console.error('Failed to send test notification:', err);
      const errorMessage =
        err.response?.data?.message || err.message || 'Failed to send test notification';
      setTestResult({ message: errorMessage, isSuccess: false });
      setError(errorMessage);
    } finally {
      setIsTesting(false);
    }
  };

  const handleTestModalSubmit = () => {
    // Clear previous test result
    setTestResult(null);

    let configObj: any;
    let contentObj: any;

    // Get configuration and content based on type (same logic as handleTest)
    if (formData.type === 'email') {
      configObj = emailConfiguration;
      contentObj = emailContent;
    } else if (formData.type === 'slack') {
      configObj = slackConfiguration;
      contentObj = {
        text: slackContent.text,
        ...(slackContent.bot_name && { bot_name: slackContent.bot_name }),
        ...(slackContent.icon_emoji && { icon_emoji: slackContent.icon_emoji }),
        ...(slackContent.channel && { channel: slackContent.channel }),
      };
    } else if (formData.type === 'webhook') {
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
    } else if (formData.type === 'stream') {
      configObj = streamConfiguration;
      contentObj = streamContent;
    } else {
      try {
        configObj = JSON.parse(formData.configuration);
        contentObj = JSON.parse(formData.content);
      } catch (err) {
        setError('Please fix the configuration/content JSON before testing');
        return;
      }
    }

    sendTestNotification(configObj, contentObj, testVariables);
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: '400px' }}
        >
          <div className="spinner-border text-primary" role="status">
            <span className="sr-only">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleCancel} disabled={isSaving}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-bell me-2"></i>
            {isEditMode ? 'Edit integration' : 'Add integration'}
          </h1>
          <p className="text-muted mt-2">
            {isEditMode ? 'Update integration configuration' : 'Create a new integration'}
          </p>
        </div>
        <div>
          {(formData.type === 'email' ||
            formData.type === 'slack' ||
            formData.type === 'webhook' ||
            formData.type === 'stream') && (
            <button
              className="btn btn-sm btn-info me-2"
              onClick={handleTest}
              disabled={isTesting || isSaving}
            >
              {isTesting ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Testing...
                </>
              ) : (
                <>
                  <i className="fas fa-paper-plane me-1"></i>
                  Test
                </>
              )}
            </button>
          )}
          {isEditMode && (
            <>
              <button
                className="btn btn-sm btn-primary me-2"
                onClick={handleSubmit}
                disabled={isSaving || isTesting || !isModified || hasMissingVariables}
                title={hasMissingVariables ? 'Cannot save: integration has missing variables' : ''}
              >
                {isSaving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-1"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Saving...
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-1"></i>
                    Save
                  </>
                )}
              </button>
              <DeleteButton
                onDelete={handleDelete}
                className="me-2"
                title="Delete this integration"
                disabled={isSaving}
                variant="danger"
              >
                Delete
              </DeleteButton>
            </>
          )}
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
                <div className="alert alert-danger alert-dismissible fade show" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  {error}
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setError('')}
                    aria-label="Close"
                  />
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
                  <div className="mb-3">
                    <label htmlFor="type" className="form-label">
                      Integration Type *
                    </label>
                    <select
                      id="type"
                      name="type"
                      className="form-control dropdown-styling"
                      value={formData.type}
                      onChange={handleChange}
                      disabled={isSaving || configLoading}
                      required
                    >
                      {integrationConfig?.types.map(t => (
                        <option key={t.enum_value} value={t.enum_value} title={t.description}>
                          {t.name}
                        </option>
                      ))}
                    </select>
                    <small className="form-text text-muted">
                      <i className="fas fa-info-circle me-1"></i>
                      {integrationConfig?.types.find(t => t.enum_value === formData.type)
                        ?.description || 'How notifications will be sent'}
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="category" className="form-label">
                      Category *
                    </label>
                    <select
                      id="category"
                      name="category"
                      className="form-control dropdown-styling"
                      value={formData.category || 'general'}
                      onChange={handleChange}
                      disabled={isSaving || configLoading}
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
                      {categories.find(c => c.enum_value === formData.category)?.description ||
                        'Context determines which runtime variables are available'}
                    </small>
                  </div>

                  {isEditMode && id && (
                    <div className="mb-3">
                      <label htmlFor="id" className="form-label">
                        Integration ID
                      </label>
                      <input
                        type="text"
                        id="id"
                        name="id"
                        className="form-control"
                        value={id}
                        disabled
                        readOnly
                      />
                      <small className="form-text text-muted">
                        <i className="fas fa-info-circle me-1"></i>
                        Unique identifier for this integration
                      </small>
                    </div>
                  )}

                  <div className="mb-3">
                    <label htmlFor="name" className="form-label">
                      Integration Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      className="form-control"
                      value={formData.name}
                      onChange={handleChange}
                      placeholder="e.g., Email integration"
                      disabled={isSaving}
                      required
                    />
                  </div>

                  <div className="mb-3">
                    <label htmlFor="description" className="form-label">
                      Description
                    </label>
                    <input
                      id="description"
                      name="description"
                      className="form-control"
                      value={formData.description}
                      onChange={handleChange}
                      placeholder="Describe the purpose..."
                      disabled={isSaving}
                    />
                  </div>

                  {formData.type === 'email' ? (
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
                      disabled={isSaving}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : formData.type === 'slack' ? (
                    <SlackIntegrationForm
                      configuration={slackConfiguration}
                      content={slackContent}
                      onConfigurationChange={(config: SlackConfiguration) => {
                        setSlackConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={(content: SlackContent) => {
                        setSlackContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSaving}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : formData.type === 'webhook' ? (
                    <WebhookIntegrationForm
                      key={`webhook-${payloadVersion}`}
                      configuration={webhookConfiguration}
                      content={webhookContent}
                      onConfigurationChange={(config: WebhookConfiguration) => {
                        setWebhookConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={(content: WebhookContent) => {
                        setWebhookContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSaving}
                      validRuntimeVars={validRuntimeVars}
                    />
                  ) : formData.type === 'stream' ? (
                    <StreamIntegrationForm
                      key={`stream-${payloadVersion}`}
                      configuration={streamConfiguration}
                      content={streamContent}
                      onConfigurationChange={(config: StreamConfiguration) => {
                        setStreamConfiguration(config);
                        setIsModified(true);
                      }}
                      onContentChange={(content: StreamContent) => {
                        setStreamContent(content);
                        setIsModified(true);
                      }}
                      disabled={isSaving}
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
                          name="configuration"
                          className="form-control font-monospace"
                          rows={10}
                          value={formData.configuration}
                          onChange={handleChange}
                          placeholder={getConfigurationPlaceholder(formData.type)}
                          disabled={isSaving}
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
                          name="content"
                          className="form-control font-monospace"
                          rows={10}
                          value={formData.content}
                          onChange={handleChange}
                          placeholder={getContentPlaceholder(formData.type)}
                          disabled={isSaving}
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

                  <div className="mb-3">
                    <div className="custom-control custom-switch">
                      <input
                        type="checkbox"
                        className="custom-control-input"
                        id="enabled"
                        name="enabled"
                        checked={formData.status === 'active'}
                        onChange={handleChange}
                        disabled={isSaving}
                      />
                      <label className="custom-control-label" htmlFor="enabled">
                        Enabled
                      </label>
                    </div>
                    <small className="form-text text-muted">
                      When disabled, this integration will not send notifications
                    </small>
                  </div>

                  <div className="d-flex justify-content-between">
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={handleClear}
                      disabled={isSaving || !isModified}
                      title={isEditMode ? 'Revert to saved values' : 'Clear form'}
                    >
                      <i className="fas fa-times me-1"></i>
                      Clear
                    </button>
                    <div>
                      <button
                        type="button"
                        className="btn btn-sm btn-info me-2"
                        onClick={handleTest}
                        disabled={isSaving || isTesting}
                      >
                        {isTesting ? (
                          <>
                            <span
                              className="spinner-border spinner-border-sm me-1"
                              role="status"
                              aria-hidden="true"
                            ></span>
                            Testing...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-paper-plane me-1"></i>
                            Test
                          </>
                        )}
                      </button>
                      <button
                        type="submit"
                        className="btn btn-sm btn-primary"
                        disabled={
                          isSaving ||
                          isTesting ||
                          (isEditMode && !isModified) ||
                          hasMissingVariables
                        }
                        title={
                          hasMissingVariables
                            ? 'Cannot save: integration has missing variables'
                            : ''
                        }
                      >
                        {isSaving ? (
                          <>
                            <span
                              className="spinner-border spinner-border-sm me-2"
                              role="status"
                              aria-hidden="true"
                            ></span>
                            Saving...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-save me-1"></i>
                            {isEditMode ? 'Save Changes' : 'Create integration'}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          {formData.category === AUDIT_INTEGRATION_CATEGORY && (
            <AuditIntegrationCard
              type={formData.type}
              onUseTemplate={handleUseAuditTemplate}
              disabled={isSaving}
            />
          )}
          {formData.type === 'email' ? (
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

              {/* Available Runtime Variables */}
              <RuntimeVariablesSidebar
                category={formData.category}
                configuration={emailConfiguration}
                content={emailContent}
                onMissingVariablesChange={count => setHasMissingVariables(count > 0)}
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
          ) : formData.type === 'slack' ? (
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

              {/* Available Runtime Variables */}
              <RuntimeVariablesSidebar
                category={formData.category}
                configuration={slackConfiguration}
                content={slackContent}
                onMissingVariablesChange={count => setHasMissingVariables(count > 0)}
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
          ) : formData.type === 'webhook' ? (
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

              {/* Available Runtime Variables */}
              <RuntimeVariablesSidebar
                category={formData.category}
                configuration={webhookConfiguration}
                content={webhookContent}
                onMissingVariablesChange={count => setHasMissingVariables(count > 0)}
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
          ) : formData.type === 'stream' ? (
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

              {/* Available Runtime Variables */}
              <RuntimeVariablesSidebar
                category={formData.category}
                configuration={streamConfiguration}
                content={streamContent}
                onMissingVariablesChange={count => setHasMissingVariables(count > 0)}
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
          )}
        </div>
      </div>
      <br />

      {/* Template Variables Test Modal */}
      <TestNotifierModal
        show={showTestModal}
        integrationName={formData.name || 'Notifier'}
        variables={testVariables}
        isTesting={isTesting}
        testResult={testResult}
        onVariableChange={(varName, value) =>
          setTestVariables({
            ...testVariables,
            [varName]: value,
          })
        }
        onCancel={() => {
          setShowTestModal(false);
          setTestResult(null);
        }}
        onTest={handleTestModalSubmit}
      />
    </div>
  );
};

export default EditIntegrationPage;
