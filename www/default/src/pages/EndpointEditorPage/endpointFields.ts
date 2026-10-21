import { Endpoint, EndpointType } from '../../integrationsApi';

/**
 * The configuration fields of each endpoint type, as the gateway's publishers read them.
 * Secret fields are written but never read back (the catalog's `secret_fields`).
 */

export type FieldKind = 'text' | 'number' | 'list' | 'switch' | 'select' | 'secret' | 'secret-json';

export interface FieldSpec {
  name: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  /** Write-only: kept when left out of an update, cleared when sent as null. */
  secret?: boolean;
  defaultValue?: string | boolean;
  options?: { value: string; label: string }[];
  placeholder?: string;
  help?: string;
  /** Shown, and sent, only when this holds for the form's values. */
  shownWhen?: (values: Record<string, unknown>) => boolean;
}

const platformIs =
  (...platforms: string[]) =>
  (values: Record<string, unknown>) =>
    platforms.includes(String(values.platform ?? 'kafka'));

export const ENDPOINT_FIELDS: Record<EndpointType, FieldSpec[]> = {
  email: [
    {
      name: 'smtp_host',
      label: 'SMTP host',
      kind: 'text',
      required: true,
      placeholder: 'smtp.example.com',
    },
    { name: 'smtp_port', label: 'SMTP port', kind: 'number', required: true, defaultValue: '587' },
    { name: 'smtp_username', label: 'SMTP username', kind: 'text', required: true },
    { name: 'smtp_password', label: 'SMTP password', kind: 'secret', required: true, secret: true },
    {
      name: 'from',
      label: 'From',
      kind: 'text',
      required: true,
      placeholder: 'gateway@example.com',
    },
    {
      name: 'to',
      label: 'To',
      kind: 'list',
      required: true,
      help: 'One address per line, or separated by commas.',
    },
    { name: 'cc', label: 'Cc', kind: 'list', help: 'Optional. One address per line.' },
    { name: 'bcc', label: 'Bcc', kind: 'list', help: 'Optional. One address per line.' },
    {
      name: 'use_tls',
      label: 'Use TLS',
      kind: 'switch',
      defaultValue: true,
      help: 'Implicit TLS, as on port 465.',
    },
    {
      name: 'use_starttls',
      label: 'Use STARTTLS',
      kind: 'switch',
      defaultValue: true,
      help: 'Upgrade a plain connection to TLS, as on port 587.',
    },
  ],
  slack: [
    {
      name: 'webhook_url',
      label: 'Incoming webhook URL',
      kind: 'secret',
      required: true,
      secret: true,
      placeholder: 'https://hooks.slack.com/services/...',
      help: 'The URL carries its own credential, so it is kept like a password.',
    },
    { name: 'bot_name', label: 'Sender name', kind: 'text', placeholder: 'Agent Gateway' },
    { name: 'icon_emoji', label: 'Sender icon', kind: 'text', placeholder: ':robot_face:' },
  ],
  webhook: [
    {
      name: 'url',
      label: 'URL',
      kind: 'text',
      required: true,
      placeholder: 'https://example.com/hooks/gateway',
    },
    {
      name: 'method',
      label: 'Method',
      kind: 'select',
      defaultValue: 'POST',
      options: ['POST', 'PUT', 'PATCH'].map(method => ({ value: method, label: method })),
    },
    {
      name: 'signing_secret',
      label: 'Signing secret',
      kind: 'secret',
      secret: true,
      help: 'Signs each request with X-Webhook-Signature-256 so the receiver can check it.',
    },
    {
      name: 'headers',
      label: 'Headers',
      kind: 'secret-json',
      secret: true,
      placeholder: '{"Authorization": "Bearer ..."}',
      help: 'Extra request headers as a JSON object; a value may be $SECRET:<secret_id> to use a stored secret. Kept like a password, since headers often carry credentials.',
    },
  ],
  stream: [
    {
      name: 'platform',
      label: 'Platform',
      kind: 'select',
      required: true,
      defaultValue: 'kafka',
      options: [
        { value: 'kafka', label: 'Apache Kafka' },
        { value: 'kinesis', label: 'Amazon Kinesis' },
        { value: 'pulsar', label: 'Apache Pulsar' },
        { value: 'redis', label: 'Redis Streams' },
      ],
    },
    { name: 'topic', label: 'Topic or stream', kind: 'text', required: true },
    {
      name: 'brokers',
      label: 'Brokers',
      kind: 'text',
      required: true,
      placeholder: 'broker-1:9092,broker-2:9092',
      shownWhen: platformIs('kafka', 'pulsar'),
    },
    {
      name: 'auth_type',
      label: 'Authentication',
      kind: 'select',
      defaultValue: 'none',
      options: [
        { value: 'none', label: 'None' },
        { value: 'sasl', label: 'SASL PLAIN' },
      ],
      shownWhen: platformIs('kafka'),
    },
    {
      name: 'sasl_username',
      label: 'SASL username',
      kind: 'text',
      required: true,
      shownWhen: values => platformIs('kafka')(values) && values.auth_type === 'sasl',
    },
    {
      name: 'sasl_password',
      label: 'SASL password',
      kind: 'secret',
      required: true,
      secret: true,
      shownWhen: values => platformIs('kafka')(values) && values.auth_type === 'sasl',
    },
    {
      name: 'region',
      label: 'AWS region',
      kind: 'text',
      required: true,
      placeholder: 'eu-west-1',
      help: 'Credentials come from the gateway host’s AWS credential chain.',
      shownWhen: platformIs('kinesis'),
    },
    {
      name: 'partition_key',
      label: 'Partition key',
      kind: 'text',
      shownWhen: platformIs('kinesis'),
    },
    {
      name: 'redis_url',
      label: 'Redis URL',
      kind: 'secret',
      required: true,
      secret: true,
      placeholder: 'redis://cache:6379',
      help: 'The URL may carry a password, so it is kept like one.',
      shownWhen: platformIs('redis'),
    },
  ],
};

export type SecretEdit = { state: 'keep' } | { state: 'set'; value: string } | { state: 'clear' };

export interface EndpointForm {
  values: Record<string, string | boolean>;
  secrets: Record<string, SecretEdit>;
  /** Secret fields the gateway holds a value for, a stored secret or a `$SECRET:` reference. */
  stored: string[];
}

/** The fields of `type` to show for these values. */
export function visibleFields(type: EndpointType, values: Record<string, unknown>): FieldSpec[] {
  return ENDPOINT_FIELDS[type].filter(field => !field.shownWhen || field.shownWhen(values));
}

/** The form for a new endpoint of `type`, or for a stored one. */
export function initialForm(type: EndpointType, endpoint?: Endpoint): EndpointForm {
  const configuration = endpoint?.configuration ?? {};
  const form: EndpointForm = { values: {}, secrets: {}, stored: [] };
  for (const field of ENDPOINT_FIELDS[type]) {
    const value = configuration[field.name];
    if (field.secret) {
      if (typeof value === 'string' || endpoint?.secrets.includes(field.name)) {
        form.stored.push(field.name);
      }
      form.secrets[field.name] =
        typeof value === 'string'
          ? { state: 'set', value }
          : endpoint?.secrets.includes(field.name)
            ? { state: 'keep' }
            : { state: 'set', value: '' };
    } else if (field.kind === 'switch') {
      form.values[field.name] = typeof value === 'boolean' ? value : field.defaultValue === true;
    } else if (field.kind === 'list') {
      form.values[field.name] = Array.isArray(value) ? value.join('\n') : '';
    } else {
      form.values[field.name] =
        value === undefined || value === null ? String(field.defaultValue ?? '') : String(value);
    }
  }
  return form;
}

const listItems = (text: string) =>
  text
    .split(/[\n,]/)
    .map(item => item.trim())
    .filter(Boolean);

/** Header names to string values, or null when `text` is not such an object. */
function parseHeaders(text: string): Record<string, string> | null {
  try {
    const parsed = JSON.parse(text);
    const isHeaderObject =
      parsed !== null &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      Object.values(parsed).every(value => typeof value === 'string');
    return isHeaderObject ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The configuration to send. Hidden and empty optional fields are left out; a kept secret is
 * left out so the gateway keeps it. When `updating`, a stored secret that is cleared or left
 * empty is sent as null, since one left out would be kept.
 */
export function buildConfiguration(
  type: EndpointType,
  form: EndpointForm,
  updating: boolean
): Record<string, unknown> {
  const configuration: Record<string, unknown> = {};
  const visible = visibleFields(type, form.values);
  if (updating) {
    // The gateway keeps a secret left out of an update, so one the form now hides (SASL
    // switched off, another stream platform) would stay stored unseen; clear it instead.
    for (const field of ENDPOINT_FIELDS[type]) {
      if (field.secret && !visible.includes(field) && form.stored.includes(field.name)) {
        configuration[field.name] = null;
      }
    }
  }
  for (const field of visible) {
    if (field.secret) {
      const edit = form.secrets[field.name];
      if (edit?.state === 'set' && edit.value.trim()) {
        const text = edit.value.trim();
        configuration[field.name] = field.kind === 'secret-json' ? parseHeaders(text) : text;
      } else if (
        updating &&
        (edit?.state === 'clear' || (edit?.state === 'set' && form.stored.includes(field.name)))
      ) {
        configuration[field.name] = null;
      }
      continue;
    }
    const value = form.values[field.name];
    if (field.kind === 'switch') {
      configuration[field.name] = value === true;
    } else if (field.kind === 'list') {
      const items = listItems(String(value ?? ''));
      if (items.length) configuration[field.name] = items;
    } else if (field.kind === 'number') {
      const text = String(value ?? '').trim();
      if (text) configuration[field.name] = Number(text);
    } else {
      const text = String(value ?? '').trim();
      if (text) configuration[field.name] = text;
    }
  }
  return configuration;
}

/** What keeps the form from being saved: required fields left empty, or malformed values. */
export function missingRequired(type: EndpointType, form: EndpointForm): string[] {
  const problems: string[] = [];
  for (const field of visibleFields(type, form.values)) {
    if (field.secret) {
      const edit = form.secrets[field.name];
      const present = edit?.state === 'keep' || (edit?.state === 'set' && edit.value.trim());
      if (field.required && !present) problems.push(field.label);
      if (
        field.kind === 'secret-json' &&
        edit?.state === 'set' &&
        edit.value.trim() &&
        !parseHeaders(edit.value)
      ) {
        problems.push(`${field.label} must be a JSON object of header names to values`);
      }
      continue;
    }
    if (!field.required || field.kind === 'switch') continue;
    const value = form.values[field.name];
    const empty =
      field.kind === 'list'
        ? listItems(String(value ?? '')).length === 0
        : !String(value ?? '').trim();
    if (empty) problems.push(field.label);
  }
  return problems;
}
