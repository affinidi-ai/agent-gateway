import {
  buildConfiguration,
  ENDPOINT_FIELDS,
  initialForm,
  missingRequired,
  visibleFields,
} from '../endpointFields';
import { Endpoint } from '../../../integrationsApi';

function stored(overrides: Partial<Endpoint>): Endpoint {
  return {
    id: 'e1',
    name: 'Endpoint',
    description: '',
    type: 'email',
    configuration: {},
    status: 'active',
    secrets: [],
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
    ...overrides,
  };
}

const names = (fields: { name: string }[]) => fields.map(field => field.name);

describe('fields per endpoint type', () => {
  test('mark exactly the secret fields the gateway keeps write-only', () => {
    const secretsOf = (type: keyof typeof ENDPOINT_FIELDS) =>
      ENDPOINT_FIELDS[type].filter(field => field.secret).map(field => field.name);

    expect(secretsOf('email')).toEqual(['smtp_password']);
    expect(secretsOf('slack')).toEqual(['webhook_url']);
    expect(secretsOf('webhook')).toEqual(['signing_secret', 'headers']);
    expect(secretsOf('stream')).toEqual(['sasl_password', 'redis_url']);
  });

  test('email offers cc and bcc', () => {
    expect(names(ENDPOINT_FIELDS.email)).toEqual(
      expect.arrayContaining(['to', 'cc', 'bcc', 'use_tls', 'use_starttls'])
    );
  });

  test('slack sets the sender name and icon but no channel', () => {
    expect(names(ENDPOINT_FIELDS.slack)).toEqual(['webhook_url', 'bot_name', 'icon_emoji']);
  });

  test('stream shows SASL only for Kafka with SASL, and no AWS keys', () => {
    const shown = (configuration: Record<string, unknown>) =>
      names(visibleFields('stream', configuration));

    expect(shown({ platform: 'kafka', auth_type: 'sasl' })).toEqual([
      'platform',
      'topic',
      'brokers',
      'auth_type',
      'sasl_username',
      'sasl_password',
    ]);
    expect(shown({ platform: 'kafka', auth_type: 'none' })).toEqual([
      'platform',
      'topic',
      'brokers',
      'auth_type',
    ]);
    expect(shown({ platform: 'pulsar' })).toEqual(['platform', 'topic', 'brokers']);
    expect(shown({ platform: 'kinesis' })).toEqual([
      'platform',
      'topic',
      'region',
      'partition_key',
    ]);
    expect(shown({ platform: 'redis' })).toEqual(['platform', 'topic', 'redis_url']);
    expect(names(ENDPOINT_FIELDS.stream)).not.toEqual(
      expect.arrayContaining(['access_key', 'secret_key', 'auth_token'])
    );
  });
});

describe('initialForm', () => {
  test('a new endpoint starts from each field default', () => {
    const form = initialForm('email');

    expect(form.values).toMatchObject({ smtp_port: '587', use_tls: true, to: '', cc: '' });
    expect(form.secrets.smtp_password).toEqual({ state: 'set', value: '' });
  });

  test('a stored endpoint keeps its stored secrets and shows its secret references', () => {
    const form = initialForm(
      'webhook',
      stored({
        type: 'webhook',
        configuration: {
          url: 'https://ops.example.com/hook',
          method: 'PUT',
          headers: '$SECRET:hook-headers',
        },
        secrets: ['signing_secret'],
      })
    );

    expect(form.values).toMatchObject({ url: 'https://ops.example.com/hook', method: 'PUT' });
    expect(form.secrets.signing_secret).toEqual({ state: 'keep' });
    expect(form.secrets.headers).toEqual({ state: 'set', value: '$SECRET:hook-headers' });
  });

  test('lists are shown one per line', () => {
    const form = initialForm(
      'email',
      stored({ configuration: { to: ['a@example.com', 'b@example.com'], smtp_port: 25 } })
    );

    expect(form.values.to).toBe('a@example.com\nb@example.com');
    expect(form.values.smtp_port).toBe('25');
  });
});

describe('buildConfiguration', () => {
  test('converts numbers, lists and switches and leaves out empty optional fields', () => {
    const form = initialForm('email');
    form.values = {
      ...form.values,
      smtp_host: 'smtp.example.com',
      smtp_port: '465',
      smtp_username: 'mailer',
      from: 'gateway@example.com',
      to: 'a@example.com, b@example.com\nc@example.com',
      cc: '',
      bcc: 'audit@example.com',
      use_tls: false,
    };
    form.secrets.smtp_password = { state: 'set', value: 'hunter2' };

    expect(buildConfiguration('email', form, false)).toEqual({
      smtp_host: 'smtp.example.com',
      smtp_port: 465,
      smtp_username: 'mailer',
      smtp_password: 'hunter2',
      from: 'gateway@example.com',
      to: ['a@example.com', 'b@example.com', 'c@example.com'],
      bcc: ['audit@example.com'],
      use_tls: false,
      use_starttls: true,
    });
  });

  test('a kept secret is left out, a cleared one is sent as null', () => {
    const form = initialForm(
      'webhook',
      stored({
        type: 'webhook',
        configuration: { url: 'https://ops.example.com/hook' },
        secrets: ['signing_secret', 'headers'],
      })
    );
    form.secrets.headers = { state: 'clear' };

    expect(buildConfiguration('webhook', form, true)).toEqual({
      url: 'https://ops.example.com/hook',
      method: 'POST',
      headers: null,
    });
  });

  test('webhook headers are sent as an object', () => {
    const form = initialForm('webhook');
    form.values.url = 'https://ops.example.com/hook';
    form.secrets.headers = { state: 'set', value: '{"Authorization": "Bearer x"}' };

    expect(buildConfiguration('webhook', form, false)).toMatchObject({
      headers: { Authorization: 'Bearer x' },
    });
  });

  test('hidden fields are not sent', () => {
    const form = initialForm('stream');
    form.values = { ...form.values, platform: 'redis', topic: 'events', brokers: 'b:9092' };
    form.secrets.redis_url = { state: 'set', value: 'redis://cache:6379' };
    form.secrets.sasl_password = { state: 'set', value: 'unused' };

    expect(buildConfiguration('stream', form, false)).toEqual({
      platform: 'redis',
      topic: 'events',
      redis_url: 'redis://cache:6379',
    });
  });
});

describe('missingRequired', () => {
  test('names required fields left empty, and required secrets neither set nor stored', () => {
    const form = initialForm('email');

    expect(missingRequired('email', form)).toEqual([
      'SMTP host',
      'SMTP username',
      'SMTP password',
      'From',
      'To',
    ]);
  });

  test('a stored required secret counts as present', () => {
    const form = initialForm(
      'slack',
      stored({ type: 'slack', configuration: {}, secrets: ['webhook_url'] })
    );

    expect(missingRequired('slack', form)).toEqual([]);
  });

  test('webhook headers must be a JSON object of strings', () => {
    const form = initialForm('webhook');
    form.values.url = 'https://ops.example.com/hook';
    form.secrets.headers = { state: 'set', value: '["not", "an object"]' };

    expect(missingRequired('webhook', form)).toEqual([
      'Headers must be a JSON object of header names to values',
    ]);
  });
});
