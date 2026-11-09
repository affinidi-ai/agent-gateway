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

  test('stream shows SASL only for Kafka with a SASL protocol, and no AWS keys', () => {
    const shown = (configuration: Record<string, unknown>) =>
      names(visibleFields('stream', configuration));
    const sasl = [
      'platform',
      'topic',
      'brokers',
      'security_protocol',
      'sasl_mechanism',
      'sasl_username',
      'sasl_password',
    ];

    expect(shown({ platform: 'kafka', security_protocol: 'sasl_ssl' })).toEqual(sasl);
    expect(shown({ platform: 'kafka', security_protocol: 'sasl_plaintext' })).toEqual(sasl);
    for (const security_protocol of ['plaintext', 'ssl']) {
      expect(shown({ platform: 'kafka', security_protocol })).toEqual([
        'platform',
        'topic',
        'brokers',
        'security_protocol',
      ]);
    }
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

  test('Kafka offers the protocols and mechanisms the gateway accepts', () => {
    const optionsOf = (name: string) =>
      ENDPOINT_FIELDS.stream
        .find(field => field.name === name)
        ?.options?.map(option => option.value);

    expect(optionsOf('security_protocol')).toEqual([
      'plaintext',
      'ssl',
      'sasl_plaintext',
      'sasl_ssl',
    ]);
    expect(optionsOf('sasl_mechanism')).toEqual(['PLAIN', 'SCRAM-SHA-256', 'SCRAM-SHA-512']);
  });
});

describe('Kafka security settings', () => {
  const kafka = (configuration: Record<string, unknown>) =>
    stored({
      type: 'stream',
      configuration: { platform: 'kafka', topic: 'events', brokers: 'b:9092', ...configuration },
      secrets: ['sasl_password'],
    });

  test('a new endpoint starts as plaintext with PLAIN ready for SASL', () => {
    expect(initialForm('stream').values).toMatchObject({
      security_protocol: 'plaintext',
      sasl_mechanism: 'PLAIN',
    });
  });

  test('a stored endpoint with auth_type sasl and no protocol reads as the gateway reads it', () => {
    expect(
      initialForm('stream', kafka({ auth_type: 'sasl', sasl_username: 'svc' })).values
    ).toMatchObject({ security_protocol: 'sasl_plaintext', sasl_mechanism: 'PLAIN' });
    expect(initialForm('stream', kafka({ auth_type: 'sasl' })).values).toMatchObject({
      security_protocol: 'plaintext',
    });
    expect(
      initialForm(
        'stream',
        kafka({ auth_type: 'sasl', sasl_username: 'svc', security_protocol: 'sasl_ssl' })
      ).values
    ).toMatchObject({ security_protocol: 'sasl_ssl' });
  });

  test('a legacy SASL endpoint is saved with the protocol and mechanism it used', () => {
    const form = initialForm('stream', kafka({ auth_type: 'sasl', sasl_username: 'svc' }));

    expect(buildConfiguration('stream', form, true)).toEqual({
      platform: 'kafka',
      topic: 'events',
      brokers: 'b:9092',
      security_protocol: 'sasl_plaintext',
      sasl_mechanism: 'PLAIN',
      sasl_username: 'svc',
    });
  });

  test('a stored endpoint shows and sends its own protocol and mechanism', () => {
    const form = initialForm(
      'stream',
      kafka({
        security_protocol: 'sasl_ssl',
        sasl_mechanism: 'SCRAM-SHA-512',
        sasl_username: 'svc',
      })
    );

    expect(buildConfiguration('stream', form, true)).toEqual({
      platform: 'kafka',
      topic: 'events',
      brokers: 'b:9092',
      security_protocol: 'sasl_ssl',
      sasl_mechanism: 'SCRAM-SHA-512',
      sasl_username: 'svc',
    });
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
          signing_secret: '$SECRET:hook-signing',
        },
        secrets: ['headers'],
      })
    );

    expect(form.values).toMatchObject({ url: 'https://ops.example.com/hook', method: 'PUT' });
    expect(form.secrets.headers).toEqual({ state: 'keep' });
    expect(form.secrets.signing_secret).toEqual({ state: 'set', value: '$SECRET:hook-signing' });
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

  test('a secret reference changed to none is sent as null', () => {
    const form = initialForm(
      'webhook',
      stored({
        type: 'webhook',
        configuration: {
          url: 'https://ops.example.com/hook',
          signing_secret: '$SECRET:hook-signing',
        },
      })
    );
    form.secrets.signing_secret = { state: 'set', value: '' };

    expect(buildConfiguration('webhook', form, true)).toEqual({
      url: 'https://ops.example.com/hook',
      method: 'POST',
      signing_secret: null,
    });
  });

  test('an optional stored secret replaced with nothing is sent as null', () => {
    const form = initialForm(
      'webhook',
      stored({
        type: 'webhook',
        configuration: { url: 'https://ops.example.com/hook' },
        secrets: ['signing_secret'],
      })
    );
    form.secrets.signing_secret = { state: 'set', value: '  ' };

    expect(buildConfiguration('webhook', form, true)).toMatchObject({ signing_secret: null });
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

describe('buildConfiguration for stored secrets the form now hides', () => {
  const kafka = (secrets: string[], configuration: Record<string, unknown> = {}) =>
    stored({
      type: 'stream',
      configuration: {
        platform: 'kafka',
        topic: 'events',
        brokers: 'b:9092',
        auth_type: 'sasl',
        sasl_username: 'svc',
        ...configuration,
      },
      secrets,
    });

  test('switching SASL off clears the stored SASL password', () => {
    const form = initialForm('stream', kafka(['sasl_password']));
    form.values.security_protocol = 'ssl';

    expect(buildConfiguration('stream', form, true)).toEqual({
      platform: 'kafka',
      topic: 'events',
      brokers: 'b:9092',
      security_protocol: 'ssl',
      sasl_password: null,
    });
  });

  test('leaving the Redis platform clears the stored Redis URL', () => {
    const form = initialForm(
      'stream',
      stored({
        type: 'stream',
        configuration: { platform: 'redis', topic: 'events' },
        secrets: ['redis_url'],
      })
    );
    form.values.platform = 'kinesis';
    form.values.region = 'eu-west-1';

    expect(buildConfiguration('stream', form, true)).toMatchObject({
      platform: 'kinesis',
      redis_url: null,
    });
  });

  test('a stored secret reference the form now hides is cleared too', () => {
    const form = initialForm('stream', kafka([], { sasl_password: '$SECRET:kafka-password' }));
    form.values.security_protocol = 'plaintext';

    expect(buildConfiguration('stream', form, true)).toMatchObject({ sasl_password: null });
  });

  test('a hidden secret that was never stored is not sent', () => {
    const form = initialForm('stream', kafka(['sasl_password']));

    const configuration = buildConfiguration('stream', form, true);

    expect(configuration).not.toHaveProperty('redis_url');
    expect(configuration).not.toHaveProperty('sasl_password');
  });

  test('a visible stored secret left alone is still left out, so the gateway keeps it', () => {
    const form = initialForm('stream', kafka(['sasl_password']));

    expect(buildConfiguration('stream', form, true)).not.toHaveProperty('sasl_password');
  });

  test('a new endpoint clears nothing', () => {
    const form = initialForm('stream');
    form.values.platform = 'redis';

    expect(Object.values(buildConfiguration('stream', form, false))).not.toContain(null);
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

  test.each([
    ['an array', '["not", "an object"]'],
    // The gateway resolves references inside header values only; a reference as the whole
    // field would resolve to a string, and no headers would be sent.
    ['a reference to a secret', '$SECRET:hook-headers'],
  ])('webhook headers must be a JSON object of strings, not %s', (_, headers) => {
    const form = initialForm('webhook');
    form.values.url = 'https://ops.example.com/hook';
    form.secrets.headers = { state: 'set', value: headers };

    expect(missingRequired('webhook', form)).toEqual([
      'Headers must be a JSON object of header names to values',
    ]);
  });

  test('webhook header values may reference secrets', () => {
    const form = initialForm('webhook');
    form.values.url = 'https://ops.example.com/hook';
    form.secrets.headers = { state: 'set', value: '{"Authorization": "$SECRET:hook-token"}' };

    expect(missingRequired('webhook', form)).toEqual([]);
    expect(buildConfiguration('webhook', form, false)).toMatchObject({
      headers: { Authorization: '$SECRET:hook-token' },
    });
  });
});
