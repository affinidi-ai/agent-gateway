/* eslint-disable no-template-curly-in-string */
import { RuntimeVariablesResponse } from '../runtimeVariables';
import { auditPayloadTemplate } from '../auditIntegrations';
import {
  IntegrationContents,
  buildIntegrationSamples,
  untouchedReplacements,
} from '../integrationSamples';

const category = (name: string, label: string, variables: [string, string][]) => ({
  category: name,
  label,
  description: label,
  variables: variables.map(([variable, variableLabel]) => ({
    name: variable,
    label: variableLabel,
    description: variableLabel,
    example: variable,
    category: name,
  })),
});

const CATALOGUE: RuntimeVariablesResponse = {
  categories: [
    category('general', 'General', [
      ['OLD_STATE', 'Old State'],
      ['NEW_STATE', 'New State'],
      ['EVENT_TYPE', 'Event Type'],
      ['TIMESTAMP', 'Timestamp'],
      ['SERVER_NAME', 'Server Name'],
      ['SERVER_DOMAIN', 'Server Domain'],
      ['MESSAGE_ID', 'Message ID'],
    ]),
    category('connection_point', 'Connection Point', [
      ['CP_ID', 'Connection Point ID'],
      ['CP_NAME', 'Connection Point Name'],
      ['CP_DESCRIPTION', 'Connection Point Description'],
      ['GATEWAY', 'Gateway Name'],
      ['GATEWAY_ID', 'Gateway ID'],
    ]),
    category('user', 'User Management', [
      ['USER_ID', 'User ID'],
      ['USERNAME', 'Username'],
      ['USER_EMAIL', 'User Email'],
      ['USER_ROLE', 'User Role'],
      ['USER_STATUS', 'User Status'],
      ['EVENT_TYPE', 'Event Type'],
    ]),
    category('audit', 'Governance Audit', [
      ['AUDIT_RECORD', 'Audit Record'],
      ['AUDIT_CATEGORY', 'Audit Category'],
      ['AUDIT_TRACE_ID', 'Trace ID'],
      ['AUDIT_SURFACE_ID', 'Surface ID'],
      ['AUDIT_VP_JWT', 'Signed VP'],
    ]),
  ],
};

const CATEGORIES = ['general', 'connection_point', 'user', 'audit', 'pipe'];

function placeholders(value: unknown): string[] {
  return Array.from(JSON.stringify(value).matchAll(/\$\{([^:}]+)\}/g), match => match[1]);
}

function offeredVariables(name: string): Set<string> {
  return new Set(
    CATALOGUE.categories
      .filter(c => c.category === 'general' || c.category === name)
      .flatMap(c => c.variables.map(v => v.name))
  );
}

const EMPTY: IntegrationContents = {
  webhook: {},
  stream: {},
  email: { subject: '', body: '', format: 'plain' },
  slack: { text: '', bot_name: 'bot' },
};

describe('buildIntegrationSamples', () => {
  it.each(CATEGORIES)('uses only variables the %s category offers', name => {
    const samples = buildIntegrationSamples(CATALOGUE, name);
    const offered = offeredVariables(name);
    const used = placeholders(samples);

    expect(used.length).toBeGreaterThan(0);
    expect(used.filter(variable => !offered.has(variable))).toEqual([]);
  });

  it('builds a connection point payload from its own variables', () => {
    const { webhook } = buildIntegrationSamples(CATALOGUE, 'connection_point');
    expect(webhook).toEqual({
      event_type: '${EVENT_TYPE}',
      timestamp: '${TIMESTAMP}',
      server: '${SERVER_NAME}',
      message_id: '${MESSAGE_ID}',
      state: { old: '${OLD_STATE}', new: '${NEW_STATE}' },
      connection_point: {
        cp_id: '${CP_ID}',
        cp_name: '${CP_NAME}',
        cp_description: '${CP_DESCRIPTION}',
        gateway: '${GATEWAY}',
        gateway_id: '${GATEWAY_ID}',
      },
    });
    expect(Object.keys(webhook)).toEqual([
      'event_type',
      'timestamp',
      'server',
      'message_id',
      'state',
      'connection_point',
    ]);
  });

  it('lists general variables once even when a category repeats them', () => {
    const { email } = buildIntegrationSamples(CATALOGUE, 'user');
    expect(email.body.match(/\$\{EVENT_TYPE\}/g)).toHaveLength(1);
  });

  it('sends user events with only the fields that correlate them', () => {
    const { webhook, stream } = buildIntegrationSamples(CATALOGUE, 'user');
    const minimal = {
      event_type: '${EVENT_TYPE}',
      timestamp: '${TIMESTAMP}',
      user: { user_id: '${USER_ID}', user_role: '${USER_ROLE}', user_status: '${USER_STATUS}' },
    };

    expect(webhook).toEqual(minimal);
    expect(stream).toEqual(minimal);
  });

  it('writes readable Email and Slack messages with labelled fields', () => {
    const { email, slack } = buildIntegrationSamples(CATALOGUE, 'connection_point');
    expect(email.subject).toBe('${EVENT_TYPE} on ${SERVER_NAME}');
    expect(email.body).toContain('Connection Point\nConnection Point ID: ${CP_ID}');
    expect(email.body).toContain('Old State: ${OLD_STATE}');
    expect(slack.text).toBe(
      [
        '*${EVENT_TYPE}* on ${SERVER_NAME} at ${TIMESTAMP}',
        '• *Connection Point ID:* ${CP_ID}',
        '• *Connection Point Name:* ${CP_NAME}',
        '• *Connection Point Description:* ${CP_DESCRIPTION}',
        '• *Gateway Name:* ${GATEWAY}',
        '• *Gateway ID:* ${GATEWAY_ID}',
      ].join('\n')
    );
  });

  it('builds a surface payload from the SURFACE_* variables', () => {
    const catalogue: RuntimeVariablesResponse = {
      categories: [
        ...CATALOGUE.categories,
        category('surface', 'Surface', [
          ['SURFACE_ID', 'Surface ID'],
          ['SURFACE_NAME', 'Surface Name'],
        ]),
      ],
    };
    const { webhook, slack } = buildIntegrationSamples(catalogue, 'surface');
    expect(webhook.surface).toEqual({
      surface_id: '${SURFACE_ID}',
      surface_name: '${SURFACE_NAME}',
    });
    expect(slack.text).toContain('• *Surface ID:* ${SURFACE_ID}');
  });

  it('falls back to general variables for a category the backend has none for', () => {
    const { webhook } = buildIntegrationSamples(CATALOGUE, 'pipe');
    expect(Object.keys(webhook)).toEqual([
      'event_type',
      'timestamp',
      'server',
      'message_id',
      'state',
    ]);
  });

  it('keeps the full-record payload for audit Stream and Webhook integrations', () => {
    const samples = buildIntegrationSamples(CATALOGUE, 'audit');
    expect(samples.webhook).toEqual(auditPayloadTemplate());
    expect(samples.stream).toEqual(auditPayloadTemplate());
  });
});

describe('untouchedReplacements', () => {
  const general = buildIntegrationSamples(CATALOGUE, 'general');
  const user = buildIntegrationSamples(CATALOGUE, 'user');

  it('fills empty content with the samples, keeping other Email and Slack fields', () => {
    expect(untouchedReplacements(EMPTY, null, general)).toEqual({
      webhook: general.webhook,
      stream: general.stream,
      email: { ...general.email, format: 'plain' },
      slack: { text: general.slack.text, bot_name: 'bot' },
    });
  });

  it("replaces the previous category's untouched samples", () => {
    const contents: IntegrationContents = {
      webhook: general.webhook,
      stream: general.stream,
      email: { ...general.email },
      slack: { ...general.slack },
    };
    expect(untouchedReplacements(contents, general, user)).toEqual({
      webhook: user.webhook,
      stream: user.stream,
      email: user.email,
      slack: user.slack,
    });
  });

  it('keeps content the user edited', () => {
    const contents: IntegrationContents = {
      webhook: { custom: true },
      stream: { ...general.stream, extra: 'kept' },
      email: { ...general.email, subject: 'Edited' },
      slack: { text: 'Edited' },
    };
    expect(untouchedReplacements(contents, general, user)).toEqual({});
  });

  it('recognises a stored sample whose keys the gateway sorted', () => {
    const reordered = Object.fromEntries(
      Object.entries(general.webhook).sort(([a], [b]) => b.localeCompare(a))
    );
    const contents: IntegrationContents = { ...EMPTY, webhook: reordered };

    expect(untouchedReplacements(contents, general, user).webhook).toEqual(user.webhook);
  });

  it('keeps content that already matches the new samples', () => {
    const contents: IntegrationContents = {
      webhook: user.webhook,
      stream: user.stream,
      email: { ...user.email },
      slack: { ...user.slack },
    };
    expect(untouchedReplacements(contents, null, user)).toEqual({});
  });
});
