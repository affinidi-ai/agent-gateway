/* eslint-disable no-template-curly-in-string -- ${NAME} is the gateway's placeholder syntax */
import { IntegrationCatalog } from '../../../integrationsApi';
import {
  DEFAULT_ENVELOPE,
  TEMPLATE_FIELDS,
  templateVariables,
  unfilledVariables,
  variablesForEvents,
} from '../templateModel';

const variable = (name: string) => ({ name, label: name, description: `${name} value` });

const CATALOG: IntegrationCatalog = {
  events: [
    {
      id: 'gateway.created',
      name: 'Gateway Created',
      description: '',
      family: 'gateway',
      family_label: 'Gateway',
      variables: ['EVENT_NAME', 'EVENT_SUMMARY', 'GATEWAY_NAME'],
    },
    {
      id: 'user.login',
      name: 'User Login',
      description: '',
      family: 'user',
      family_label: 'User',
      variables: ['EVENT_NAME', 'EVENT_SUMMARY', 'USERNAME'],
    },
  ],
  variables: ['EVENT_NAME', 'EVENT_SUMMARY', 'GATEWAY_NAME', 'USERNAME', 'AUDIT_RECORD'].map(
    variable
  ),
  endpoint_types: [],
  variable_pattern: '\\$\\{([^:}]+)(?::[^}]+)?\\}',
};

describe('template fields', () => {
  test('email has a subject, a body and a format, defaulting to the event name and summary', () => {
    expect(TEMPLATE_FIELDS.email.map(field => [field.name, field.defaultText])).toEqual([
      ['subject', '${EVENT_NAME}'],
      ['body', '${EVENT_SUMMARY}'],
      ['format', undefined],
    ]);
  });

  test('slack has one text, defaulting to the bold event name and the summary', () => {
    expect(TEMPLATE_FIELDS.slack).toEqual([
      expect.objectContaining({ name: 'text', defaultText: '*${EVENT_NAME}*\n${EVENT_SUMMARY}' }),
    ]);
  });

  test('webhook and stream send a JSON payload, defaulting to the event envelope', () => {
    expect(TEMPLATE_FIELDS.webhook).toEqual([expect.objectContaining({ kind: 'json' })]);
    expect(TEMPLATE_FIELDS.stream).toEqual([expect.objectContaining({ kind: 'json' })]);
    expect(DEFAULT_ENVELOPE).toEqual({
      event_type: '${EVENT_TYPE}',
      event_name: '${EVENT_NAME}',
      timestamp: '${TIMESTAMP}',
      appliance_id: '${APPLIANCE_ID}',
      summary: '${EVENT_SUMMARY}',
      data: '${EVENT_DATA}',
    });
  });
});

describe('variablesForEvents', () => {
  test('gives the variables any of the events fills, in catalog order', () => {
    expect(variablesForEvents(CATALOG, ['user.login', 'gateway.created']).map(v => v.name)).toEqual(
      ['EVENT_NAME', 'EVENT_SUMMARY', 'GATEWAY_NAME', 'USERNAME']
    );
  });

  test('ignores events the catalog does not list', () => {
    expect(variablesForEvents(CATALOG, ['identity.created'])).toEqual([]);
  });
});

describe('templateVariables', () => {
  test('finds variables in every string of the template, once each', () => {
    expect(
      templateVariables({
        subject: '${EVENT_NAME}: ${GATEWAY_NAME}',
        nested: { lines: ['${USERNAME}', '${GATEWAY_NAME:Gateway}'] },
        count: 3,
      })
    ).toEqual(['EVENT_NAME', 'GATEWAY_NAME', 'USERNAME']);
  });
});

describe('unfilledVariables', () => {
  test('names the template variables no event of the set fills', () => {
    const available = variablesForEvents(CATALOG, ['gateway.created']);

    expect(
      unfilledVariables({ text: '${GATEWAY_NAME} by ${USERNAME} ${NOPE}' }, available)
    ).toEqual(['NOPE', 'USERNAME']);
  });
});
