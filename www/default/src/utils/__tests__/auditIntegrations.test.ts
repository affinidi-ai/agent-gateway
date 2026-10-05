import { auditPayloadTemplate, selectableCategories, selectableTypes } from '../auditIntegrations';

const categories = [{ enum_value: 'general' }, { enum_value: 'audit' }, { enum_value: 'gateway' }];
const types = ['email', 'slack', 'webhook', 'stream'].map(enum_value => ({ enum_value }));
const values = (items: { enum_value: string }[]) => items.map(item => item.enum_value);

describe('selectableCategories', () => {
  it('offers the audit category only to callers with audit.view', () => {
    expect(values(selectableCategories(categories, true))).toEqual(['general', 'audit', 'gateway']);
    expect(values(selectableCategories(categories, false))).toEqual(['general', 'gateway']);
  });

  it('offers the audit category only to Stream and Webhook integrations', () => {
    expect(values(selectableCategories(categories, true, 'stream'))).toContain('audit');
    expect(values(selectableCategories(categories, true, 'webhook'))).toContain('audit');
    expect(values(selectableCategories(categories, true, 'email'))).toEqual(['general', 'gateway']);
    expect(values(selectableCategories(categories, true, 'slack'))).toEqual(['general', 'gateway']);
  });
});

describe('selectableTypes', () => {
  it('limits the audit category to Stream and Webhook and leaves others alone', () => {
    expect(values(selectableTypes(types, 'audit'))).toEqual(['webhook', 'stream']);
    expect(values(selectableTypes(types, 'general'))).toEqual([
      'email',
      'slack',
      'webhook',
      'stream',
    ]);
  });
});

describe('auditPayloadTemplate', () => {
  it('embeds the full record alongside the routing fields', () => {
    expect(auditPayloadTemplate()).toEqual({
      event_type: '${EVENT_TYPE}', // eslint-disable-line no-template-curly-in-string
      category: '${AUDIT_CATEGORY}', // eslint-disable-line no-template-curly-in-string
      timestamp: '${TIMESTAMP}', // eslint-disable-line no-template-curly-in-string
      trace_id: '${AUDIT_TRACE_ID}', // eslint-disable-line no-template-curly-in-string
      surface_id: '${AUDIT_SURFACE_ID}', // eslint-disable-line no-template-curly-in-string
      record: '${AUDIT_RECORD}', // eslint-disable-line no-template-curly-in-string
    });
  });

  it('returns a fresh copy each time', () => {
    const first = auditPayloadTemplate();
    first.record = 'edited';
    expect(auditPayloadTemplate().record).not.toBe('edited');
  });
});
