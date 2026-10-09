/**
 * Starting content for each integration type, built from the runtime variables
 * the backend offers for a category, so a sample never references a variable
 * the category cannot substitute. Some Stream/Webhook payloads are curated instead:
 * the Governance Audit full-record template and the minimal user template.
 */
import { RuntimeVariable, RuntimeVariablesResponse } from './runtimeVariables';
import { AUDIT_INTEGRATION_CATEGORY, auditPayloadTemplate } from './auditIntegrations';

export interface IntegrationContents {
  webhook: Record<string, unknown>;
  stream: Record<string, unknown>;
  email: { subject: string; body: string; format?: 'plain' | 'html' };
  slack: { text: string; bot_name?: string; icon_emoji?: string; channel?: string };
}

export interface IntegrationSamples {
  webhook: Record<string, unknown>;
  stream: Record<string, unknown>;
  email: { subject: string; body: string };
  slack: { text: string };
}

const GENERAL_CATEGORY = 'general';

/** General variables summarising the event, in display order. */
const SUMMARY_VARIABLES = ['EVENT_TYPE', 'TIMESTAMP', 'SERVER_NAME', 'MESSAGE_ID'];

/** JSON keys for the summary variables in Stream/Webhook payloads. */
const SUMMARY_KEYS: Record<string, string> = {
  EVENT_TYPE: 'event_type',
  TIMESTAMP: 'timestamp',
  SERVER_NAME: 'server',
  MESSAGE_ID: 'message_id',
};

const placeholder = (name: string): string => `\${${name}}`;

/**
 * User events carry only what correlates them: the event, its time, and the user's id, role
 * and status. Names, emails and the state blocks stay on the appliance unless an operator
 * adds them.
 */
const userPayloadTemplate = (): Record<string, unknown> => ({
  event_type: placeholder('EVENT_TYPE'),
  timestamp: placeholder('TIMESTAMP'),
  user: {
    user_id: placeholder('USER_ID'),
    user_role: placeholder('USER_ROLE'),
    user_status: placeholder('USER_STATUS'),
  },
});

/** Stream/Webhook payloads curated per category instead of built from its variables. */
const CURATED_PAYLOADS: Record<string, () => Record<string, unknown>> = {
  [AUDIT_INTEGRATION_CATEGORY]: auditPayloadTemplate,
  user: userPayloadTemplate,
};

function categoryVariables(
  catalogue: RuntimeVariablesResponse,
  category: string
): { label: string; variables: RuntimeVariable[] } {
  const entry = catalogue.categories.find(c => c.category === category);
  return { label: entry?.label ?? category, variables: entry?.variables ?? [] };
}

export function buildIntegrationSamples(
  catalogue: RuntimeVariablesResponse,
  category: string
): IntegrationSamples {
  const general = categoryVariables(catalogue, GENERAL_CATEGORY).variables;
  const generalByName = new Map(general.map(v => [v.name, v]));
  const own =
    category === GENERAL_CATEGORY
      ? { label: '', variables: [] }
      : categoryVariables(catalogue, category);
  const specific = own.variables.filter(v => !generalByName.has(v.name));
  const summary = SUMMARY_VARIABLES.flatMap(name => generalByName.get(name) ?? []);
  const state = ['OLD_STATE', 'NEW_STATE'].flatMap(n => generalByName.get(n) ?? []);
  const has = (name: string) => generalByName.has(name);

  const payload: Record<string, unknown> = Object.fromEntries(
    summary.map(v => [SUMMARY_KEYS[v.name], placeholder(v.name)])
  );
  if (state.length > 0) {
    payload.state = Object.fromEntries(
      state.map(v => [v.name === 'OLD_STATE' ? 'old' : 'new', placeholder(v.name)])
    );
  }
  if (specific.length > 0) {
    payload[category] = Object.fromEntries(
      specific.map(v => [v.name.toLowerCase(), placeholder(v.name)])
    );
  }
  const json = CURATED_PAYLOADS[category]?.() ?? payload;

  const title = has('EVENT_TYPE') ? placeholder('EVENT_TYPE') : own.label || 'Notification';
  const subject = has('SERVER_NAME') ? `${title} on ${placeholder('SERVER_NAME')}` : title;

  const bodySections = [
    summary.map(v => `${v.label}: ${placeholder(v.name)}`),
    specific.length > 0
      ? [own.label, ...specific.map(v => `${v.label}: ${placeholder(v.name)}`)]
      : [],
    state.map(v => `${v.label}: ${placeholder(v.name)}`),
  ].filter(section => section.length > 0);

  const headline = [
    `*${title}*`,
    has('SERVER_NAME') ? ` on ${placeholder('SERVER_NAME')}` : '',
    has('TIMESTAMP') ? ` at ${placeholder('TIMESTAMP')}` : '',
  ].join('');

  return {
    webhook: json,
    stream: { ...json },
    email: { subject, body: bodySections.map(lines => lines.join('\n')).join('\n\n') },
    slack: {
      text: [headline, ...specific.map(v => `• *${v.label}:* ${placeholder(v.name)}`)].join('\n'),
    },
  };
}

/** JSON with object keys sorted, so a payload the gateway stored (keys sorted) still compares equal. */
function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
        )
      : v
  );
}

function sameJson(a: Record<string, unknown>, b: Record<string, unknown> | undefined): boolean {
  return b !== undefined && canonicalJson(a) === canonicalJson(b);
}

/**
 * The contents to replace when the category's samples change: a type whose
 * content is empty, or still equal to the previous category's sample, gets
 * the new sample. Anything the user wrote is kept.
 */
export function untouchedReplacements(
  contents: IntegrationContents,
  previous: IntegrationSamples | null,
  next: IntegrationSamples
): Partial<IntegrationContents> {
  const replacements: Partial<IntegrationContents> = {};

  (['webhook', 'stream'] as const).forEach(type => {
    const content = contents[type];
    if (Object.keys(content).length === 0 || sameJson(content, previous?.[type])) {
      if (!sameJson(content, next[type])) {
        replacements[type] = next[type];
      }
    }
  });

  const { email } = contents;
  const emailUntouched =
    (!email.subject && !email.body) ||
    (email.subject === previous?.email.subject && email.body === previous?.email.body);
  if (emailUntouched && (email.subject !== next.email.subject || email.body !== next.email.body)) {
    replacements.email = { ...email, ...next.email };
  }

  const { slack } = contents;
  const slackUntouched = !slack.text || slack.text === previous?.slack.text;
  if (slackUntouched && slack.text !== next.slack.text) {
    replacements.slack = { ...slack, text: next.slack.text };
  }

  return replacements;
}
