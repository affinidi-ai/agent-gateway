/* eslint-disable no-template-curly-in-string -- ${NAME} is the gateway's placeholder syntax */
import { CatalogVariable, EndpointType, IntegrationCatalog } from '../../integrationsApi';
import { extractAllTemplateVariables } from '../../utils/templateVariables';

/**
 * The template an integration sends, per endpoint type. A field the template leaves out takes
 * the gateway's default for the type, so an empty template still sends a complete message.
 */

export type TemplateFieldKind = 'text' | 'textarea' | 'select' | 'json';

export interface TemplateField {
  /** The content key; a `json` field is the whole content. */
  name: string;
  label: string;
  kind: TemplateFieldKind;
  /** What the gateway sends when the field is left out. */
  defaultText?: string;
  options?: { value: string; label: string }[];
  help?: string;
}

/** The webhook and stream payload of an empty template. */
export const DEFAULT_ENVELOPE = {
  event_type: '${EVENT_TYPE}',
  event_name: '${EVENT_NAME}',
  timestamp: '${TIMESTAMP}',
  appliance_id: '${APPLIANCE_ID}',
  summary: '${EVENT_SUMMARY}',
  data: '${EVENT_DATA}',
};

const PAYLOAD: TemplateField = {
  name: 'payload',
  label: 'Payload',
  kind: 'json',
  defaultText: JSON.stringify(DEFAULT_ENVELOPE, null, 2),
  help: 'A JSON object. A string that is exactly ${EVENT_DATA} or ${AUDIT_RECORD} is sent as JSON.',
};

export const TEMPLATE_FIELDS: Record<EndpointType, TemplateField[]> = {
  email: [
    { name: 'subject', label: 'Subject', kind: 'text', defaultText: '${EVENT_NAME}' },
    { name: 'body', label: 'Body', kind: 'textarea', defaultText: '${EVENT_SUMMARY}' },
    {
      name: 'format',
      label: 'Format',
      kind: 'select',
      options: [
        { value: '', label: 'Plain text' },
        { value: 'html', label: 'HTML' },
      ],
      help: 'In HTML, values are escaped so they cannot add markup.',
    },
  ],
  slack: [
    {
      name: 'text',
      label: 'Message',
      kind: 'textarea',
      defaultText: '*${EVENT_NAME}*\n${EVENT_SUMMARY}',
      help: 'Slack mrkdwn. Values are escaped so they cannot mention people or add links.',
    },
  ],
  webhook: [PAYLOAD],
  stream: [PAYLOAD],
};

/** The variables any of `events` fills, in catalog order. */
export function variablesForEvents(
  catalog: IntegrationCatalog,
  events: string[]
): CatalogVariable[] {
  const filled = new Set(
    catalog.events.filter(event => events.includes(event.id)).flatMap(event => event.variables)
  );
  return catalog.variables.filter(variable => filled.has(variable.name));
}

/** The variable names the template uses, in every string it holds, sorted. */
export function templateVariables(content: unknown): string[] {
  const names = new Set<string>();
  const visit = (value: unknown) => {
    if (typeof value === 'string') {
      extractAllTemplateVariables(value).forEach(variable => names.add(variable.name));
    } else if (value && typeof value === 'object') {
      Object.values(value).forEach(visit);
    }
  };
  visit(content);
  return Array.from(names).sort();
}

/** The template variables none of the available variables provides; they would send empty. */
export function unfilledVariables(content: unknown, available: CatalogVariable[]): string[] {
  const known = new Set(available.map(variable => variable.name));
  return templateVariables(content).filter(name => !known.has(name));
}
