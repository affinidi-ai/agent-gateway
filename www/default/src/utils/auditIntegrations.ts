/** Integration category that receives every record written to the VP Audit Log. */
export const AUDIT_INTEGRATION_CATEGORY = 'audit';

/**
 * Integration types an audit integration may use. Every VP Audit Log write is
 * a delivery, more than Email or Slack can carry; the gateway enforces the
 * same list.
 */
export const AUDIT_INTEGRATION_TYPES = ['stream', 'webhook'];

const variable = (name: string): string => `\${${name}}`;

/**
 * Payload for audit Stream and Webhook integrations: routing fields plus the
 * full signed record. AUDIT_RECORD as a whole value is embedded as JSON.
 */
const AUDIT_PAYLOAD_TEMPLATE: Readonly<Record<string, string>> = {
  event_type: variable('EVENT_TYPE'),
  category: variable('AUDIT_CATEGORY'),
  timestamp: variable('TIMESTAMP'),
  trace_id: variable('AUDIT_TRACE_ID'),
  surface_id: variable('AUDIT_SURFACE_ID'),
  record: variable('AUDIT_RECORD'),
};

export function auditPayloadTemplate(): Record<string, string> {
  return { ...AUDIT_PAYLOAD_TEMPLATE };
}

/**
 * Categories the caller may choose. The audit category requires `audit.view`
 * and, when the integration's type is fixed, a Stream or Webhook type.
 */
export function selectableCategories<T extends { enum_value: string }>(
  categories: T[],
  canViewAudit: boolean,
  integrationType?: string
): T[] {
  const auditAllowed =
    canViewAudit &&
    (integrationType === undefined || AUDIT_INTEGRATION_TYPES.includes(integrationType));
  return auditAllowed
    ? categories
    : categories.filter(category => category.enum_value !== AUDIT_INTEGRATION_CATEGORY);
}

/** Integration types offered for a category: Stream and Webhook only for audit. */
export function selectableTypes<T extends { enum_value: string }>(
  types: T[],
  category: string
): T[] {
  return category === AUDIT_INTEGRATION_CATEGORY
    ? types.filter(type => AUDIT_INTEGRATION_TYPES.includes(type.enum_value))
    : types;
}
