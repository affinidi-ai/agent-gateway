/** Integration category that receives every record written to the VP Audit Log. */
export const AUDIT_INTEGRATION_CATEGORY = 'audit';

/** Integration types with a JSON payload that can carry the full audit record. */
export const AUDIT_PAYLOAD_TYPES = ['stream', 'webhook'];

const variable = (name: string): string => `\${${name}}`;

/**
 * Payload for audit Stream and Webhook integrations: routing fields plus the
 * full signed record. AUDIT_RECORD as a whole value is embedded as JSON.
 */
const AUDIT_PAYLOAD_TEMPLATE: Readonly<Record<string, string>> = {
  appliance_id: variable('APPLIANCE_ID'),
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

/** Categories the caller may choose. The audit category requires `audit.view`. */
export function selectableCategories<T extends { enum_value: string }>(
  categories: T[],
  canViewAudit: boolean
): T[] {
  return canViewAudit
    ? categories
    : categories.filter(category => category.enum_value !== AUDIT_INTEGRATION_CATEGORY);
}
