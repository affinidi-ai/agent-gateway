/** Integration category that receives the audit events it selects. */
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

/**
 * The delivery limits of a Governance Audit integration as typed in the form:
 * `audit_max_attempts` and `audit_drop_after_secs`. An empty value means no limit.
 */
export interface AuditDeliveryLimits {
  maxAttempts: string;
  dropAfterSecs: string;
}

export const AUDIT_MAX_ATTEMPTS_LABEL = 'Give up on a record after N attempts';
export const AUDIT_DROP_AFTER_LABEL = 'Skip records older than N seconds';

const LIMIT_RULE = 'a whole number of 1 or more, or leave it empty.';

function isValidLimit(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === '') return true;
  const parsed = Number(trimmed);
  return /^\d+$/.test(trimmed) && Number.isSafeInteger(parsed) && parsed >= 1;
}

/** Why a typed limit is invalid, or null when it is empty or a whole number of 1 or more. */
export function auditLimitError(value: string): string | null {
  return isValidLimit(value) ? null : `Enter ${LIMIT_RULE}`;
}

/** The stored limits of an integration, empty where unset. */
export function auditDeliveryLimitsOf(integration: {
  audit_max_attempts?: number | null;
  audit_drop_after_secs?: number | null;
}): AuditDeliveryLimits {
  return {
    maxAttempts: integration.audit_max_attempts?.toString() ?? '',
    dropAfterSecs: integration.audit_drop_after_secs?.toString() ?? '',
  };
}

/** The first invalid limit, named by its field, or null when both are valid. */
export function auditDeliveryLimitsError(limits: AuditDeliveryLimits): string | null {
  const invalid = (
    [
      [AUDIT_MAX_ATTEMPTS_LABEL, limits.maxAttempts],
      [AUDIT_DROP_AFTER_LABEL, limits.dropAfterSecs],
    ] as const
  ).find(([, value]) => !isValidLimit(value));
  return invalid ? `${invalid[0]}: enter ${LIMIT_RULE}` : null;
}

/** A typed limit for the API: a number, or for an empty one null or nothing. */
function limitValue(value: string, clearEmpty: boolean): number | null | undefined {
  const trimmed = value.trim();
  if (trimmed !== '') return Number(trimmed);
  return clearEmpty ? null : undefined;
}

/**
 * The API fields for valid limits: each one set as a number, and each empty
 * one as null when `clearEmpty` (an edit, where null clears the stored limit)
 * or left out otherwise.
 */
export function auditDeliveryLimitsPayload(
  limits: AuditDeliveryLimits,
  clearEmpty: boolean
): { audit_max_attempts?: number | null; audit_drop_after_secs?: number | null } {
  const payload: { audit_max_attempts?: number | null; audit_drop_after_secs?: number | null } =
    {};
  const maxAttempts = limitValue(limits.maxAttempts, clearEmpty);
  if (maxAttempts !== undefined) payload.audit_max_attempts = maxAttempts;
  const dropAfterSecs = limitValue(limits.dropAfterSecs, clearEmpty);
  if (dropAfterSecs !== undefined) payload.audit_drop_after_secs = dropAfterSecs;
  return payload;
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
