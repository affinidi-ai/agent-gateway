/**
 * Workload Binding — form ⇆ API converters and validation.
 *
 * Shared by the `workload-binding` element definition, its config panel, and
 * the transit-point factory (which aggregates the per-Transit-Point
 * `transit.points[*].workload_binding` slice). Kept converter-only so the
 * wire shape lives in one place.
 *
 * Wire shape (Transit Point-scoped, matches the backend `WorkloadBindingConfig`):
 *   {
 *     "enabled": true,
 *     "caller_source": "transit_token" | "authorization_bearer_jwt" | "did",
 *     "caller_context_fields": ["sub", "email"],   // omitted when empty
 *     "chain_caller_credentials": false             // omitted when false
 *   }
 *
 * The legacy `agent_fields` / `user_fields` shape is intentionally NOT produced
 * here — Workload Binding is now Transit Point-scoped and caller-context driven.
 */

export type WorkloadBindingCallerSource = 'transit_token' | 'authorization_bearer_jwt' | 'did';

/** Panel/form state for a Transit Point's Workload Binding. */
export interface WorkloadBindingFormConfig {
  enabled: boolean;
  caller_source: WorkloadBindingCallerSource;
  /** Operator-configured allowlist of top-level caller claim names. */
  caller_context_fields: string[];
  /** Chain a caller-supplied VC/VP into the binding VP. */
  chain_caller_credentials: boolean;
}

/** Wire shape written to `transit.points[*].workload_binding`. */
export interface WorkloadBindingApi {
  enabled: boolean;
  caller_source: WorkloadBindingCallerSource;
  caller_context_fields?: string[];
  chain_caller_credentials?: boolean;
}

const CALLER_SOURCES: WorkloadBindingCallerSource[] = [
  'transit_token',
  'authorization_bearer_jwt',
  'did',
];

export function defaultWorkloadBindingConfig(): WorkloadBindingFormConfig {
  return {
    enabled: false,
    caller_source: 'transit_token',
    caller_context_fields: [],
    chain_caller_credentials: false,
  };
}

function normalizeCallerSource(value: unknown): WorkloadBindingCallerSource {
  return CALLER_SOURCES.includes(value as WorkloadBindingCallerSource)
    ? (value as WorkloadBindingCallerSource)
    : 'transit_token';
}

/** Hydrate panel state from the wire shape (or a null/missing value). */
export function workloadBindingApiToForm(api: unknown): WorkloadBindingFormConfig {
  if (!api || typeof api !== 'object') {
    return defaultWorkloadBindingConfig();
  }
  const raw = api as Record<string, unknown>;
  const fields = Array.isArray(raw.caller_context_fields)
    ? (raw.caller_context_fields as unknown[]).filter((f): f is string => typeof f === 'string')
    : [];
  return {
    enabled: raw.enabled === true,
    caller_source: normalizeCallerSource(raw.caller_source),
    caller_context_fields: fields,
    chain_caller_credentials: raw.chain_caller_credentials === true,
  };
}

/**
 * Serialize panel state to the wire shape. Returns `undefined` when the binding
 * is disabled so the owning Transit Point omits `workload_binding` entirely.
 * `caller_context_fields` is omitted when empty and `chain_caller_credentials`
 * when false, matching the backend's `skip_serializing_if` wire shape.
 */
export function workloadBindingFormToApi(
  config: WorkloadBindingFormConfig | null | undefined
): WorkloadBindingApi | undefined {
  if (!config || !config.enabled) {
    return undefined;
  }
  const fields = config.caller_context_fields.map(f => f.trim()).filter(f => f.length > 0);
  const api: WorkloadBindingApi = {
    enabled: true,
    caller_source: config.caller_source,
  };
  if (fields.length > 0) {
    api.caller_context_fields = fields;
  }
  if (config.chain_caller_credentials) {
    api.chain_caller_credentials = true;
  }
  return api;
}

export interface WorkloadBindingValidationError {
  field?: string;
  message: string;
}

/**
 * Validate the caller allowlist, mirroring the backend
 * `WorkloadBindingConfig::validate`: reject blank, duplicate, and nested-path
 * (`a.b`) claim names. Aliasing and masking are out of scope in v1.
 */
export function validateWorkloadBinding(
  config: WorkloadBindingFormConfig | null | undefined
): WorkloadBindingValidationError[] {
  if (!config) return [];
  const errors: WorkloadBindingValidationError[] = [];
  const seen = new Set<string>();
  for (const raw of config.caller_context_fields) {
    const name = raw.trim();
    if (name.length === 0) {
      errors.push({
        field: 'caller_context_fields',
        message: 'Caller field names cannot be blank',
      });
      continue;
    }
    if (name.includes('.')) {
      errors.push({
        field: 'caller_context_fields',
        message: `Caller field '${name}' uses nested path syntax; only top-level claim names are supported`,
      });
      continue;
    }
    if (seen.has(name)) {
      errors.push({ field: 'caller_context_fields', message: `Duplicate caller field '${name}'` });
      continue;
    }
    seen.add(name);
  }
  return errors;
}
