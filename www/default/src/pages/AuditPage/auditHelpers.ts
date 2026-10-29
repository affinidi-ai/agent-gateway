import { parseVp } from '../../components/shared/VpViewer';
import {
  POLICY_CHANGE_EVENTS,
  type AuditEntry,
  type EmbeddedDecision,
  type PolicyChangeData,
  type PolicyChangeEvent,
  type PolicyDecisionData,
  type RequestRejectedData,
  type TraceTerminatedData,
  type TrustCheckData,
  type WorkloadIntent,
} from './types';

export const PAGE_LIMIT = 50;

export const CATEGORY_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'policy_decision', label: 'Policy Decisions' },
  { value: 'trust_check', label: 'Trust Checks' },
  { value: 'trace_terminated', label: 'Trace Terminated', lowFrequency: true },
  { value: 'vp_injected', label: 'VP Injected', lowFrequency: true },
  { value: 'token_injected', label: 'Token Injected', lowFrequency: true },
  { value: 'consent_granted', label: 'Consent Granted', lowFrequency: true },
  { value: 'policy_created', label: 'Policy Created', lowFrequency: true },
  { value: 'policy_updated', label: 'Policy Updated', lowFrequency: true },
  { value: 'policy_deleted', label: 'Policy Deleted', lowFrequency: true },
  { value: 'policy_attached', label: 'Policy Attached', lowFrequency: true },
  { value: 'policy_detached', label: 'Policy Detached', lowFrequency: true },
  { value: 'policy_attachment_changed', label: 'Policy Attachment Changed', lowFrequency: true },
  { value: 'policy_change_refused', label: 'Policy Change Refused', lowFrequency: true },
] as const;

const CATEGORY_BADGE: Record<string, string> = {
  policy_created: 'badge-success',
  policy_attached: 'badge-success',
  policy_updated: 'badge-info',
  policy_attachment_changed: 'badge-info',
  policy_deleted: 'badge-warning',
  policy_detached: 'badge-warning',
  policy_change_refused: 'badge-danger',
  policy_decision: 'badge-primary',
  trust_check: 'badge-info',
  trace_terminated: 'badge-warning',
  vp_injected: 'badge-success',
  token_injected: 'badge-success',
  token_refreshed: 'badge-info',
  consent_granted: 'badge-success',
  consent_required: 'badge-warning',
  refresh_failed: 'badge-danger',
  token_revoked: 'badge-danger',
};

export function categoryBadgeClass(name: string): string {
  return CATEGORY_BADGE[name] ?? 'badge-secondary';
}

/** Human label for a policy-decision flow marker (ingress vs egress vs fabric). */
export function flowLabel(flow?: string | null): string {
  switch (flow) {
    case 'access_point':
      return 'Access Point';
    case 'transit_point':
      return 'Transit Point';
    case 'fabric':
      return 'Fabric';
    default:
      return flow ?? '';
  }
}

/** Bootstrap badge class for a policy-decision flow marker. */
export function flowBadgeClass(flow?: string | null): string {
  switch (flow) {
    case 'transit_point':
      return 'text-bg-warning';
    case 'fabric':
      return 'text-bg-info';
    default:
      return 'text-bg-secondary';
  }
}

/** Font Awesome icon (FA5 solid) for a policy-decision flow marker. */
export function flowIcon(flow?: string | null): string {
  switch (flow) {
    case 'access_point':
      return 'fa-sign-in-alt';
    case 'transit_point':
      return 'fa-sign-out-alt';
    case 'fabric':
      return 'fa-network-wired';
    default:
      return 'fa-question-circle';
  }
}

/** Human label for a policy scope (the policy "type"). */
export function scopeLabel(scope?: string | null): string {
  switch (scope) {
    case 'gateway':
      return 'Gateway';
    case 'surface':
      return 'Surface';
    case 'mcp_tool':
      return 'MCP Tool';
    case 'response':
      return 'Response';
    default:
      return scope ?? '';
  }
}

/** Font Awesome icon (FA5 solid) for a policy scope. */
export function scopeIcon(scope?: string | null): string {
  switch (scope) {
    case 'gateway':
      return 'fa-shield-alt';
    case 'surface':
      return 'fa-exchange-alt';
    case 'mcp_tool':
      return 'fa-tools';
    case 'response':
      return 'fa-reply';
    default:
      return 'fa-scale-balanced';
  }
}

/** Bootstrap badge class for a policy scope. */
export function scopeBadgeClass(scope?: string | null): string {
  switch (scope) {
    case 'gateway':
      return 'text-bg-primary';
    case 'surface':
      return 'text-bg-info';
    case 'mcp_tool':
      return 'text-bg-dark';
    default:
      return 'text-bg-secondary';
  }
}

export function categoryLabel(name: string): string {
  switch (name) {
    case 'policy_decision':
      return 'Policy Decision';
    case 'trust_check':
      return 'Trust Check';
    case 'trace_terminated':
      return 'Trace Terminated';
    case 'vp_injected':
      return 'VP Injected';
    case 'token_injected':
      return 'Token Injected';
    case 'token_refreshed':
      return 'Token Refreshed';
    case 'consent_granted':
      return 'Consent Granted';
    case 'consent_required':
      return 'Consent Required';
    case 'refresh_failed':
      return 'Refresh Failed';
    case 'token_revoked':
      return 'Revoked';
    case 'user_tokens_revoked':
      return 'User Revoked';
    case 'token_not_found':
      return 'Not Found';
    case 'policy_created':
    case 'policy_updated':
    case 'policy_deleted':
    case 'policy_attached':
    case 'policy_detached':
    case 'policy_attachment_changed':
    case 'policy_change_refused':
      return CATEGORY_OPTIONS.find(option => option.value === name)?.label ?? name;
    default:
      return name.replace(/_/g, ' ');
  }
}

export function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

/** Returns the snake_case variant name, e.g. "policy_decision" */
export function eventTypeName(entry: AuditEntry): string {
  if (typeof entry.event === 'string') return entry.event;
  if (typeof entry.event === 'object' && entry.event !== null) {
    return Object.keys(entry.event)[0] ?? 'unknown';
  }
  return 'unknown';
}

/** Extracts the PolicyDecision payload if present, else null */
export function policyDecision(entry: AuditEntry): PolicyDecisionData | null {
  if (typeof entry.event === 'object' && entry.event !== null && 'policy_decision' in entry.event) {
    return (entry.event as { policy_decision: PolicyDecisionData }).policy_decision;
  }
  return null;
}

/** Extracts the TrustCheck payload if present, else null */
export function trustCheck(entry: AuditEntry): TrustCheckData | null {
  if (typeof entry.event === 'object' && entry.event !== null && 'trust_check' in entry.event) {
    return (entry.event as { trust_check: TrustCheckData }).trust_check;
  }
  return null;
}

/** Extracts the TraceTerminated payload if present, else null */
export function traceTerminated(entry: AuditEntry): TraceTerminatedData | null {
  if (
    typeof entry.event === 'object' &&
    entry.event !== null &&
    'trace_terminated' in entry.event
  ) {
    return (entry.event as { trace_terminated: TraceTerminatedData }).trace_terminated;
  }
  return null;
}

/** Extracts the RequestRejected payload if present, else null */
export function requestRejected(entry: AuditEntry): RequestRejectedData | null {
  if (
    typeof entry.event === 'object' &&
    entry.event !== null &&
    'request_rejected' in entry.event
  ) {
    return (entry.event as { request_rejected: RequestRejectedData }).request_rejected;
  }
  return null;
}

/** Extracts a policy change event's name and body if present, else null */
export function policyChange(
  entry: AuditEntry
): { name: PolicyChangeEvent; change: PolicyChangeData } | null {
  if (typeof entry.event !== 'object' || entry.event === null) return null;
  const event = entry.event as Partial<Record<PolicyChangeEvent, PolicyChangeData>>;
  for (const name of POLICY_CHANGE_EVENTS) {
    const change = event[name];
    if (change) {
      return {
        name,
        change: { ...change, surface_variant: change.surface_variant ?? change.variant },
      };
    }
  }
  return null;
}

/** Sentence-case name of a policy change, e.g. "Policy attached". */
export function policyChangeTitle(name: PolicyChangeEvent): string {
  const label = categoryLabel(name);
  return label.charAt(0) + label.slice(1).toLowerCase();
}

/** Where on its target a change applies, e.g. "inbound policy" or "MCP tool gate condition". */
export function slotLabel(change: PolicyChangeData): string | undefined {
  switch (change.slot) {
    case 'target':
      return change.target?.kind === 'gateway' ? 'gateway policy' : 'request policy';
    case 'inbound':
      return 'inbound policy';
    case 'response':
      return 'response policy';
    case 'transit':
      return 'transit policy';
    case 'transit_point':
      return `transit point ${change.scope === 'response' ? 'response' : 'request'} policy`;
    case 'mcp_tool':
      return 'MCP tool policy';
    case 'mcp_tool_gate':
      return 'MCP tool gate condition';
    case 'plane':
      return 'appliance-wide plane';
    default:
      return change.slot ?? undefined;
  }
}

/** An appliance-wide plane in words, e.g. "agent surface". */
export function planeLabel(plane?: string | null): string {
  return (plane ?? '').replace(/_/g, ' ');
}

/**
 * The surface, gateway or appliance-wide plane a change applies to, e.g. "surface Orders".
 * A refused assignment change names no plane, so it is "the appliance".
 */
export function targetLabel(change: PolicyChangeData): string | undefined {
  const target = change.target;
  if (!target) return undefined;
  if (target.kind === 'appliance') {
    return change.plane ? `the appliance-wide ${planeLabel(change.plane)} plane` : 'the appliance';
  }
  const name = target.name || target.id;
  return name ? `${target.kind} ${name}` : target.kind;
}

/** The dashboard page of a change's target, when it has one. */
export function targetHref(change: PolicyChangeData): string | undefined {
  const id = change.target?.id;
  if (!id) return undefined;
  if (change.target?.kind === 'surface') return `/surfaces/${encodeURIComponent(id)}`;
  if (change.target?.kind === 'gateway') return `/gateways/${encodeURIComponent(id)}`;
  return undefined;
}

const POLICY_FIELD_LABEL: Record<string, string> = {
  rego: 'Rego',
  sample_input: 'sample input',
};

/** The parts of a definition an update changed, e.g. "Rego, name". */
export function changedPartsLabel(changed?: string[]): string | undefined {
  if (!changed?.length) return undefined;
  return changed.map(part => POLICY_FIELD_LABEL[part] ?? part.replace(/_/g, ' ')).join(', ');
}

/** `enforced` or `monitor-only`. */
export function modeLabel(mode?: string | null): string | undefined {
  return mode ? mode.replace(/_/g, '-') : undefined;
}

/** Pull `workloadBinding.intent` out of an entry's signed VP, when present. */
export function extractIntent(entry: AuditEntry): WorkloadIntent | null {
  if (!entry.vp_jwt) return null;
  const { parsed } = parseVp(entry.vp_jwt);
  if (!parsed || typeof parsed !== 'object') return null;
  const root = parsed as Record<string, unknown>;
  const vcCandidate = root.verifiableCredential ?? root.vp ?? root;
  const vc = Array.isArray(vcCandidate)
    ? (vcCandidate[0] as Record<string, unknown>)
    : (vcCandidate as Record<string, unknown>);
  if (!vc || typeof vc !== 'object') return null;
  const subject = (vc as Record<string, unknown>).credentialSubject as
    | Record<string, unknown>
    | undefined;
  if (!subject) return null;
  const subj = Array.isArray(subject) ? (subject[0] as Record<string, unknown>) : subject;
  const wb = subj?.workloadBinding as Record<string, unknown> | undefined;
  const intent = wb?.intent as WorkloadIntent | undefined;
  return intent ?? null;
}

/** Extract the signed `workloadBinding.policyDecisions` array from an entry's VP, else null. */
export function extractEmbeddedDecisions(entry: AuditEntry): EmbeddedDecision[] | null {
  if (!entry.vp_jwt) return null;
  try {
    const { parsed } = parseVp(entry.vp_jwt);
    if (!parsed || typeof parsed !== 'object') return null;
    const root = parsed as Record<string, unknown>;
    const vcArr = (root.verifiableCredential ?? root.vp) as unknown[];
    const vcs = Array.isArray(vcArr) ? vcArr : [vcArr];
    for (const vc of vcs) {
      const subj = (vc as Record<string, unknown>)?.credentialSubject;
      const sub = Array.isArray(subj) ? subj[0] : subj;
      const wb = (sub as Record<string, unknown>)?.workloadBinding as Record<string, unknown>;
      const pd2 = wb?.policyDecisions;
      if (Array.isArray(pd2) && pd2.length > 0) return pd2 as EmbeddedDecision[];
    }
  } catch {
    return null;
  }
  return null;
}

/** The effective caller DID for an entry, across every identity mode. */
export function callerDidOf(entry: AuditEntry): string | null {
  const pd = policyDecision(entry);
  return pd?.caller_did ?? (entry.caller?.did as string | undefined) ?? null;
}

/** The surface id an entry refers to, from the policy decision or the entry itself. */
export function surfaceIdOf(entry: AuditEntry): string | null {
  const pd = policyDecision(entry);
  return pd?.surface_id ?? (entry.surface_id as string | undefined) ?? null;
}

/** Coerce an index-signature (`unknown`) field to a display string, or undefined when absent/blank. */
export function fieldStr(value: unknown): string | undefined {
  if (value === null || value === undefined || value === '') return undefined;
  return String(value);
}
