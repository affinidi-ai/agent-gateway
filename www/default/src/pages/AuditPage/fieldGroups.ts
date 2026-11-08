import {
  callerDidOf,
  changedPartsLabel,
  fieldStr,
  flowLabel,
  modeLabel,
  planeLabel,
  policyChange,
  policyChangeTitle,
  requestRejected,
  scopeLabel,
  slotLabel,
  surfaceIdOf,
  targetHref,
  targetLabel,
  traceTerminated,
} from './auditHelpers';
import { actorLabel, trustErrorClause, type UserNameResolver } from './eventNarrative';
import { surfaceVariantLabel } from '../../utils/surfaceVariant';
import type {
  AuditEntry,
  PolicyChangeData,
  PolicyChangeEvent,
  PolicyDecisionData,
  TrustCheckData,
} from './types';

export interface FieldItem {
  term: string;
  value: string;
  /** Render the value in a monospace font (DIDs, hashes, paths). */
  mono?: boolean;
  /** Optional in-app link target for the value. */
  href?: string;
}

export interface FieldGroup {
  label: string;
  items: FieldItem[];
}

/**
 * Flattens an audit entry into ordered, grouped key/value rows for the "Details"
 * list. Deliberately omits fields the panel already shows elsewhere (timestamp,
 * event type, trace id, VP fingerprint) to avoid duplication. Pure and
 * order-stable so the list reads the same every render.
 */
export function fieldGroups(
  entry: AuditEntry,
  pd: PolicyDecisionData | null,
  tc: TrustCheckData | null,
  userName?: UserNameResolver
): FieldGroup[] {
  const caller = entry.caller;
  const surfaceId = surfaceIdOf(entry);
  const surfaceName = fieldStr(entry.channel_name) ?? surfaceId ?? undefined;
  const callerDid = callerDidOf(entry) ?? undefined;
  const providerId = fieldStr(entry.provider_id);
  const providerName = fieldStr(entry.provider_name);
  const scopes = Array.isArray(entry.scopes) ? (entry.scopes as string[]) : [];

  const add = (
    arr: FieldItem[],
    term: string,
    value?: string,
    extra?: Omit<FieldItem, 'term' | 'value'>
  ) => {
    if (value != null && value !== '') arr.push({ term, value, ...extra });
  };

  const identity: FieldItem[] = [];
  add(identity, 'Auth method', fieldStr(caller?.auth_method));
  add(identity, 'Caller DID', callerDid, { mono: true });
  if (entry.agent_did) add(identity, 'Agent DID', String(entry.agent_did), { mono: true });
  if (entry.agent_identity_did && entry.agent_identity_did !== entry.agent_did) {
    add(identity, 'Agent identity', String(entry.agent_identity_did), { mono: true });
  }
  add(identity, 'User hash', fieldStr(entry.user_identity_hash), { mono: true });
  add(identity, 'Issuer', fieldStr(caller?.iss), { mono: true });
  add(identity, 'Audience', fieldStr(caller?.aud), { mono: true });
  add(identity, 'Subject', fieldStr(caller?.sub), { mono: true });
  add(identity, 'Email', fieldStr(caller?.email ?? caller?.email_redacted));
  add(identity, 'Name', fieldStr(caller?.name ?? caller?.name_redacted));

  const change = policyChange(entry);
  if (change)
    return [{ label: 'Identity', items: identity }, ...changeGroups(entry, change, add, userName)];

  const routing: FieldItem[] = [];
  if (surfaceName) {
    routing.push({
      term: 'Agent surface',
      value: surfaceName,
      href: surfaceId ? `/surfaces/${encodeURIComponent(surfaceId)}` : undefined,
    });
  }
  add(routing, 'Variant', surfaceVariantLabel(fieldStr(entry.surface_variant)));
  add(routing, 'Target', fieldStr(entry.target_endpoint), { mono: true });
  add(routing, 'Protocol', fieldStr(entry.protocol));
  add(routing, 'MCP tool', fieldStr(entry.mcp_tool_name), { mono: true });
  add(routing, 'Inject as', fieldStr(entry.inject_as), { mono: true });
  routing.push({ term: 'Via fabric', value: entry.via_fabric ? 'Yes (G2G)' : 'No' });

  const credentials: FieldItem[] = [];
  if (providerName || providerId) {
    credentials.push({
      term: 'Provider',
      value: providerName ?? providerId!,
      href: providerId ? `/credential-providers/${encodeURIComponent(providerId)}` : undefined,
    });
  }
  add(credentials, 'Token ID', fieldStr(entry.token_id), { mono: true });
  if (scopes.length) add(credentials, 'Scopes', scopes.join(', '));

  const policy: FieldItem[] = [];
  if (pd) {
    add(policy, 'Policy', fieldStr(pd.policy_name) ?? fieldStr(pd.policy_id), { mono: true });
    add(policy, 'Policy definition', fieldStr(pd.policy_definition_id), { mono: true });
    add(
      policy,
      'Policy version',
      typeof pd.policy_version === 'number' ? `v${pd.policy_version}` : undefined
    );
    add(policy, 'Policy SHA', fieldStr(pd.policy_content_hash), { mono: true });
    add(policy, 'Scope', pd.scope === 'gateway' ? 'Gateway (all surfaces)' : scopeLabel(pd.scope));
    if (pd.flow) add(policy, 'Flow', flowLabel(pd.flow));
    add(policy, 'Decision', pd.decision);
    add(policy, 'Deny reason', fieldStr(pd.deny_reason));
    if (pd.http_method && pd.http_path) {
      add(policy, 'Request', `${pd.http_method} ${pd.http_path}`, { mono: true });
    }
  }
  if (tc) {
    add(policy, 'Trust leg', tc.leg);
    // `authority_id` / `entity_id` are omitted on the target-leg
    // "unavailable" paths (AGENT_CARD_UNAVAILABLE,
    // TRUST_REGISTRY_METADATA_UNAVAILABLE). `add()` already suppresses
    // blank values via `fieldStr`, but we route through it explicitly so
    // the two rows disappear entirely rather than showing an "n/a"
    // placeholder — matching the wire-shape "not applicable" semantics.
    add(policy, 'Authority', fieldStr(tc.authority_id), { mono: true });
    add(policy, 'Entity', fieldStr(tc.entity_id), { mono: true });
    policy.push({ term: 'Result', value: tc.ok ? 'Passed' : 'Failed' });
    if (!tc.ok) add(policy, 'Failure', trustErrorClause(tc.error_code, tc.leg));
  }

  // Trace-termination bridge: show the own → downstream mapping explicitly. The
  // raw `detail` (`downstream_trace_id=…`) is redundant with these fields, so it
  // is omitted from the Policy group below for this event type.
  const tt = traceTerminated(entry);
  const trace: FieldItem[] = [];
  if (tt) {
    add(trace, 'Own trace', tt.own_trace_id, { mono: true });
    add(trace, 'Downstream trace', tt.downstream_trace_id, { mono: true });
    add(trace, 'Flow', flowLabel(tt.flow));
  }

  if (!tt) add(policy, 'Detail', fieldStr(entry.detail));

  // `http_status` is absent on a Fabric refusal, and `rpc_error_code` present only when the
  // caller was answered with a JSON-RPC error; each row shows only when recorded.
  const rejected = requestRejected(entry);
  const refusal: FieldItem[] = [];
  if (rejected) {
    add(refusal, 'Stage', fieldStr(rejected.stage));
    add(refusal, 'Reason', fieldStr(rejected.reason)?.replace(/_/g, ' '));
    add(refusal, 'HTTP status', fieldStr(rejected.http_status));
    add(refusal, 'JSON-RPC error', fieldStr(rejected.rpc_error_code));
    add(refusal, 'Requested variant', fieldStr(rejected.requested_variant), { mono: true });
  }

  return [
    { label: 'Identity', items: identity },
    { label: 'Surface & routing', items: routing },
    { label: 'Credentials', items: credentials },
    { label: 'Trace', items: trace },
    { label: 'Policy', items: policy },
    { label: 'Refusal', items: refusal },
  ];
}

type AddField = (
  arr: FieldItem[],
  term: string,
  value?: string,
  extra?: Omit<FieldItem, 'term' | 'value'>
) => void;

const SOURCE_LABEL: Record<string, string> = {
  definition_deleted: 'Definition deleted',
  ownership: 'Owner reassigned',
};

/** "before → after" when a value changed, else the current value. */
function transition(before?: string, after?: string): string | undefined {
  return before && after && before !== after ? `${before} → ${after}` : after;
}

const yesNo = (value?: boolean | null) =>
  typeof value === 'boolean' ? (value ? 'Yes' : 'No') : undefined;

const version = (value?: number | null) => (typeof value === 'number' ? `v${value}` : undefined);

/** The Change, Policy, Where and Refusal groups of a policy change record. */
function changeGroups(
  entry: AuditEntry,
  { name, change }: { name: PolicyChangeEvent; change: PolicyChangeData },
  add: AddField,
  userName?: UserNameResolver
): FieldGroup[] {
  const what: FieldItem[] = [];
  add(what, 'Action', policyChangeTitle(name));
  add(what, 'Actor', actorLabel(change.actor, userName));
  add(what, 'Source', SOURCE_LABEL[change.source]);
  add(what, 'Request', fieldStr(entry.request_id), { mono: true });

  const policy: FieldItem[] = [];
  const policyTab =
    change.policy_type === 'gateway' || change.policy_type === 'agent_surface'
      ? `/policies?tab=${change.policy_type}`
      : undefined;
  add(policy, 'Policy', fieldStr(change.policy_name) ?? fieldStr(change.policy_definition_id), {
    ...(policyTab ? { href: policyTab } : {}),
  });
  add(policy, 'Policy definition', fieldStr(change.policy_definition_id), { mono: true });
  add(
    policy,
    'Policy version',
    transition(version(change.previous_policy_version), version(change.policy_version))
  );
  add(policy, 'Policy SHA', fieldStr(change.policy_content_hash), { mono: true });
  add(policy, 'Previous SHA', fieldStr(change.previous_policy_content_hash), { mono: true });
  add(policy, 'Changed', changedPartsLabel(change.changed));

  const where: FieldItem[] = [];
  const target = targetLabel(change);
  const href = targetHref(change);
  add(where, 'Target', target, href ? { href } : {});
  add(where, 'Slot', slotLabel(change));
  add(where, 'Scope', change.scope ? scopeLabel(change.scope) : undefined);
  add(where, 'Variant', surfaceVariantLabel(fieldStr(change.surface_variant)));
  add(where, 'Transit point', fieldStr(change.transit_point), { mono: true });
  add(where, 'MCP tool', fieldStr(change.mcp_tool_name), { mono: true });
  add(where, 'Gate', fieldStr(change.gate));
  add(where, 'Plane', change.plane ? planeLabel(change.plane) : undefined);
  add(where, 'Mode', transition(modeLabel(change.previous_mode), modeLabel(change.mode)));
  add(where, 'Enabled', transition(yesNo(change.previous_enabled), yesNo(change.enabled)));

  const refusal: FieldItem[] = [];
  if (name === 'policy_change_refused') {
    add(refusal, 'Attempted', change.action ? policyChangeTitle(change.action) : undefined);
    add(refusal, 'Status', change.status != null ? String(change.status) : undefined);
    add(refusal, 'Reason', fieldStr(change.reason));
  }

  return [
    { label: 'Change', items: what },
    { label: 'Policy', items: policy },
    { label: 'Where', items: where },
    { label: 'Refusal', items: refusal },
  ];
}
