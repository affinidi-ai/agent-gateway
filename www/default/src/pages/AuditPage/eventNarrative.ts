import {
  callerDidOf,
  categoryLabel,
  changedPartsLabel,
  eventTypeName,
  flowLabel,
  modeLabel,
  policyChange,
  policyChangeTitle,
  policyDecision,
  scopeLabel,
  slotLabel,
  surfaceIdOf,
  targetLabel,
  traceTerminated,
  trustCheck,
} from './auditHelpers';
import type { AuditEntry, PolicyChangeActor, PolicyChangeData, PolicyChangeEvent } from './types';

export type EventTone = 'allow' | 'deny' | 'warn' | 'neutral';

/** A user's name for their id, when it is known. */
export type UserNameResolver = (userId: string) => string | undefined;

export interface EventNarrative {
  title: string;
  tone: EventTone;
  summary: string;
  detail?: string;
}

const DENY_EVENTS = new Set([
  'refresh_failed',
  'token_revoked',
  'user_tokens_revoked',
  'token_not_found',
]);

const ALLOW_EVENTS = new Set([
  'vp_injected',
  'token_injected',
  'token_refreshed',
  'consent_granted',
]);

/** Human-readable clause explaining why a trust check failed, keyed by TRQP error code. */
const TRUST_ERROR_LABEL: Record<string, string> = {
  TRUST_REGISTRY_UNREACHABLE: 'the trust registry was unreachable',
  QUERY_FAILED: 'the registry query failed',
  QUERY_TIMEOUT: 'the registry query timed out',
  TRUST_REGISTRY_PROBLEM_REPORT: 'the registry returned a problem report',
  TRUST_REGISTRY_PARSE_ERROR: 'the registry response could not be parsed',
  TEMPLATE_RESOLUTION_FAILED: 'a query template could not be resolved',
  AGENT_CARD_UNAVAILABLE: "the target's agent card was unavailable",
  IDENTITY_VP_VERIFICATION_FAILED: "the target's agent identity credential could not be verified",
  TARGET_AGENT_IDENTITY_UNAVAILABLE: "the target's agent card carries no agent identity credential",
};

export function trustErrorClause(code?: string | null, leg?: string | null): string | undefined {
  if (!code) return undefined;
  if (code === 'TRUST_REGISTRY_METADATA_UNAVAILABLE') {
    return leg === 'caller'
      ? "the caller's request payload is missing the trust registry metadata extension"
      : "the target's agent card is missing the trust registry metadata extension";
  }
  return TRUST_ERROR_LABEL[code] ?? code;
}

function isAllowDecision(decision?: string | null): boolean {
  return decision === 'allow' || decision === 'Allow';
}

/** Semantic tone for an entry — drives the list-item title colour and accent. */
export function eventTone(entry: AuditEntry): EventTone {
  const change = policyChange(entry);
  if (change) return describePolicyChange(change.name, change.change).tone;
  const pd = policyDecision(entry);
  if (pd) return isAllowDecision(pd.decision) ? 'allow' : 'deny';
  const tc = trustCheck(entry);
  if (tc) return tc.ok ? 'allow' : 'deny';
  const name = eventTypeName(entry);
  if (name === 'consent_required') return 'warn';
  if (DENY_EVENTS.has(name)) return 'deny';
  if (ALLOW_EVENTS.has(name)) return 'allow';
  return 'neutral';
}

/** Who made a policy change, e.g. "user alice" or "access token tok-1 of alice". */
export function actorLabel(actor: PolicyChangeActor, userName?: UserNameResolver): string {
  const user = (id: string) => userName?.(id) ?? `user ${id}`;
  switch (actor.kind) {
    case 'user':
      return `user ${userName?.(actor.id) ?? actor.id}`;
    case 'pat':
      return actor.user_id
        ? `access token ${actor.id} of ${user(actor.user_id)}`
        : `access token ${actor.id}`;
    default:
      return 'the gateway';
  }
}

const REFUSED_VERB: Record<PolicyChangeEvent, string> = {
  policy_created: 'Creating',
  policy_updated: 'Updating',
  policy_deleted: 'Deleting',
  policy_attached: 'Attaching',
  policy_detached: 'Detaching',
  policy_attachment_changed: 'Changing',
  policy_change_refused: 'Changing',
};

const SOURCE_CLAUSE: Record<string, string> = {
  definition_deleted: ', because the policy definition was deleted',
  ownership: ', by reassigning its owner',
};

function describePolicyChange(
  name: PolicyChangeEvent,
  change: PolicyChangeData,
  userName?: UserNameResolver
): EventNarrative {
  const policy = change.policy_name || change.policy_definition_id;
  const quoted = policy ? `“${policy}”` : 'a policy';
  const versioned =
    typeof change.policy_version === 'number' ? `${quoted} v${change.policy_version}` : quoted;
  const target = targetLabel(change);
  const slot = slotLabel(change);
  const variant = change.variant ? ` (variant ${change.variant})` : '';
  const where =
    change.target?.kind === 'surface' && slot
      ? `${target} as ${surfaceSlotPhrase(change, slot)}${variant}`
      : `${target ?? 'its target'}${variant}`;
  const detail = `By ${actorLabel(change.actor, userName)}${SOURCE_CLAUSE[change.source] ?? ''}.`;
  const tone: EventTone =
    name === 'policy_change_refused'
      ? 'deny'
      : name === 'policy_deleted' || name === 'policy_detached'
        ? 'warn'
        : 'neutral';
  const narrative = (summary: string) => ({
    title: policyChangeTitle(name),
    tone,
    summary,
    detail,
  });

  switch (name) {
    case 'policy_created':
      return narrative(`Policy definition ${versioned} was created.`);
    case 'policy_deleted':
      return narrative(`Policy definition ${quoted} was deleted.`);
    case 'policy_updated': {
      const on = !change.policy_definition_id && target ? ` on ${target}` : '';
      const versions =
        typeof change.previous_policy_version === 'number' &&
        typeof change.policy_version === 'number' &&
        change.previous_policy_version !== change.policy_version
          ? ` from v${change.previous_policy_version} to v${change.policy_version}`
          : '';
      const parts = changedPartsLabel(change.changed);
      return narrative(`${quoted}${on} changed${versions}${parts ? `: ${parts}` : ''}.`);
    }
    case 'policy_attached':
      return narrative(`${versioned} was added to ${where}.`);
    case 'policy_detached':
      return narrative(`${versioned} was removed from ${where}.`);
    case 'policy_attachment_changed':
      if (change.previous_mode && change.mode) {
        return narrative(
          `${quoted} on ${where} switched from ${modeLabel(change.previous_mode)} to ${modeLabel(change.mode)}.`
        );
      }
      return narrative(`${quoted} on ${where} was ${change.enabled ? 'enabled' : 'disabled'}.`);
    case 'policy_change_refused': {
      const attempted = change.action ?? 'policy_change_refused';
      const owner = attempted === 'policy_updated' && change.changed?.includes('owner');
      const verb = owner ? 'Reassigning the owner of' : REFUSED_VERB[attempted];
      const object = policy
        ? quoted
        : attempted === 'policy_created'
          ? 'a policy definition'
          : `a policy${target ? ` to ${target}` : ''}`;
      const status = [change.status, change.reason?.replace(/_/g, ' ')].filter(Boolean).join(', ');
      return narrative(`${verb} ${object} was refused${status ? ` (${status})` : ''}.`);
    }
  }
}

/** A surface slot as the policy a surface holds, e.g. "its inbound policy". */
function surfaceSlotPhrase(change: PolicyChangeData, slot: string): string {
  if (change.slot === 'transit_point' && change.transit_point) {
    return `the ${change.scope === 'response' ? 'response' : 'request'} policy of transit point ${change.transit_point}`;
  }
  if (change.slot === 'mcp_tool' && change.mcp_tool_name) {
    return `the MCP tool policy for ${change.mcp_tool_name}`;
  }
  if (change.slot === 'mcp_tool_gate' && change.gate) {
    return `the condition of MCP tool gate ${change.gate}`;
  }
  return `its ${slot}`;
}

/**
 * Turns an audit entry into a human-friendly title + two-line description used
 * by the master list. Title colour comes from {@link eventTone}; the summary and
 * detail lines read as plain English so an operator can scan the log without
 * decoding badges.
 */
export function describeEntry(entry: AuditEntry, userName?: UserNameResolver): EventNarrative {
  const change = policyChange(entry);
  if (change) return describePolicyChange(change.name, change.change, userName);
  const tone = eventTone(entry);
  const pd = policyDecision(entry);
  const tc = trustCheck(entry);
  const name = eventTypeName(entry);
  const surface = entry.channel_name || surfaceIdOf(entry) || undefined;
  const caller = callerDidOf(entry) || undefined;
  const provider = entry.provider_name || entry.provider_id || undefined;

  if (pd) {
    const allow = isAllowDecision(pd.decision);
    const target =
      pd.http_method && pd.http_path
        ? `${pd.http_method} ${pd.http_path}`
        : surface
          ? `request to ${surface}`
          : 'request';
    const policyName = pd.policy_name || pd.policy_id || 'policy';
    const flow = pd.flow ? ` on the ${flowLabel(pd.flow)} leg` : '';
    const parts: string[] = [];
    if (caller) parts.push(`Caller ${caller}`);
    if (surface) parts.push(caller ? `→ ${surface}` : surface);
    if (entry.protocol) parts.push(`(${entry.protocol})`);
    let detail = parts.join(' ');
    if (!allow && pd.deny_reason) {
      detail = detail ? `${detail} — ${pd.deny_reason}` : pd.deny_reason;
    }
    return {
      title: `${allow ? 'Allowed' : 'Denied'} ${target}`,
      tone,
      summary: `${scopeLabel(pd.scope)} policy “${policyName}”${flow}.`,
      detail: detail || undefined,
    };
  }

  if (tc) {
    // `authority_id` / `entity_id` are omitted on the target-leg
    // "unavailable" paths (`AGENT_CARD_UNAVAILABLE`,
    // `TRUST_REGISTRY_METADATA_UNAVAILABLE`), so the summary falls
    // back to a plain phrasing that doesn't invent noise strings.
    const summary =
      tc.authority_id && tc.entity_id
        ? `The ${tc.leg} leg verified ${tc.entity_id} against ${tc.authority_id}.`
        : `The ${tc.leg} leg trust check could not be evaluated.`;
    return {
      title: tc.ok ? 'Trust check passed' : 'Trust check failed',
      tone,
      summary,
      detail:
        !tc.ok && tc.error_code
          ? `Failed because ${trustErrorClause(tc.error_code, tc.leg)}.`
          : undefined,
    };
  }

  const tt = traceTerminated(entry);
  if (tt) {
    const leg = `${flowLabel(tt.flow)} leg`;
    return {
      title: 'Trace terminated at egress',
      tone: 'neutral',
      summary: `This gateway kept its own trace and forwarded a fresh one on the ${leg}${
        surface ? ` to ${surface}` : ''
      }.`,
      detail: `own ${tt.own_trace_id} → downstream ${tt.downstream_trace_id}`,
    };
  }

  switch (name) {
    case 'vp_injected': {
      const holder = entry.agent_identity_did || entry.agent_did || caller;
      return {
        title: 'Verifiable Presentation injected',
        tone,
        summary: holder
          ? `A signed VP for agent ${holder} was injected into the request.`
          : 'A signed VP was injected into the request.',
        detail: surface
          ? `Forwarded to ${surface}${entry.protocol ? ` (${entry.protocol})` : ''}.`
          : undefined,
      };
    }
    case 'token_injected':
    case 'token_refreshed': {
      const action = name === 'token_injected' ? 'injected' : 'refreshed';
      const scopes = Array.isArray(entry.scopes) ? (entry.scopes as string[]) : [];
      return {
        title: `Access token ${action}`,
        tone,
        summary: provider
          ? `A ${provider} access token was ${action}${
              entry.inject_as ? ` as ${entry.inject_as}` : ''
            }.`
          : `An access token was ${action}.`,
        detail: scopes.length ? `Scopes: ${scopes.join(', ')}.` : undefined,
      };
    }
    case 'consent_granted':
      return {
        title: 'Consent granted',
        tone,
        summary: provider
          ? `The user granted consent for ${provider}.`
          : 'The user granted consent.',
      };
    case 'consent_required':
      return {
        title: 'Consent required',
        tone,
        summary: provider
          ? `Access to ${provider} is paused until the user grants consent.`
          : 'Access is paused until the user grants consent.',
      };
    case 'refresh_failed':
      return {
        title: 'Token refresh failed',
        tone,
        summary: provider
          ? `Refreshing the ${provider} token failed.`
          : 'Refreshing the access token failed.',
      };
    case 'token_revoked':
      return {
        title: 'Token revoked',
        tone,
        summary: provider ? `The ${provider} token was revoked.` : 'The token was revoked.',
      };
    case 'user_tokens_revoked':
      return {
        title: 'User tokens revoked',
        tone,
        summary: 'All of the user’s stored tokens were revoked.',
      };
    case 'token_not_found':
      return {
        title: 'Token not found',
        tone,
        summary: provider ? `No stored ${provider} token was found.` : 'No stored token was found.',
      };
    default:
      return {
        title: categoryLabel(name),
        tone,
        summary: surface ? `Event recorded for ${surface}.` : 'Audit event recorded.',
        detail: caller ? `Caller ${caller}.` : undefined,
      };
  }
}
