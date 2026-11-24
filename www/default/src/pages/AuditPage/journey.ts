import { eventTypeName, policyDecision, trustCheck } from './auditHelpers';
import { describeEntry, type EventTone } from './eventNarrative';
import type { AuditEntry } from './types';

export interface JourneyStep {
  key: string;
  title: string;
  tone: EventTone;
  detail?: string;
  occurred_at: string;
}

/**
 * Rough pipeline position of an event, so the journey reads in request order
 * even when occurrence times collide. Lower = earlier in the request lifecycle.
 */
function stageRank(entry: AuditEntry): number {
  const tc = trustCheck(entry);
  if (tc) {
    if (tc.leg === 'caller') return 20;
    return tc.leg === 'managed_agent' ? 25 : 60;
  }

  const pd = policyDecision(entry);
  if (pd) {
    switch (pd.scope) {
      case 'gateway':
        return 30;
      case 'surface':
        return 40;
      case 'mcp_tool':
        return 45;
      case 'response':
        return 70;
      default:
        return 42;
    }
  }

  switch (eventTypeName(entry)) {
    case 'consent_required':
      return 10;
    case 'consent_granted':
      return 12;
    case 'token_injected':
    case 'token_refreshed':
    case 'refresh_failed':
      return 50;
    case 'vp_injected':
      return 55;
    case 'trace_terminated':
      return 80;
    default:
      return 90;
  }
}

/**
 * Orders a request's correlated events into a readable journey (pipeline stage,
 * then occurrence time, then original index). Reuses {@link describeEntry} so
 * titles, tone, and the human summary stay consistent with the list. Pure.
 */
export function buildJourney(siblings: AuditEntry[]): JourneyStep[] {
  return siblings
    .map((entry, index) => ({ entry, index, rank: stageRank(entry) }))
    .sort(
      (a, b) =>
        a.rank - b.rank ||
        a.entry.occurred_at.localeCompare(b.entry.occurred_at) ||
        a.index - b.index
    )
    .map(({ entry, index }) => {
      const narrative = describeEntry(entry);
      return {
        key: entry.id ?? `${index}`,
        title: narrative.title,
        tone: narrative.tone,
        detail: narrative.summary,
        occurred_at: entry.occurred_at,
      };
    });
}
