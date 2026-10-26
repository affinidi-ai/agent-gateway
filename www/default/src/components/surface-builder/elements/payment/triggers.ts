import type { A2AMethodFilter, McpPaymentTriggers } from '../../../../types';
import type { PaymentNodeConfig } from './types';

export type TriggerMode = McpPaymentTriggers['mode'];

const MAX_CHECKED_LENGTH = 1000;
const UNSUPPORTED_BY_GATEWAY = /\(\?<?[=!]|\\[1-9]/;
const INLINE_FLAGS = /\(\?[imsxUu-]+\)/g;
const SCOPED_FLAGS = /\(\?[imsxUu-]+:/g;
const NAMED_GROUP = /\(\?P</g;

/**
 * Why the browser doubts the gateway will compile `pattern`, or null. The gateway
 * checks patterns with Rust's regex engine, whose syntax differs from the browser's
 * (inline flags such as `(?i)` are valid there), so this only advises and the
 * gateway's answer on Save is final.
 */
export function triggerPatternAdvice(pattern: string): string | null {
  if (pattern.length > MAX_CHECKED_LENGTH) {
    return 'This pattern is too long for the browser to check. The gateway checks it when you save.';
  }
  if (UNSUPPORTED_BY_GATEWAY.test(pattern.replace(/\\\\/g, ''))) {
    return 'Lookaround and backreferences are not supported by the gateway.';
  }
  try {
    new RegExp(
      pattern.replace(INLINE_FLAGS, '').replace(SCOPED_FLAGS, '(?:').replace(NAMED_GROUP, '(?<')
    );
    return null;
  } catch {
    return 'The browser could not read this pattern. The gateway checks it when you save.';
  }
}

const nonBlank = (patterns: unknown): string[] =>
  Array.isArray(patterns)
    ? patterns.filter((p): p is string => typeof p === 'string' && p.trim() !== '')
    : [];

export function normaliseMcpTriggers(raw: unknown): McpPaymentTriggers | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const t = raw as { mode?: unknown; patterns?: unknown };
  if (t.mode === 'all') return { mode: 'all' };
  if (t.mode === 'match' || t.mode === 'exclude') {
    return { mode: t.mode, patterns: nonBlank(t.patterns) };
  }
  return undefined;
}

export function normaliseA2aFilters(raw: unknown): A2AMethodFilter[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const filters = raw
    .filter(
      (f): f is A2AMethodFilter =>
        !!f && typeof f === 'object' && typeof f.method === 'string' && f.method.trim() !== ''
    )
    .map(f => ({ method: f.method, message_patterns: nonBlank(f.message_patterns) }));
  return filters.length > 0 ? filters : undefined;
}

/** The gateway rejects a Match trigger that has no text to match. */
export function mcpMatchHasNoPatterns(raw: unknown): boolean {
  const t = normaliseMcpTriggers(raw);
  return t?.mode === 'match' && t.patterns.length === 0;
}

/** MCP trigger patterns the browser doubts the gateway accepts. A2A texts are plain text and never checked. */
export function questionableMcpPatterns(config: PaymentNodeConfig | undefined): string[] {
  const mcp = normaliseMcpTriggers(config?.mcp_payment_triggers);
  if (!mcp || mcp.mode === 'all') return [];
  return mcp.patterns.filter(p => triggerPatternAdvice(p) !== null);
}

export const DEFAULT_A2A_METHODS = ['message/send', 'message/stream'];

export const defaultA2aFilters = (): A2AMethodFilter[] =>
  DEFAULT_A2A_METHODS.map(method => ({ method, message_patterns: [] }));

export function describeTriggers(config: PaymentNodeConfig, protocol?: string): string {
  if (config.require_all === true) return 'Every request is charged';
  if (protocol === 'a2a') {
    const filters = normaliseA2aFilters(config.a2a_method_filters) ?? [];
    if (filters.length === 0) return 'No filters set: message/send and message/stream are charged';
    return `${filters.length} A2A method${filters.length === 1 ? '' : 's'} charged`;
  }
  const t = normaliseMcpTriggers(config.mcp_payment_triggers);
  if (!t) return 'No trigger is set: every tool call is charged';
  if (t.mode === 'all') return 'Every tool call is charged';
  const n = t.patterns.length;
  if (n === 0)
    return t.mode === 'match' ? 'Match needs at least one pattern' : 'Every tool call is charged';
  const noun = `${n} pattern${n === 1 ? '' : 's'}`;
  return t.mode === 'match' ? `Tools matching ${noun}` : `All tools except ${noun}`;
}
