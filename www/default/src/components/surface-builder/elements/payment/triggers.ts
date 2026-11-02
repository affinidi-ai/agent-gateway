import type { A2AMethodFilter, McpPaymentTriggers } from '../../../../types';
import type { PaymentNodeConfig } from './types';

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

const HAS_INLINE_FLAGS = /\(\?[imsxUu-]+[:)]/;

/**
 * The browser's reading of `pattern`, or null when the browser cannot read it the way the
 * gateway does. Like the gateway, a pattern matches anywhere in the tool name unless anchored.
 */
export function browserTriggerRegExp(pattern: string): RegExp | null {
  if (pattern.length > MAX_CHECKED_LENGTH || HAS_INLINE_FLAGS.test(pattern)) return null;
  if (UNSUPPORTED_BY_GATEWAY.test(pattern.replace(/\\\\/g, ''))) return null;
  try {
    return new RegExp(pattern.replace(NAMED_GROUP, '(?<'));
  } catch {
    return null;
  }
}

const REGEX_SPECIAL = /[\\^$.*+?()[\]{}|]/g;
const EXACT_TOOL_PATTERN = /^\^((?:\\[\\^$.*+?()[\]{}|]|[^\\^$.*+?()[\]{}|])+)\$$/;

/** The pattern that matches exactly one tool name, in both the gateway's and the browser's syntax. */
export const exactToolPattern = (name: string): string =>
  `^${name.replace(REGEX_SPECIAL, '\\$&')}$`;

/** The tool a pattern written by `exactToolPattern` names, or null for any other pattern. */
export function toolFromExactPattern(pattern: string): string | null {
  const m = EXACT_TOOL_PATTERN.exec(pattern);
  return m ? m[1].replace(/\\(.)/g, '$1') : null;
}

export interface ToolCharge {
  charged: boolean;
  /** A pattern other than an exact tool pattern decides this tool, so it is edited as a pattern. */
  decidedBy?: string;
}

/** Whether a `tools/call` of `tool` is charged under `raw`, by the gateway's rule. */
export function toolCharge(raw: unknown, tool: string): ToolCharge {
  const t = normaliseMcpTriggers(raw);
  if (!t || t.mode === 'all') return { charged: true };
  const exact = t.patterns.some(p => toolFromExactPattern(p) === tool);
  const decidedBy = t.patterns.find(
    p => toolFromExactPattern(p) === null && browserTriggerRegExp(p)?.test(tool)
  );
  const matched = exact || decidedBy !== undefined;
  return {
    charged: t.mode === 'match' ? matched : !matched,
    ...(decidedBy !== undefined ? { decidedBy } : {}),
  };
}

/**
 * Whether the selected tools and patterns are charged (Match, or All and no trigger, where
 * nothing is selected yet) rather than free (Exclude).
 */
export const mcpSelectionCharged = (raw: unknown): boolean =>
  normaliseMcpTriggers(raw)?.mode !== 'exclude';

/**
 * The trigger for a selection: a charged one is Match, or All while it is empty, so clearing
 * the last tool charges every tool again; a free one is Exclude, whose empty list also charges
 * every tool.
 */
export function buildMcpTriggers(
  selectionCharged: boolean,
  patterns: string[]
): McpPaymentTriggers {
  if (!selectionCharged) return { mode: 'exclude', patterns };
  return patterns.length > 0 ? { mode: 'match', patterns } : { mode: 'all' };
}

/** The stored patterns as the editor lists them, blank rows included. */
export function storedMcpPatterns(raw: unknown): string[] {
  const t = (raw ?? {}) as { mode?: unknown; patterns?: unknown };
  return t.mode === 'all' || !Array.isArray(t.patterns)
    ? []
    : t.patterns.filter((p): p is string => typeof p === 'string');
}

/** The tools selected by their exact pattern, in list order. */
export const selectedToolNames = (raw: unknown): string[] =>
  storedMcpPatterns(raw)
    .map(toolFromExactPattern)
    .filter((tool): tool is string => tool !== null);

/**
 * Selects `tools` by appending the exact patterns they lack, or clears them by removing their
 * exact patterns. Every other row keeps its place.
 */
export function setToolsSelected(
  raw: unknown,
  tools: string[],
  selected: boolean
): McpPaymentTriggers {
  const stored = storedMcpPatterns(raw);
  const listed = stored.map(toolFromExactPattern);
  const next = selected
    ? [
        ...stored,
        ...tools
          .filter((tool, i) => !listed.includes(tool) && tools.indexOf(tool) === i)
          .map(exactToolPattern),
      ]
    : stored.filter((_, i) => listed[i] === null || !tools.includes(listed[i] as string));
  return buildMcpTriggers(mcpSelectionCharged(raw), next);
}

/** The same patterns with the other meaning: what was charged becomes free, and the reverse. */
export const setMcpSelectionCharged = (raw: unknown, charged: boolean): McpPaymentTriggers =>
  buildMcpTriggers(charged, storedMcpPatterns(raw));

/** Patterns the browser cannot evaluate, so the tool list may not show their effect. */
export function uncheckedMcpPatterns(raw: unknown): string[] {
  const t = normaliseMcpTriggers(raw);
  if (!t || t.mode === 'all') return [];
  return t.patterns.filter(p => toolFromExactPattern(p) === null && !browserTriggerRegExp(p));
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
