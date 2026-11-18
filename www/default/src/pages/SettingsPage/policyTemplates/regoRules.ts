import type { PolicyDecision } from './types';

export type RuleKind = 'allow' | 'deny' | 'helper';

export interface PolicyRule {
  /** The rule's head, such as `allow` or `jwt_claim_values(v)`. */
  head: string;
  kind: RuleKind;
  /** First and last line of the rule, counted from 1. */
  startLine: number;
  endLine: number;
  /** The rule on one line, shortened, without comments. */
  summary: string;
}

export type RuleSource = { kind: 'editor' } | { kind: 'template'; name: string };

export interface RuleGroup {
  source: RuleSource;
  /** For a template group, from its `# Inserted from template` line to its end line. */
  startLine: number;
  endLine: number;
  rules: PolicyRule[];
}

export type ParsedPolicy =
  | { ok: true; defaultDecision: PolicyDecision | null; groups: RuleGroup[] }
  | { ok: false };

export const TEMPLATE_BEGIN_PREFIX = '# Inserted from template: ';
export const TEMPLATE_END_PREFIX = '# End of template: ';

const BEGIN_MARKER = /^\s*#\s*Inserted from template:\s*(.*)$/;
const END_MARKER = /^\s*#\s*End of template:/;

/** True for a `# Inserted from template:` or `# End of template:` comment line. */
export function isTemplateMarker(line: string): boolean {
  return BEGIN_MARKER.test(line) || END_MARKER.test(line);
}
const DEFAULT_ALLOW = /^default\s+allow\s*:?=\s*(true|false)\b/;
const DEFAULT_ALLOW_TRUE = /^(\s*default\s+allow\s*:?=\s*)true\b/m;
const OPEN_ENDING = /(\bif|\belse|:=|=|,)$/;
const SUMMARY_LENGTH = 90;

type Item =
  | { type: 'statement'; start: number; end: number; code: string[] }
  | { type: 'begin'; line: number; name: string }
  | { type: 'end'; line: number };

/**
 * Splits Rego into top-level statements by bracket depth, ignoring brackets inside strings
 * and comments. Returns null when the brackets don't balance.
 */
function scan(lines: string[]): Item[] | null {
  const items: Item[] = [];
  let depth = 0;
  let inRaw = false;
  let current: Extract<Item, { type: 'statement' }> | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const atTop = depth === 0 && !inRaw;

    if (atTop && (!trimmed || trimmed.startsWith('#'))) {
      const begin = trimmed.match(BEGIN_MARKER);
      if (begin) {
        items.push({ type: 'begin', line: i, name: begin[1].trim() });
        current = null;
      } else if (END_MARKER.test(trimmed)) {
        items.push({ type: 'end', line: i });
        current = null;
      }
      continue;
    }

    if (atTop) {
      const lastCode = current?.code[current.code.length - 1] ?? '';
      const continues =
        current !== null && (OPEN_ENDING.test(lastCode) || /^(else\b|\{)/.test(trimmed));
      if (!continues) {
        current = { type: 'statement', start: i, end: i, code: [] };
        items.push(current);
      }
    }

    let inString = false;
    let codeEnd = line.length;
    for (let k = 0; k < line.length; k++) {
      const c = line[k];
      if (inRaw) {
        if (c === '`') inRaw = false;
        continue;
      }
      if (inString) {
        if (c === '\\') k++;
        else if (c === '"') inString = false;
        continue;
      }
      if (c === '#') {
        codeEnd = k;
        break;
      }
      if (c === '"') inString = true;
      else if (c === '`') inRaw = true;
      else if (c === '{' || c === '[' || c === '(') depth++;
      else if (c === '}' || c === ']' || c === ')') depth--;
      if (depth < 0) return null;
    }
    if (current) {
      current.end = i;
      const code = line.slice(0, codeEnd).trim();
      if (code) current.code.push(code);
    }
  }
  return depth === 0 && !inRaw ? items : null;
}

function toRule(statement: Extract<Item, { type: 'statement' }>): PolicyRule | null {
  const first = statement.code[0] ?? '';
  if (/^(package|import)\s/.test(first) || DEFAULT_ALLOW.test(first)) return null;
  const head = first.match(/^(default\s+)?[A-Za-z_][\w.]*(\([^)]*\))?/)?.[0] ?? first;
  const name = head.replace(/^default\s+/, '').replace(/\(.*$/, '');
  const kind: RuleKind =
    name === 'allow' ? 'allow' : name === 'deny' || name.startsWith('deny_') ? 'deny' : 'helper';
  const oneLine = statement.code.join(' ').replace(/\s+/g, ' ');
  return {
    head,
    kind,
    startLine: statement.start + 1,
    endLine: statement.end + 1,
    summary: oneLine.length > SUMMARY_LENGTH ? `${oneLine.slice(0, SUMMARY_LENGTH - 1)}…` : oneLine,
  };
}

/**
 * Lists a policy's rules, grouped by where they came from: the rules written in the editor,
 * then one group per inserted template, in the order they appear.
 */
export function parsePolicyRules(rego: string): ParsedPolicy {
  const lines = rego.split('\n');
  const items = scan(lines);
  if (!items) return { ok: false };

  let defaultDecision: PolicyDecision | null = null;
  const editor: RuleGroup = {
    source: { kind: 'editor' },
    startLine: 1,
    endLine: lines.length,
    rules: [],
  };
  const templates: RuleGroup[] = [];
  let open: RuleGroup | null = null;

  for (const item of items) {
    if (item.type === 'begin') {
      open = {
        source: { kind: 'template', name: item.name },
        startLine: item.line + 1,
        endLine: item.line + 1,
        rules: [],
      };
      templates.push(open);
    } else if (item.type === 'end') {
      if (open) open.endLine = item.line + 1;
      open = null;
    } else {
      const match = (item.code[0] ?? '').match(DEFAULT_ALLOW);
      if (match) defaultDecision = match[1] === 'true' ? 'allow' : 'deny';
      const rule = toRule(item);
      if (!rule) continue;
      if (open) {
        open.rules.push(rule);
        open.endLine = rule.endLine;
      } else {
        editor.rules.push(rule);
      }
    }
  }
  return {
    ok: true,
    defaultDecision,
    groups: editor.rules.length > 0 ? [editor, ...templates] : templates,
  };
}

/** Removes a group's lines, from its `# Inserted from template` line to its last line. */
export function removeRuleGroup(rego: string, group: RuleGroup): string {
  const lines = rego.split('\n');
  lines.splice(group.startLine - 1, group.endLine - group.startLine + 1);
  return `${lines
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/\s+$/, '')}\n`;
}

/** Turns `default allow := true` (or `= true`) into `false`, keeping the operator. */
export function setDefaultDeny(rego: string): string {
  return rego.replace(DEFAULT_ALLOW_TRUE, '$1false');
}

/** A rule's name without `default` or a function's arguments, such as `allow` or `jwt_claim_values`. */
export function ruleName(rule: PolicyRule): string {
  return rule.head.replace(/^default\s+/, '').replace(/\(.*$/, '');
}

/**
 * Whether removing a helper rule would leave another rule referring to it. Removing an `allow`
 * or deny-reason rule only narrows the policy, but removing a helper can widen it: a rule that
 * reads `not helper` matches everything once the helper is gone. A helper with another
 * identical definition left, from the same template added twice, is free to remove.
 */
export function ruleInUse(rego: string, parsed: ParsedPolicy, rule: PolicyRule): boolean {
  if (rule.kind !== 'helper' || !parsed.ok) return false;
  const name = ruleName(rule);
  const lines = rego.split('\n');
  const text = (r: PolicyRule) =>
    lines
      .slice(r.startLine - 1, r.endLine)
      .map(l => l.split('#')[0].trim())
      .join(' ');
  // Only an identical copy, from the same template added twice, leaves the helper unchanged;
  // removing one of several different definitions weakens it.
  const identicalCopy = parsed.groups
    .flatMap(g => g.rules)
    .some(r => r.startLine !== rule.startLine && ruleName(r) === name && text(r) === text(rule));
  if (identicalCopy) return false;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const reference = new RegExp(`(^|[^\\w.])${escaped}\\b`);
  return lines.some(
    (line, i) =>
      (i + 1 < rule.startLine || i + 1 > rule.endLine) && reference.test(line.split('#')[0])
  );
}

/** Removes one rule's lines, with the comment lines directly above it. */
export function removeRule(rego: string, rule: PolicyRule): string {
  const lines = rego.split('\n');
  let start = rule.startLine - 1;
  while (start > 0 && /^\s*#/.test(lines[start - 1]) && !isTemplateMarker(lines[start - 1])) {
    start--;
  }
  lines.splice(start, rule.endLine - start);
  return `${lines
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/\s+$/, '')}\n`;
}
