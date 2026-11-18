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
  /** The rule's code lines, trimmed, with comments removed and strings kept. */
  code: string[];
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
  | {
      ok: true;
      defaultDecision: PolicyDecision | null;
      groups: RuleGroup[];
      /**
       * The Rego imports a `data` path, or reads its own package (or a parent) as a whole
       * document, so a rule can be read under a name no reference scan sees.
       */
      readsPackageDocument: boolean;
    }
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
const ALLOW_ALL_COMMENT =
  /^[ \t]*# Allow all traffic by default[ \t]*\r?\n(?=[ \t]*default\s+allow\s*:?=\s*true\b)/m;
const OPEN_ENDING = /(\bif|\belse|:=|=|,)$/;
const SUMMARY_LENGTH = 90;
const DENY_REASON = 'deny_reason';
const STRING_LITERAL = /"(?:\\.|[^"\\])*"|`[^`]*`/g;
const PACKAGE = /^package\s+([\w.]+)/;
const IMPORT_DATA = /^import\s+data\b/;
const DATA_REF = /(?:^|[^\w.])data((?:\.\w+)*)/gm;

const withoutStrings = (code: string[]) => code.join('\n').replace(STRING_LITERAL, '""');

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
  const kind: RuleKind = name === 'allow' ? 'allow' : name === DENY_REASON ? 'deny' : 'helper';
  const oneLine = statement.code.join(' ').replace(/\s+/g, ' ');
  return {
    head,
    kind,
    startLine: statement.start + 1,
    endLine: statement.end + 1,
    summary: oneLine.length > SUMMARY_LENGTH ? `${oneLine.slice(0, SUMMARY_LENGTH - 1)}…` : oneLine,
    code: statement.code,
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
    readsPackageDocument: readsPackageDocument(
      items.flatMap(item => (item.type === 'statement' ? [item.code] : []))
    ),
  };
}

/**
 * Whether a statement imports a `data` path, or reads `data`, the package or one of its parents
 * without naming a rule after it, such as `data.<package>["name"]` or `doc := data.<package>`.
 */
function readsPackageDocument(statements: string[][]): boolean {
  const packageLine = statements.find(code => PACKAGE.test(code[0] ?? ''))?.[0] ?? '';
  const packagePath = packageLine.match(PACKAGE)?.[1].split('.') ?? [];
  return statements.some(code => {
    if (IMPORT_DATA.test(code[0] ?? '')) return true;
    return Array.from(withoutStrings(code).matchAll(DATA_REF)).some(match => {
      const path = match[1].split('.').filter(Boolean);
      return path.length <= packagePath.length && path.every((s, i) => s === packagePath[i]);
    });
  });
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
  return rego.replace(ALLOW_ALL_COMMENT, '').replace(DEFAULT_ALLOW_TRUE, '$1false');
}

/** A rule's name without `default` or a function's arguments, such as `allow` or `jwt_claim_values`. */
export function ruleName(rule: PolicyRule): string {
  return rule.head.replace(/^default\s+/, '').replace(/\(.*$/, '');
}

const sameCode = (a: PolicyRule, b: PolicyRule) => a.code.join('\n') === b.code.join('\n');

const referencePattern = (name: string) => {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\w.])(data(\\.\\w+)*\\.)?${escaped}\\b`, 'm');
};

/** The name other rules read a rule by: the first segment of a dotted head such as `blocked.ip`. */
const readName = (rule: PolicyRule) => ruleName(rule).split('.')[0];

/**
 * The rule names `allow` reads, directly or through other rules, walking every rule the
 * predicate doesn't exclude. `deny_reason` is never a starting point: the gateway decides on
 * `allow` and reads `deny_reason` only as text. Text inside strings is not a reference.
 */
function reachableFromAllow(
  rules: PolicyRule[],
  excluded: (rule: PolicyRule) => boolean
): Set<string> {
  const patterns = new Map(
    Array.from(new Set(rules.map(readName)), name => [name, referencePattern(name)])
  );
  const reached = new Set<string>();
  const queue = rules.filter(r => r.kind === 'allow' && !excluded(r));
  const visited = new Set(queue);
  while (queue.length > 0) {
    const text = withoutStrings(queue.pop()!.code);
    patterns.forEach((pattern, name) => {
      if (reached.has(name) || !pattern.test(text)) return;
      reached.add(name);
      rules
        .filter(r => readName(r) === name && !excluded(r) && !visited.has(r))
        .forEach(r => {
          visited.add(r);
          queue.push(r);
        });
    });
  }
  return reached;
}

/**
 * Whether removing a rule changes what `allow` decides: `allow` reads its name, directly or
 * through other rules, from outside the rule, or the Rego reads its package as a whole
 * document. Removing an `allow` rule, or a rule with an identical definition left from the same
 * template added twice, is always allowed; one of several different definitions is in use.
 */
export function ruleInUse(parsed: ParsedPolicy, rule: PolicyRule): boolean {
  const name = ruleName(rule);
  if (!parsed.ok || name === 'allow') return false;
  const rules = parsed.groups.flatMap(g => g.rules);
  const self = (r: PolicyRule) => r.startLine === rule.startLine;
  if (rules.some(r => !self(r) && ruleName(r) === name && sameCode(r, rule))) return false;
  return parsed.readsPackageDocument || reachableFromAllow(rules, self).has(readName(rule));
}

/**
 * Whether removing a template group changes what `allow` decides: `allow` reads a name the
 * group defines through rules outside the group, or the Rego reads its package as a whole
 * document, and some definition of that name in the group has no identical copy outside it.
 */
export function groupInUse(parsed: ParsedPolicy, group: RuleGroup): boolean {
  if (!parsed.ok) return false;
  const rules = parsed.groups.flatMap(g => g.rules);
  const inGroup = (r: PolicyRule) => r.startLine >= group.startLine && r.endLine <= group.endLine;
  const outside = rules.filter(r => !inGroup(r));
  const reached = reachableFromAllow(rules, inGroup);
  return group.rules.some(
    rule =>
      ruleName(rule) !== 'allow' &&
      (parsed.readsPackageDocument || reached.has(readName(rule))) &&
      !outside.some(r => ruleName(r) === ruleName(rule) && sameCode(r, rule))
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
