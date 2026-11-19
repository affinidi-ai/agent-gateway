import type { PolicyDecision } from './types';

type RuleKind = 'allow' | 'deny' | 'helper';

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
function isTemplateMarker(line: string): boolean {
  return BEGIN_MARKER.test(line) || END_MARKER.test(line);
}
const DEFAULT_ALLOW = /^default\s+allow\s*:?=\s*(true|false)\b/;
const DEFAULT_ALLOW_TRUE = /^(\s*default\s+allow\s*:?=\s*)true\b/m;
const ALLOW_ALL_COMMENT =
  /^[ \t]*# Allow all traffic by default[ \t]*\r?\n(?=[ \t]*default\s+allow\s*:?=\s*true\b)/m;
const OPEN_ENDING = /((^|[^\w.])(if|else|contains)|:=|=|,)$/;
const CLOSED_STATEMENT = /^(package|import)\s/;
const CONTINUING_START = /^((if|contains|else)\b|:?=(?!=)|\{)/;
const REGO_KEYWORD =
  /^(as|contains|default|else|every|false|if|import|in|not|null|package|some|true|with)$/;
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
        current !== null &&
        !CLOSED_STATEMENT.test(current.code[0] ?? '') &&
        (OPEN_ENDING.test(lastCode) || CONTINUING_START.test(trimmed));
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

/**
 * The statement as a rule, null for one that defines no rule, or `unparsed` for a head that
 * is not a rule name.
 */
function toRule(statement: Extract<Item, { type: 'statement' }>): PolicyRule | null | 'unparsed' {
  const first = statement.code[0] ?? '';
  if (CLOSED_STATEMENT.test(first) || DEFAULT_ALLOW.test(first)) return null;
  const head = first.match(/^(default\s+)?[A-Za-z_][\w.]*(\([^)]*\))?/)?.[0];
  if (!head) return 'unparsed';
  const name = head.replace(/^default\s+/, '').replace(/\(.*$/, '');
  if (REGO_KEYWORD.test(name.split('.')[0])) return 'unparsed';
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
      if (rule === 'unparsed') return { ok: false };
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

const allRules = (parsed: ParsedPolicy) => (parsed.ok ? parsed.groups.flatMap(g => g.rules) : []);

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
): { reached: Set<string>; readers: PolicyRule[] } {
  const patterns = new Map(
    Array.from(new Set(rules.map(readName)), name => [name, referencePattern(name)])
  );
  const reached = new Set<string>();
  const queue = rules.filter(r => readName(r) === 'allow' && !excluded(r));
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
  return { reached, readers: Array.from(visited) };
}

/** Why a rule or group can't be removed: the rule that reads it, or the whole-document read. */
export type RuleUse =
  | { kind: 'reader'; name: string; line: number }
  | { kind: 'document' }
  | { kind: 'unnamed' };

/**
 * The first rule, by line, among `readers` that reads one of `names` and defines none of them;
 * a reason without a reader when none is found, so a name `allow` reaches is always refused.
 */
function firstReader(readers: PolicyRule[], names: Set<string>): RuleUse {
  const reader = readers
    .filter(r => !names.has(readName(r)))
    .filter(r => Array.from(names).some(n => referencePattern(n).test(withoutStrings(r.code))))
    .sort((a, b) => a.startLine - b.startLine)[0];
  return reader
    ? { kind: 'reader', name: ruleName(reader), line: reader.startLine }
    : { kind: 'unnamed' };
}

/**
 * Why removing a rule would change what `allow` decides, or null when it wouldn't: `allow` reads
 * its name, directly or through other rules, from outside the rule (the reason names the first
 * rule, by line, that reads it), or the Rego reads its package as a whole document. Removing an
 * `allow` rule, or a rule with an identical definition left from the same template added twice,
 * is always allowed; one of several different definitions is in use.
 */
export function ruleUse(parsed: ParsedPolicy, rule: PolicyRule): RuleUse | null {
  const name = ruleName(rule);
  if (!parsed.ok || name === 'allow') return null;
  const rules = allRules(parsed);
  const self = (r: PolicyRule) => r.startLine === rule.startLine;
  if (rules.some(r => !self(r) && ruleName(r) === name && sameCode(r, rule))) return null;
  if (parsed.readsPackageDocument) return { kind: 'document' };
  const { reached, readers } = reachableFromAllow(rules, self);
  return reached.has(readName(rule)) ? firstReader(readers, new Set([readName(rule)])) : null;
}

/**
 * Why removing a template group would change what `allow` decides, or null when it wouldn't:
 * `allow` reads a name the group defines through rules outside the group, or the Rego reads its
 * package as a whole document, and some definition of that name in the group has no identical
 * copy outside it.
 */
export function groupUse(parsed: ParsedPolicy, group: RuleGroup): RuleUse | null {
  if (!parsed.ok) return null;
  const rules = allRules(parsed);
  const inGroup = (r: PolicyRule) => r.startLine >= group.startLine && r.endLine <= group.endLine;
  const outside = rules.filter(r => !inGroup(r));
  const { reached, readers } = reachableFromAllow(rules, inGroup);
  const used = group.rules.filter(
    rule =>
      ruleName(rule) !== 'allow' &&
      (parsed.readsPackageDocument || reached.has(readName(rule))) &&
      !outside.some(r => ruleName(r) === ruleName(rule) && sameCode(r, rule))
  );
  if (used.length === 0) return null;
  if (parsed.readsPackageDocument) return { kind: 'document' };
  return firstReader(readers, new Set(used.map(readName)));
}

const PLAIN_ALLOW_REST = /^(?::?=\s*true\b)?\s*(if\b|\{|$)/;

/** The code after a plain allow's head and value, or null when the rule is not a plain allow. */
function plainAllowBody(rule: PolicyRule): string | null {
  if (rule.head !== 'allow' || /\belse\b/.test(withoutStrings(rule.code))) return null;
  const rest = rule.code.join(' ').slice('allow'.length).trim();
  const match = rest.match(PLAIN_ALLOW_REST);
  if (!match) return null;
  return rest.slice(match[0].length - (match[1] === '{' ? 1 : 0)).trim();
}

/**
 * Whether the rule is `allow` with no arguments, dot, `[ ]` or `contains`, with no value or
 * `= true` / `:= true`, followed by `if`, `{` or nothing, and no `else` outside strings.
 */
export function isPlainAllow(rule: PolicyRule): boolean {
  return plainAllowBody(rule) !== null;
}

/** Whether the rule is a plain allow whose body is empty or exactly `true`. */
export function isUnconditionalAllow(rule: PolicyRule): boolean {
  const body = plainAllowBody(rule);
  if (body === null) return false;
  const inner = /^\{[\s\S]*\}$/.test(body) ? body.slice(1, -1).trim() : body;
  const statement = inner.replace(/;\s*$/, '').trim();
  return statement === '' || statement === 'true';
}

export type DecisionSummary =
  | { kind: 'unsummarised' }
  | { kind: 'allows-all'; reason: 'default' | 'unconditional' }
  | { kind: 'any-allow'; allowRules: number; hasDefault: boolean }
  | { kind: 'denies-all'; hasDefault: boolean };

/**
 * What the policy decides, from the parse alone, or null when there is nothing to summarise:
 * the Rego doesn't parse, is empty, or has no rules (`defaultDecision` then says what applies).
 */
export function summarizeDecision(parsed: ParsedPolicy): DecisionSummary | null {
  const rules = allRules(parsed);
  if (!parsed.ok || rules.length === 0) return null;
  const allows = rules.filter(r => readName(r) === 'allow');
  if (!allows.every(isPlainAllow)) return { kind: 'unsummarised' };
  if (parsed.defaultDecision === 'allow') return { kind: 'allows-all', reason: 'default' };
  if (allows.some(isUnconditionalAllow)) return { kind: 'allows-all', reason: 'unconditional' };
  const hasDefault = parsed.defaultDecision !== null;
  return allows.length > 0
    ? { kind: 'any-allow', allowRules: allows.length, hasDefault }
    : { kind: 'denies-all', hasDefault };
}

export type RuleRole = 'allow' | 'deny-reason' | 'used-by-allow' | 'not-used-by-allow';

/**
 * Each rule's part in the decision: an allow rule, a deny reason, or whether `allow` reads it,
 * directly or through other rules. Every rule is used while the Rego reads its package as a
 * whole document or doesn't parse.
 */
export function ruleRoles(parsed: ParsedPolicy): (rule: PolicyRule) => RuleRole {
  const document = !parsed.ok || parsed.readsPackageDocument;
  const { reached } = reachableFromAllow(allRules(parsed), () => false);
  return rule => {
    if (rule.kind === 'allow') return 'allow';
    if (rule.kind === 'deny') return 'deny-reason';
    return document || reached.has(readName(rule)) ? 'used-by-allow' : 'not-used-by-allow';
  };
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

/** Input paths a module reads, such as `jwt.sub`, shown as tags on the template. */
export function readsFromRego(rego: string): string[] {
  const paths = Array.from(rego.matchAll(/\binput\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)/g), m => m[1]);
  return Array.from(new Set(paths)).slice(0, 6);
}
