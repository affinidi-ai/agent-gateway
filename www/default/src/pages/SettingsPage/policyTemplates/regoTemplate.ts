import type {
  ParameterValues,
  PolicyDecision,
  PolicyTemplate,
  PolicyTemplateParameter,
} from './types';
import { TEMPLATE_BEGIN_PREFIX, TEMPLATE_END_PREFIX } from './regoRules';

const PACKAGE_LINE = /^\s*package\s+/;
const IMPORT_LINE = /^\s*import\s+/;
const DEFAULT_ALLOW_LINE = /^\s*default\s+allow\s*:?=\s*(true|false)\b/m;
const LINE_BREAKS = new RegExp('[\\r\\n\\u2028\\u2029]+', 'g');

export function defaultParameterValues(template: PolicyTemplate): ParameterValues {
  return Object.fromEntries(template.parameters.map(p => [p.key, p.default]));
}

/** Splits a comma- or line-separated text field into trimmed, non-empty values. */
export function parseListInput(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map(v => v.trim())
    .filter(Boolean);
}

type Literal = { literal: string } | { error: string };

function toRegoLiteral(param: PolicyTemplateParameter, value: unknown): Literal {
  if (param.kind === 'integer') {
    const n = typeof value === 'number' ? value : NaN;
    if (!Number.isInteger(n) || n < param.min || n > param.max) {
      return { error: `Enter a whole number from ${param.min} to ${param.max}.` };
    }
    return { literal: String(n) };
  }
  // JSON string literals are valid Rego string literals, so quotes, backslashes and
  // control characters in a value stay inside the string.
  if (param.kind === 'string') {
    const text = typeof value === 'string' ? value.trim() : '';
    if (!text) return { error: 'Enter a value.' };
    if (param.format === 'time_zone') {
      const zone = canonicalTimeZone(text);
      if (!zone) return { error: 'Enter an IANA time zone, for example Europe/Berlin.' };
      return { literal: JSON.stringify(zone) };
    }
    return { literal: JSON.stringify(text) };
  }
  if (param.kind === 'choice') {
    const option = param.options.find(o => o.value === value);
    if (!option) return { error: `Pick one of ${param.options.map(o => o.label).join(', ')}.` };
    return { literal: option.rego };
  }
  if (param.kind === 'time_of_day') {
    const minutes = minutesOfDay(value);
    if (minutes === null) return { error: 'Enter a time from 00:00 to 23:59.' };
    return { literal: String(minutes) };
  }
  const items = Array.isArray(value) ? value : [];
  let cleaned = items.map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  if (param.allowed) {
    const byLowerCase = new Map(param.allowed.map(a => [a.toLowerCase(), a]));
    const unknown = cleaned.find(v => !byLowerCase.has(v.toLowerCase()));
    if (unknown) {
      return { error: `"${unknown}" isn't accepted. Use ${param.allowed.join(', ')}.` };
    }
    cleaned = cleaned.map(v => byLowerCase.get(v.toLowerCase()) as string);
  }
  cleaned = Array.from(new Set(cleaned));
  if (cleaned.length === 0) {
    return param.optional ? { literal: 'set()' } : { error: 'Enter at least one value.' };
  }
  return { literal: `{${cleaned.map(v => JSON.stringify(v)).join(', ')}}` };
}

/** Minutes since midnight of an `HH:MM` time, or null for anything else. */
function minutesOfDay(value: unknown): number | null {
  const match = typeof value === 'string' ? /^(\d{1,2}):(\d{2})$/.exec(value.trim()) : null;
  if (!match) return null;
  const [hours, minutes] = [Number(match[1]), Number(match[2])];
  return hours < 24 && minutes < 60 ? hours * 60 + minutes : null;
}

/**
 * The canonical spelling of an IANA time zone name, or null for a name that isn't one. Browsers
 * also accept UTC offsets such as `+01:00`, which the gateway's Regorus (chrono-tz) rejects, so
 * a name must start with a letter and hold no `:`.
 */
function canonicalTimeZone(name: string): string | null {
  const ianaName = (zone: string) => /^[A-Za-z]/.test(zone) && !zone.includes(':');
  if (!ianaName(name)) return null;
  try {
    const zone = new Intl.DateTimeFormat('en-US', { timeZone: name }).resolvedOptions().timeZone;
    return ianaName(zone) ? zone : null;
  } catch {
    return null;
  }
}

export interface RenderResult {
  /** The module with every setting filled in, or null while any setting is invalid. */
  rego: string | null;
  errors: Record<string, string>;
}

export function renderTemplate(template: PolicyTemplate, values: ParameterValues): RenderResult {
  const errors: Record<string, string> = {};
  const literals = new Map<string, string>();
  for (const param of template.parameters) {
    const result = toRegoLiteral(param, values[param.key] ?? param.default);
    if ('error' in result) {
      errors[param.key] = result.error;
      continue;
    }
    literals.set(param.key, result.literal);
  }
  for (const param of template.parameters) {
    if (param.kind !== 'time_of_day' || !param.differs_from) continue;
    const other = template.parameters.find(p => p.key === param.differs_from);
    if (!other || errors[param.key] || errors[other.key]) continue;
    if (literals.get(param.key) === literals.get(other.key)) {
      errors[param.key] = `Must differ from ${other.label}.`;
    }
  }
  if (Object.keys(errors).length > 0) return { rego: null, errors };
  const rego = template.rego.replace(
    /\{\{([^{}]+)\}\}/g,
    (placeholder, key: string) => literals.get(key) ?? placeholder
  );
  return { rego, errors };
}

/** The decision a module gives when no rule matches; a module without a default denies. */
export function defaultDecision(rego: string): PolicyDecision {
  return explicitDefault(rego) ?? 'deny';
}

/**
 * `policy` for a template meant to be the whole policy: a standalone one, one for MCP tool
 * bindings, or one that adds no rules past its `default allow` line. Only `rules` templates can
 * be added to a policy.
 */
export function templateRole(template: PolicyTemplate): 'policy' | 'rules' {
  if (template.standalone || template.policy_input === 'mcp_tool') return 'policy';
  return insertTemplateRules('', template.name, template.rego).added.trim() ? 'rules' : 'policy';
}

function explicitDefault(rego: string): PolicyDecision | null {
  const match = rego.match(DEFAULT_ALLOW_LINE);
  if (!match) return null;
  return match[1] === 'true' ? 'allow' : 'deny';
}

function trimBlankLines(lines: string[]): string[] {
  let start = 0;
  let end = lines.length;
  while (start < end && !lines[start].trim()) start++;
  while (end > start && !lines[end - 1].trim()) end--;
  return lines.slice(start, end);
}

export interface InsertResult {
  policy: string;
  /** The rule lines appended to the policy. */
  added: string;
}

/**
 * Appends a template's rules to an existing module between begin and end comments naming the
 * template. The template's `default allow` line is never copied, and its `package` line only
 * when the module has none; its imports go after the `package` line unless already present.
 */
export function insertTemplateRules(
  existingPolicy: string,
  templateName: string,
  templateRego: string
): InsertResult {
  const templateLines = templateRego.split('\n');
  const existingImports = new Set(
    existingPolicy
      .split('\n')
      .filter(l => IMPORT_LINE.test(l))
      .map(l => l.trim())
  );
  const newImports = templateLines
    .filter(l => IMPORT_LINE.test(l))
    .map(l => l.trim())
    .filter(l => !existingImports.has(l));
  const body = trimBlankLines(
    templateLines.filter(
      l => !PACKAGE_LINE.test(l) && !IMPORT_LINE.test(l) && !DEFAULT_ALLOW_LINE.test(l)
    )
  );
  const added = body.join('\n');

  const existingLines = existingPolicy.trim() ? existingPolicy.replace(/\s+$/, '').split('\n') : [];
  if (!existingLines.some(l => PACKAGE_LINE.test(l))) {
    const templatePackage = templateLines.find(l => PACKAGE_LINE.test(l));
    if (templatePackage) existingLines.unshift(templatePackage.trim(), '');
  }
  if (newImports.length > 0) {
    const packageIndex = existingLines.findIndex(l => PACKAGE_LINE.test(l));
    existingLines.splice(packageIndex + 1, 0, ...newImports);
  }
  const safeName = templateName.replace(LINE_BREAKS, ' ').trim();
  const policy = `${existingLines.join('\n').replace(/\s+$/, '')}\n\n${TEMPLATE_BEGIN_PREFIX}${safeName}\n${added}\n${TEMPLATE_END_PREFIX}${safeName}\n`;

  return { policy, added };
}
