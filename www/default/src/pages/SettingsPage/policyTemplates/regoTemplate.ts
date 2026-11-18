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
  if (cleaned.length === 0) return { error: 'Enter at least one value.' };
  return { literal: `{${cleaned.map(v => JSON.stringify(v)).join(', ')}}` };
}

/** The canonical spelling of an IANA time zone name, or null for a name that isn't one. */
function canonicalTimeZone(name: string): string | null {
  try {
    return new Intl.DateTimeFormat('en-US', { timeZone: name }).resolvedOptions().timeZone;
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
  let rego = template.rego;
  for (const param of template.parameters) {
    const result = toRegoLiteral(param, values[param.key] ?? param.default);
    if ('error' in result) {
      errors[param.key] = result.error;
      continue;
    }
    rego = rego.split(`{{${param.key}}}`).join(result.literal);
  }
  for (const param of template.parameters) {
    if (param.kind !== 'integer' || !param.after || errors[param.key] || errors[param.after]) {
      continue;
    }
    const earlier = template.parameters.find(p => p.key === param.after);
    const value = values[param.key] ?? param.default;
    const earlierValue = earlier ? (values[earlier.key] ?? earlier.default) : undefined;
    if (
      earlier &&
      typeof earlierValue === 'number' &&
      typeof value === 'number' &&
      value <= earlierValue
    ) {
      errors[param.key] = `Must be later than ${earlier.label}.`;
    }
  }
  return { rego: Object.keys(errors).length > 0 ? null : rego, errors };
}

/** The decision a module gives when no rule matches; a module without a default denies. */
export function defaultDecision(rego: string): PolicyDecision {
  return explicitDefault(rego) ?? 'deny';
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
  /** Whether the template's own `default allow` line was left out. */
  droppedDefault: boolean;
  /** The existing policy's `default allow`, or null when it has none. */
  existingDefault: PolicyDecision | null;
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
  const droppedDefault = templateLines.some(l => DEFAULT_ALLOW_LINE.test(l));
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

  return { policy, added, droppedDefault, existingDefault: explicitDefault(existingPolicy) };
}
