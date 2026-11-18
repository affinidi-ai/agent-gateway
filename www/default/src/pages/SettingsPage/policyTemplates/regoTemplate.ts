import type {
  ParameterValues,
  PolicyDecision,
  PolicyTemplate,
  PolicyTemplateParameter,
} from './types';

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
    return { literal: JSON.stringify(text) };
  }
  const items = Array.isArray(value) ? value : [];
  const cleaned = Array.from(
    new Set(items.map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean))
  );
  if (cleaned.length === 0) return { error: 'Enter at least one value.' };
  return { literal: `{${cleaned.map(v => JSON.stringify(v)).join(', ')}}` };
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
 * Appends a template's rules to an existing module. The template's `package` and
 * `default allow` lines are never copied, since a module has one of each; its imports go
 * after the existing `package` line unless the policy already has them.
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

  const existingLines = existingPolicy.replace(/\s+$/, '').split('\n');
  if (newImports.length > 0) {
    const packageIndex = existingLines.findIndex(l => PACKAGE_LINE.test(l));
    existingLines.splice(packageIndex + 1, 0, ...newImports);
  }
  const safeName = templateName.replace(LINE_BREAKS, ' ').trim();
  const policy = `${existingLines.join('\n')}\n\n# Inserted from template: ${safeName}\n${added}\n`;

  return { policy, added, droppedDefault, existingDefault: explicitDefault(existingPolicy) };
}
