import { parseListInput, renderTemplate, sampleOf } from './regoTemplate';
import type { FieldText, ParameterValues, PolicyTemplate } from './types';

const asText = (value: number | string | string[]) =>
  Array.isArray(value) ? value.join(', ') : String(value);

/** Each setting's default as the field shows it, a list joined with commas. */
export function initialFieldText(template: PolicyTemplate): FieldText {
  return Object.fromEntries(template.parameters.map(p => [p.key, asText(p.default)]));
}

/** A deployment-specific setting's sample as its field's placeholder, such as `e.g. admin`. */
export function samplePlaceholder(template: PolicyTemplate, key: string): string | undefined {
  const param = template.parameters.find(p => p.key === key);
  const sample = param && sampleOf(param);
  return sample === undefined ? undefined : `e.g. ${asText(sample)}`;
}

/** The deployment-specific settings still empty, which block Use and Add to policy. */
export function missingSettings(template: PolicyTemplate, text: FieldText): Set<string> {
  return new Set(
    template.parameters
      .filter(p => {
        if (sampleOf(p) === undefined) return false;
        const raw = text[p.key] ?? '';
        return p.kind === 'string_list' ? parseListInput(raw).length === 0 : raw.trim() === '';
      })
      .map(p => p.key)
  );
}

function valuesFromText(template: PolicyTemplate, text: FieldText): ParameterValues {
  return Object.fromEntries(
    template.parameters.map(p => {
      const raw = text[p.key] ?? '';
      if (p.kind === 'integer') return [p.key, raw.trim() ? Number(raw) : NaN];
      return [p.key, p.kind === 'string_list' ? parseListInput(raw) : raw];
    })
  );
}

/** The Rego a template renders to with its settings as typed. */
export function renderWithText(template: PolicyTemplate, text: FieldText) {
  return renderTemplate(template, valuesFromText(template, text));
}

/**
 * The Rego to preview: the settings as typed, with each empty deployment-specific setting's
 * sample in its place. Only previews use it; Use and Add to policy write `renderWithText`.
 */
export function renderPreview(template: PolicyTemplate, text: FieldText) {
  const missing = missingSettings(template, text);
  const filled = Object.fromEntries(
    template.parameters.map(p => {
      const sample = sampleOf(p);
      return [p.key, missing.has(p.key) && sample !== undefined ? asText(sample) : text[p.key]];
    })
  );
  return { ...renderWithText(template, filled), usesSamples: missing.size > 0 };
}
