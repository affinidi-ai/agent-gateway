import { parseListInput, renderTemplate } from './regoTemplate';
import type { FieldText, ParameterValues, PolicyTemplate } from './types';

/** Each setting's default as the field shows it, a list joined with commas. */
export function initialFieldText(template: PolicyTemplate): FieldText {
  return Object.fromEntries(
    template.parameters.map(p => [
      p.key,
      p.kind === 'string_list' ? p.default.join(', ') : String(p.default),
    ])
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
