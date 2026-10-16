/**
 * Reads template variables with the gateway's placeholder syntax: ${VARIABLE}, or
 * ${VARIABLE:Label} where the label is only a hint.
 */

export interface TemplateVariable {
  name: string;
  label?: string;
}

// The placeholder syntax; the integrations catalog replaces it with the gateway's own.
let VARIABLE_PATTERN = /\$\{([^:}]+)(?::([^}]+))?\}/g;

/**
 * Use the placeholder syntax the integrations catalog gives, a regular expression whose first
 * group is the variable name.
 */
export function setVariablePattern(pattern: string): void {
  try {
    VARIABLE_PATTERN = new RegExp(pattern, 'g');
  } catch (error) {
    console.warn('[templateVariables] Invalid variable pattern, keeping the current one:', error);
  }
}

/** Every variable a template string uses, once each, sorted by name. */
export function extractAllTemplateVariables(template: string): TemplateVariable[] {
  const regex = new RegExp(VARIABLE_PATTERN.source, 'g');
  const matches = new Map<string, TemplateVariable>();
  let match;

  while ((match = regex.exec(template)) !== null) {
    const name = match[1].trim();
    const label = match[2]?.trim();
    if (name) {
      matches.set(name, { name, label });
    }
  }

  return Array.from(matches.values()).sort((a, b) => a.name.localeCompare(b.name));
}
