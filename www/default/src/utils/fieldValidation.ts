/**
 * Utility functions for validating fields containing template variables
 */

import { extractAllTemplateVariables } from './templateVariables';

/**
 * Check if a field value contains missing variables
 * @param value - The field value to check
 * @param validRuntimeVars - Set of valid runtime variable names
 * @param customPrefix - Prefix for custom variables (default: '_')
 * @returns true if the field contains missing variables
 */
export function fieldHasMissingVariables(
  value: string,
  validRuntimeVars: Set<string>,
  customPrefix: string = '_'
): boolean {
  if (!value) return false;

  const variables = extractAllTemplateVariables(value);

  for (const varInfo of variables) {
    // Skip custom variables (they're always valid)
    if (varInfo.name.startsWith(customPrefix)) {
      continue;
    }

    // Check if runtime variable is valid
    if (!validRuntimeVars.has(varInfo.name)) {
      return true; // Found a missing variable
    }
  }

  return false;
}

/**
 * Get CSS class names for a field based on whether it has missing variables
 * @param baseClass - Base CSS class name
 * @param hasMissingVars - Whether the field has missing variables
 * @returns Combined CSS class names
 */
export function getFieldClassName(baseClass: string, hasMissingVars: boolean): string {
  return hasMissingVars ? `${baseClass} is-invalid` : baseClass;
}
