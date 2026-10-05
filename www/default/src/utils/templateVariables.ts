/**
 * Utility functions for extracting and working with template variables
 * Supports formats: ${VARIABLE} or ${VARIABLE:Label}
 */

import { apiClient } from '../api';

export interface TemplateVariable {
  name: string;
  label?: string;
}

// Global variable patterns loaded from config
let VARIABLE_PATTERN = /\$\{([^:}]+)(?::([^}]+))?\}/g;
let CUSTOM_VARIABLE_PREFIX = '_';

// Flag to track if patterns have been loaded
let patternsLoaded = false;

/**
 * Load variable patterns from the backend config
 * This should be called once during app initialization
 */
export async function loadVariablePatterns(): Promise<void> {
  if (patternsLoaded) return;

  try {
    const response = await apiClient.fetch('/api/v1/integrations/config');
    if (response.ok) {
      const config = await response.json();
      if (config.variable_pattern) {
        // Convert regex string from backend to JavaScript RegExp
        // Backend sends escaped pattern like "\\$\\{([^:}]+)(?::([^}]+))?\\}"
        // We need to unescape it for JavaScript
        const patternStr = config.variable_pattern.replace(/\\\\/g, '\\');
        VARIABLE_PATTERN = new RegExp(patternStr, 'g');
      }
      if (config.custom_variable_prefix) {
        CUSTOM_VARIABLE_PREFIX = config.custom_variable_prefix;
      }
      patternsLoaded = true;
    }
  } catch (error) {
    console.warn(
      '[templateVariables] Failed to load variable patterns from config, using defaults:',
      error
    );
    // Keep using defaults
    patternsLoaded = true;
  }
}

/**
 * Get the current variable pattern (for testing/debugging)
 */
export function getVariablePattern(): RegExp {
  return VARIABLE_PATTERN;
}

/**
 * Get the custom variable prefix (for testing/debugging)
 */
export function getCustomVariablePrefix(): string {
  return CUSTOM_VARIABLE_PREFIX;
}

/**
 * Extract ALL template variables from a string (including runtime and custom variables)
 * @param template - The template string to extract variables from
 * @returns Array of all variables with their names and optional labels
 */
export function extractAllTemplateVariables(template: string): TemplateVariable[] {
  // Create a new RegExp instance with the global pattern
  const regex = new RegExp(VARIABLE_PATTERN.source, 'g');
  const matches = new Map<string, TemplateVariable>();
  let match;

  while ((match = regex.exec(template)) !== null) {
    // Remove any leading $ if present (for migration from old format)
    const varName = match[1].replace(/^\$/, '').trim();
    const label = match[2]?.trim(); // Optional label after colon

    if (varName) {
      matches.set(varName, { name: varName, label });
    }
  }

  return Array.from(matches.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Extract template variables from a string
 * @param template - The template string to extract variables from
 * @returns Array of custom variables (those starting with custom_variable_prefix) with their names and optional labels
 */
export function extractTemplateVariables(template: string): TemplateVariable[] {
  // Create a new RegExp instance with the global pattern
  const regex = new RegExp(VARIABLE_PATTERN.source, 'g');
  const matches = new Map<string, TemplateVariable>();
  let match;

  while ((match = regex.exec(template)) !== null) {
    // Remove any leading $ if present (for migration from old format)
    const varName = match[1].replace(/^\$/, '').trim();
    const label = match[2]?.trim(); // Optional label after colon

    // Only include custom variables (those starting with the custom prefix)
    // Runtime variables (like TIMESTAMP, CP_NAME, etc.) are auto-populated and don't need user input
    if (varName && varName.startsWith(CUSTOM_VARIABLE_PREFIX)) {
      matches.set(varName, { name: varName, label });
    }
  }

  return Array.from(matches.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Extract template variable names only from a string
 * @param template - The template string to extract variables from
 * @returns Array of variable names (without labels)
 */
export function extractTemplateVariableNames(template: string): string[] {
  return extractTemplateVariables(template).map(v => v.name);
}

/**
 * Extract template variables from an object (recursively searches all string values)
 * @param content - Object containing template strings
 * @returns Array of unique variable names
 */
export function extractTemplateVariablesFromObject(content: any): string[] {
  const variables = new Set<string>();

  const extractFromValue = (value: any) => {
    if (typeof value === 'string') {
      const vars = extractTemplateVariableNames(value);
      vars.forEach(v => variables.add(v));
    } else if (typeof value === 'object' && value !== null) {
      // Recursively search nested objects and arrays
      Object.values(value).forEach(nestedValue => {
        extractFromValue(nestedValue);
      });
    }
  };

  extractFromValue(content);

  return Array.from(variables).sort();
}

/**
 * Extract ALL template variables with labels from an object (recursively searches all string values)
 * @param content - Object containing template strings
 * @returns Array of unique TemplateVariable objects with names and labels (includes ALL variables)
 */
export function extractAllTemplateVariablesWithLabelsFromObject(content: any): TemplateVariable[] {
  const variablesMap = new Map<string, TemplateVariable>();

  const extractFromValue = (value: any) => {
    if (typeof value === 'string') {
      const vars = extractAllTemplateVariables(value);
      vars.forEach(v => {
        // If variable already exists and has a label, keep it
        const existing = variablesMap.get(v.name);
        if (!existing || !existing.label) {
          variablesMap.set(v.name, v);
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      // Recursively search nested objects and arrays
      Object.values(value).forEach(nestedValue => {
        extractFromValue(nestedValue);
      });
    }
  };

  extractFromValue(content);

  return Array.from(variablesMap.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Extract template variables with labels from an object (recursively searches all string values)
 * @param content - Object containing template strings
 * @returns Array of unique TemplateVariable objects with names and labels (ONLY custom variables starting with _)
 */
export function extractTemplateVariablesWithLabelsFromObject(content: any): TemplateVariable[] {
  const variablesMap = new Map<string, TemplateVariable>();

  const extractFromValue = (value: any) => {
    if (typeof value === 'string') {
      const vars = extractTemplateVariables(value);
      vars.forEach(v => {
        // If variable already exists and has a label, keep it
        const existing = variablesMap.get(v.name);
        if (!existing || !existing.label) {
          variablesMap.set(v.name, v);
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      // Recursively search nested objects and arrays
      Object.values(value).forEach(nestedValue => {
        extractFromValue(nestedValue);
      });
    }
  };

  extractFromValue(content);

  return Array.from(variablesMap.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Substitute variables in a template string
 * @param template - Template string with ${VARIABLE} or ${VARIABLE:Label} placeholders
 * @param variables - Object mapping variable names to their values
 * @returns Template with variables replaced by their values
 */
export function substituteTemplateVariables(
  template: string,
  variables: Record<string, string>
): string {
  // Create a new RegExp instance with the global pattern
  const regex = new RegExp(VARIABLE_PATTERN.source, 'g');
  return template.replace(regex, (match, varName) => {
    const cleanVarName = varName.trim();
    return variables[cleanVarName] || match; // Keep original if no value provided
  });
}

/**
 * Get default test value for a template variable
 * @param varName - The variable name
 * @returns A sensible default test value for the variable
 */
export function getDefaultVariableValue(varName: string): string {
  const defaults: Record<string, string> = {
    CP_NAME: 'Test Connection Point',
    MESSAGE_ID: 'test-msg-' + Date.now(),
    TIMESTAMP: new Date().toISOString(),
    MEDIATOR: 'Test Mediator',
    GATEWAY: 'Test Gateway',
    CP_ID: 'test-cp-id',
    CP_DESCRIPTION: 'Test connection point description',
    GATEWAY_ID: 'test-gateway-id',
    MEDIATOR_ID: 'test-mediator-id',
    MESSAGE_TYPE: 'test-message',
    FROM_DID: 'did:example:test',
    SUBJECT: 'Test Notification',
    MESSAGE: 'This is a test notification from Agent Gateway',
  };

  // For custom variables (starting with _), remove the leading underscore in the test value
  const displayName = varName.startsWith('_') ? varName.substring(1) : varName;
  return defaults[varName] || `test-${displayName.toLowerCase()}`;
}

/**
 * Create a test variables object for a list of variable names
 * @param variableNames - Array of variable names
 * @returns Object mapping each variable name to its default test value
 */
export function createTestVariables(variableNames: string[]): Record<string, string> {
  return variableNames.reduce(
    (acc, varName) => {
      acc[varName] = getDefaultVariableValue(varName);
      return acc;
    },
    {} as Record<string, string>
  );
}

/**
 * Get success message for a integration test based on type
 * @param integrationType - The type of integration (email, slack, webhook, etc.)
 * @returns User-friendly success message
 */
export function getNotifierTestSuccessMessage(notifierType: string): string {
  const messages: Record<string, string> = {
    email: 'Test email sent successfully! Check your inbox.',
    slack: 'Test notification sent successfully! Check your Slack channel.',
    webhook: 'Test webhook sent successfully!',
    stream: 'Test stream event published successfully!',
  };

  return messages[notifierType] || 'Test notification sent successfully!';
}
