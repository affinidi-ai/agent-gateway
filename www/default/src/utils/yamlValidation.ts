/**
 * Utility functions for YAML validation
 */

import * as yaml from 'js-yaml';
import { apiClient } from '../api';

export interface YamlValidationResult {
  valid: boolean;
  error?: string;
}

export interface OpenApiValidationResult {
  valid: boolean;
  error?: string;
  tools_count?: number;
  message?: string;
}

/**
 * Perform basic client-side YAML validation
 * @param yamlContent - The YAML content to validate
 * @returns Validation result with valid flag and optional error message
 */
export function validateYamlBasic(yamlContent: string): YamlValidationResult {
  if (!yamlContent || !yamlContent.trim()) {
    return {
      valid: false,
      error: 'YAML content is empty',
    };
  }

  // Check if it looks like YAML (has proper structure with colons)
  if (!yamlContent.includes(':')) {
    return {
      valid: false,
      error: 'Invalid YAML format. Must contain key-value pairs.',
    };
  }

  // Try to parse the YAML to validate syntax
  try {
    yaml.load(yamlContent);
    return { valid: true };
  } catch (error: any) {
    return {
      valid: false,
      error: `YAML syntax error: ${error.message}`,
    };
  }
}

/**
 * Perform basic client-side OpenAPI specification validation
 * @param openApiSpec - The OpenAPI specification in YAML format
 * @returns Validation result with valid flag and optional error message
 */
export function validateOpenApiSpecBasic(openApiSpec: string): YamlValidationResult {
  // First check basic YAML validity
  const yamlResult = validateYamlBasic(openApiSpec);
  if (!yamlResult.valid) {
    return yamlResult;
  }

  // Check for OpenAPI-specific requirements
  if (!openApiSpec.includes('openapi')) {
    return {
      valid: false,
      error: 'Invalid OpenAPI specification. Must include "openapi" version field.',
    };
  }

  if (!openApiSpec.includes('paths')) {
    return {
      valid: false,
      error: 'Invalid OpenAPI specification. Must include "paths" section.',
    };
  }

  return { valid: true };
}

/**
 * Validate OpenAPI specification using the backend API
 * @param openApiSpec - The OpenAPI specification in YAML format
 * @param baseUrl - The base URL of the REST API
 * @returns Promise resolving to validation result from server
 */
export async function validateOpenApiSpecServer(
  openApiSpec: string,
  baseUrl: string
): Promise<OpenApiValidationResult> {
  try {
    const response = await apiClient.post('/mcp-proxies/validate', {
      openapi_spec: openApiSpec,
      base_url: baseUrl,
    });
    return response.data;
  } catch (error: any) {
    return {
      valid: false,
      error: error.message || 'Failed to validate OpenAPI specification',
    };
  }
}

/**
 * Check if a filename has a valid YAML extension
 * @param filename - The filename to check
 * @returns true if the file has a .yml, .yaml, or .txt extension
 */
export function isYamlFile(filename: string): boolean {
  const lowerName = filename.toLowerCase();
  return lowerName.endsWith('.yml') || lowerName.endsWith('.yaml') || lowerName.endsWith('.txt');
}
