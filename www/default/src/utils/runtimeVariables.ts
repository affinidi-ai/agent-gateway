/**
 * Runtime Variables Utility
 *
 * This module provides access to runtime variables available for integration templates.
 * The variables are fetched from the backend to ensure consistency between what the
 * frontend displays and what the backend can actually substitute at runtime.
 */

import { apiClient } from '../api';

export interface RuntimeVariable {
  name: string;
  label: string;
  description: string;
  example: string;
  category: string;
}

export interface RuntimeVariableCategory {
  category: string;
  label: string;
  description: string;
  variables: RuntimeVariable[];
}

export interface RuntimeVariablesResponse {
  categories: RuntimeVariableCategory[];
}

// Cache for runtime variables
let runtimeVariablesCache: RuntimeVariablesResponse | null = null;
let fetchPromise: Promise<RuntimeVariablesResponse> | null = null;

/**
 * Fetches runtime variables from the backend.
 * Results are cached to avoid repeated API calls.
 */
export async function fetchRuntimeVariables(): Promise<RuntimeVariablesResponse> {
  // Return cached data if available
  if (runtimeVariablesCache) {
    return runtimeVariablesCache;
  }

  // Return existing promise if fetch is in progress
  if (fetchPromise) {
    return fetchPromise;
  }

  // Fetch from backend
  fetchPromise = apiClient
    .get('/integrations/runtime-variables')
    .then(response => {
      runtimeVariablesCache = response.data;
      fetchPromise = null;
      return response.data;
    })
    .catch(error => {
      fetchPromise = null;
      console.warn('[fetchRuntimeVariables] API call failed, using fallback variables:', error);
      const fallback = getFallbackRuntimeVariables();
      console.log(
        '[fetchRuntimeVariables] Fallback categories:',
        fallback.categories.map(c => c.category)
      );
      return fallback;
    });

  return fetchPromise;
}

/**
 * Gets runtime variables for a specific category
 */
export async function getRuntimeVariablesForCategory(
  categoryName: string
): Promise<Record<string, { label: string; example: string; description?: string }>> {
  const data = await fetchRuntimeVariables();
  const category = data.categories.find(c => c.category === categoryName);

  if (!category) {
    return {};
  }

  const variables: Record<string, { label: string; example: string; description?: string }> = {};
  category.variables.forEach(v => {
    variables[v.name] = {
      label: v.label,
      example: v.example,
      description: v.description,
    };
  });

  return variables;
}

/**
 * Gets runtime variables for multiple categories (e.g., general + specific category)
 * This is useful for showing all variables available to a integration of a certain category
 */
export async function getRuntimeVariablesForCategories(
  categoryNames: string[]
): Promise<Record<string, { label: string; example: string; description?: string }>> {
  const data = await fetchRuntimeVariables();
  const variables: Record<string, { label: string; example: string; description?: string }> = {};

  categoryNames.forEach(categoryName => {
    const category = data.categories.find(c => c.category === categoryName);
    if (category) {
      category.variables.forEach(v => {
        variables[v.name] = {
          label: v.label,
          example: v.example,
          description: v.description,
        };
      });
    }
  });

  return variables;
}

/**
 * Clears the runtime variables cache.
 * Useful if you need to force a refresh.
 */
export function clearRuntimeVariablesCache(): void {
  runtimeVariablesCache = null;
  fetchPromise = null;
}

/**
 * Fallback runtime variables when backend API is not available yet.
 * This ensures the frontend works even if the backend endpoint isn't implemented.
 *
 * TODO: Remove this once backend API is fully implemented.
 */
function getFallbackRuntimeVariables(): RuntimeVariablesResponse {
  return {
    categories: [
      {
        category: 'general',
        label: 'General',
        description: 'Variables available to all integrations regardless of category',
        variables: [
          {
            name: 'TIMESTAMP',
            label: 'Timestamp',
            description: 'Current timestamp in ISO 8601 format',
            example: '$TIMESTAMP',
            category: 'general',
          },
          {
            name: 'EVENT_TYPE',
            label: 'Event Type',
            description: 'Type of event that triggered the integration',
            example: '$EVENT_TYPE',
            category: 'general',
          },
          {
            name: 'MESSAGE_ID',
            label: 'Message ID',
            description: 'Unique identifier for the message/event',
            example: '$MESSAGE_ID',
            category: 'general',
          },
        ],
      },
      {
        category: 'connection_point',
        label: 'Connection Point',
        description:
          'Variables available when notifications are triggered from connection point events',
        variables: [
          {
            name: 'CP_ID',
            label: 'Connection Point ID',
            description: 'Unique identifier of the connection point',
            example: '$CP_ID',
            category: 'connection_point',
          },
          {
            name: 'CP_NAME',
            label: 'Connection Point Name',
            description: 'Display name of the connection point',
            example: '$CP_NAME',
            category: 'connection_point',
          },
          {
            name: 'CP_DESCRIPTION',
            label: 'Connection Point Description',
            description: 'Description of the connection point',
            example: '$CP_DESCRIPTION',
            category: 'connection_point',
          },
          {
            name: 'GATEWAY',
            label: 'Gateway Name',
            description: 'Name of the associated gateway',
            example: '$GATEWAY',
            category: 'connection_point',
          },
          {
            name: 'GATEWAY_ID',
            label: 'Gateway ID',
            description: 'Unique identifier of the gateway',
            example: '$GATEWAY_ID',
            category: 'connection_point',
          },
          {
            name: 'TIMESTAMP',
            label: 'Timestamp',
            description: 'Current timestamp in ISO 8601 format',
            example: '$TIMESTAMP',
            category: 'connection_point',
          },
          {
            name: 'MESSAGE_ID',
            label: 'Message ID',
            description: 'Unique identifier for the message/event',
            example: '$MESSAGE_ID',
            category: 'connection_point',
          },
        ],
      },
      {
        category: 'user',
        label: 'User Management',
        description:
          'Variables available when notifications are triggered from user management events',
        variables: [
          {
            name: 'USER_ID',
            label: 'User ID',
            description: 'Unique identifier of the user',
            example: '$USER_ID',
            category: 'user',
          },
          {
            name: 'USERNAME',
            label: 'Username',
            description: 'Username of the user',
            example: '$USERNAME',
            category: 'user',
          },
          {
            name: 'USER_EMAIL',
            label: 'User Email',
            description: 'Email address of the user',
            example: '$USER_EMAIL',
            category: 'user',
          },
          {
            name: 'USER_ROLE',
            label: 'User Role',
            description: 'Role assigned to the user (administrator, poweruser, user)',
            example: '$USER_ROLE',
            category: 'user',
          },
          {
            name: 'USER_STATUS',
            label: 'User Status',
            description: 'Current status of the user (new, approved, disabled)',
            example: '$USER_STATUS',
            category: 'user',
          },
          {
            name: 'EVENT_TYPE',
            label: 'Event Type',
            description:
              'Type of user event (user.created, user.approved, user.updated, user.deleted, user.login)',
            example: '$EVENT_TYPE',
            category: 'user',
          },
          {
            name: 'TIMESTAMP',
            label: 'Timestamp',
            description: 'Current timestamp in ISO 8601 format',
            example: '$TIMESTAMP',
            category: 'user',
          },
        ],
      },
      {
        category: 'gateway',
        label: 'Gateway',
        description: 'Variables available when notifications are triggered from gateway events',
        variables: [
          {
            name: 'GATEWAY_ID',
            label: 'Gateway ID',
            description: 'Unique identifier of the gateway',
            example: '$GATEWAY_ID',
            category: 'gateway',
          },
          {
            name: 'GATEWAY_NAME',
            label: 'Gateway Name',
            description: 'Display name of the gateway',
            example: '$GATEWAY_NAME',
            category: 'gateway',
          },
          {
            name: 'GATEWAY_STATUS',
            label: 'Gateway Status',
            description: 'Current status of the gateway',
            example: '$GATEWAY_STATUS',
            category: 'gateway',
          },
          {
            name: 'EVENT_TYPE',
            label: 'Event Type',
            description: 'Type of gateway event',
            example: '$EVENT_TYPE',
            category: 'gateway',
          },
          {
            name: 'TIMESTAMP',
            label: 'Timestamp',
            description: 'Current timestamp in ISO 8601 format',
            example: '$TIMESTAMP',
            category: 'gateway',
          },
        ],
      },
      {
        category: 'surface',
        label: 'Surface',
        description:
          'Variables available when notifications are triggered from Agent Surface events',
        variables: [
          {
            name: 'SURFACE_ID',
            label: 'Surface ID',
            description: 'Unique identifier of the Agent Surface',
            example: '$SURFACE_ID',
            category: 'surface',
          },
          {
            name: 'SURFACE_NAME',
            label: 'Surface Name',
            description: 'Display name of the Agent Surface',
            example: '$SURFACE_NAME',
            category: 'surface',
          },
          {
            name: 'SURFACE_PROTOCOL',
            label: 'Surface Protocol',
            description: 'Protocol type (a2a, mcp)',
            example: '$SURFACE_PROTOCOL',
            category: 'surface',
          },
          {
            name: 'EVENT_TYPE',
            label: 'Event Type',
            description: 'Type of Agent Surface event',
            example: '$EVENT_TYPE',
            category: 'surface',
          },
          {
            name: 'TIMESTAMP',
            label: 'Timestamp',
            description: 'Current timestamp in ISO 8601 format',
            example: '$TIMESTAMP',
            category: 'surface',
          },
        ],
      },
    ],
  };
}
