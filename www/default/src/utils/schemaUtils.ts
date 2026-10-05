/**
 * JSON Schema generation utilities
 * Protocol-aware logic for deriving JSON schemas from payload structures
 */

/**
 * Protocol type for routing schema extraction
 */
export type ProtocolType = 'a2a' | 'ap2' | 'mcp' | 'ucp' | 'unknown';

/**
 * Protocol-specific identity extension URIs
 */
const PROTOCOL_IDENTITY_EXTENSIONS = {
  a2a: 'https://fabric.affinidi.io/extensions/agent-identity/v1',
  ap2: 'https://fabric.affinidi.io/extensions/agent-identity/v1',
  ucp: 'https://fabric.affinidi.io/extensions/agent-identity/v1',
};

/**
 * Generate a JSON schema from a JSON payload
 * Inspects the payload structure and generates a matching schema
 */
export const generateSchemaFromPayload = (payload: any): string => {
  const inferType = (value: any): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  };

  const buildSchemaFromObject = (obj: any): any => {
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
      return { type: inferType(obj) };
    }

    const properties: any = {};
    const required: string[] = [];

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        const firstItem = value.length > 0 ? value[0] : null;
        properties[key] = {
          type: 'array',
          items:
            typeof firstItem === 'object' && firstItem !== null && !Array.isArray(firstItem)
              ? buildSchemaFromObject(firstItem)
              : { type: inferType(firstItem) },
        };
      } else if (typeof value === 'object' && value !== null) {
        properties[key] = buildSchemaFromObject(value);
      } else {
        properties[key] = { type: inferType(value) };
      }
      required.push(key);
    }

    return {
      type: 'object',
      properties,
      required,
    };
  };

  const schema = buildSchemaFromObject(payload);
  return JSON.stringify(schema, null, 2);
};

/**
 * A2A JSON-RPC method names in both protocol eras: the v0.3 slash-form and the
 * v1.0 PascalCase form. A2A 1.0 renamed every method, and Agent Gateway accepts
 * either spelling, so a captured payload can legitimately use either one.
 *
 * Mirrors the canonical table in `src/a2a/methods.rs`; keep the two in step.
 */
const A2A_METHODS = new Set([
  // v0.3 slash-form
  'message/send',
  'message/stream',
  'tasks/get',
  'tasks/list',
  'tasks/cancel',
  'tasks/resubscribe',
  'tasks/pushNotificationConfig/set',
  'tasks/pushNotificationConfig/get',
  'tasks/pushNotificationConfig/list',
  'tasks/pushNotificationConfig/delete',
  'agent/getAuthenticatedExtendedCard',
  // v1.0 PascalCase
  'SendMessage',
  'SendStreamingMessage',
  'GetTask',
  'ListTasks',
  'CancelTask',
  'SubscribeToTask',
  'CreateTaskPushNotificationConfig',
  'GetTaskPushNotificationConfig',
  'ListTaskPushNotificationConfigs',
  'DeleteTaskPushNotificationConfig',
  'GetExtendedAgentCard',
]);

/**
 * Detect protocol type from payload structure.
 *
 * Order matters, and the order is: AP2, then MCP's `_meta` container, then the
 * A2A method table, then a generic JSON-RPC fallback. Each step is justified at
 * its own branch below. A slash in the method name is not an MCP signal: A2A
 * v0.3 methods such as `message/send` contain one too.
 */
const detectProtocol = (payload: any): ProtocolType => {
  if (!payload || typeof payload !== 'object') return 'unknown';
  if (payload.jsonrpc !== '2.0') return 'unknown';

  const method = typeof payload.method === 'string' ? payload.method : undefined;

  // AP2 namespaces its methods, so it is unambiguous and is checked first.
  if (method?.startsWith('ap2.')) {
    return 'ap2';
  }

  // MCP carries its metadata in a `_meta` container, canonically under
  // `params._meta` and in legacy payloads at the top level. That container is an MCP-only
  // signal and must win before the A2A method table, because MCP's opt-in Tasks
  // extension defines `tasks/get`, `tasks/update` and `tasks/cancel`, two of
  // which collide with A2A v0.3's `tasks/get` and `tasks/cancel`. (`tasks/list`
  // is A2A-only, and `tasks/update` is MCP-only, so neither is ambiguous.) The
  // extension is negotiated through `params._meta`, so the container is exactly
  // the right tie-breaker: a client using MCP Tasks is required to send it.
  // This mirrors the backend, where MCP wire validation runs ahead of generic
  // method-prefix classification for the same reason.
  if (payload._meta || payload.params?._meta) {
    return 'mcp';
  }

  // A2A: a known method name in either era, or the A2A message envelope.
  // A `tasks/*` payload carrying no `_meta` at all is genuinely ambiguous, but
  // it also carries no identity metadata for either extractor to find, so the
  // resulting schema is empty whichever way it is labelled.
  if ((method && A2A_METHODS.has(method)) || payload.params?.message) {
    return 'a2a';
  }

  // Any other JSON-RPC payload carrying a method.
  if (method) {
    return 'mcp';
  }

  return 'unknown';
};

/**
 * Extract identity data from A2A/AP2/UCP protocol payload
 * These protocols use JSON-RPC 2.0 with params.message.metadata structure
 */
const extractIdentityFromJsonRpcProtocol = (
  payload: any,
  fieldName: string,
  protocol: ProtocolType
): any => {
  // Get the extension URI for this protocol
  const extensionUri =
    PROTOCOL_IDENTITY_EXTENSIONS[protocol as keyof typeof PROTOCOL_IDENTITY_EXTENSIONS];
  if (!extensionUri) return null;

  // Try params.message.metadata first (JSON-RPC wrapped format)
  const metadata =
    payload.params?.message?.metadata || payload.message?.metadata || payload.metadata;

  if (metadata && typeof metadata === 'object') {
    // Look for the extension URI. A2A/AP2 identity management validates the
    // extension payload itself; there is no `_meta.<fieldName>` layer like MCP.
    const extensionData = metadata[extensionUri];
    if (extensionData && typeof extensionData === 'object') {
      return extensionData;
    }

    // Fallback: check if the field exists directly in metadata.
    if (metadata[fieldName]) {
      return metadata[fieldName];
    }
  }

  return null;
};

/**
 * Extract identity data from MCP protocol payload
 * MCP uses _meta field for metadata
 */
const extractIdentityFromMcp = (payload: any, fieldName: string): any => {
  if (payload._meta && typeof payload._meta === 'object') {
    return payload._meta[fieldName] || null;
  }
  return null;
};

/**
 * Extract agentIdentity schema from a payload in the format needed for channel configuration
 * Returns a schema formatted for the channel edit request schema field
 * @param payload - The payload to extract the identity schema from
 * @param fieldName - The name of the identity field (defaults to 'agentIdentity')
 * @param protocol - Optional protocol type (will auto-detect if not provided)
 */
export const extractAgentIdentitySchema = (
  payload: any,
  fieldName: string = 'agentIdentity',
  protocol?: ProtocolType
): string => {
  // Auto-detect protocol if not provided
  const detectedProtocol = protocol || detectProtocol(payload);

  console.log(`[Schema Extraction] Protocol: ${detectedProtocol}, Field: ${fieldName}`);

  // Extract identity data based on protocol
  let identityData = null;

  switch (detectedProtocol) {
    case 'a2a':
    case 'ap2':
    case 'ucp':
      identityData = extractIdentityFromJsonRpcProtocol(payload, fieldName, detectedProtocol);
      console.log(
        `[Schema Extraction] ${detectedProtocol.toUpperCase()} - Identity found:`,
        !!identityData
      );
      break;

    case 'mcp':
      identityData = extractIdentityFromMcp(payload, fieldName);
      console.log(`[Schema Extraction] MCP - Identity found:`, !!identityData);
      break;

    default:
      // Fallback: try generic extraction
      console.log('[Schema Extraction] Unknown protocol - trying generic extraction');
      if (payload && typeof payload === 'object' && payload[fieldName]) {
        identityData = payload[fieldName];
      }
      break;
  }

  const usesMetaFieldWrapper = detectedProtocol === 'mcp';

  // If no identity data found, return empty schema
  if (!identityData) {
    return JSON.stringify(
      usesMetaFieldWrapper
        ? {
            type: 'object',
            properties: {
              [fieldName]: {
                type: 'object',
                properties: {},
              },
            },
            required: [] as string[],
          }
        : {
            type: 'object',
            properties: {},
            required: [] as string[],
          },
      null,
      2
    );
  }

  // Build schema from agentIdentity
  const inferType = (value: any): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  };

  const buildSchemaFromObject = (obj: any): any => {
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
      return { type: inferType(obj) };
    }

    const properties: any = {};
    const required: string[] = [];

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        const firstItem = value.length > 0 ? value[0] : null;
        properties[key] = {
          type: 'array',
          items:
            typeof firstItem === 'object' && firstItem !== null && !Array.isArray(firstItem)
              ? buildSchemaFromObject(firstItem)
              : { type: inferType(firstItem) },
        };
      } else if (typeof value === 'object' && value !== null) {
        properties[key] = buildSchemaFromObject(value);
      } else {
        properties[key] = { type: inferType(value) };
      }
      required.push(key);
    }

    return {
      type: 'object',
      properties,
      required,
    };
  };

  const agentIdentitySchema = buildSchemaFromObject(identityData);

  if (!usesMetaFieldWrapper) {
    return JSON.stringify(agentIdentitySchema, null, 2);
  }

  // Wrap in the channel configuration format used by MCP `_meta.<fieldName>` payloads.
  const channelSchema = {
    type: 'object',
    properties: {
      [fieldName]: agentIdentitySchema,
    },
    required: [] as string[],
  };

  return JSON.stringify(channelSchema, null, 2);
};
