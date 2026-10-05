export const HEADER_METADATA_EXTENSION_URI =
  'https://fabric.affinidi.io/extensions/header-metadata/v1';

export const COPILOT_HEADER_METADATA_PRESET = [
  { header: 'x-ms-entra-agent-id', field: 'entra_agent_id' },
  { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
  { header: 'x-ms-client-session-id', field: 'session_id' },
  { header: 'x-ms-correlation-id', field: 'correlation_id' },
  { header: 'x-ms-coreframework-caller-activity-id', field: 'activity_id' },
  { header: 'x-ms-apim-referrer', field: 'referrer' },
] as const;

export interface HeaderMetadataFieldMapping {
  header: string;
  field: string;
}

export interface HeaderMetadataMappingConfig {
  extension_uri?: string;
  headers?: HeaderMetadataFieldMapping[];
  strip_mapped_headers?: boolean;
}

export function isSensitiveMappedHeader(header: string): boolean {
  const normalized = header.trim().toLowerCase();
  return (
    normalized === 'authorization' ||
    normalized === 'proxy-authorization' ||
    normalized === 'cookie' ||
    normalized === 'set-cookie' ||
    normalized.includes('token') ||
    normalized.includes('secret') ||
    normalized.includes('credential') ||
    normalized.includes('api-key') ||
    normalized.includes('apikey')
  );
}

export function validateHeaderMetadataMapping(
  mapping: HeaderMetadataMappingConfig | undefined
): Array<{ field?: string; message: string }> {
  if (!mapping) return [];
  const errors: Array<{ field?: string; message: string }> = [];
  const uri = (mapping.extension_uri || '').trim();
  if (!uri) {
    errors.push({
      field: 'header_metadata_mapping.extension_uri',
      message: 'Extension URI is required',
    });
  } else {
    try {
      const parsed = new URL(uri);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        errors.push({
          field: 'header_metadata_mapping.extension_uri',
          message: 'Extension URI must be an absolute http(s) URI',
        });
      }
    } catch {
      errors.push({
        field: 'header_metadata_mapping.extension_uri',
        message: 'Extension URI must be an absolute http(s) URI',
      });
    }
  }

  const seenFields = new Set<string>();
  for (const [index, row] of (mapping.headers || []).entries()) {
    const header = (row.header || '').trim();
    const field = (row.field || '').trim();
    if (!header) {
      errors.push({
        field: `header_metadata_mapping.headers.${index}.header`,
        message: 'Header is required',
      });
    } else if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header)) {
      errors.push({
        field: `header_metadata_mapping.headers.${index}.header`,
        message: 'Header name is invalid',
      });
    } else if (isSensitiveMappedHeader(header)) {
      errors.push({
        field: `header_metadata_mapping.headers.${index}.header`,
        message: `Sensitive header '${header}' cannot be mapped`,
      });
    }
    if (!field) {
      errors.push({
        field: `header_metadata_mapping.headers.${index}.field`,
        message: 'Metadata field is required',
      });
    } else if (seenFields.has(field)) {
      errors.push({
        field: `header_metadata_mapping.headers.${index}.field`,
        message: `Duplicate metadata field '${field}'`,
      });
    } else {
      seenFields.add(field);
    }
  }
  return errors;
}

export function copilotHeaderMetadataIdentitySchema(): Record<string, unknown> {
  return {
    type: 'object',
    properties: {
      entra_agent_id: { type: 'string', 'x-identity': true },
      client_tenant_id: { type: 'string', 'x-identity': true },
      session_id: { type: 'string' },
      correlation_id: { type: 'string' },
      activity_id: { type: 'string' },
      referrer: { type: 'string' },
    },
    required: ['entra_agent_id', 'client_tenant_id'],
  };
}

export const COPILOT_HEADER_METADATA_IDENTITY_FIELDS = ['entra_agent_id', 'client_tenant_id'];
