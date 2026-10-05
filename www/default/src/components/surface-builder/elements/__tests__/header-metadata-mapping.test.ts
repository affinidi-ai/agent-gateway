import {
  COPILOT_HEADER_METADATA_PRESET,
  HEADER_METADATA_EXTENSION_URI,
  COPILOT_HEADER_METADATA_IDENTITY_FIELDS,
  copilotHeaderMetadataIdentitySchema,
  validateHeaderMetadataMapping,
} from '../access-point/headerMetadataMapping';
import { identityConfigToWire } from '../identity/definition';
import { registry } from '../index';

function makeCtx(nodes: any[], overrides: any = {}) {
  return {
    protocol: 'a2a',
    surfaceMeta: {
      name: 'test-surface',
      tags: [],
      status: 'active',
    },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
    ...overrides,
  };
}

describe('Header Metadata Mapping dashboard model', () => {
  it('round-trips Access Point header metadata mapping through a Metadata Extraction node', () => {
    const payload = registry.buildPayload(
      makeCtx([
        {
          id: 'access-point',
          type: 'access-point',
          config: { route: '/example' },
        },
        {
          id: 'metadata-extraction',
          type: 'metadata-extraction',
          slotId: 'request:metadata-extraction',
          config: {
            header_metadata_mapping: {
              extension_uri: HEADER_METADATA_EXTENSION_URI,
              headers: [
                { header: 'x-ms-entra-agent-id', field: 'entra_agent_id' },
                { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
              ],
              strip_mapped_headers: true,
            },
          },
        },
      ])
    );

    expect(payload.access_point.header_metadata_mapping).toEqual({
      extension_uri: HEADER_METADATA_EXTENSION_URI,
      headers: [
        { header: 'x-ms-entra-agent-id', field: 'entra_agent_id' },
        { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
      ],
      strip_mapped_headers: true,
    });

    const nodes = registry.nodesFromPayload(payload);
    const accessPoint = nodes.find(node => node.type === 'access-point');
    expect(accessPoint?.config.header_metadata_mapping).toBeUndefined();
    const metadata = nodes.find(
      node => node.type === 'metadata-extraction' && node.id === 'metadata-extraction'
    );
    expect(metadata?.config.header_metadata_mapping).toEqual(
      payload.access_point.header_metadata_mapping
    );
  });

  it('preserves a blank Namespace URI so validation can block it instead of silently defaulting', () => {
    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'metadata-extraction',
          type: 'metadata-extraction',
          slotId: 'request:metadata-extraction',
          config: {
            header_metadata_mapping: {
              extension_uri: '',
              headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
              strip_mapped_headers: true,
            },
          },
        },
      ])
    );

    expect(payload.access_point.header_metadata_mapping.extension_uri).toBe('');
    expect(
      validateHeaderMetadataMapping({
        extension_uri: '',
        headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
        strip_mapped_headers: true,
      }).map(error => error.message)
    ).toContain('Extension URI is required');
  });

  it('validates sensitive headers and duplicate destination fields', () => {
    const errors = validateHeaderMetadataMapping({
      extension_uri: HEADER_METADATA_EXTENSION_URI,
      headers: [
        { header: 'authorization', field: 'agent_id' },
        { header: 'x-ms-entra-agent-id', field: 'agent_id' },
      ],
      strip_mapped_headers: true,
    }).map(error => error.message);

    expect(errors).toContain("Sensitive header 'authorization' cannot be mapped");
    expect(errors).toContain("Duplicate metadata field 'agent_id'");
  });

  it('exposes the Copilot preset rows used by the panel', () => {
    expect(COPILOT_HEADER_METADATA_PRESET).toEqual([
      { header: 'x-ms-entra-agent-id', field: 'entra_agent_id' },
      { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
      { header: 'x-ms-client-session-id', field: 'session_id' },
      { header: 'x-ms-correlation-id', field: 'correlation_id' },
      { header: 'x-ms-coreframework-caller-activity-id', field: 'activity_id' },
      { header: 'x-ms-apim-referrer', field: 'referrer' },
    ]);
  });

  it('round-trips Transit Point header metadata mapping through a Metadata Extraction node', () => {
    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'tp-a',
          type: 'transit-point-a2a',
          config: {
            id: 'tp-a',
            name: 'Partner A',
            alias: 'partner-a',
            listen_address: 'http://127.0.0.1:9100',
            target_endpoint: 'https://partner.example/a2a',
          },
        },
        {
          id: 'metadata-extraction-tp-a',
          type: 'metadata-extraction',
          parentId: 'tp-a',
          slotId: 'request:metadata-extraction',
          config: {
            header_metadata_mapping: {
              extension_uri: HEADER_METADATA_EXTENSION_URI,
              headers: [
                { header: ' x-ms-entra-agent-id ', field: ' entra_agent_id ' },
                { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
              ],
              strip_mapped_headers: false,
            },
          },
        },
      ])
    );

    expect(payload.transit.points[0].header_metadata_mapping).toEqual({
      extension_uri: HEADER_METADATA_EXTENSION_URI,
      headers: [
        { header: 'x-ms-entra-agent-id', field: 'entra_agent_id' },
        { header: 'x-ms-client-tenant-id', field: 'client_tenant_id' },
      ],
      strip_mapped_headers: false,
    });

    const nodes = registry.nodesFromPayload(payload);
    const tp = nodes.find(node => node.type === 'transit-point-a2a');
    expect(tp?.config.header_metadata_mapping).toBeUndefined();
    const metadata = nodes.find(
      node => node.type === 'metadata-extraction' && node.parentId === tp?.id
    );
    expect(metadata?.slotId).toBe('request:metadata-extraction');
    expect(metadata?.config.header_metadata_mapping).toEqual(
      payload.transit.points[0].header_metadata_mapping
    );
  });

  it('hydrates Transit Point header metadata mapping when the wire protocol is defaulted', () => {
    const wire = {
      name: 'test-surface',
      access_point: {
        listen_address: '0.0.0.0:8443',
        route: '/example',
        protocol: 'a2a',
      },
      target: {
        endpoint: 'https://managed.example/a2a',
      },
      transit: {
        points: [
          {
            id: 'tp-a',
            alias: 'partner-a',
            listen_address: 'http://127.0.0.1:9100',
            target_endpoint: 'https://partner.example/a2a',
            header_metadata_mapping: {
              extension_uri: HEADER_METADATA_EXTENSION_URI,
              headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
              strip_mapped_headers: true,
            },
          },
        ],
      },
    };

    const nodes = registry.nodesFromPayload(wire);
    const tp = nodes.find(node => node.type === 'transit-point-a2a');
    expect(tp?.config.header_metadata_mapping).toBeUndefined();
    const metadata = nodes.find(
      node => node.type === 'metadata-extraction' && node.parentId === tp?.id
    );
    expect(metadata?.config.header_metadata_mapping).toEqual(
      wire.transit.points[0].header_metadata_mapping
    );

    const roundTrip = registry.buildPayload(makeCtx(nodes));
    expect(roundTrip.transit.points[0].header_metadata_mapping).toEqual(
      wire.transit.points[0].header_metadata_mapping
    );
  });

  it('omits disabled Transit Point header metadata mapping', () => {
    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'tp-a',
          type: 'transit-point-a2a',
          config: {
            id: 'tp-a',
            alias: 'partner-a',
            listen_address: 'http://127.0.0.1:9100',
            target_endpoint: 'https://partner.example/a2a',
          },
        },
      ])
    );

    expect(payload.transit.points[0].header_metadata_mapping).toBeUndefined();
  });

  it('does not emit Transit Point header metadata mapping for unsupported protocols', () => {
    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'tp-mcp',
          type: 'transit-point-mcp',
          config: {
            id: 'tp-mcp',
            alias: 'partner-mcp',
            listen_address: 'http://127.0.0.1:9100',
            target_endpoint: 'https://partner.example/mcp',
          },
        },
        {
          id: 'metadata-extraction-tp-mcp',
          type: 'metadata-extraction',
          parentId: 'tp-mcp',
          slotId: 'request:metadata-extraction',
          config: {
            header_metadata_mapping: {
              extension_uri: HEADER_METADATA_EXTENSION_URI,
              headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
              strip_mapped_headers: true,
            },
          },
        },
      ])
    );

    expect(payload.transit.points[0].protocol).toBe('mcp');
    expect(payload.transit.points[0].header_metadata_mapping).toBeUndefined();
  });

  it('does not persist or configure a Metadata Extraction node without header rows', () => {
    const config = {
      header_metadata_mapping: {
        extension_uri: HEADER_METADATA_EXTENSION_URI,
        headers: [],
        strip_mapped_headers: false,
      },
    };

    expect(registry.getIncompleteReason('metadata-extraction', config)).toBe(
      'Configure at least one header mapping'
    );

    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'metadata-extraction',
          type: 'metadata-extraction',
          slotId: 'request:metadata-extraction',
          config,
        },
      ])
    );

    expect(payload.access_point.header_metadata_mapping).toBeUndefined();
  });

  it('round-trips identity helper config for header metadata source', () => {
    const wire = identityConfigToWire({
      type: 'from_payload',
      extension_uri: HEADER_METADATA_EXTENSION_URI,
      meta_field: 'agentIdentity',
      json_schema: copilotHeaderMetadataIdentitySchema(),
      fields: [...COPILOT_HEADER_METADATA_IDENTITY_FIELDS],
    });

    expect(wire).toEqual({
      type: 'from_payload',
      extension_uri: HEADER_METADATA_EXTENSION_URI,
      meta_field: 'agentIdentity',
      json_schema: copilotHeaderMetadataIdentitySchema(),
      fields: ['entra_agent_id', 'client_tenant_id'],
    });

    const payload = registry.buildPayload(
      makeCtx([
        { id: 'access-point', type: 'access-point', config: { route: '/example' } },
        {
          id: 'identity-inbound',
          type: 'identity',
          slotId: 'request:identity-inbound',
          config: {
            type: 'from_payload',
            extension_uri: HEADER_METADATA_EXTENSION_URI,
            meta_field: 'agentIdentity',
            json_schema: copilotHeaderMetadataIdentitySchema(),
            fields: [...COPILOT_HEADER_METADATA_IDENTITY_FIELDS],
          },
        },
      ])
    );
    expect(payload.identity_slots.inbound.extension_uri).toBe(HEADER_METADATA_EXTENSION_URI);
    expect(payload.access_point.header_metadata_mapping).toBeUndefined();
  });
});
