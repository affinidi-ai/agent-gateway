import { trustCheckDefinition } from '../trust-check/definition';
import {
  AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
  INPUT_GATEWAY_SOURCE_ID_TEMPLATE,
  subjectForTemplate,
  subjectLabel,
  templateForSubject,
} from '../trust-check/definition';
import { registry } from '../index';
import { buildCanvasBlob } from '../registry';
import type { CanvasNode, PayloadContext } from '../types';

function makeCtx(nodes: CanvasNode[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 't', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any;
}

function makeNode(id: string, slotId: string, config: Record<string, unknown>): CanvasNode {
  return {
    id,
    type: 'trust-check',
    label: '',
    configured: true,
    config,
    parentId: slotId.includes('access_point') ? 'access-point' : 'target',
    slotId,
  } as any;
}

const AP_SLOT = 'request:trust-check-access_point_trust_check_list';
const TP_SLOT = 'request:trust-check-target_trust_check_list';

describe('trustCheckDefinition — incompleteReason', () => {
  it('flags missing registry', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        query_type: 'authorization',
        query: { action: 'a', resource: 'r' },
      })
    ).toMatch(/registry/i);
  });

  it('defaults missing query_type to authorization (no error)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query: { authority_id: 'a', entity_id: 'e', action: 'x', resource: 'r' },
      })
    ).toBeNull();
  });

  it('does not require action or resource for a recognition query (backend defaults them)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: 'did:web:auth.example' },
      })
    ).toBeNull();
  });

  it('flags a missing action on an authorization query', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: { authority_id: 'did:web:auth.example', resource: 'cred' },
      })
    ).toMatch(/action.*required.*authorization/i);
  });

  it('flags a missing resource on an authorization query', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: { authority_id: 'did:web:auth.example', action: 'issue' },
      })
    ).toMatch(/resource.*required.*authorization/i);
  });

  it('flags both fields as missing when the authorization query is empty (action reported first)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: { authority_id: 'did:web:auth.example' },
      })
    ).toMatch(/action.*required.*authorization/i);
  });

  it('treats whitespace-only action/resource as missing on an authorization query', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: { authority_id: 'did:web:auth.example', action: '   ', resource: '   ' },
      })
    ).toMatch(/action.*required.*authorization/i);
  });

  it('returns null when fully configured (recognition)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: 'did:web:auth.example', entity_id: 'e' },
      })
    ).toBeNull();
  });

  it('returns null when fully configured (authorization)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: {
          authority_id: 'did:web:auth.example',
          entity_id: 'e',
          action: 'issue',
          resource: 'cred',
        },
      })
    ).toBeNull();
  });

  it('accepts a blank authority on the caller leg (defaults to the verified issuer)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: {},
      })
    ).toBeNull();
  });

  it('accepts the verified-issuer template on the caller leg', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: '{{ input.agent.identity_issuer_did }}' },
      })
    ).toBeNull();
  });

  it('accepts the sending-gateway template on the caller leg (fabric-inbound root of trust)', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: '{{ input.gateway.source_id }}' },
      })
    ).toBeNull();
  });

  it('flags a leftover non-issuer template authority on the caller leg', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: '{{ input.agent.provider_did }}' },
      })
    ).toMatch(/Replace the caller-leg Authority template/i);
  });

  it('flags a missing authority on the target leg', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        _edge: 'ma-tp',
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: {},
      })
    ).toMatch(/Issuer or Authority for the target-leg Authority/i);
  });
});

describe('trustCheckDefinition — authority selection', () => {
  it('defaults the caller-leg authority_id to the verified-issuer template when nothing is selected', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: {},
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      '{{ input.agent.identity_issuer_did }}'
    );
  });

  it('treats a whitespace-only caller-leg authority_id as unset (defaults to the verified issuer)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: '   ' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      '{{ input.agent.identity_issuer_did }}'
    );
  });

  it('honours an explicitly selected Department DID (operator picked it on the panel)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'did:webvh:Qabc:example.test:departments:dep-42' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      'did:webvh:Qabc:example.test:departments:dep-42'
    );
  });

  it('passes through a custom template override verbatim (e.g. legacy authority_did)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: '{{ input.agent.authority_did }}' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      '{{ input.agent.authority_did }}'
    );
  });

  it('target leg passes through a stored literal DID verbatim (Authority is now selectable)', () => {
    const node = makeNode('trust-check-1', TP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: {
        authority_id: 'did:webvh:Qxyz:example.test:departments:a8d8b235',
      },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      'did:webvh:Qxyz:example.test:departments:a8d8b235'
    );
  });

  it('target leg passes through a custom template override verbatim (e.g. authority_did)', () => {
    const node = makeNode('trust-check-1', TP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: '{{ input.agent.authority_did }}' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.authority_id).toBe(
      '{{ input.agent.authority_did }}'
    );
  });
});

describe('trustCheckDefinition — entity_id auto-injection', () => {
  it('caller leg defaults entity_id to input.agent.did', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.entity_id).toBe('{{ input.agent.did }}');
  });

  it('target leg defaults entity_id to input.agent.did', () => {
    const node = makeNode('trust-check-1', TP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.entity_id).toBe('{{ input.agent.did }}');
  });

  it('honours an operator-supplied entity_id override from the Advanced editor', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a', entity_id: '{{ input.extension_identity.did }}' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.entity_id).toBe(
      '{{ input.extension_identity.did }}'
    );
  });

  it('falls back to the default template when stored entity_id is blank / whitespace', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a', entity_id: '   ' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].query.entity_id).toBe('{{ input.agent.did }}');
  });
});

describe('trustCheckDefinition — buildPayload', () => {
  it('returns undefined when no nodes', () => {
    expect(trustCheckDefinition.buildPayload!(makeCtx([]))).toBeUndefined();
  });

  it('emits a caller-leg slice for AP→MA nodes', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      id: 'tc-caller',
      trust_registry_id: 'tr-1',
      query_type: 'authorization',
      query: { action: 'issue', resource: 'cred' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices).toHaveLength(1);
    expect(slices[0].path).toBe('access_point.trust_check_list');
    expect(slices[0].value).toEqual([
      {
        id: 'tc-caller',
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        query: {
          authority_id: '{{ input.agent.identity_issuer_did }}',
          entity_id: '{{ input.agent.did }}',
          action: 'issue',
          resource: 'cred',
        },
      },
    ]);
    expect((slices[0].value as any[])[0]).not.toHaveProperty('phase');
  });

  it('emits a target-leg slice for MA→TP nodes', () => {
    const node = makeNode('trust-check-2', TP_SLOT, {
      id: 'tc-target',
      trust_registry_id: 'tr-2',
      query_type: 'recognition',
      query: {},
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices).toHaveLength(1);
    expect(slices[0].path).toBe('target.trust_check_list');
    expect((slices[0].value as any[])[0]).toMatchObject({
      id: 'tc-target',
      query_type: 'recognition',
      query: {
        authority_id: '',
        entity_id: '{{ input.agent.did }}',
      },
    });
    expect((slices[0].value as any[])[0]).not.toHaveProperty('timeout_secs');
    expect((slices[0].value as any[])[0]).not.toHaveProperty('phase');
  });

  it('partitions multiple nodes across both legs and preserves order', () => {
    const nodes = [
      makeNode('trust-check-1', AP_SLOT, {
        id: 'c1',
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: 'a', entity_id: 'e1' },
      }),
      makeNode('trust-check-2', TP_SLOT, {
        id: 't1',
        trust_registry_id: 'tr-2',
        query_type: 'recognition',
        query: { authority_id: 'a', entity_id: 'e2' },
      }),
      makeNode('trust-check-3', AP_SLOT, {
        id: 'c2',
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: 'a', entity_id: 'e3' },
      }),
    ];
    const slices = trustCheckDefinition.buildPayload!(makeCtx(nodes))!;
    const byPath = Object.fromEntries(slices.map(s => [s.path, s.value as any[]]));
    expect(byPath['access_point.trust_check_list'].map(e => e.id)).toEqual(['c1', 'c2']);
    expect(byPath['target.trust_check_list'].map(e => e.id)).toEqual(['t1']);
  });

  it('preserves action and resource for recognition queries (backend applies defaults when omitted)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { action: 'is', resource: 'ownedAgent' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    const entry = (slices[0].value as any[])[0];
    expect(entry.query).toEqual({
      authority_id: '{{ input.agent.identity_issuer_did }}',
      entity_id: '{{ input.agent.did }}',
      action: 'is',
      resource: 'ownedAgent',
    });
  });

  it('omits action and resource when blank for recognition queries', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: {},
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    const entry = (slices[0].value as any[])[0];
    expect(entry.query).toEqual({
      authority_id: '{{ input.agent.identity_issuer_did }}',
      entity_id: '{{ input.agent.did }}',
    });
  });

  it('auto-generates a UUID-shaped id when config.id is missing', () => {
    const node = makeNode('trust-check-7', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a', entity_id: 'e' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    const id = (slices[0].value as any[])[0].id as string;
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThanOrEqual(8);
    expect(id).not.toBe('trust-check-7');
  });

  it('preserves an existing config.id verbatim', () => {
    const node = makeNode('trust-check-7', AP_SLOT, {
      id: 'stable-uuid-1234',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { entity_id: 'e' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].id).toBe('stable-uuid-1234');
  });

  it('never emits timeout_secs (the dashboard defers to the trust-registry transport default)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { entity_id: 'e' },
      // even if a stored config has a leftover number, it must NOT round-trip
      timeout_secs: 99,
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0]).not.toHaveProperty('timeout_secs');
  });

  it('preserves an operator-supplied name through the round-trip', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { entity_id: 'e' },
      name: 'Issuer accreditation',
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].name).toBe('Issuer accreditation');
  });

  it('preserves a name carried on a queries[] entry', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      queries: [
        {
          id: 'q1',
          trust_registry_id: 'tr-1',
          query_type: 'recognition',
          query: {},
          name: 'Ownership check',
        },
      ],
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0].name).toBe('Ownership check');
  });

  it('omits name when unset or blank (backend uses Option::is_none)', () => {
    const node = makeNode('trust-check-1', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { entity_id: 'e' },
      name: '',
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect((slices[0].value as any[])[0]).not.toHaveProperty('name');
  });

  it('falls back to ap-ma when slotId is unknown but _edge is unset', () => {
    const node = makeNode('trust-check-1', 'request:unknown-slot', {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { entity_id: 'e' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices[0].path).toBe('access_point.trust_check_list');
  });

  it('honours config._edge when slotId is unknown', () => {
    const node = makeNode('trust-check-1', 'request:unknown-slot', {
      _edge: 'ma-tp',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a', entity_id: 'e' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices[0].path).toBe('target.trust_check_list');
  });
});

describe('trustCheckDefinition — summary', () => {
  it('returns just the query type (no phase suffix)', () => {
    expect(
      trustCheckDefinition.summary!({
        id: 'tc-a',
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
      })
    ).toBe('authorization');
    expect(
      trustCheckDefinition.summary!({
        id: 'tc-b',
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
      })
    ).toBe('recognition');
  });

  it('reports the count when a node holds multiple queries', () => {
    expect(
      trustCheckDefinition.summary!({
        queries: [
          { trust_registry_id: 'tr-1', query_type: 'recognition', query: {} },
          {
            trust_registry_id: 'tr-1',
            query_type: 'authorization',
            query: { action: 'a', resource: 'r' },
          },
        ],
      })
    ).toBe('2 queries');
  });
});

describe('trustCheckDefinition — multiple queries per node', () => {
  it('fans out queries[] into N wire entries on the same leg, preserving order', () => {
    const node = makeNode('trust-check-caller', AP_SLOT, {
      _edge: 'ap-ma',
      queries: [
        {
          id: 'q1',
          trust_registry_id: 'tr-1',
          query_type: 'recognition',
          query: { authority_id: 'a' },
        },
        {
          id: 'q2',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: { action: 'send', resource: 'message' },
        },
      ],
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices).toHaveLength(1);
    expect(slices[0].path).toBe('access_point.trust_check_list');
    const entries = slices[0].value as any[];
    expect(entries.map(e => e.id)).toEqual(['q1', 'q2']);
    expect(entries[0].query_type).toBe('recognition');
    expect(entries[1].query_type).toBe('authorization');
    expect(entries[1].query.action).toBe('send');
    expect(entries[1].query.resource).toBe('message');
    expect(entries[0].query).not.toHaveProperty('action');
  });

  it('emits each leg from a separate node when both legs are populated', () => {
    const nodes = [
      makeNode('trust-check-caller', AP_SLOT, {
        _edge: 'ap-ma',
        queries: [{ id: 'c1', trust_registry_id: 'tr-1', query_type: 'recognition', query: {} }],
      }),
      makeNode('trust-check-target', TP_SLOT, {
        _edge: 'ma-tp',
        queries: [
          {
            id: 't1',
            trust_registry_id: 'tr-2',
            query_type: 'authorization',
            query: { action: 'send', resource: 'message' },
          },
          { id: 't2', trust_registry_id: 'tr-2', query_type: 'recognition', query: {} },
        ],
      }),
    ];
    const slices = trustCheckDefinition.buildPayload!(makeCtx(nodes))!;
    const byPath = Object.fromEntries(slices.map(s => [s.path, s.value as any[]]));
    expect(byPath['access_point.trust_check_list'].map(e => e.id)).toEqual(['c1']);
    expect(byPath['target.trust_check_list'].map(e => e.id)).toEqual(['t1', 't2']);
  });

  it('walks every query in incompleteReason and prefixes "Query N: " on the first failure', () => {
    expect(
      trustCheckDefinition.incompleteReason({
        queries: [
          {
            trust_registry_id: 'tr-1',
            query_type: 'authorization',
            query: { authority_id: 'did:web:auth.example', action: 'a', resource: 'r' },
          },
          { trust_registry_id: '', query_type: 'recognition', query: {} },
        ],
      })
    ).toMatch(/Query 2.*registry/i);
  });

  it('keeps reading the legacy flat config shape (no migration step)', () => {
    const node = makeNode('trust-check-legacy', AP_SLOT, {
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_id: 'a' },
    });
    const slices = trustCheckDefinition.buildPayload!(makeCtx([node]))!;
    expect(slices).toHaveLength(1);
    const entries = slices[0].value as any[];
    expect(entries).toHaveLength(1);
    expect(entries[0].trust_registry_id).toBe('tr-1');
    expect(entries[0].query_type).toBe('recognition');
  });

  it('flags an empty queries[] as incomplete', () => {
    expect(trustCheckDefinition.incompleteReason({ queries: [] })).toMatch(/at least one/i);
  });
});

describe('trustCheckDefinition — hydrate → buildPayload round-trip', () => {
  it('preserves `name` across nodesFromPayload → buildPayload', () => {
    const payload = {
      name: 'roundtrip',
      status: 'active' as const,
      tags: [],
      access_point: {
        listener_url: 'https://gw/x',
        trust_check_list: [
          {
            id: 'tc-1',
            trust_registry_id: 'tr-1',
            query_type: 'recognition',
            query: { authority_id: 'a' },
            name: 'Issuer accreditation',
          },
        ],
      },
      target: { endpoint: 'https://upstream/y' },
    };
    const nodes = registry.nodesFromPayload(payload);
    const tc = nodes.find(n => n.type === 'trust-check');
    expect(tc).toBeDefined();
    const ctx: PayloadContext = {
      protocol: 'a2a',
      surfaceMeta: { name: 'roundtrip', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: (type: string) => nodes.filter(n => n.type === type),
      firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
    } as any;
    const slices = trustCheckDefinition.buildPayload!(ctx)!;
    const entry = (slices[0].value as any[])[0];
    expect(entry.name).toBe('Issuer accreditation');
    expect(entry.id).toBe('tc-1');
  });

  it('drops `timeout_secs` across the round-trip (intentional — see backend docs)', () => {
    const payload = {
      name: 'roundtrip',
      status: 'active' as const,
      tags: [],
      access_point: {
        listener_url: 'https://gw/x',
        trust_check_list: [
          {
            id: 'tc-1',
            trust_registry_id: 'tr-1',
            query_type: 'recognition',
            query: { authority_id: 'a' },
            timeout_secs: 42,
          },
        ],
      },
      target: { endpoint: 'https://upstream/y' },
    };
    const nodes = registry.nodesFromPayload(payload);
    const ctx: PayloadContext = {
      protocol: 'a2a',
      surfaceMeta: { name: 'roundtrip', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: (type: string) => nodes.filter(n => n.type === type),
      firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
    } as any;
    const slices = trustCheckDefinition.buildPayload!(ctx)!;
    expect((slices[0].value as any[])[0]).not.toHaveProperty('timeout_secs');
  });
});

describe('trust_check_list — canvas removal clears the config', () => {
  it('rebuilds effective root without trust_check_list when the trust-check node is deleted', () => {
    const ctxWithNode = makeCtx([
      makeNode('trust-check-target', TP_SLOT, {
        _edge: 'ma-tp',
        queries: [
          {
            trust_registry_id: 'tr-1',
            query_type: 'recognition',
            query: { authority_id: 'a' },
          },
        ],
      }),
    ]);
    const withSlices = trustCheckDefinition.buildPayload!(ctxWithNode);
    expect(withSlices).toBeDefined();
    expect(withSlices!.some(s => s.path === 'target.trust_check_list')).toBe(true);

    const ctxWithoutNode = makeCtx([]);
    const withoutSlices = trustCheckDefinition.buildPayload!(ctxWithoutNode);
    expect(withoutSlices).toBeUndefined();
  });

  it('strips a stale trust_check_list from a non-trust-check node in buildCanvasBlob', () => {
    const blob = buildCanvasBlob([
      {
        id: 'target',
        type: 'target',
        label: 'Managed Agent',
        parentId: undefined,
        position: { x: 100, y: 100 },
        config: {
          endpoint: 'https://upstream/y',
          trust_check_list: [{ id: 'tc-1', trust_registry_id: 'tr-1' }],
        },
      },
      {
        id: 'access-point',
        type: 'access-point',
        label: 'Access Point',
        parentId: undefined,
        position: { x: 10, y: 100 },
        config: {
          route: '/x',
          trust_check_list: [{ id: 'tc-2', trust_registry_id: 'tr-2' }],
        },
      },
    ]);
    const targetNode = blob.nodes.find(n => n.id === 'target')!;
    const apNode = blob.nodes.find(n => n.id === 'access-point')!;
    expect(targetNode.config).not.toHaveProperty('trust_check_list');
    expect(targetNode.config).toEqual({ endpoint: 'https://upstream/y' });
    expect(apNode.config).not.toHaveProperty('trust_check_list');
    expect(apNode.config).toEqual({ route: '/x' });
  });

  it('preserves trust_check_list on a genuine trust-check canvas node', () => {
    const blob = buildCanvasBlob([
      {
        id: 'trust-check-target',
        type: 'trust-check',
        label: '',
        parentId: 'target',
        position: { x: 200, y: 100 },
        config: {
          _edge: 'ma-tp',
          queries: [{ trust_registry_id: 'tr-1', query_type: 'recognition', query: {} }],
        },
      },
    ]);
    const tcNode = blob.nodes.find(n => n.id === 'trust-check-target')!;
    expect(tcNode.config).toHaveProperty('queries');
  });

  it('strips a stale trust_check_list from the target slice at hydration time', () => {
    const nodes = registry.nodesFromPayload({
      name: 'stale',
      status: 'active',
      tags: [],
      access_point: {
        route: '/x',
        trust_check_list: [{ id: 'tc-2', trust_registry_id: 'tr-2' }],
      },
      target: {
        endpoint: 'https://upstream/y',
        trust_check_list: [{ id: 'tc-1', trust_registry_id: 'tr-1' }],
      },
    });
    const target = nodes.find(n => n.id === 'target')!;
    const ap = nodes.find(n => n.id === 'access-point')!;
    expect(target.config).not.toHaveProperty('trust_check_list');
    expect(ap.config).not.toHaveProperty('trust_check_list');
    const tcCaller = nodes.find(n => n.id === 'trust-check-caller');
    const tcTarget = nodes.find(n => n.id === 'trust-check-target');
    expect(tcCaller?.config?.queries).toHaveLength(1);
    expect(tcTarget?.config?.queries).toHaveLength(1);
  });
});

describe('trustCheckDefinition — subject vocabulary (identity-issuer + sending-gateway)', () => {
  it('maps the identity-issuer subject to the verified VP issuer template', () => {
    expect(templateForSubject('identity-issuer')).toBe(AGENT_IDENTITY_ISSUER_DID_TEMPLATE);
    expect(subjectForTemplate(AGENT_IDENTITY_ISSUER_DID_TEMPLATE)).toBe('identity-issuer');
  });

  it('maps the sending-gateway subject to the input.gateway.source_id template', () => {
    expect(templateForSubject('sending-gateway')).toBe(INPUT_GATEWAY_SOURCE_ID_TEMPLATE);
    expect(subjectForTemplate(INPUT_GATEWAY_SOURCE_ID_TEMPLATE)).toBe('sending-gateway');
  });

  it('labels the identity-issuer subject leg-specifically', () => {
    expect(subjectLabel('identity-issuer', true)).toMatch(
      /caller.*verified identity credential issuer/i
    );
    expect(subjectLabel('identity-issuer', false)).toMatch(
      /target.*verified identity credential issuer/i
    );
  });

  it('labels the sending-gateway subject as fabric-only regardless of leg', () => {
    expect(subjectLabel('sending-gateway', true)).toMatch(/sending gateway.*fabric-inbound/i);
    expect(subjectLabel('sending-gateway', false)).toMatch(/sending gateway.*fabric-inbound/i);
  });
});
