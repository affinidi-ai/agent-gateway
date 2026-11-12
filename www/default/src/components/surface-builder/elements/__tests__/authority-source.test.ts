import { registry } from '../index';
import { hydrateSurfaceCanvas } from '../../nodesFromSurface';
import { computeOverridesFromPayload, resolveVariant } from '../../variants/resolve';
import type { AgentSurface } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import {
  AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
  applyPresetToQuery,
  classifyTargetAuthoritySelection,
  missingTrustCheckAuthorities,
  queriesFromWire,
  addAuthorityRow,
  authorityRows,
  canAddAuthorityRow,
  removeAuthorityRow,
  setAuthorityRow,
  TRUST_CHECK_AUTHORITIES_MAX,
  type TrustCheckQueryConfig,
} from '../trust-check/definition';
import {
  missingTrustRecorderAuthorities,
  readEntries,
  SURFACE_ISSUER_DID_TEMPLATE,
} from '../trust-recorder/definition';
import { authoritySourceFor, missingAuthorityDid } from '../_shared/authorityReference';
import {
  firstMissingAuthorityNode,
  missingAuthorityCanvasReason,
  missingAuthorityWarning,
} from '../missingAuthority';

const AUTHORITY = 'did:web:authority.example';
const ISSUER = 'did:web:issuer.example';
const GONE = 'did:web:deleted-authority.example';

const authorities = [{ did: AUTHORITY, name: 'Payments Authority' }];
const issuers = [{ did: ISSUER, name: 'Acme Issuer' }];

const check = (id: string, authority_id: string, authority_source?: string) => ({
  id,
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  ...(authority_source ? { authority_source } : {}),
  query: { authority_id, entity_id: '{{ input.agent.did }}' },
});

const recorderEntry = (authority_did: string, authority_source?: string) => ({
  trust_registry_id: 'tr-1',
  issuer_did: ISSUER,
  authority_did,
  ...(authority_source ? { authority_source } : {}),
  include_owned_agent: true,
  custom_resources: [],
});

function rebuild(nodes: CanvasNode[]): any {
  return registry.buildPayload({
    protocol: 'a2a',
    surfaceMeta: { name: 'authority-source', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any);
}

function surface(extra: Record<string, any> = {}): any {
  return {
    name: 'authority-source',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://0.0.0.0:8443',
      route: '/a2a',
      protocol: 'a2a',
      trust_check_list: [check('caller-1', AUTHORITY, 'authority')],
      trust_recorder: {
        entries: [recorderEntry(AUTHORITY, 'authority'), recorderEntry(ISSUER, 'issuer')],
      },
    },
    target: {
      endpoint: 'a2a-proxy://proxy-1',
      trust_check_list: [check('target-1', 'did:web:literal.example')],
    },
    transit: {
      points: [
        {
          id: 'tp-uuid-1',
          alias: 'tp1',
          protocol: 'a2a',
          target_endpoint: 'https://one.example.com/a2a',
          trust_check_list: [check('tp-1', ISSUER, 'issuer')],
        },
      ],
    },
    ...extra,
  };
}

describe('authority_source — wire round-trip', () => {
  it('keeps authority_source on every Trust Check list and Trust Recorder entry through hydration and save', () => {
    const payload = surface();
    const rebuilt = rebuild(hydrateSurfaceCanvas(payload as AgentSurface).nodes);

    expect(rebuilt.access_point.trust_check_list[0].authority_source).toBe('authority');
    expect(rebuilt.target.trust_check_list[0]).not.toHaveProperty('authority_source');
    expect(rebuilt.transit.points[0].trust_check_list[0].authority_source).toBe('issuer');
    expect(rebuilt.access_point.trust_recorder.entries.map((e: any) => e.authority_source)).toEqual(
      ['authority', 'issuer']
    );
  });

  it('keeps authority_source on a variant’s own lists through a snapshot round-trip', () => {
    const variantPayload = surface();
    variantPayload.access_point.trust_check_list = [check('variant-1', GONE, 'authority')];
    variantPayload.access_point.trust_recorder = { entries: [recorderEntry(GONE, 'authority')] };
    const overrides = computeOverridesFromPayload(variantPayload);

    const resolved = resolveVariant(surface(), overrides);
    const rebuilt = rebuild(registry.nodesFromPayload(resolved) as CanvasNode[]);

    expect(rebuilt.access_point.trust_check_list[0]).toMatchObject({
      id: 'variant-1',
      authority_source: 'authority',
      query: { authority_id: GONE },
    });
    expect(rebuilt.access_point.trust_recorder.entries[0]).toMatchObject({
      authority_did: GONE,
      authority_source: 'authority',
    });
  });

  it('sends no authority_source beside a template, including the caller-leg default', () => {
    const payload = surface();
    payload.access_point.trust_check_list = [
      check('templated', AGENT_IDENTITY_ISSUER_DID_TEMPLATE, 'authority'),
      { ...check('blank', ''), authority_source: 'issuer' },
    ];
    payload.access_point.trust_recorder = {
      entries: [recorderEntry(SURFACE_ISSUER_DID_TEMPLATE, 'authority')],
    };
    const rebuilt = rebuild(registry.nodesFromPayload(payload) as CanvasNode[]);

    const [templated, blank] = rebuilt.access_point.trust_check_list;
    expect(templated).not.toHaveProperty('authority_source');
    expect(blank.query.authority_id).toBe(AGENT_IDENTITY_ISSUER_DID_TEMPLATE);
    expect(blank).not.toHaveProperty('authority_source');
    expect(rebuilt.access_point.trust_recorder.entries[0]).not.toHaveProperty('authority_source');
  });

  it('keeps a stored authority list and its sources through hydration and save', () => {
    const payload = surface();
    const listed = {
      id: 'authority-recognised',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      authority_sources: { [AUTHORITY]: 'authority' },
      query: { authority_ids: [AUTHORITY, ISSUER], entity_id: '{{ input.agent.did }}' },
    };
    payload.access_point.trust_check_list = [listed];
    payload.transit.points[0].trust_check_list = [{ ...listed, id: 'tp-listed' }];
    const nodes = hydrateSurfaceCanvas(payload as AgentSurface).nodes;
    const rebuilt = rebuild(nodes);

    for (const element of [
      rebuilt.access_point.trust_check_list[0],
      rebuilt.transit.points[0].trust_check_list[0],
    ]) {
      expect(element.query).toEqual({
        authority_ids: [AUTHORITY, ISSUER],
        entity_id: '{{ input.agent.did }}',
      });
      expect(element.authority_sources).toEqual({ [AUTHORITY]: 'authority' });
      expect(element).not.toHaveProperty('authority_source');
    }
    const trustChecks = nodes.filter(n => n.type === 'trust-check');
    expect(trustChecks.map(n => registry.getIncompleteReason(n.type, n.config, n))).toEqual(
      trustChecks.map(() => null)
    );
  });

  it('sends no authority_source when none is stored', () => {
    const payload = surface();
    payload.access_point.trust_check_list = [check('plain', AUTHORITY)];
    const rebuilt = rebuild(registry.nodesFromPayload(payload) as CanvasNode[]);

    expect(rebuilt.access_point.trust_check_list[0]).not.toHaveProperty('authority_source');
  });

  it('drops an unknown authority_source value on read', () => {
    expect(queriesFromWire([check('odd', AUTHORITY, 'register')])[0]).not.toHaveProperty(
      'authority_source'
    );
    expect(readEntries({ entries: [recorderEntry(AUTHORITY, 'register')] })[0]).not.toHaveProperty(
      'authority_source'
    );
  });

  it('drops authority_source when a preset replaces the Authority', () => {
    const next = applyPresetToQuery(
      { id: 'q', trust_registry_id: 'tr-1', authority_source: 'authority', query: {} },
      {
        id: 'p',
        name: 'Preset',
        description: '',
        query_type: 'recognition',
        query: {
          authority_id: '{{ input.agent.provider_did }}',
          entity_id: '{{ input.agent.did }}',
        },
        origin: 'builtin',
      }
    );
    expect(next).not.toHaveProperty('authority_source');
    expect(next.id).toBe('q');
  });
});

describe('several Authorities per query', () => {
  const LISTED = ['did:web:authority-a', 'did:web:authority-b', 'did:web:authority-c'];
  const single = (authority_id: string, authority_source?: 'authority' | 'issuer') =>
    ({
      id: 'q',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      ...(authority_source ? { authority_source } : {}),
      query: { authority_id, entity_id: '{{ input.agent.did }}' },
    }) as TrustCheckQueryConfig;

  /** Pick each DID in a new row after the first, as the editor's Add Authority does. */
  const listOf = (dids: string[], source: 'authority' | 'issuer' = 'authority') => {
    let q = single(dids[0], source);
    for (let i = 1; i < dids.length; i++) {
      q = setAuthorityRow(addAuthorityRow(q), i, dids[i], source);
    }
    return q;
  };

  it('turns a picked Authority into the first of several when a row is added', () => {
    const multi = addAuthorityRow(single(AUTHORITY, 'authority'));
    expect(multi.query).toEqual({
      authority_ids: [AUTHORITY, ''],
      entity_id: '{{ input.agent.did }}',
    });
    expect(multi.authority_sources).toEqual({ [AUTHORITY]: 'authority' });
    expect(multi).not.toHaveProperty('authority_source');
  });

  it('records an Issuer row as picked from the Issuers', () => {
    const q = setAuthorityRow(addAuthorityRow(single(AUTHORITY, 'authority')), 1, ISSUER, 'issuer');
    expect(q.query?.authority_ids).toEqual([AUTHORITY, ISSUER]);
    expect(q.authority_sources).toEqual({ [AUTHORITY]: 'authority', [ISSUER]: 'issuer' });
  });

  it('adds no row beside a template, an empty row, or at the limit', () => {
    expect(canAddAuthorityRow(single(AGENT_IDENTITY_ISSUER_DID_TEMPLATE))).toBe(false);
    expect(canAddAuthorityRow(single(''))).toBe(false);
    expect(canAddAuthorityRow(addAuthorityRow(single(AUTHORITY, 'authority')))).toBe(false);
    const full = listOf(
      Array.from({ length: TRUST_CHECK_AUTHORITIES_MAX }, (_, i) => `did:web:authority-${i}`)
    );
    expect(authorityRows(full)).toHaveLength(TRUST_CHECK_AUTHORITIES_MAX);
    expect(canAddAuthorityRow(full)).toBe(false);
    expect(addAuthorityRow(full)).toBe(full);
  });

  it('removes a row, and goes back to a single authority_id at one row', () => {
    const q = removeAuthorityRow(listOf(LISTED), 0);
    expect(q.query?.authority_ids).toEqual([LISTED[1], LISTED[2]]);
    expect(q.authority_sources).toEqual({ [LISTED[1]]: 'authority', [LISTED[2]]: 'authority' });
    const back = removeAuthorityRow(q, 1);
    expect(back.query).toEqual({ authority_id: LISTED[1], entity_id: '{{ input.agent.did }}' });
    expect(back.authority_source).toBe('authority');
    expect(back).not.toHaveProperty('authority_sources');
    expect(removeAuthorityRow(back, 0)).toBe(back);
  });

  it('saves the picked list and its sources, with no authority_id', () => {
    const q = listOf(LISTED);
    const nodes = [
      {
        id: 'tc',
        type: 'trust-check',
        slotId: 'request:trust-check-access_point_trust_check_list',
        parentId: 'access-point',
        config: { queries: [q] },
      },
    ] as unknown as CanvasNode[];
    const [element] = rebuild(nodes).access_point.trust_check_list;
    expect(element.query).toEqual({ authority_ids: LISTED, entity_id: '{{ input.agent.did }}' });
    expect(element.authority_sources).toEqual(
      Object.fromEntries(LISTED.map(d => [d, 'authority']))
    );
    expect(element).not.toHaveProperty('authority_source');
  });

  it('is incomplete while an added row is empty', () => {
    const open = addAuthorityRow(single(AUTHORITY, 'authority'));
    expect(registry.getIncompleteReason('trust-check', { queries: [open] })).toBe(
      'Select an Issuer or Authority for every Authority row'
    );
  });

  it('summarises the number of authorities', () => {
    const q = listOf(LISTED);
    expect(registry.get('trust-check')?.summary?.({ queries: [q] })).toBe(
      'recognition · 3 authorities'
    );
  });
});

describe('authoritySourceFor / missingAuthorityDid', () => {
  it('keeps a known source beside a literal DID only, and drops an unknown one', () => {
    expect(authoritySourceFor(AUTHORITY, 'authority')).toBe('authority');
    expect(authoritySourceFor(AUTHORITY, 'issuer')).toBe('issuer');
    expect(authoritySourceFor(AUTHORITY, 'did')).toBeUndefined();
    expect(authoritySourceFor(AGENT_IDENTITY_ISSUER_DID_TEMPLATE, 'authority')).toBeUndefined();
    expect(authoritySourceFor('', 'authority')).toBeUndefined();
    expect(authoritySourceFor(AUTHORITY, undefined)).toBeUndefined();
  });

  it('reports an Authority-register DID the loaded register no longer has', () => {
    const dids = new Set([AUTHORITY]);
    expect(missingAuthorityDid(GONE, 'authority', dids)).toBe(GONE);
    expect(missingAuthorityDid(AUTHORITY, 'authority', dids)).toBeNull();
  });

  it('reports nothing for another source, a template, no source, or a register not loaded', () => {
    const dids = new Set([AUTHORITY]);
    expect(missingAuthorityDid(GONE, 'issuer', dids)).toBeNull();
    expect(missingAuthorityDid(GONE, 'did', dids)).toBeNull();
    expect(missingAuthorityDid(GONE, undefined, dids)).toBeNull();
    expect(missingAuthorityDid(SURFACE_ISSUER_DID_TEMPLATE, 'authority', dids)).toBeNull();
    expect(missingAuthorityDid(GONE, 'authority', null)).toBeNull();
    expect(missingAuthorityDid(GONE, 'authority', undefined)).toBeNull();
  });
});

describe('classifyTargetAuthoritySelection — authority_source', () => {
  it('is missing-authority for an Authority-register DID the loaded register no longer has', () => {
    expect(classifyTargetAuthoritySelection(GONE, issuers, authorities, 'authority')).toEqual({
      kind: 'missing-authority',
      did: GONE,
    });
  });

  it('is missing-authority even when an Issuer has the same DID', () => {
    expect(classifyTargetAuthoritySelection(ISSUER, issuers, authorities, 'authority').kind).toBe(
      'missing-authority'
    );
  });

  it('is the Authority while the register still has it', () => {
    expect(classifyTargetAuthoritySelection(AUTHORITY, issuers, authorities, 'authority')).toEqual({
      kind: 'authority',
      name: 'Payments Authority',
      did: AUTHORITY,
    });
  });

  it('is not missing while the register has not loaded', () => {
    expect(classifyTargetAuthoritySelection(GONE, issuers, [], 'authority', false).kind).toBe(
      'custom-did'
    );
  });

  it('is not missing for an issuer source, a template, or no source', () => {
    expect(classifyTargetAuthoritySelection(GONE, issuers, authorities, 'issuer').kind).toBe(
      'custom-did'
    );
    expect(classifyTargetAuthoritySelection(GONE, issuers, authorities).kind).toBe('custom-did');
    expect(
      classifyTargetAuthoritySelection('{{ input.agent.provider_did }}', [], [], 'authority').kind
    ).toBe('legacy-template');
  });
});

describe('missing Authority — nodes and Save', () => {
  const dids = new Set([AUTHORITY]);
  const trustCheck = (queries: unknown[]) => ({
    id: 'tc',
    type: 'trust-check',
    config: { queries },
  });
  const trustRecorder = (entries: unknown[]) => ({
    id: 'tr',
    type: 'trust-recorder',
    config: { entries },
  });

  it('lists each query and entry whose Authority was deleted', () => {
    expect(
      missingTrustCheckAuthorities(
        { queries: [check('a', AUTHORITY, 'authority'), check('b', GONE, 'authority')] },
        dids
      )
    ).toEqual([{ index: 1, did: GONE }]);
    expect(
      missingTrustRecorderAuthorities(
        { entries: [recorderEntry(GONE, 'authority'), recorderEntry(GONE, 'issuer')] },
        dids
      )
    ).toEqual([{ index: 0, did: GONE }]);
    expect(
      missingTrustCheckAuthorities({ queries: [check('b', GONE, 'authority')] }, null)
    ).toEqual([]);
  });

  it('words the Trust Check warning with the DID and AUTHORITY_NOT_FOUND', () => {
    expect(missingAuthorityWarning(trustCheck([check('b', GONE, 'authority')]), dids)).toBe(
      `The Authority this Trust Check uses (${GONE}) no longer exists, so the check fails with AUTHORITY_NOT_FOUND. Pick another Authority, add an Authority with that DID, or remove the Trust Check.`
    );
    expect(
      missingAuthorityWarning(
        trustCheck([check('a', AUTHORITY, 'authority'), check('b', GONE, 'authority')]),
        dids
      )
    ).toMatch(/^Query 2: The Authority this Trust Check uses/);
  });

  it('words the Trust Recorder warning with the DID and the skipped records', () => {
    expect(missingAuthorityWarning(trustRecorder([recorderEntry(GONE, 'authority')]), dids)).toBe(
      `The Authority this Trust Recorder entry uses (${GONE}) no longer exists, so the entry writes no records. Pick another Authority, add an Authority with that DID, or remove the entry.`
    );
  });

  it('gives the canvas reason and blocks Save on the first such node', () => {
    const nodes = [
      trustCheck([check('a', AUTHORITY, 'authority')]),
      trustRecorder([recorderEntry(GONE, 'authority')]),
    ];
    expect(missingAuthorityCanvasReason(nodes[1], dids)).toBe('Authority deleted');
    expect(missingAuthorityCanvasReason(nodes[0], dids)).toBeNull();
    expect(firstMissingAuthorityNode(nodes, dids)?.node.id).toBe('tr');
  });

  it('blocks nothing while the register is not loaded or nothing names a deleted Authority', () => {
    const gone = trustCheck([check('b', GONE, 'authority')]);
    expect(firstMissingAuthorityNode([gone], null)).toBeNull();
    expect(firstMissingAuthorityNode([trustCheck([check('b', GONE, 'issuer')])], dids)).toBeNull();
    expect(
      firstMissingAuthorityNode([{ id: 'x', type: 'policy', config: { queries: [] } }], dids)
    ).toBeNull();
  });
});
