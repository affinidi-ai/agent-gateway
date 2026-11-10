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
