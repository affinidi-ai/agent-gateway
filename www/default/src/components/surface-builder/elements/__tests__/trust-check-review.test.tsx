import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import {
  countTrustCheckReviews,
  countTrustCheckReviewsInPayload,
  MANAGED_AGENT_TRUST_CHECK_DUPLICATED_NOTE,
  MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE,
  STORED_TRUST_CHECK_LIST_KEY,
  trustCheckLeg,
  trustCheckReviewBadge,
} from '../trust-check/definition';
import { syncTrustCheckReviewBadge } from '../trust-check/reviewBadge';
import { dependencyErrorBlocker } from '../../dependencyBlocker';
import MigratedTrustChecksSummary from '../trust-check/MigratedTrustChecksSummary';
import TrustCheckPanel from '../trust-check/TrustCheckPanel';
import TrustCheckFullscreenPanel from '../trust-check/TrustCheckFullscreenPanel';
import { deriveEdges } from '../edges/deriveEdges';
import {
  makeSurfaceSlotFilter,
  tryDrop,
  TRUST_CHECK_CALLER_SLOT_ID,
  TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
  TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
} from '../edges/archetypes';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';

jest.mock('../../../../api', () => ({
  apiClient: {
    get: jest.fn(),
    fetch: jest.fn(),
    listTrustRegistries: () => Promise.resolve([]),
  },
}));
jest.mock('../../../../utils/issuersCache', () => ({
  getIssuers: () => Promise.resolve([]),
}));
jest.mock('../../../../utils/authoritiesCache', () => ({
  getAuthorities: () => Promise.resolve([]),
}));

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockImplementation(() =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          available_listen_addresses: [],
          available_outbound_listen_addresses: [],
          channel_path_prefix: [],
        }),
    })
  );
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
});

const ISSUER = 'did:web:issuer.example';
const entry = (id: string) => ({
  id,
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
});

const tp = (alias: string, extra: Record<string, unknown> = {}) => ({
  id: `uuid-${alias}`,
  alias,
  protocol: 'a2a',
  target_endpoint: `https://${alias}.example.com/a2a`,
  ...extra,
});

const surface = (points: unknown[], canvasNodes?: unknown[]) => ({
  name: 'review',
  status: 'active',
  tags: [],
  access_point: { route: '/a2a', protocol: 'a2a' },
  target: { endpoint: 'https://agent.example.com/a2a' },
  transit: { points },
  ...(canvasNodes ? { canvas: { version: 1, nodes: canvasNodes } } : {}),
});

function rebuild(nodes: CanvasNode[]): any {
  return registry.buildPayload({
    protocol: 'a2a',
    surfaceMeta: { name: 'review', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any);
}

const hydrate = (payload: unknown) => registry.nodesFromPayload(payload) as CanvasNode[];
const migratedMcp = () =>
  surface([
    tp('mcp1', {
      protocol: 'mcp',
      target_endpoint: 'https://mcp1.example.com/mcp',
      trust_check_list: [entry('mcp-copy')],
      trust_check_migrated: true,
    }),
    tp('a2a1'),
  ]);
const MCP_TC = 'trust-check-transit-point-mcp-1';
const withConfig = (nodes: CanvasNode[], id: string, patch: Record<string, unknown>) =>
  nodes.map(n => (n.id === id ? { ...n, config: { ...n.config, ...patch } } : n));
const mcpPoint = (payload: any) => payload.transit.points.find((p: any) => p.alias === 'mcp1');

describe('migrated Trust Check copy on an MCP Transit Point', () => {
  it('hydrates as a Trust Check on that Transit Point, flagged for review', () => {
    const nodes = hydrate(migratedMcp());
    const tc = nodes.find(n => n.id === MCP_TC)!;
    expect([tc.type, tc.parentId, tc.slotId]).toEqual([
      'trust-check',
      'transit-point-mcp-1',
      TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
    ]);
    expect(tc.config.queries.map((q: any) => q.id)).toEqual(['mcp-copy']);
    expect(tc.config.trust_check_migrated).toBe(true);
    expect(trustCheckReviewBadge(tc)?.testid).toBe('surface-node-trust-check-migrated-badge');
    expect(countTrustCheckReviews(nodes)).toBe(1);
  });

  it('binds to the Managed Agent → MCP Transit Point arrow', () => {
    const nodes = hydrate(migratedMcp());
    const edge = deriveEdges(nodes).find(
      e => e.archetype === 'ma-tp' && e.endpoints.target === 'transit-point-mcp-1'
    )!;
    expect(edge.slots.get(TRUST_CHECK_TRANSIT_POINT_SLOT_ID)).toEqual([MCP_TC]);
  });

  it('saves the untouched copy back with its flag', () => {
    const point = mcpPoint(rebuild(hydrate(migratedMcp())));
    expect(point.trust_check_list.map((e: any) => e.id)).toEqual(['mcp-copy']);
    expect(point.trust_check_migrated).toBe(true);
  });

  it('Keep keeps the list and drops the flag', () => {
    const kept = withConfig(hydrate(migratedMcp()), MCP_TC, { trust_check_migrated: false });
    const point = mcpPoint(rebuild(kept));
    expect(point.trust_check_list.map((e: any) => e.id)).toEqual(['mcp-copy']);
    expect(point).not.toHaveProperty('trust_check_migrated');
    const reloaded = hydrate(surface([point]));
    expect(reloaded.find(n => n.id === MCP_TC)?.config.queries.map((q: any) => q.id)).toEqual([
      'mcp-copy',
    ]);
    expect(countTrustCheckReviews(reloaded)).toBe(0);
  });

  it('removing the node drops the list and the flag', () => {
    const point = mcpPoint(rebuild(hydrate(migratedMcp()).filter(n => n.id !== MCP_TC)));
    expect(point).not.toHaveProperty('trust_check_list');
    expect(point).not.toHaveProperty('trust_check_migrated');
  });

  const panelProps = (nodes: CanvasNode[], id: string) => {
    const tc = nodes.find(n => n.id === id)!;
    return {
      node: tc,
      config: tc.config,
      allNodes: nodes,
      updateField: jest.fn(),
      updateFields: jest.fn(),
      openFullscreenEditor: jest.fn(),
      closeFullscreenEditor: jest.fn(),
    };
  };
  const READ_ONLY_LINE =
    "Trust Checks can't be changed on an MCP Transit Point; keep or remove this migrated copy.";

  it('shows the read-only line and the migrated banner with Keep in the panel', () => {
    const props = panelProps(hydrate(migratedMcp()), MCP_TC);
    render(<TrustCheckPanel {...(props as any)} />);
    expect(screen.getByTestId('trust-check-panel-read-only')).toHaveTextContent(READ_ONLY_LINE);
    expect(screen.getByTestId('trust-check-panel-configure')).toHaveTextContent('View Queries…');
    expect(screen.getByTestId('trust-check-panel-migrated-warning')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('trust-check-panel-migrated-warning-keep'));
    expect(props.updateField).toHaveBeenCalledWith('trust_check_migrated', false);
  });

  it('shows the queries read-only in the fullscreen editor, with Keep still working', () => {
    const props = panelProps(hydrate(migratedMcp()), MCP_TC);
    render(<TrustCheckFullscreenPanel {...(props as any)} />);
    expect(screen.getByTestId('trust-check-fullscreen-read-only')).toHaveTextContent(
      READ_ONLY_LINE
    );
    const queries = within(screen.getByTestId('trust-check-fullscreen-queries'));
    const controls = [...queries.getAllByRole('button'), ...queries.queryAllByRole('textbox')];
    expect(controls.length).toBeGreaterThan(2);
    controls.forEach(control => expect(control).toBeDisabled());
    expect(screen.getByTestId('trust-check-add-query')).toBeDisabled();
    expect(screen.getByTestId('trust-check-query-0-remove')).toBeDisabled();
    expect(screen.queryByTestId('trust-check-save')).toBeNull();
    fireEvent.click(screen.getByTestId('trust-check-fullscreen-migrated-warning-keep'));
    expect(props.updateField).toHaveBeenCalledWith('trust_check_migrated', false);
    expect(props.updateFields).not.toHaveBeenCalled();
  });

  it('keeps an A2A migrated copy editable', () => {
    const nodes = hydrate(
      surface([tp('a2a1', { trust_check_list: [entry('a2a-copy')], trust_check_migrated: true })])
    );
    const props = panelProps(nodes, 'trust-check-transit-point-a2a-1');
    const { unmount } = render(<TrustCheckPanel {...(props as any)} />);
    expect(screen.queryByTestId('trust-check-panel-read-only')).toBeNull();
    expect(screen.getByTestId('trust-check-panel-configure')).toHaveTextContent(
      'Configure Queries…'
    );
    unmount();
    render(<TrustCheckFullscreenPanel {...(props as any)} />);
    expect(screen.queryByTestId('trust-check-fullscreen-read-only')).toBeNull();
    expect(screen.getByTestId('trust-check-add-query')).toBeEnabled();
    expect(screen.getByTestId('trust-check-query-0-remove')).toBeEnabled();
    fireEvent.click(screen.getByTestId('trust-check-add-query'));
    expect(screen.getByTestId('trust-check-save')).toBeEnabled();
  });

  it('saves a read-only copy back exactly as stored', () => {
    const stored = [
      {
        id: 'raw-1',
        trust_registry_id: 'tr-1',
        query_type: 'authorization',
        name: '',
        timeout_secs: 7,
        query: {
          authority_id: '  did:web:issuer.example  ',
          entity_id: '',
          action: '',
          resource: '',
        },
      },
    ];
    const payload = surface([
      tp('mcp1', { protocol: 'mcp', trust_check_list: stored, trust_check_migrated: true }),
    ]);
    const nodes = hydrate(payload);
    expect(nodes.find(n => n.id === MCP_TC)?.config[STORED_TRUST_CHECK_LIST_KEY]).toEqual(stored);
    expect(mcpPoint(rebuild(nodes))).toMatchObject({
      trust_check_list: stored,
      trust_check_migrated: true,
    });
    const kept = withConfig(nodes, MCP_TC, { trust_check_migrated: false });
    const point = mcpPoint(rebuild(kept));
    expect(point.trust_check_list).toEqual(stored);
    expect(point).not.toHaveProperty('trust_check_migrated');
  });

  it('rebuilds an editable A2A copy from its queries', () => {
    const payload = surface([
      tp('a2a1', {
        trust_check_list: [{ ...entry('a'), timeout_secs: 7 }],
        trust_check_migrated: true,
      }),
    ]);
    const nodes = hydrate(payload);
    const tc = nodes.find(n => n.id === 'trust-check-transit-point-a2a-1')!;
    expect(tc.config).not.toHaveProperty(STORED_TRUST_CHECK_LIST_KEY);
    expect(rebuild(nodes).transit.points[0].trust_check_list[0]).not.toHaveProperty('timeout_secs');
  });

  it('refuses a new Trust Check dropped on the MCP Transit Point arrow', () => {
    const nodes = hydrate(migratedMcp()).filter(n => n.id !== MCP_TC);
    const edges = deriveEdges(nodes);
    const filter = makeSurfaceSlotFilter('https://agent.example.com/a2a', true, nodes);
    const typeOf = (id: string) => nodes.find(n => n.id === id)?.type;
    const mcpEdge = edges.find(
      e => e.archetype === 'ma-tp' && e.endpoints.target === 'transit-point-mcp-1'
    )!;
    const a2aEdge = edges.find(
      e => e.archetype === 'ma-tp' && e.endpoints.target === 'transit-point-a2a-1'
    )!;
    expect(tryDrop(mcpEdge, 'trust-check', 'request', typeOf, filter).ok).toBe(false);
    expect(tryDrop(a2aEdge, 'trust-check', 'request', typeOf, filter)).toEqual({
      ok: true,
      slotId: TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
    });
  });
});

describe('Trust Check review summary across variants', () => {
  const flaggedCopy = (alias: string, protocol = 'a2a') =>
    tp(alias, { protocol, trust_check_list: [entry(alias)], trust_check_migrated: true });

  it('counts each Transit Point with a flagged copy once', () => {
    const payload = surface([flaggedCopy('tp1'), flaggedCopy('tp2', 'mcp'), tp('tp3')]);
    expect(countTrustCheckReviews(hydrate(payload))).toBe(2);
    expect(countTrustCheckReviewsInPayload(payload)).toBe(2);
    expect(countTrustCheckReviewsInPayload({})).toBe(0);
  });

  it('reports Transit Points held in other variants while the canvas has none', () => {
    render(
      <MigratedTrustChecksSummary
        nodes={hydrate(surface([tp('tp1')]))}
        otherVariantSnapshots={[
          surface([flaggedCopy('v1'), flaggedCopy('v2', 'mcp')]),
          surface([tp('v3')]),
        ]}
      />
    );
    const summary = screen.getByTestId('surface-migrated-trust-checks-summary');
    expect(summary).toHaveTextContent('2 Transit Points need Trust Check review');
    expect(summary).toHaveTextContent('2 of them are in other variants');
  });

  it('adds the canvas and the other variants together', () => {
    render(
      <MigratedTrustChecksSummary
        nodes={hydrate(surface([flaggedCopy('tp1', 'mcp')]))}
        otherVariantSnapshots={[surface([flaggedCopy('v1')])]}
      />
    );
    const summary = screen.getByTestId('surface-migrated-trust-checks-summary');
    expect(summary).toHaveTextContent('2 Transit Points need Trust Check review');
    expect(summary).toHaveTextContent('1 of them is in another variant');
  });

  it('is hidden when no variant has anything to review', () => {
    render(
      <MigratedTrustChecksSummary
        nodes={hydrate(surface([tp('tp1')]))}
        otherVariantSnapshots={[surface([tp('v1')])]}
      />
    );
    expect(screen.queryByTestId('surface-migrated-trust-checks-summary')).toBeNull();
  });
});

describe("Managed Agent's own Trust Check on an unsupported target", () => {
  const queries = [entry('q1')];
  const nodesWith = (endpoint: string): CanvasNode[] => [
    { id: 'access-point', type: 'access-point', label: '', configured: true, config: {} },
    {
      id: 'target',
      type: 'target',
      label: '',
      configured: true,
      parentId: 'access-point',
      config: { endpoint },
    },
    {
      id: 'transit-point-a2a-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      parentId: 'access-point',
      config: { target_endpoint: 'https://tp.example.com' },
    },
    {
      id: 'trust-check-target',
      type: 'trust-check',
      label: '',
      configured: true,
      parentId: 'target',
      slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
      config: { _edge: 'ma-tp', queries },
    },
    {
      id: 'trust-check-transit-point-a2a-1',
      type: 'trust-check',
      label: '',
      configured: true,
      parentId: 'transit-point-a2a-1',
      slotId: TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
      config: { _edge: 'ma-tp', queries },
    },
    {
      id: 'trust-check-caller',
      type: 'trust-check',
      label: '',
      configured: true,
      parentId: 'access-point',
      slotId: TRUST_CHECK_CALLER_SLOT_ID,
      config: { _edge: 'ap-ma', queries },
    },
  ];
  const panelFor = (nodes: CanvasNode[]) => {
    const tc = nodes.find(n => n.id === 'trust-check-target')!;
    return {
      node: tc,
      config: tc.config,
      allNodes: nodes,
      updateField: jest.fn(),
      updateFields: jest.fn(),
      openFullscreenEditor: jest.fn(),
    };
  };
  const errorsFor = (nodes: CanvasNode[]) => {
    const ctx = buildSurfaceContext('a2a', nodes);
    return nodes.flatMap(n =>
      registry
        .getDependencyWarnings(n.type, n.config, ctx, n)
        .filter(w => w.severity === 'error')
        .map(w => [n.id, w.message])
    );
  };

  const withTransitPointQueries = (nodes: CanvasNode[], tpQueries: unknown[]) =>
    nodes.map(n =>
      n.id === 'trust-check-transit-point-a2a-1'
        ? { ...n, config: { ...n.config, queries: tpQueries } }
        : n
    );

  it('blocks Save on a URL target with a message naming both fixes', () => {
    const nodes = withTransitPointQueries(nodesWith('https://agent.example.com/a2a'), [
      entry('other'),
    ]);
    nodes[
      nodes.findIndex(n => n.id === 'trust-check-transit-point-a2a-1')
    ].config.queries[0].query = {
      authority_id: 'did:web:other.example',
      entity_id: '{{ input.agent.did }}',
    };
    expect(errorsFor(nodes)).toEqual([
      ['trust-check-target', MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE],
    ]);
    expect(MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE).toBe(
      "The Managed Agent's own Trust Check runs only on an A2A Proxy or gateway target. Remove it or switch the target."
    );
    const panel = panelFor(nodes);
    render(<TrustCheckPanel {...(panel as any)} />);
    expect(screen.getByTestId('trust-check-panel-managed-agent-target-warning')).toHaveTextContent(
      "To check a Transit Point's target, drop a Trust Check on its arrow instead."
    );
  });

  it('says removing it loses nothing when every Transit Point runs the same checks', () => {
    const nodes = nodesWith('https://agent.example.com/a2a');
    const sameWithOtherIds = [{ ...entry('copied-id'), name: 'copied' }];
    const copied = withTransitPointQueries(nodes, sameWithOtherIds);
    expect(errorsFor(copied)).toEqual([
      [
        'trust-check-target',
        "The Managed Agent's own Trust Check runs only on an A2A Proxy or gateway target. Remove it or switch the target. The same checks already run on this surface's Transit Points, so removing it loses nothing.",
      ],
    ]);
    render(<TrustCheckPanel {...(panelFor(copied) as any)} />);
    const banner = screen.getByTestId('trust-check-panel-managed-agent-target-warning');
    expect(banner).toHaveTextContent(MANAGED_AGENT_TRUST_CHECK_DUPLICATED_NOTE);
    expect(banner).not.toHaveTextContent('drop a Trust Check on its arrow instead');
  });

  it('keeps the plain message when a Transit Point has no copy', () => {
    const nodes = nodesWith('https://agent.example.com/a2a').filter(
      n => n.id !== 'trust-check-transit-point-a2a-1'
    );
    expect(errorsFor(nodes)).toEqual([
      ['trust-check-target', MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE],
    ]);
  });

  it('reports the error as a blocker for Save and variant switching', () => {
    const nodes = nodesWith('https://agent.example.com/a2a').filter(
      n => n.id !== 'trust-check-transit-point-a2a-1'
    );
    const ctx = buildSurfaceContext('a2a', nodes);
    const errors = nodes.flatMap(n =>
      registry
        .getDependencyWarnings(n.type, n.config, ctx, n)
        .filter(w => w.severity === 'error')
        .map(w => ({ nodeId: n.id, nodeType: n.type, message: w.message }))
    );
    expect(dependencyErrorBlocker(errors)).toEqual({
      message: `Trust Check: ${MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE}`,
      nodeId: 'trust-check-target',
    });
    expect(dependencyErrorBlocker([])).toBeNull();
  });

  describe('slotless placeholders from the canvas blob', () => {
    const placeholder = (id: string, parentId: string) => ({
      id,
      type: 'trust-check',
      label: '',
      parentId,
      position: { x: 1, y: 2 },
      config: { _edge: 'ma-tp', queries: [] },
    });
    const load = (blob: unknown[]) =>
      hydrate({
        ...surface(
          [tp('a2a1')],
          [
            {
              id: 'transit-point-a2a-1',
              type: 'transit-point-a2a',
              label: '',
              parentId: 'access-point',
              config: { id: 'uuid-a2a1' },
            },
            ...blob,
          ]
        ),
      });
    const trustCheckIds = (nodes: CanvasNode[]) =>
      nodes.filter(n => n.type === 'trust-check').map(n => [n.id, n.parentId]);

    it('drops one parented on the Managed Agent, so it blocks nothing and writes nothing', () => {
      const nodes = load([placeholder('tc-old', 'target')]);
      expect(trustCheckIds(nodes)).toEqual([]);
      expect(errorsFor(nodes)).toEqual([]);
      const payload = rebuild(nodes);
      expect(payload.access_point?.trust_check_list).toBeUndefined();
      expect(payload.target).not.toHaveProperty('trust_check_list');
    });

    it('keeps one on the Access Point as the caller leg and one on a Transit Point', () => {
      const nodes = load([
        placeholder('tc-caller', 'access-point'),
        placeholder('tc-tp', 'transit-point-a2a-1'),
      ]);
      expect(trustCheckIds(nodes)).toEqual([
        ['tc-caller', 'access-point'],
        ['tc-tp', 'transit-point-a2a-1'],
      ]);
      expect(trustCheckLeg(nodes.find(n => n.id === 'tc-caller')!, nodes)).toBe('caller');
      expect(trustCheckLeg(nodes.find(n => n.id === 'tc-tp')!, nodes)).toBe('transit-point');
    });
  });

  it('resolves the leg from the parent before the slot id', () => {
    const nodes = nodesWith('fabric://gw-1/surface-a');
    const tpParentedManagedAgentSlot = {
      ...nodes.find(n => n.id === 'trust-check-transit-point-a2a-1')!,
      slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
    };
    expect(trustCheckLeg(tpParentedManagedAgentSlot, nodes)).toBe('transit-point');
    expect(trustCheckLeg(nodes.find(n => n.id === 'trust-check-target')!, nodes)).toBe(
      'managed-agent'
    );
    expect(trustCheckLeg(nodes.find(n => n.id === 'trust-check-caller')!, nodes)).toBe('caller');
  });

  it.each(['a2a-proxy://proxy-1', 'fabric://gw-1/surface-a'])(
    'raises nothing on a %s target',
    endpoint => {
      expect(errorsFor(nodesWith(endpoint))).toEqual([]);
    }
  );

  it('raises nothing once the Managed Agent Trust Check is removed', () => {
    const nodes = nodesWith('https://agent.example.com/a2a').filter(
      n => n.id !== 'trust-check-target'
    );
    expect(errorsFor(nodes)).toEqual([]);
  });

  it('does not judge the node without its placement', () => {
    const nodes = nodesWith('https://agent.example.com/a2a');
    const ctx = buildSurfaceContext('a2a', nodes);
    const node = nodes.find(n => n.id === 'trust-check-target')!;
    expect(registry.getDependencyWarnings(node.type, node.config, ctx)).toEqual([]);
  });
});

describe('Trust Check review badge sync', () => {
  const flagged = { type: 'trust-check', config: { queries: [], trust_check_migrated: true } };
  const kept = { type: 'trust-check', config: { queries: [], trust_check_migrated: false } };
  const BADGE = 'surface-node-trust-check-migrated-badge';

  it('draws, removes and redraws the badge as the flag toggles with the structure unchanged', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    svg.appendChild(g);
    document.body.appendChild(svg);
    syncTrustCheckReviewBadge(g, flagged, 20);
    expect(screen.getByTestId(BADGE)).toHaveAttribute('transform', 'translate(15, -15)');
    expect(screen.getByTestId(BADGE)).toHaveTextContent('!');
    syncTrustCheckReviewBadge(g, kept, 20);
    expect(screen.queryAllByTestId(BADGE)).toHaveLength(0);
    syncTrustCheckReviewBadge(g, flagged, 20);
    syncTrustCheckReviewBadge(g, flagged, 20);
    expect(screen.queryAllByTestId(BADGE)).toHaveLength(1);
    svg.remove();
  });

  it('does nothing without a node group', () => {
    expect(() => syncTrustCheckReviewBadge(null, flagged, 20)).not.toThrow();
  });
});
