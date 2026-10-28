import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { registry } from '../index';
import { countTrustCheckReviews, isMigratedTrustCheck } from '../trust-check/definition';
import TrustCheckPanel from '../trust-check/TrustCheckPanel';
import TrustCheckFullscreenPanel from '../trust-check/TrustCheckFullscreenPanel';
import MigratedTrustChecksSummary from '../trust-check/MigratedTrustChecksSummary';
import type { CanvasNode } from '../../SurfaceCanvas';

jest.mock('../../../../api', () => ({
  apiClient: { listTrustRegistries: () => Promise.resolve([]) },
}));
jest.mock('../../../../utils/issuersCache', () => ({
  getIssuers: () => Promise.resolve([]),
}));
jest.mock('../../../../utils/authoritiesCache', () => ({
  getAuthorities: () => Promise.resolve([]),
}));

const ISSUER = 'did:web:issuer.example';
const TP_SLOT = 'request:trust-check-transit_points_trust_check_list';

const entry = (id: string) => ({
  id,
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
});

const tp = (alias: string, migrated: boolean) => ({
  id: `uuid-${alias}`,
  alias,
  protocol: 'a2a',
  target_endpoint: `https://${alias}.example.com/a2a`,
  trust_check_list: [entry(`tc-${alias}`)],
  ...(migrated ? { trust_check_migrated: true } : {}),
});

const migratedSurface = () => ({
  name: 'migrated',
  status: 'active',
  tags: [],
  access_point: { route: '/a2a', protocol: 'a2a' },
  target: { endpoint: 'https://agent.example.com/a2a' },
  transit: { points: [tp('tp1', true), tp('tp2', true), tp('tp3', false)] },
});

function rebuild(nodes: CanvasNode[]): any {
  return registry.buildPayload({
    protocol: 'a2a',
    surfaceMeta: { name: 'migrated', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any);
}

const hydrate = () => registry.nodesFromPayload(migratedSurface()) as CanvasNode[];
const trustCheckOf = (nodes: CanvasNode[], tpNodeId: string) =>
  nodes.find(n => n.type === 'trust-check' && n.parentId === tpNodeId)!;
const updateConfig = (nodes: CanvasNode[], id: string, patch: Record<string, unknown>) =>
  nodes.map(n => (n.id === id ? { ...n, config: { ...n.config, ...patch } } : n));
const flags = (payload: any) =>
  payload.transit.points.map((p: any) => [p.alias, p.trust_check_migrated === true]);

describe('migrated Trust Check — hydration and payload', () => {
  it('moves the flag onto each flagged Transit Point Trust Check node', () => {
    const nodes = hydrate();
    expect(isMigratedTrustCheck(trustCheckOf(nodes, 'transit-point-a2a-1').config)).toBe(true);
    expect(isMigratedTrustCheck(trustCheckOf(nodes, 'transit-point-a2a-2').config)).toBe(true);
    expect(isMigratedTrustCheck(trustCheckOf(nodes, 'transit-point-a2a-3').config)).toBe(false);
    const tpNode = nodes.find(n => n.id === 'transit-point-a2a-1')!;
    expect(tpNode.config).not.toHaveProperty('trust_check_migrated');
    expect(countTrustCheckReviews(nodes)).toBe(2);
  });

  it('keeps the flag on untouched Transit Points', () => {
    expect(flags(rebuild(hydrate()))).toEqual([
      ['tp1', true],
      ['tp2', true],
      ['tp3', false],
    ]);
  });

  it('Keep drops the flag from that Transit Point only and keeps its list', () => {
    const nodes = hydrate();
    const kept = updateConfig(nodes, trustCheckOf(nodes, 'transit-point-a2a-1').id, {
      trust_check_migrated: false,
    });
    const payload = rebuild(kept);
    expect(flags(payload)).toEqual([
      ['tp1', false],
      ['tp2', true],
      ['tp3', false],
    ]);
    expect(payload.transit.points[0]).not.toHaveProperty('trust_check_migrated');
    expect(payload.transit.points[0].trust_check_list.map((e: any) => e.id)).toEqual(['tc-tp1']);
  });

  it('editing the queries drops the flag', () => {
    const nodes = hydrate();
    const edited = updateConfig(nodes, trustCheckOf(nodes, 'transit-point-a2a-2').id, {
      queries: [{ id: 'edited', trust_registry_id: 'tr-2', query_type: 'recognition', query: {} }],
      trust_check_migrated: false,
    });
    const payload = rebuild(edited);
    expect(flags(payload)).toEqual([
      ['tp1', true],
      ['tp2', false],
      ['tp3', false],
    ]);
    expect(payload.transit.points[1].trust_check_list.map((e: any) => e.id)).toEqual(['edited']);
  });

  it('removing the node drops both the list and the flag', () => {
    const nodes = hydrate();
    const removedId = trustCheckOf(nodes, 'transit-point-a2a-2').id;
    const payload = rebuild(nodes.filter(n => n.id !== removedId));
    expect(payload.transit.points[1]).not.toHaveProperty('trust_check_list');
    expect(payload.transit.points[1]).not.toHaveProperty('trust_check_migrated');
    expect(payload.transit.points[0].trust_check_migrated).toBe(true);
  });
});

describe('migrated Trust Check — surface summary', () => {
  it('counts the flagged Transit Points', () => {
    render(<MigratedTrustChecksSummary nodes={hydrate()} />);
    expect(screen.getByTestId('surface-migrated-trust-checks-summary')).toHaveTextContent(
      '2 Transit Points need Trust Check review'
    );
  });

  it('uses the singular for one Transit Point', () => {
    const nodes = hydrate();
    const one = updateConfig(nodes, trustCheckOf(nodes, 'transit-point-a2a-1').id, {
      trust_check_migrated: false,
    });
    render(<MigratedTrustChecksSummary nodes={one} />);
    expect(screen.getByTestId('surface-migrated-trust-checks-summary')).toHaveTextContent(
      '1 Transit Point needs Trust Check review'
    );
  });

  it('is hidden when nothing is flagged', () => {
    const { container } = render(
      <MigratedTrustChecksSummary
        nodes={registry.nodesFromPayload({
          ...migratedSurface(),
          transit: { points: [tp('tp1', false)] },
        })}
      />
    );
    expect(screen.queryByTestId('surface-migrated-trust-checks-summary')).toBeNull();
    expect(container).toBeEmptyDOMElement();
  });
});

function panelProps(config: Record<string, unknown>, slotId = TP_SLOT) {
  return {
    node: {
      id: 'trust-check-tp',
      type: 'trust-check',
      label: '',
      configured: true,
      config,
      parentId: 'tp',
      slotId,
    } as CanvasNode,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    openFullscreenEditor: jest.fn(),
    closeFullscreenEditor: jest.fn(),
  };
}

const queries = [
  {
    id: 'q-1',
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    query: { authority_id: ISSUER },
  },
];

describe('migrated Trust Check — sidebar panel', () => {
  it('shows the review banner on a flagged Transit Point Trust Check', () => {
    const props = panelProps({ queries, trust_check_migrated: true });
    render(<TrustCheckPanel {...(props as any)} />);
    expect(screen.getByTestId('trust-check-panel-migrated-warning')).toHaveTextContent(
      'copied from the surface-wide Trust Check list'
    );
    fireEvent.click(screen.getByTestId('trust-check-panel-migrated-warning-keep'));
    expect(props.updateField).toHaveBeenCalledWith('trust_check_migrated', false);
  });

  it('shows no banner on an unflagged Transit Point Trust Check', () => {
    render(<TrustCheckPanel {...(panelProps({ queries }) as any)} />);
    expect(screen.queryByTestId('trust-check-panel-migrated-warning')).toBeNull();
  });

  it('shows no banner outside a Transit Point', () => {
    const props = panelProps(
      { queries, trust_check_migrated: true },
      'request:trust-check-access_point_trust_check_list'
    );
    render(<TrustCheckPanel {...(props as any)} />);
    expect(screen.queryByTestId('trust-check-panel-migrated-warning')).toBeNull();
  });
});

describe('migrated Trust Check — fullscreen panel', () => {
  it('shows the banner and Keep clears the flag', async () => {
    const props = panelProps({ queries, trust_check_migrated: true });
    render(<TrustCheckFullscreenPanel {...(props as any)} />);
    await screen.findByTestId('trust-check-save');
    expect(screen.getByTestId('trust-check-fullscreen-migrated-warning')).toBeInTheDocument();
    expect(screen.getByTestId('trust-check-fullscreen-leg')).toHaveTextContent(
      'of this Transit Point only'
    );
    fireEvent.click(screen.getByTestId('trust-check-fullscreen-migrated-warning-keep'));
    expect(props.updateField).toHaveBeenCalledWith('trust_check_migrated', false);
  });

  it('saving edited queries clears the flag with the new queries', async () => {
    const props = panelProps({ queries, trust_check_migrated: true });
    render(<TrustCheckFullscreenPanel {...(props as any)} />);
    await screen.findByTestId('trust-check-save');
    fireEvent.click(screen.getByTestId('trust-check-query-0-remove'));
    fireEvent.click(screen.getByTestId('trust-check-save'));
    expect(props.updateFields).toHaveBeenCalledWith({
      queries: [],
      trust_check_migrated: false,
    });
  });

  it('shows no banner for an unflagged Trust Check', async () => {
    render(<TrustCheckFullscreenPanel {...(panelProps({ queries }) as any)} />);
    await screen.findByTestId('trust-check-save');
    expect(screen.queryByTestId('trust-check-fullscreen-migrated-warning')).toBeNull();
  });
});
