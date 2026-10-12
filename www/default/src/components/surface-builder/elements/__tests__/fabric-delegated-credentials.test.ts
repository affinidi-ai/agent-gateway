import { registry } from '../index';
import type { SurfaceContext } from '../types';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'mcp',
    surfaceMeta: { name: 'fabric-delegation', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function savedAgain(payload: Record<string, unknown>) {
  const nodes = registry.nodesFromPayload({
    access_point: { route: '/mcp', protocol: 'mcp' },
    target: { endpoint: 'https://upstream.example.com' },
    ...payload,
  });
  return registry.buildPayload(makeCtx(nodes));
}

function targetFromSaved(target: Record<string, unknown>) {
  return savedAgain({ target }).target;
}

function transitPointFromSaved(point: Record<string, unknown>) {
  return savedAgain({ transit: { points: [{ alias: 'partner', protocol: 'mcp', ...point }] } })
    .transit.points[0];
}

describe('target.fabric_delegated_credentials', () => {
  it('keeps an opted-in fabric target opted in across a dashboard save', () => {
    const target = targetFromSaved({
      endpoint: 'fabric://peer/surface',
      fabric_delegated_credentials: true,
    });
    expect(target.fabric_delegated_credentials).toBe(true);
  });

  it('leaves a fabric target without the opt-in opted out', () => {
    const target = targetFromSaved({ endpoint: 'fabric://peer/surface' });
    expect(target).not.toHaveProperty('fabric_delegated_credentials');
  });

  it('drops the opt-in when the target is not fabric', () => {
    const target = targetFromSaved({
      endpoint: 'https://upstream.example.com',
      fabric_delegated_credentials: true,
    });
    expect(target).not.toHaveProperty('fabric_delegated_credentials');
  });
});

describe('transit.points[*].fabric_delegated_credentials', () => {
  it('keeps an opted-in fabric transit point opted in across a dashboard save', () => {
    const point = transitPointFromSaved({
      target_endpoint: 'fabric://peer/surface',
      fabric_delegated_credentials: true,
    });
    expect(point.fabric_delegated_credentials).toBe(true);
  });

  it('leaves a fabric transit point without the opt-in opted out', () => {
    const point = transitPointFromSaved({ target_endpoint: 'fabric://peer/surface' });
    expect(point).not.toHaveProperty('fabric_delegated_credentials');
  });

  it('drops the opt-in when the transit point is not fabric', () => {
    const point = transitPointFromSaved({
      target_endpoint: 'https://partner.example/mcp',
      fabric_delegated_credentials: true,
    });
    expect(point).not.toHaveProperty('fabric_delegated_credentials');
  });
});
