import { apiClient } from '../../../../api';
import type { PaymentManifest } from '../../../../types';
import { buildCanvasBlob, registry } from '../index';
import type { CanvasNode } from '../types';

const fetchMock = jest.fn();

const manifest = (amount: string): PaymentManifest => ({
  version: '1',
  payable: { id: 'pay-ch', name: 'Premium' },
  amount: { amount, unit: 'USDC' },
  payment_points: [],
});

const policy = (surfaceId: string, snapshot?: PaymentManifest) => ({
  type: 'agent_pay',
  payment_gateway_id: 'gw-1',
  payment_surface_id: surfaceId,
  ...(snapshot ? { manifest_snapshot: snapshot } : {}),
});

/** A canvas blob as an earlier save left it: the old surface's snapshot in two places. */
const staleBlob = {
  version: 1,
  nodes: [
    {
      id: 'payment',
      type: 'payment',
      config: {
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-old',
        manifest_snapshot: manifest('0.10'),
      },
    },
    {
      id: 'target',
      type: 'target',
      config: {
        endpoint: 'https://upstream/y',
        payment_policy: policy('pay-old', manifest('0.10')),
      },
    },
  ],
};

const stored = (payment_policy: Record<string, unknown>, canvas?: unknown) => ({
  surface_id: 's1',
  name: 'paid',
  status: 'active',
  tags: [],
  access_point: { listener_url: 'https://gw/x', protocol: 'mcp' },
  target: { endpoint: 'https://upstream/y', payment_policy },
  ...(canvas ? { canvas } : {}),
});

const json = (body: unknown) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

const paymentNode = (nodes: CanvasNode[]) => nodes.find(n => n.type === 'payment')!;

/** What the surface page does to a loaded surface before it shows it: rebuild it from its own payload and blob. */
function rebuild(nodes: CanvasNode[]) {
  return {
    ...registry.buildPayload({
      protocol: 'mcp',
      surfaceMeta: { name: 'paid', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: type => nodes.filter(n => n.type === type),
      firstNodeOfType: type => nodes.find(n => n.type === type),
    }),
    canvas: buildCanvasBlob(nodes),
  };
}

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
});

describe('the saved price of a payment surface', () => {
  it('is not taken from a stale canvas blob when the server stored no snapshot', async () => {
    fetchMock.mockResolvedValue(json(stored(policy('pay-new'), staleBlob)));

    const loaded = await apiClient.getSurface('s1');
    const nodes = registry.nodesFromPayload(loaded);

    expect(paymentNode(nodes).config).toEqual({
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-new',
    });
  });

  it('is shown for the stored surface, also after the page rebuilds it from its own payload', async () => {
    fetchMock.mockResolvedValue(json(stored(policy('pay-ch', manifest('0.05')), staleBlob)));

    const loaded = await apiClient.getSurface('s1');
    const nodes = registry.nodesFromPayload(loaded);
    expect(paymentNode(nodes).config.manifest_snapshot).toEqual(manifest('0.05'));

    const rebuilt = registry.nodesFromPayload(rebuild(nodes));
    expect(paymentNode(rebuilt).config.manifest_snapshot).toEqual(manifest('0.05'));
    expect(paymentNode(rebuilt).config.payment_surface_id).toBe('pay-ch');
  });

  it('is gone once another surface is chosen, and nothing of it is saved', async () => {
    fetchMock.mockResolvedValueOnce(json(stored(policy('pay-ch', manifest('0.05')), staleBlob)));
    const loaded = await apiClient.getSurface('s1');
    const nodes = registry.nodesFromPayload(loaded);
    const chosen = nodes.map(n =>
      n.type === 'payment'
        ? {
            ...n,
            config: { ...n.config, payment_surface_id: 'card-ch', manifest_snapshot: undefined },
          }
        : n
    );

    fetchMock.mockResolvedValueOnce(json(stored(policy('card-ch'), rebuild(chosen).canvas)));
    await apiClient.updateSurface('s1', rebuild(chosen));

    const sent = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(sent.target.payment_policy).toEqual(policy('card-ch'));
    expect(JSON.stringify(sent)).not.toContain('manifest_snapshot');
  });

  it('is never sent in the policy or in any canvas blob, even when the page still holds it', async () => {
    fetchMock.mockResolvedValueOnce(json(stored(policy('pay-ch', manifest('0.05')), staleBlob)));
    const nodes = registry.nodesFromPayload(await apiClient.getSurface('s1'));
    const holding = rebuild(nodes);
    expect(JSON.stringify(holding)).toContain('manifest_snapshot');

    fetchMock.mockResolvedValueOnce(json(stored(policy('pay-ch'))));
    await apiClient.updateSurface('s1', holding);

    expect(JSON.stringify(JSON.parse(fetchMock.mock.calls[1][1].body))).not.toContain(
      'manifest_snapshot'
    );
  });
});
