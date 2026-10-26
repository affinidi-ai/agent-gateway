import { apiClient, stripServerWrittenFields } from './api';
import type { AgentSurface } from './api';

const fetchMock = jest.fn();

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const snapshot = { version: '1', amount: { amount: '0.01', unit: 'USDC' } };

const canvasWithSnapshot = () => ({
  version: 1,
  nodes: [
    {
      id: 'payment',
      type: 'payment',
      config: {
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-ch',
        manifest_snapshot: snapshot,
      },
    },
    {
      id: 'target',
      type: 'target',
      config: {
        endpoint: 'https://agent.example',
        payment_policy: {
          type: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
          manifest_snapshot: snapshot,
        },
      },
    },
    { id: 'human', type: 'human', config: { description: 'a person' } },
  ],
});

const savedSurface = {
  surface_id: 's1',
  name: 'Paid',
  tags: [],
  status: 'active',
  target: {
    endpoint: 'https://agent.example',
    payment_policy: {
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      manifest_snapshot: snapshot,
    },
  },
  canvas: canvasWithSnapshot(),
  variants: [
    {
      id: 'v1',
      alias: 'eu',
      name: 'Europe',
      overrides: {
        canvas: canvasWithSnapshot(),
        target: {
          payment_policy: {
            type: 'agent_pay',
            payment_gateway_id: 'gw-1',
            payment_surface_id: 'pay-ch$eu',
            manifest_snapshot: snapshot,
          },
        },
      },
    },
  ],
  warnings: [{ code: 'payment_unverified', message: 'agent-pay unreachable' }],
} as unknown as AgentSurface;

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
});

describe('stripServerWrittenFields', () => {
  it('drops save warnings and every manifest_snapshot', () => {
    const out = stripServerWrittenFields(savedSurface) as unknown as {
      target: { endpoint: string; payment_policy: Record<string, unknown> };
      variants: Array<{ overrides: { target: { payment_policy: Record<string, unknown> } } }>;
    };
    expect(out).not.toHaveProperty('warnings');
    expect(out.target.payment_policy).toEqual({
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
    });
    const variantPolicy = out.variants[0].overrides.target.payment_policy;
    expect(variantPolicy).not.toHaveProperty('manifest_snapshot');
    expect(variantPolicy).toHaveProperty('payment_surface_id', 'pay-ch$eu');
    expect(out.target.endpoint).toBe('https://agent.example');
  });

  it('drops the snapshot from the canvas blob, whether a node holds it or its copy of the policy', () => {
    interface Canvas {
      version: number;
      nodes: Array<{ config: Record<string, unknown> }>;
    }
    const out = stripServerWrittenFields(savedSurface) as unknown as {
      canvas: Canvas;
      variants: Array<{ overrides: { canvas: Canvas } }>;
    };

    const configs = (canvas: Canvas) => canvas.nodes.map(n => n.config);
    const expected = [
      { payment_gateway_id: 'gw-1', payment_surface_id: 'pay-ch' },
      {
        endpoint: 'https://agent.example',
        payment_policy: {
          type: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
        },
      },
      { description: 'a person' },
    ];
    expect(configs(out.canvas)).toEqual(expected);
    expect(configs(out.variants[0].overrides.canvas)).toEqual(expected);
    expect(out.canvas.version).toBe(1);
    expect(JSON.stringify(out)).not.toContain('manifest_snapshot');
  });

  it('does not change the surface it was given', () => {
    stripServerWrittenFields(savedSurface);

    expect(savedSurface.canvas.nodes[0].config).toHaveProperty('manifest_snapshot');
    expect(savedSurface.target.payment_policy).toHaveProperty('manifest_snapshot');
  });

  it('leaves a surface without server-written fields unchanged', () => {
    const plain = { name: 'Free', target: { endpoint: 'https://a' }, variants: [{ id: 'v' }] };
    expect(stripServerWrittenFields(plain as unknown as Partial<AgentSurface>)).toEqual(plain);
  });
});

describe('surface saves', () => {
  it('returns the save warnings but never sends them back', async () => {
    fetchMock.mockResolvedValue(json(savedSurface));

    const saved = await apiClient.updateSurface('s1', savedSurface);

    expect(saved.warnings).toEqual([
      { code: 'payment_unverified', message: 'agent-pay unreachable' },
    ]);
    const sent = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(sent).not.toHaveProperty('warnings');
    expect(sent.target.payment_policy).not.toHaveProperty('manifest_snapshot');
    expect(sent.variants[0].overrides.target.payment_policy).not.toHaveProperty(
      'manifest_snapshot'
    );
    expect(JSON.stringify(sent)).not.toContain('manifest_snapshot');
  });

  it('does not believe a snapshot an earlier save left in the canvas blob', async () => {
    fetchMock.mockResolvedValue(
      json({
        ...savedSurface,
        target: {
          endpoint: 'https://agent.example',
          payment_policy: {
            type: 'agent_pay',
            payment_gateway_id: 'gw-1',
            payment_surface_id: 'pay-new',
          },
        },
      })
    );

    const loaded = await apiClient.getSurface('s1');

    expect(JSON.stringify(loaded.canvas)).not.toContain('manifest_snapshot');
    expect(JSON.stringify(loaded.variants?.[0].overrides.canvas)).not.toContain(
      'manifest_snapshot'
    );
    expect(loaded.canvas.nodes[0].config.payment_gateway_id).toBe('gw-1');
  });

  it('keeps the snapshot the server wrote in the policy it stored', async () => {
    fetchMock.mockResolvedValue(json(savedSurface));

    const loaded = await apiClient.getSurface('s1');

    expect(loaded.target.payment_policy).toHaveProperty('manifest_snapshot');
  });

  it('rejects a refused save with its code and details', async () => {
    fetchMock.mockResolvedValue(
      json(
        {
          error: 'Bad Request',
          code: 'payment_manifest_invalid',
          details: 'The payment surface offers no payment point',
        },
        400
      )
    );

    await expect(apiClient.createSurface({ name: 'Paid' })).rejects.toMatchObject({
      status: 400,
      code: 'payment_manifest_invalid',
      message: 'The payment surface offers no payment point (400)',
    });
  });
});

describe('getPaymentManifest', () => {
  it('asks for a forced refresh only when requested', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(json({ gateway_id: 'gw-1', surface_id: 'pay-ch', manifest: snapshot }))
    );

    await expect(apiClient.getPaymentManifest('gw-1', 'pay-ch$eu')).resolves.toEqual(snapshot);
    await apiClient.getPaymentManifest('gw-1', 'pay-ch', true);

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/gateways/gw-1/surfaces/pay-ch%24eu/payment-manifest'
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      '/api/v1/gateways/gw-1/surfaces/pay-ch/payment-manifest?force_refresh=true'
    );
  });

  it('rejects with the route error code', async () => {
    fetchMock.mockResolvedValue(json({ error: 'payment_gateway_unavailable' }, 503));

    await expect(apiClient.getPaymentManifest('gw-1', 'pay-ch')).rejects.toMatchObject({
      status: 503,
      code: 'payment_gateway_unavailable',
    });
  });
});

describe('surface reads', () => {
  it('scrubs the snapshot from the canvas blobs of every listed surface', async () => {
    fetchMock.mockResolvedValue(json([savedSurface]));

    const [listed] = await apiClient.listSurfaces();

    expect(JSON.stringify(listed.canvas)).not.toContain('manifest_snapshot');
    expect(JSON.stringify(listed.variants?.[0].overrides.canvas)).not.toContain(
      'manifest_snapshot'
    );
    expect(listed.target.payment_policy).toHaveProperty('manifest_snapshot');
  });

  it('scrubs the canvas blobs of a surface a save returns', async () => {
    fetchMock.mockResolvedValue(json(savedSurface));

    const saved = await apiClient.createSurface({ name: 'Paid' });

    expect(JSON.stringify(saved.canvas)).not.toContain('manifest_snapshot');
  });

  it('sends the write path scrub once and leaves the caller’s surface untouched', async () => {
    fetchMock.mockResolvedValue(json(savedSurface));
    const input = JSON.parse(JSON.stringify(savedSurface));

    await apiClient.updateSurface('s1', input);

    expect(JSON.stringify(input.canvas)).toContain('manifest_snapshot');
  });
});
