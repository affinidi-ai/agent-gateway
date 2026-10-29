import { apiClient, type AgentSurface } from '../api';

const WARNING = {
  code: 'fail_open_policy',
  message: 'A failed caller is admitted.',
  path: 'access_point.inbound_policy',
  variant: null,
};

const SURFACE = {
  surface_id: 's1',
  name: 'S',
  description: '',
  status: 'active',
  tags: [],
  access_point: { listen_address: 'https://gw', route: '/a', protocol: 'a2a' },
  target: { endpoint: 'https://up' },
} as unknown as AgentSurface;

let fetchMock: jest.Mock;
let responseBody: unknown;

beforeEach(() => {
  responseBody = { ...SURFACE, warnings: [WARNING], declarations: [] };
  fetchMock = jest.fn().mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )
  );
  (globalThis as unknown as { fetch: jest.Mock }).fetch = fetchMock;
});

const sentBody = (): Record<string, any> => JSON.parse(fetchMock.mock.calls[0][1].body);

describe('surface save contract', () => {
  it('returns the warnings and declarations of a create response', async () => {
    const created = await apiClient.createSurface(SURFACE);
    expect(created.warnings).toEqual([WARNING]);
    expect(created.declarations).toEqual([]);
    expect(created.surface_id).toBe('s1');
  });

  it('returns a save response without the fields as a plain surface', async () => {
    responseBody = SURFACE;
    const updated = await apiClient.updateSurface('s1', SURFACE);
    expect(updated.surface_id).toBe('s1');
    expect(updated.warnings).toBeUndefined();
    expect(updated.declarations).toBeUndefined();
  });

  it('does not send warnings or declarations back on update', async () => {
    await apiClient.updateSurface('s1', {
      ...SURFACE,
      warnings: [WARNING],
      declarations: [{ variant: null, outcome: 'strip', reason: 'not_pinned', resource: null }],
    });
    const body = sentBody();
    expect(fetchMock.mock.calls[0][1].method).toBe('PUT');
    expect(body).not.toHaveProperty('warnings');
    expect(body).not.toHaveProperty('declarations');
    expect(body.surface_id).toBe('s1');
    expect(body.target.endpoint).toBe('https://up');
  });

  it('does not send them back on a write without a target either', async () => {
    await apiClient.updateSurface('s1', {
      name: 'S',
      status: 'disabled',
      warnings: [WARNING],
      declarations: [],
    });
    expect(sentBody()).toEqual({ name: 'S', status: 'disabled', trust_check_split: true });
  });

  it('keeps the per Transit Point Trust Check marker on the update', async () => {
    await apiClient.updateSurface('s1', { ...SURFACE, warnings: [WARNING] });
    expect(sentBody().trust_check_split).toBe(true);
  });

  it('keeps a protected resource removal in the update', async () => {
    await apiClient.updateSurface('s1', {
      ...SURFACE,
      access_point: {
        ...SURFACE.access_point,
        protocol: 'mcp',
        caller_authentication: { methods: [], protected_resource: null },
      },
      declarations: [],
    } as AgentSurface);
    const body = sentBody();
    expect(body.access_point.caller_authentication).toEqual({
      methods: [],
      protected_resource: null,
    });
    expect(body).not.toHaveProperty('declarations');
  });

  it('does not change the surface object the caller passed', async () => {
    const surface = { ...SURFACE, warnings: [WARNING] };
    await apiClient.updateSurface('s1', surface);
    expect(surface.warnings).toEqual([WARNING]);
  });
});
