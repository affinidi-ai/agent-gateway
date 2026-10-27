import { apiClient } from './api';

const fetchMock = jest.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify({ id: 'x' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )
  );
  global.fetch = fetchMock;
});

const sentBody = (): any => JSON.parse(fetchMock.mock.calls[0][1].body);

const surface = {
  name: 's',
  access_point: { route: '/a2a', protocol: 'a2a' },
  target: { endpoint: 'https://agent.example.com', trust_check_list: [] },
} as any;

describe('trust_check_split on surface writes', () => {
  it('is sent when creating a surface', async () => {
    await apiClient.createSurface(surface);
    expect(sentBody().trust_check_split).toBe(true);
    expect(sentBody().target.endpoint).toBe('https://agent.example.com');
  });

  it('is sent when updating a surface', async () => {
    await apiClient.updateSurface('s-1', surface);
    expect(sentBody().trust_check_split).toBe(true);
  });

  it('is sent for a surface write without a target', async () => {
    await apiClient.updateSurface('s-1', { name: 's', status: 'inactive' } as any);
    expect(sentBody()).toEqual({ name: 's', status: 'inactive', trust_check_split: true });
  });
});

describe('trust_check_split on Surface Template writes', () => {
  const template = { id: 't-1', name: 't', kind: 'full' as const, surface };

  it('is set inside the surface when creating a template', async () => {
    await apiClient.createSurfaceTemplate(template);
    expect(sentBody().surface.trust_check_split).toBe(true);
    expect(sentBody()).not.toHaveProperty('trust_check_split');
  });

  it('is set inside the surface when updating a template', async () => {
    await apiClient.updateSurfaceTemplate('t-1', template);
    expect(sentBody().surface.trust_check_split).toBe(true);
  });

  it('is set inside the surface when importing a template', async () => {
    await apiClient.importSurfaceTemplate(template);
    expect(sentBody().surface.trust_check_split).toBe(true);
  });

  it('leaves a template without a surface unchanged', async () => {
    const partial = { id: 't-2', name: 'p', kind: 'partial' as const, items: [] };
    await apiClient.createSurfaceTemplate(partial);
    expect(sentBody()).toEqual(partial);
  });
});
