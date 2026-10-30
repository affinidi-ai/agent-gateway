import { apiClient } from './api';

const fetchMock = jest.fn();

const respond = (
  headers: Record<string, string>,
  body: unknown = { surface_id: 's', target: {} }
) =>
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...headers },
      })
    )
  );

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
});

const sentBody = (): any => JSON.parse(fetchMock.mock.calls[0][1].body);
const surface = { name: 's', target: { endpoint: 'https://a.example.com' } } as any;

describe('Warning headers of a surface write', () => {
  it('hands each one to the caller after an update', async () => {
    respond({ Warning: '299 - "Transit Point \'crm\' is open"' });
    const onWarnings = jest.fn();
    await apiClient.updateSurface('s', surface, { onWarnings });
    expect(onWarnings).toHaveBeenCalledWith(["Transit Point 'crm' is open"]);
  });

  it('hands over an empty list when there are none, and after a create', async () => {
    respond({});
    const onWarnings = jest.fn();
    await apiClient.createSurface(surface, { onWarnings });
    expect(onWarnings).toHaveBeenCalledWith([]);
  });

  it('does not pass the listener on to fetch, and works without one', async () => {
    respond({});
    await apiClient.updateSurface('s', surface);
    expect(fetchMock.mock.calls[0][1]).not.toHaveProperty('onResponse');
  });
});

describe('transit_point_source_auth on a surface write', () => {
  it('is never sent: the gateway derives it from the Transit Points it stores', async () => {
    respond({});
    await apiClient.updateSurface('s', { ...surface, transit_point_source_auth: true });
    expect(sentBody()).not.toHaveProperty('transit_point_source_auth');
    expect(sentBody().name).toBe('s');
  });

  it('is kept on what a read returns', async () => {
    respond({}, { surface_id: 's', target: {}, transit_point_source_auth: true });
    const read = await apiClient.getSurface('s');
    expect(read.transit_point_source_auth).toBe(true);
  });
});
