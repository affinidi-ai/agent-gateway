/* eslint-disable no-template-curly-in-string -- ${NAME} is the gateway's placeholder syntax */
import { apiClient } from './api';
import {
  createEndpoint,
  createEventSet,
  createIntegration,
  deleteEndpoint,
  deleteEventSet,
  deleteIntegration,
  getCatalog,
  getEndpoint,
  getEventSet,
  getIntegration,
  IntegrationCatalog,
  listEndpoints,
  listEventSets,
  listIntegrations,
  resetCatalogCache,
  testDraftIntegration,
  testEndpoint,
  testIntegration,
  updateEndpoint,
  updateEventSet,
  updateIntegration,
} from './integrationsApi';
import { extractAllTemplateVariables } from './utils/templateVariables';

jest.mock('./api', () => ({
  apiClient: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() },
}));

const client = apiClient as unknown as Record<'get' | 'post' | 'put' | 'delete', jest.Mock>;

const catalog: IntegrationCatalog = {
  events: [
    {
      id: 'gateway.created',
      name: 'Gateway Created',
      description: 'A gateway was created',
      family: 'gateway',
      family_label: 'Gateway',
      variables: ['EVENT_NAME', 'GATEWAY_NAME'],
    },
  ],
  variables: [{ name: 'EVENT_NAME', label: 'Event name', description: 'The event name' }],
  endpoint_types: [{ type: 'slack', secret_fields: ['webhook_url'] }],
  variable_pattern: '\\{\\{([^}]+)\\}\\}',
};

beforeEach(() => {
  Object.values(client).forEach(mock => mock.mockReset().mockResolvedValue({ data: {} }));
  resetCatalogCache();
});

test('loads the catalog once and adopts its placeholder syntax', async () => {
  client.get.mockResolvedValue({ data: catalog });

  await expect(getCatalog()).resolves.toEqual(catalog);
  await getCatalog();

  expect(client.get).toHaveBeenCalledTimes(1);
  expect(client.get).toHaveBeenCalledWith('/integrations/catalog');
  expect(extractAllTemplateVariables('{{GATEWAY_NAME}} and ${IGNORED}')).toEqual([
    { name: 'GATEWAY_NAME', label: undefined },
  ]);
});

test('loads the catalog again after a failure', async () => {
  client.get.mockRejectedValueOnce(new Error('Forbidden (403)')).mockResolvedValue({
    data: catalog,
  });

  await expect(getCatalog()).rejects.toThrow('Forbidden (403)');
  await expect(getCatalog()).resolves.toEqual(catalog);
});

test.each([
  ['integrations', listIntegrations, '/integrations'],
  ['endpoints', listEndpoints, '/integrations/endpoints'],
  ['event sets', listEventSets, '/integrations/event-sets'],
])('lists %s', async (_, list, path) => {
  client.get.mockResolvedValue({ data: [{ id: 'a' }] });

  await expect(list()).resolves.toEqual([{ id: 'a' }]);
  expect(client.get).toHaveBeenCalledWith(path);
});

test.each([
  ['integration', getIntegration, '/integrations/a%2Fb'],
  ['endpoint', getEndpoint, '/integrations/endpoints/a%2Fb'],
  ['event set', getEventSet, '/integrations/event-sets/a%2Fb'],
])('reads one %s by its encoded id', async (_, read, path) => {
  client.get.mockResolvedValue({ data: { id: 'a/b' } });

  await expect(read('a/b')).resolves.toEqual({ id: 'a/b' });
  expect(client.get).toHaveBeenCalledWith(path);
});

test('creates, changes and removes integrations', async () => {
  const request = {
    name: 'Alerts',
    description: '',
    endpoint_id: 'e1',
    event_set_id: 's1',
    content: { text: '${EVENT_NAME}' },
    status: 'active' as const,
  };
  client.post.mockResolvedValue({ data: { id: 'i1', ...request } });
  client.put.mockResolvedValue({ data: { id: 'i1', ...request } });

  await expect(createIntegration(request)).resolves.toMatchObject({ id: 'i1' });
  await updateIntegration('i1', request);
  await deleteIntegration('i1');

  expect(client.post).toHaveBeenCalledWith('/integrations', request);
  expect(client.put).toHaveBeenCalledWith('/integrations/i1', request);
  expect(client.delete).toHaveBeenCalledWith('/integrations/i1');
});

test('creates, changes and removes endpoints, leaving the type out of an update', async () => {
  const configuration = { webhook_url: 'https://hooks.slack.com/services/T/B/x' };
  await createEndpoint({ name: 'Ops', description: '', type: 'slack', configuration });
  await updateEndpoint('e1', { name: 'Ops', description: '', configuration, status: 'disabled' });
  await deleteEndpoint('e1');

  expect(client.post).toHaveBeenCalledWith('/integrations/endpoints', {
    name: 'Ops',
    description: '',
    type: 'slack',
    configuration,
  });
  expect(client.put).toHaveBeenCalledWith('/integrations/endpoints/e1', {
    name: 'Ops',
    description: '',
    configuration,
    status: 'disabled',
  });
  expect(client.delete).toHaveBeenCalledWith('/integrations/endpoints/e1');
});

test('creates, changes and removes event sets', async () => {
  const request = { name: 'Gateways', description: '', events: ['gateway.created'] };
  await createEventSet(request);
  await updateEventSet('s1', request);
  await deleteEventSet('s1');

  expect(client.post).toHaveBeenCalledWith('/integrations/event-sets', request);
  expect(client.put).toHaveBeenCalledWith('/integrations/event-sets/s1', request);
  expect(client.delete).toHaveBeenCalledWith('/integrations/event-sets/s1');
});

test('sends test messages with a timeout long enough for slow destinations', async () => {
  const draft = {
    name: 'Draft',
    description: '',
    endpoint_id: 'e1',
    event_set_id: 's1',
    content: {},
  };
  client.post.mockResolvedValue({ data: { delivered: true, event_type: 'gateway.created' } });

  await expect(testIntegration('i1')).resolves.toEqual({
    delivered: true,
    event_type: 'gateway.created',
  });
  await testDraftIntegration(draft);
  await testEndpoint('e1');

  expect(client.post).toHaveBeenCalledWith('/integrations/i1/test', undefined, { timeout: 30000 });
  expect(client.post).toHaveBeenCalledWith('/integrations/test', draft, { timeout: 30000 });
  expect(client.post).toHaveBeenCalledWith('/integrations/endpoints/e1/test', undefined, {
    timeout: 30000,
  });
});
