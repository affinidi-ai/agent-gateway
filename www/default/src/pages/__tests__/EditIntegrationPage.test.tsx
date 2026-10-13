import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditIntegrationPage from '../EditIntegrationPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
    getAuditEventCatalog: jest.fn(),
  },
}));

jest.mock('../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;
const mockPut = apiClient.put as jest.Mock;
const mockGetAuditEventCatalog = apiClient.getAuditEventCatalog as jest.Mock;

const AUDIT_EVENT_CATALOG = [
  {
    event: 'policy_decision',
    label: 'Policy Decision',
    description: 'An OPA policy allowed or denied a request',
    group: 'policies',
    group_label: 'Policies',
  },
  {
    event: 'auth_failed',
    label: 'Auth Failed',
    description: 'A caller failed authentication',
    group: 'auth',
    group_label: 'Auth',
  },
];

const INTEGRATION_CONFIG = {
  types: [
    { enum_value: 'stream', name: 'Stream', description: 'Stream', metadata: {} },
    { enum_value: 'webhook', name: 'Webhook', description: 'Webhook', metadata: {} },
  ],
  categories: [
    { enum_value: 'general', name: 'General', description: 'General purpose', metadata: {} },
    {
      enum_value: 'audit',
      name: 'Governance Audit',
      description: 'Sends the audit events you select',
      metadata: {},
    },
  ],
};

const variable = (name: string, category: string) => ({
  name,
  label: name,
  description: name,
  example: name,
  category,
});

const RUNTIME_VARIABLES = {
  categories: [
    {
      category: 'general',
      label: 'General',
      description: 'General',
      variables: ['APPLIANCE_ID', 'EVENT_TYPE', 'TIMESTAMP'].map(name => variable(name, 'general')),
    },
    {
      category: 'audit',
      label: 'Governance Audit',
      description: 'Governance Audit',
      variables: ['AUDIT_RECORD', 'AUDIT_CATEGORY', 'AUDIT_TRACE_ID', 'AUDIT_SURFACE_ID'].map(
        name => variable(name, 'audit')
      ),
    },
  ],
};

const STREAM_INTEGRATION = {
  id: 'int-1',
  name: 'Events to Kafka',
  description: '',
  type: 'stream',
  category: 'general',
  configuration: { platform: 'kafka', topic: 'events', brokers: 'kafka-1:9092' },
  content: { event_type: '${EVENT_TYPE}' }, // eslint-disable-line no-template-curly-in-string
  status: 'active',
};

// The Webhook form generates its signing secret with crypto.randomUUID, which jsdom lacks.
if (typeof globalThis.crypto?.randomUUID !== 'function') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { randomUUID: () => '00000000-0000-4000-8000-000000000000' },
    configurable: true,
  });
}

function renderEditor(integration: Record<string, unknown> = STREAM_INTEGRATION) {
  mockGet.mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === '/integrations/config'
          ? INTEGRATION_CONFIG
          : url === '/integrations/int-1'
            ? integration
            : RUNTIME_VARIABLES,
    })
  );
  return render(
    <MemoryRouter initialEntries={['/integrations/integrations/int-1']}>
      <Routes>
        <Route path="/integrations/integrations/:id" element={<EditIntegrationPage />} />
      </Routes>
    </MemoryRouter>
  );
}

function payloadTemplate(type = 'stream'): Record<string, unknown> {
  return JSON.parse((screen.getByTestId(`${type}-payload-template`) as HTMLTextAreaElement).value);
}

const AUDIT_INTEGRATION = {
  ...STREAM_INTEGRATION,
  name: 'Audit to Kafka',
  category: 'audit',
  content: { record: '${AUDIT_RECORD}' }, // eslint-disable-line no-template-curly-in-string
  audit_events: ['auth_failed'],
};

async function renameAndSave(name: string) {
  const nameInput = (await screen.findByLabelText(/Name/)) as HTMLInputElement;
  await waitFor(() => expect(nameInput.value).not.toBe(''));
  fireEvent.change(nameInput, { target: { value: name } });
  const saveButton = screen.getByRole('button', { name: /Save Changes/ });
  await waitFor(() => expect(saveButton).toBeEnabled());
  fireEvent.submit(screen.getByTestId('integration-form'));
  await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
  return mockPut.mock.calls[0][1];
}

describe('EditIntegrationPage governance audit', () => {
  beforeEach(() => {
    mockPermissions = { 'audit.view': true };
    mockGet.mockReset();
    mockPut.mockReset();
    mockPut.mockResolvedValue({ data: {} });
    mockGetAuditEventCatalog.mockReset();
    mockGetAuditEventCatalog.mockResolvedValue(AUDIT_EVENT_CATALOG);
  });

  it('shows the events a Governance Audit integration sends and saves the changed selection', async () => {
    renderEditor(AUDIT_INTEGRATION);

    expect(await screen.findByTestId('integration-audit-event-auth_failed')).toBeChecked();
    expect(screen.getByTestId('integration-audit-event-policy_decision')).not.toBeChecked();

    fireEvent.click(screen.getByTestId('integration-audit-event-policy_decision'));
    const saveButton = screen.getByRole('button', { name: /Save Changes/ });
    await waitFor(() => expect(saveButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    expect(mockPut.mock.calls[0][1]).toMatchObject({
      category: 'audit',
      audit_events: ['auth_failed', 'policy_decision'],
    });
  });

  it('keeps the stored events when the event list cannot be loaded', async () => {
    mockGetAuditEventCatalog.mockRejectedValue(new Error('offline'));
    renderEditor(AUDIT_INTEGRATION);

    expect(await screen.findByTestId('integration-audit-events-error')).toBeInTheDocument();
    const body = await renameAndSave('Audit to Kafka (renamed)');

    expect(body.audit_events).toEqual(['auth_failed']);
  });

  it('sends no event list for other categories', async () => {
    renderEditor();

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    expect(screen.queryByTestId('integration-audit-events')).not.toBeInTheDocument();
    const body = await renameAndSave('Events to Kafka (renamed)');

    expect(body).not.toHaveProperty('audit_events');
  });

  it('moves an existing stream into the audit category with the audit record template', async () => {
    renderEditor();

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    expect(screen.queryByTestId('integration-audit-card')).not.toBeInTheDocument();

    fireEvent.change(select, { target: { value: 'audit' } });
    expect(screen.getByTestId('integration-audit-card')).toBeInTheDocument();
    expect(payloadTemplate()).toEqual(STREAM_INTEGRATION.content);

    fireEvent.click(screen.getByTestId('integration-audit-template-button'));
    expect(payloadTemplate()).toHaveProperty('record', '${AUDIT_RECORD}'); // eslint-disable-line no-template-curly-in-string

    const saveButton = screen.getByRole('button', { name: /Save Changes/ });
    await waitFor(() => expect(saveButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    const [url, body] = mockPut.mock.calls[0];
    expect(url).toBe('/integrations/int-1');
    expect(body).toMatchObject({ category: 'audit', type: 'stream' });
    expect(body.content).toHaveProperty('record', '${AUDIT_RECORD}'); // eslint-disable-line no-template-curly-in-string
  });

  it('moves a webhook stored with the untouched sample into the audit template', async () => {
    /* eslint-disable no-template-curly-in-string */
    const storedSample = {
      appliance_id: '${APPLIANCE_ID}',
      timestamp: '${TIMESTAMP}',
      event_type: '${EVENT_TYPE}',
    };
    /* eslint-enable no-template-curly-in-string */
    renderEditor({
      ...STREAM_INTEGRATION,
      type: 'webhook',
      configuration: { url: 'https://example.test/hook', method: 'POST' },
      content: storedSample,
    });

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    expect(payloadTemplate('webhook')).toEqual(storedSample);

    fireEvent.change(select, { target: { value: 'audit' } });
    await waitFor(
      () => expect(payloadTemplate('webhook')).toHaveProperty('record', '${AUDIT_RECORD}') // eslint-disable-line no-template-curly-in-string
    );
  });

  it('hides the audit category from callers without audit.view', async () => {
    mockPermissions = {};
    renderEditor();

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    expect(Array.from(select.options).map(option => option.value)).toEqual(['general']);
  });
});
