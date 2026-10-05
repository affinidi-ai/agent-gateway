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
      description: 'Forwards every record written to the VP Audit Log',
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
      variables: ['EVENT_TYPE', 'TIMESTAMP'].map(name => variable(name, 'general')),
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

describe('EditIntegrationPage governance audit', () => {
  beforeEach(() => {
    mockPermissions = { 'audit.view': true };
    mockGet.mockReset();
    mockPut.mockReset();
    mockPut.mockResolvedValue({ data: {} });
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
    const storedSample = { timestamp: '${TIMESTAMP}', event_type: '${EVENT_TYPE}' }; // eslint-disable-line no-template-curly-in-string
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
