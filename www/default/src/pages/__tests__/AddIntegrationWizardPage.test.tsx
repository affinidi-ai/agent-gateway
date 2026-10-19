/* eslint-disable no-template-curly-in-string */
import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AddIntegrationWizardPage from '../AddIntegrationWizardPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    post: jest.fn(),
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

// The Webhook form generates its signing secret with crypto.randomUUID, which jsdom lacks.
if (typeof globalThis.crypto?.randomUUID !== 'function') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { randomUUID: () => '00000000-0000-4000-8000-000000000000' },
    configurable: true,
  });
}

const mockGet = apiClient.get as jest.Mock;
const mockPost = apiClient.post as jest.Mock;
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
    { enum_value: 'email', name: 'Email', description: 'Email', metadata: {} },
    { enum_value: 'slack', name: 'Slack', description: 'Slack', metadata: {} },
    { enum_value: 'stream', name: 'Stream', description: 'Stream', metadata: {} },
    { enum_value: 'webhook', name: 'Webhook', description: 'Webhook', metadata: {} },
  ],
  categories: [
    { enum_value: 'general', name: 'General', description: 'General purpose', metadata: {} },
    { enum_value: 'user', name: 'User', description: 'User events', metadata: {} },
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
      category: 'user',
      label: 'User Management',
      description: 'User Management',
      variables: ['USER_ID', 'USERNAME'].map(name => variable(name, 'user')),
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

const GENERAL_PAYLOAD = {
  appliance_id: '${APPLIANCE_ID}',
  event_type: '${EVENT_TYPE}',
  timestamp: '${TIMESTAMP}',
};
const USER_PAYLOAD = {
  appliance_id: '${APPLIANCE_ID}',
  event_type: '${EVENT_TYPE}',
  timestamp: '${TIMESTAMP}',
  user: { user_id: '${USER_ID}', user_role: '${USER_ROLE}', user_status: '${USER_STATUS}' },
};

const AUDIT_TEMPLATE = {
  appliance_id: '${APPLIANCE_ID}',
  event_type: '${EVENT_TYPE}',
  category: '${AUDIT_CATEGORY}',
  timestamp: '${TIMESTAMP}',
  trace_id: '${AUDIT_TRACE_ID}',
  surface_id: '${AUDIT_SURFACE_ID}',
  record: '${AUDIT_RECORD}',
};

function renderWizard(search = '?category=audit&type=stream') {
  return render(
    <MemoryRouter initialEntries={[`/integrations/integrations/wizard${search}`]}>
      <Routes>
        <Route path="/integrations/integrations/wizard" element={<AddIntegrationWizardPage />} />
        <Route path="/integrations" element={<div data-testid="integrations-list" />} />
      </Routes>
    </MemoryRouter>
  );
}

async function categorySelect(expected: string): Promise<HTMLSelectElement> {
  const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
  await waitFor(() => expect(select.value).toBe(expected));
  return select;
}

function payloadTemplate(type = 'stream'): Record<string, unknown> {
  return JSON.parse((screen.getByTestId(`${type}-payload-template`) as HTMLTextAreaElement).value);
}

async function expectPayload(expected: Record<string, unknown>, type = 'stream') {
  await waitFor(() => expect(payloadTemplate(type)).toEqual(expected));
}

function fieldValue(id: string): string {
  return (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement).value;
}

describe('AddIntegrationWizardPage category samples', () => {
  beforeEach(() => {
    mockPermissions = { 'audit.view': true };
    mockGet.mockReset();
    mockPost.mockReset();
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data: url === '/integrations/config' ? INTEGRATION_CONFIG : RUNTIME_VARIABLES,
      })
    );
    mockPost.mockResolvedValue({ data: {} });
    mockGetAuditEventCatalog.mockReset();
    mockGetAuditEventCatalog.mockResolvedValue(AUDIT_EVENT_CATALOG);
  });

  it('creates a Governance Audit integration with the events chosen to send', async () => {
    renderWizard();
    await categorySelect('audit');
    fireEvent.click(await screen.findByTestId('integration-audit-group-policies'));

    fireEvent.change(screen.getByPlaceholderText('e.g., Email integration'), {
      target: { value: 'Audit to Kafka' },
    });
    fireEvent.change(screen.getByTestId('stream-topic-input'), {
      target: { value: 'governance-audit' },
    });
    fireEvent.change(screen.getByTestId('stream-brokers-input'), {
      target: { value: 'kafka-1:9092' },
    });
    const createButton = screen.getByRole('button', { name: /Create integration/ });
    await waitFor(() => expect(createButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost.mock.calls[0][1]).toMatchObject({
      category: 'audit',
      audit_events: ['policy_decision'],
    });
  });

  it('offers events to send only for the Governance Audit category', async () => {
    renderWizard('?category=general&type=webhook');
    await categorySelect('general');

    expect(screen.queryByTestId('integration-audit-events')).not.toBeInTheDocument();
  });

  async function fillAuditStream() {
    await categorySelect('audit');
    fireEvent.change(screen.getByPlaceholderText('e.g., Email integration'), {
      target: { value: 'Audit to Kafka' },
    });
    fireEvent.change(screen.getByTestId('stream-topic-input'), {
      target: { value: 'governance-audit' },
    });
    fireEvent.change(screen.getByTestId('stream-brokers-input'), {
      target: { value: 'kafka-1:9092' },
    });
  }

  async function submitWizard() {
    const createButton = screen.getByRole('button', { name: /Create integration/ });
    await waitFor(() => expect(createButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));
  }

  it('creates a Governance Audit integration with the delivery limits set', async () => {
    renderWizard();
    await fillAuditStream();
    fireEvent.change(screen.getByTestId('integration-audit-max-attempts-input'), {
      target: { value: '10' },
    });
    fireEvent.change(screen.getByTestId('integration-audit-drop-after-input'), {
      target: { value: '3600' },
    });
    await submitWizard();

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost.mock.calls[0][1]).toMatchObject({
      category: 'audit',
      audit_max_attempts: 10,
      audit_drop_after_secs: 3600,
    });
  });

  it('leaves out the delivery limits left empty', async () => {
    renderWizard();
    await fillAuditStream();
    expect(screen.getByTestId('integration-audit-max-attempts-input')).toHaveValue(null);
    await submitWizard();

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('audit_max_attempts');
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('audit_drop_after_secs');
  });

  it('refuses a delivery limit that is not a whole number of 1 or more', async () => {
    renderWizard();
    await fillAuditStream();
    fireEvent.change(screen.getByTestId('integration-audit-max-attempts-input'), {
      target: { value: '0' },
    });
    await submitWizard();

    expect(
      await screen.findByText(
        'Give up on a record after N attempts: enter a whole number of 1 or more, or leave it empty.'
      )
    ).toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('offers the delivery limits only for the Governance Audit category', async () => {
    renderWizard('?category=general&type=webhook');
    const select = await categorySelect('general');
    expect(screen.queryByTestId('integration-audit-limits')).not.toBeInTheDocument();

    fireEvent.change(select, { target: { value: 'audit' } });
    expect(await screen.findByTestId('integration-audit-limits')).toBeInTheDocument();
  });

  it('sends no event list for other categories', async () => {
    renderWizard('?category=general&type=webhook');
    await categorySelect('general');
    fireEvent.change(screen.getByPlaceholderText('e.g., Email integration'), {
      target: { value: 'General hook' },
    });
    fireEvent.change(
      screen.getByPlaceholderText('https://api.example.com/webhooks/notifications'),
      {
        target: { value: 'https://hooks.example.test/general' },
      }
    );
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('audit_events');
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('audit_max_attempts');
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('audit_drop_after_secs');
  });

  it('opens on a Kafka audit stream seeded with the full-record template and creates it', async () => {
    renderWizard();
    await categorySelect('audit');
    expect(screen.getByTestId('integration-audit-card')).toBeInTheDocument();
    await expectPayload(AUDIT_TEMPLATE);

    fireEvent.change(screen.getByPlaceholderText('e.g., Email integration'), {
      target: { value: 'Audit to Kafka' },
    });
    fireEvent.change(screen.getByTestId('stream-topic-input'), {
      target: { value: 'governance-audit' },
    });
    fireEvent.change(screen.getByTestId('stream-brokers-input'), {
      target: { value: 'kafka-1:9092' },
    });
    const createButton = screen.getByRole('button', { name: /Create integration/ });
    await waitFor(() => expect(createButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    const [url, body] = mockPost.mock.calls[0];
    expect(url).toBe('/integrations');
    expect(body).toMatchObject({
      name: 'Audit to Kafka',
      type: 'stream',
      category: 'audit',
      configuration: { platform: 'kafka', topic: 'governance-audit', brokers: 'kafka-1:9092' },
      content: AUDIT_TEMPLATE,
    });
    expect(await screen.findByTestId('integrations-list')).toBeInTheDocument();
  });

  it("follows each category's sample while the payload is untouched", async () => {
    renderWizard('?category=general&type=webhook');
    const select = await categorySelect('general');
    await expectPayload(GENERAL_PAYLOAD, 'webhook');

    fireEvent.change(select, { target: { value: 'user' } });
    await expectPayload(USER_PAYLOAD, 'webhook');

    fireEvent.change(select, { target: { value: 'audit' } });
    await expectPayload(AUDIT_TEMPLATE, 'webhook');

    fireEvent.change(select, { target: { value: 'general' } });
    expect(screen.queryByTestId('integration-audit-card')).not.toBeInTheDocument();
    await expectPayload(GENERAL_PAYLOAD, 'webhook');
  });

  it('keeps an edited payload when the category changes', async () => {
    renderWizard('?category=general&type=webhook');
    const select = await categorySelect('general');
    await expectPayload(GENERAL_PAYLOAD, 'webhook');

    fireEvent.change(screen.getByTestId('webhook-payload-template'), {
      target: { value: '{"custom":"payload"}' },
    });
    fireEvent.change(select, { target: { value: 'user' } });
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    expect(payloadTemplate('webhook')).toEqual({ custom: 'payload' });
  });

  it('shows the sample for a type chosen after opening the wizard', async () => {
    renderWizard('');
    const select = await categorySelect('general');
    fireEvent.change(select, { target: { value: 'user' } });

    fireEvent.change(screen.getByLabelText(/Integration Type/), { target: { value: 'stream' } });
    await expectPayload(USER_PAYLOAD);
  });

  it('fills the Email subject and body with the category sample', async () => {
    renderWizard('?category=user&type=email');
    const select = await categorySelect('user');

    await waitFor(() =>
      expect(fieldValue('body')).toBe(
        'APPLIANCE_ID: ${APPLIANCE_ID}\nEVENT_TYPE: ${EVENT_TYPE}\nTIMESTAMP: ${TIMESTAMP}\n\nUser Management\nUSER_ID: ${USER_ID}\nUSERNAME: ${USERNAME}'
      )
    );
    expect(fieldValue('subject')).toBe('${EVENT_TYPE}');

    fireEvent.change(select, { target: { value: 'general' } });
    await waitFor(() =>
      expect(fieldValue('body')).toBe(
        'APPLIANCE_ID: ${APPLIANCE_ID}\nEVENT_TYPE: ${EVENT_TYPE}\nTIMESTAMP: ${TIMESTAMP}'
      )
    );
  });

  it('fills the Slack message text with the category sample', async () => {
    renderWizard('?category=user&type=slack');
    await categorySelect('user');

    await waitFor(() =>
      expect(fieldValue('text')).toBe(
        '*${EVENT_TYPE}* at ${TIMESTAMP}\n• *USER_ID:* ${USER_ID}\n• *USERNAME:* ${USERNAME}'
      )
    );
  });

  it('restores the audit template on request after the payload was edited', async () => {
    renderWizard();
    await categorySelect('audit');
    await expectPayload(AUDIT_TEMPLATE);

    fireEvent.change(screen.getByTestId('stream-payload-template'), {
      target: { value: '{"custom":"payload"}' },
    });
    expect(payloadTemplate()).toEqual({ custom: 'payload' });

    fireEvent.click(screen.getByTestId('integration-audit-template-button'));
    expect(payloadTemplate()).toEqual(AUDIT_TEMPLATE);
  });

  it('keeps Email for Governance Audit and offers every type', async () => {
    renderWizard('?category=general&type=email');
    const select = await categorySelect('general');
    const typeSelect = screen.getByLabelText(/Integration Type/) as HTMLSelectElement;
    const allTypes = Array.from(typeSelect.options).map(option => option.value);
    expect(typeSelect.value).toBe('email');

    fireEvent.change(select, { target: { value: 'audit' } });
    expect(await screen.findByTestId('integration-audit-card')).toBeInTheDocument();
    expect(typeSelect.value).toBe('email');
    expect(Array.from(typeSelect.options).map(option => option.value)).toEqual(allTypes);
    expect(screen.queryByTestId('integration-audit-template-button')).not.toBeInTheDocument();
  });

  it('says so when the requested category is unavailable instead of silently switching', async () => {
    mockPermissions = {};
    renderWizard();

    await categorySelect('general');
    const notice = await screen.findByTestId('integration-category-unavailable');
    expect(notice).toHaveTextContent('audit');
    expect(notice).toHaveTextContent('audit.view');
  });

  it('shows no unavailable-category notice when the requested category exists', async () => {
    renderWizard();
    await categorySelect('audit');
    expect(screen.queryByTestId('integration-category-unavailable')).not.toBeInTheDocument();
  });

  it('never offers the audit category without audit.view', async () => {
    mockPermissions = {};
    renderWizard();

    const select = await categorySelect('general');
    expect(Array.from(select.options).map(option => option.value)).toEqual(['general', 'user']);
    expect(screen.queryByTestId('integration-audit-card')).not.toBeInTheDocument();
    await expectPayload(GENERAL_PAYLOAD);
  });
});
