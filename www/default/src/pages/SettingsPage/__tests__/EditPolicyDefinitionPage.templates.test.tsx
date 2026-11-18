import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../../../context/PageTitleContext';
import { apiClient } from '../../../api';
import EditPolicyDefinitionPage from '../EditPolicyDefinitionPage';
import {
  resetOrganizationTemplatesForTests,
  savePolicyTemplate,
} from '../policyTemplates/policyTemplateStore';

jest.mock('../../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
    post: jest.fn().mockResolvedValue({ data: { valid: true } }),
  },
}));

let mockCanEdit = true;
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (f: string) => f !== 'policies.edit' || mockCanEdit }),
}));

const fetchMock = apiClient.fetch as jest.Mock;

const SAVED = {
  id: 'partner-only',
  name: 'partner-only',
  description: 'Partner callers',
  policy_type: 'agent_surface',
  policy:
    'package surface.policy\n\ndefault allow := false\n\nallow if input.jwt.iss == "https://login.example"',
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
};

function jsonResponse(body: unknown) {
  return { ok: true, json: async () => body, text: async () => JSON.stringify(body) };
}

/** Answers the policy load and every simulate call; simulate allows only role admin. */
function mockGateway(saved: typeof SAVED = SAVED) {
  fetchMock.mockImplementation(async (url: string, init?: { body?: string }) => {
    if (url.endsWith('/simulate')) {
      const { input } = JSON.parse(init?.body ?? '{}');
      return jsonResponse({
        allow: input?.source_auth?.claims?.role === 'admin',
        policy_type: 'agent_surface',
        content_hash: 'sha256:x',
        query: 'data.surface.policy.allow',
      });
    }
    if (url.includes('/versions')) return jsonResponse([]);
    return jsonResponse(saved);
  });
}

function renderAt(path: string) {
  return render(
    <PageTitleProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/policy-definitions/:id" element={<EditPolicyDefinitionPage />} />
        </Routes>
      </MemoryRouter>
    </PageTitleProvider>
  );
}

const rego = () => screen.getByPlaceholderText('...add policy here...') as HTMLTextAreaElement;

beforeEach(() => {
  mockCanEdit = true;
  fetchMock.mockReset();
  resetOrganizationTemplatesForTests();
});

describe('create a policy from the Template field', () => {
  it('starts on Blank with the default policy', () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(screen.getByTestId('policy-definition-template-select')).toHaveTextContent('Blank');
    expect(rego().value).toContain('default allow = true');
  });

  it('fills Name, Description and Rego from the chosen template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-definition-template-select'));
    fireEvent.click(await screen.findByRole('option', { name: /All trust checks pass/ }));

    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue(
      'All trust checks pass'
    );
    expect(screen.getByPlaceholderText('What does this policy do?')).toHaveValue(
      'Allows a request only if at least one trust check ran on the target and every one succeeded. Denies when any check failed or none ran.'
    );
    expect(rego().value).toContain('every r in input.trust_check_results.target { r.ok }');
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();
  });

  it('lists only templates of the selected type', async () => {
    renderAt('/policy-definitions/new?type=gateway');
    fireEvent.click(screen.getByTestId('policy-definition-template-select'));
    await screen.findByRole('option', { name: /Allow listed HTTP methods/ });
    expect(screen.queryByRole('option', { name: /trust checks/ })).toBeNull();
    expect(screen.queryByRole('option', { name: /Require authenticated caller/ })).toBeNull();
    expect(screen.getByRole('option', { name: /Deny by default/ })).toBeInTheDocument();
  });
});

describe('browse templates', () => {
  it('renders a setting into the Rego and fills the form with it', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-at-least-n-trust-checks-pass:agent_surface')
    );
    fireEvent.change(screen.getByTestId('policy-templates-param-min_passing'), {
      target: { value: '3' },
    });
    expect(screen.getByTestId('policy-templates-rego-preview')).toHaveTextContent(
      'count(passing) >= 3'
    );

    fireEvent.click(screen.getByTestId('policy-templates-use-button'));

    expect(rego().value).toContain('count(passing) >= 3');
    expect(screen.queryByTestId('policy-templates-panel')).toBeNull();
  });

  it('refuses a setting outside its range', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-at-least-n-trust-checks-pass:agent_surface')
    );
    fireEvent.change(screen.getByTestId('policy-templates-param-min_passing'), {
      target: { value: '0' },
    });

    expect(screen.getByText('Enter a whole number from 1 to 20.')).toBeInTheDocument();
    expect(screen.getByTestId('policy-templates-use-button')).toBeDisabled();
  });

  it('filters by category', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    fireEvent.click(await screen.findByTestId('policy-templates-category-trust_checks'));

    const rows = screen.getAllByTestId(/^policy-templates-row-/);
    expect(rows.map(r => r.textContent)).toEqual([
      expect.stringContaining('Require Trust Registry recognition'),
      expect.stringContaining('Require verified credential subject'),
      expect.stringContaining('All trust checks pass'),
      expect.stringContaining('At least N trust checks pass'),
    ]);
  });

  it('fills a single-value setting into the Rego as a string', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    fireEvent.click(await screen.findByTestId('policy-templates-category-time'));
    fireEvent.click(
      screen.getByTestId('policy-templates-row-allow-during-business-hours:agent_surface')
    );
    fireEvent.change(screen.getByTestId('policy-templates-param-time_zone'), {
      target: { value: 'Asia/Singapore' },
    });
    expect(screen.getByTestId('policy-templates-rego-preview')).toHaveTextContent(
      'time.clock([now, "Asia/Singapore"])'
    );
  });

  it('offers the ticket starter templates other than rate controls', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    const names = (await screen.findAllByTestId(/^policy-templates-row-/)).map(
      r => r.textContent ?? ''
    );
    for (const name of [
      'Deny by default',
      'Require authenticated caller',
      'Allow by JWT claim or role',
      'Allow by JWT issuer and audience',
      'Restrict MCP tools by role',
      'Require Trust Registry recognition',
      'Require verified credential subject',
      'Allowlist outbound destinations',
      'Allow during business hours',
      'Monitor-only baseline',
      'All trust checks pass',
    ]) {
      expect(names.some(n => n.startsWith(name))).toBe(true);
    }
    expect(names.some(n => /rate/i.test(n))).toBe(false);
  });

  it('shows an empty organization tab until a template is saved', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
    fireEvent.click(await screen.findByTestId('policy-templates-tab-organization'));
    expect(screen.getByTestId('policy-templates-organization-empty')).toBeInTheDocument();
  });
});

describe('insert rules while creating a policy', () => {
  const openBrowse = () => fireEvent.click(screen.getByTestId('policy-templates-browse-button'));
  const row = (id: string) => screen.findByTestId(`policy-templates-row-${id}:agent_surface`);

  it('combines the rules of several templates in one new policy', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openBrowse();
    fireEvent.click(await row('deny-by-default'));
    fireEvent.click(screen.getByTestId('policy-templates-use-button'));

    openBrowse();
    fireEvent.click(await row('allow-by-jwt-claim'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(screen.getByTestId('policy-templates-panel')).toBeInTheDocument();
    fireEvent.click(await row('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    const value = rego().value;
    expect(value.startsWith('package surface.policy\n\ndefault allow := false')).toBe(true);
    expect(value.match(/default allow/g)).toHaveLength(1);
    expect(value).toContain('# Inserted from template: Allow by JWT claim or role\n');
    expect(value).toContain(
      '# Inserted from template: Allow listed HTTP methods\nallow if input.http.method in {"GET"}\n'
    );
    expect(screen.getByTestId('policy-definition-template-select')).toHaveTextContent(
      'Custom Rego'
    );
  });

  it('keeps Name and Description when rules are inserted', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.change(screen.getByPlaceholderText('e.g. Require Authentication'), {
      target: { value: 'partner policy' },
    });
    openBrowse();
    fireEvent.click(await row('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue(
      'partner policy'
    );
  });

  it('warns that the default allow-all Rego makes inserted allow rules do nothing', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openBrowse();
    fireEvent.click(await row('allow-http-methods'));
    expect(screen.getByTestId('policy-templates-allow-default-warning')).toBeInTheDocument();
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeEnabled();
  });

  it('offers Use but not Insert for a standalone template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openBrowse();
    fireEvent.click(await row('restrict-mcp-tools-by-role'));
    expect(screen.getByTestId('policy-templates-standalone-note')).toBeInTheDocument();
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
    expect(screen.getByTestId('policy-templates-use-button')).toBeEnabled();
  });
});

describe('insert a template into a saved policy', () => {
  it('appends the rules and checks the examples against the draft', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface')
    );
    expect(screen.getByTestId('policy-templates-insert-preview')).toHaveTextContent(
      'some v in jwt_claim_values(input.source_auth.claims["role"])'
    );

    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    expect(rego().value).toContain(
      '# Inserted from template: Allow by JWT claim or role\njwt_claim_values(v) := [v] if is_string(v)'
    );
    expect(rego().value).toContain('  v in {"admin"}\n}');
    expect(rego().value.match(/default allow/g)).toHaveLength(1);
    const card = await screen.findByTestId('policy-template-examples-card');
    await waitFor(() =>
      expect(within(card).getByTestId('policy-template-example-row-0')).toHaveTextContent(
        /Role adminALLOWALLOW/
      )
    );
    expect(within(card).getByTestId('policy-template-example-row-1')).toHaveTextContent(
      /Role viewerDENYDENY/
    );
  });

  it('does not flag examples as mismatches after a setting was changed', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface')
    );
    fireEvent.change(screen.getByTestId('policy-templates-param-values'), {
      target: { value: 'operator' },
    });
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    const card = await screen.findByTestId('policy-template-examples-card');
    expect(
      within(card).getByTestId('policy-template-examples-changed-settings')
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(within(card).getByTestId('policy-template-example-row-0')).toHaveTextContent(
        /Role adminALLOWALLOW/
      )
    );
    expect(within(card).getByTestId('policy-template-example-row-0')).not.toHaveClass(
      'table-warning'
    );
    expect(within(card).queryByTestId('policy-template-examples-mismatch')).toBeNull();
  });

  it('refuses to insert a standalone template that would widen the policy', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-restrict-mcp-tools-by-role:agent_surface')
    );
    expect(screen.getByTestId('policy-templates-standalone-note')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-templates-insert-preview')).toBeNull();
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
  });

  it('warns when the policy allows every request by default', async () => {
    mockGateway({ ...SAVED, policy: 'package surface.policy\n\ndefault allow = true' });
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface')
    );
    expect(screen.getByTestId('policy-templates-allow-default-warning')).toBeInTheDocument();
  });

  it('hides Insert template and Save as template without policies.edit', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByTestId('policy-templates-insert-button')).toBeNull();
    expect(screen.queryByTestId('policy-templates-save-as-button')).toBeNull();
  });
});

describe('save a policy as a template', () => {
  it('lists the saved template under Your organization', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-save-as-button'));
    fireEvent.change(screen.getByTestId('policy-templates-save-name-input'), {
      target: { value: 'Partner traffic only' },
    });
    fireEvent.click(screen.getByTestId('policy-templates-save-add-example-button'));
    expect(await screen.findByTestId('policy-templates-save-example-name-0')).toHaveValue(
      'Example 1'
    );
    fireEvent.click(screen.getByTestId('policy-templates-save-button'));
    await waitFor(() => expect(screen.queryByTestId('policy-templates-save-panel')).toBeNull());

    fireEvent.click(screen.getByTestId('policy-templates-insert-button'));
    await waitFor(() =>
      expect(screen.getByTestId('policy-templates-tab-organization')).toHaveTextContent(
        'Your organization · 1'
      )
    );
    fireEvent.click(screen.getByTestId('policy-templates-tab-organization'));
    expect(screen.getByText('Partner traffic only')).toBeInTheDocument();
  });

  it('is disabled while the policy has unsaved edits', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByTestId('policy-templates-save-as-button');
    fireEvent.change(rego(), { target: { value: `${SAVED.policy}\n# edited` } });
    expect(screen.getByTestId('policy-templates-save-as-button')).toBeDisabled();
  });

  it('refuses a second template with the same name', async () => {
    await savePolicyTemplate({
      name: 'Partner-Only',
      summary: '',
      category: 'authentication',
      policy_type: 'agent_surface',
      rego: SAVED.policy,
      reads: [],
      examples: [],
    });
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-save-as-button'));
    fireEvent.click(screen.getByTestId('policy-templates-save-button'));
    expect(await screen.findByTestId('policy-templates-save-error')).toHaveTextContent(
      'A template named "partner-only" already exists.'
    );
  });
});
