import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../../../context/PageTitleContext';
import { apiClient } from '../../../api';
import EditPolicyDefinitionPage from '../EditPolicyDefinitionPage';
import { savePolicyTemplate } from '../policyTemplates/policyTemplateStore';

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

const mockUndo: { last?: () => void; message?: string } = {};
jest.mock('../../../utils/toaster', () => ({
  ...jest.requireActual('../../../utils/toaster'),
  showUndoToast: (options: { onUndo: () => void; message: string }) => {
    mockUndo.last = options.onUndo;
    mockUndo.message = options.message;
  },
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
  window.sessionStorage.clear();
});

/** A gallery card, after showing every template. */
async function card(id: string) {
  await screen.findAllByTestId(/^policy-template-card-(?!blank)/);
  const showAll = screen.queryByTestId('policy-template-gallery-show-all');
  if (showAll) fireEvent.click(showAll);
  return screen.getByTestId(`policy-template-card-${id}`);
}
const openAdd = () => fireEvent.click(screen.getByTestId('policy-templates-insert-button'));
const panelRow = (id: string) => screen.findByTestId(`policy-templates-row-${id}:agent_surface`);

/** Selects a gallery card, which shows its detail, and uses it. */
async function useCard(id: string) {
  fireEvent.click(await card(id));
  fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
}

describe('start a policy from the gallery', () => {
  it('starts from Deny by default on the Rules view', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(await screen.findByTestId('policy-template-card-deny-by-default')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(rego().value).toBe('package surface.policy\n\ndefault allow := false\n');
    expect(screen.getByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('policy-template-gallery-detail')).toHaveTextContent(
      'Deny by default'
    );
  });

  it('shows a card in place without filling the form until Use', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('all-trust-checks-pass'));
    expect(screen.getByTestId('policy-template-gallery-detail')).toHaveTextContent(
      'All trust checks pass'
    );
    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue('');
    expect(rego().value).not.toContain('trust_check_results');
  });

  it('fills Name, Description and Rego from the used template and shows its rules', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('all-trust-checks-pass');

    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue(
      'All trust checks pass'
    );
    expect(screen.getByPlaceholderText('What does this policy do?')).toHaveValue(
      'Allows a request only if at least one trust check ran on the target and every one succeeded. Denies when any check failed or none ran.'
    );
    expect(rego().value).toContain('every r in input.trust_check_results.target { r.ok }');
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from All trust checks pass'
    );
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();
    expect(screen.getByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
  });

  it('reopens the gallery with Change on the used template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    expect(screen.queryByTestId('policy-template-card-blank')).toBeNull();

    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));

    expect(screen.getByTestId('policy-template-card-blank')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-card-allow-http-methods')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
  });

  it('keeps a chosen template past the first six in view when the gallery reopens', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-all-monitor');
    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));
    expect(screen.getByTestId('policy-template-card-allow-all-monitor')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
  });

  it('shows six templates until Show all, and filters by search and category', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await screen.findAllByTestId(/^policy-template-card-(?!blank|type)/);
    const cards = () => screen.getAllByTestId(/^policy-template-card-(?!blank|type)/);
    expect(cards()).toHaveLength(6);

    fireEvent.click(screen.getByTestId('policy-template-gallery-show-all'));
    expect(cards().length).toBeGreaterThan(6);

    fireEvent.click(
      within(screen.getByTestId('policy-template-gallery-categories')).getByTestId(
        'filter-chip-trust_checks'
      )
    );
    expect(cards().map(c => c.textContent)).toEqual([
      expect.stringContaining('Require Trust Registry recognition'),
      expect.stringContaining('Require verified credential subject'),
      expect.stringContaining('All trust checks pass'),
      expect.stringContaining('At least N trust checks pass'),
    ]);
    expect(screen.queryByTestId('policy-template-card-blank')).toBeNull();

    fireEvent.click(
      within(screen.getByTestId('policy-template-gallery-categories')).getByTestId(
        'filter-chip-all'
      )
    );
    fireEvent.change(screen.getByTestId('policy-template-gallery-search-input'), {
      target: { value: 'business' },
    });
    expect(cards().map(c => c.textContent)).toEqual([
      expect.stringContaining('Allow during business hours'),
    ]);
  });

  it('undoes only the fields the template filled', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('all-trust-checks-pass');
    fireEvent.click(screen.getByLabelText('Enabled'));

    act(() => mockUndo.last?.());

    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue('');
    expect(rego().value).toContain('default allow := false');
    expect(screen.getByLabelText('Enabled')).not.toBeChecked();
  });

  it('offers a template of the other type and sets the Type when it is used', async () => {
    renderAt('/policy-definitions/new?type=gateway');
    const trust = await card('require-trust-registry-recognition');
    expect(within(trust).getByTestId('policy-template-card-type-badge')).toHaveTextContent(
      'Agent Surface only'
    );
    expect(
      within(await card('allow-http-methods')).queryByTestId('policy-template-card-type-badge')
    ).toBeNull();

    await useCard('require-trust-registry-recognition');

    expect(screen.getByDisplayValue('Agent Surfaces')).toBeInTheDocument();
    expect(rego().value.startsWith('package surface.policy')).toBe(true);
    expect(rego().value).toContain('input.agent.trust_verification == true');

    act(() => mockUndo.last?.());
    expect(screen.getByDisplayValue('Gateway')).toBeInTheDocument();
    expect(rego().value.startsWith('package gateway.policy')).toBe(true);
  });

  it('links the selected template to its own guide section', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-by-jwt-claim'));
    const link = screen.getByTestId('policy-template-gallery-docs-link');
    expect(link).toHaveTextContent('Guide: Use JWT claims to control access');
    expect(link).toHaveAttribute(
      'href',
      expect.stringContaining('use-jwt-claims-to-control-access-to-a-surface/#steps')
    );
  });

  it("shows each example's sample input", async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-template-gallery-example-input-0'));
    const input = screen.getByTestId('policy-template-gallery-example-input-0-json');
    expect(input).toHaveTextContent('"method": "GET"');
    expect(input).toHaveClass('policy-template-example-input');
  });

  it('starts from Allow all and warns in the Rules view once allow rules are added', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('blank');
    expect(rego().value).toContain('default allow = true');
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(screen.getByTestId('policy-rules-allow-default-warning')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('policy-rules-set-default-deny-button'));
    expect(rego().value).toContain('default allow = false');
    expect(rego().value).not.toContain('# Allow all traffic by default');
    expect(mockUndo.message).toBe(
      'Requests are now denied by default. Undo restores the Rego from before this change.'
    );
  });
});

describe('the used template', () => {
  const name = () => screen.getByPlaceholderText('e.g. Require Authentication');
  const change = () => fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));

  it('fills Name from the preselected Deny by default when it is used', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(await card('deny-by-default')).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));

    expect(name()).toHaveValue('Deny by default');
    expect(mockUndo.message).toBe(
      'Filled from the template Deny by default. Undo restores the form from before this change.'
    );
  });

  it('reopens the used template with the settings it was used with', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('at-least-n-trust-checks-pass'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-min_passing'), {
      target: { value: '3' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    change();

    expect(screen.getByTestId('policy-template-gallery-param-min_passing')).toHaveValue(3);
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('count(passing) >= 3');
  });

  it('selects no card over Rego restored by Undo after a discard', async () => {
    const restored = `${SAVED.policy}\n`;
    window.sessionStorage.setItem(
      'policy-draft:new',
      JSON.stringify({ ...SAVED, id: '', name: 'draft', policy: restored })
    );
    renderAt('/policy-definitions/new?type=agent_surface');
    await waitFor(() => expect(rego().value).toBe(restored));

    expect(await card('deny-by-default')).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByTestId('policy-template-gallery-use-button')).toBeNull();
  });

  it('no longer says Pre-filled once a Use is undone', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('all-trust-checks-pass');
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();

    act(() => mockUndo.last?.());

    expect(screen.queryByTestId('policy-definition-prefilled-hint')).toBeNull();
  });

  it('undoes a Use made before a Type change back to the policy it replaced', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.change(screen.getByDisplayValue('Agent Surfaces'), { target: { value: 'gateway' } });
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();

    act(() => mockUndo.last?.());

    expect(screen.getByDisplayValue('Agent Surfaces')).toBeInTheDocument();
    expect(rego().value).toBe('package surface.policy\n\ndefault allow := false\n');
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Deny by default'
    );
    expect(screen.queryByTestId('policy-definition-prefilled-hint')).toBeNull();
  });

  it('says Custom Rego once Rego started from Allow all is edited by hand', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('blank');
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom Rego'
    );
  });

  it('keeps the used settings and Pre-filled across a Type change', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-methods'), {
      target: { value: 'DELETE' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    fireEvent.change(screen.getByDisplayValue('Agent Surfaces'), { target: { value: 'gateway' } });

    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();
    change();
    expect(screen.getByTestId('policy-template-gallery-param-methods')).toHaveValue('DELETE');
  });

  it('replaces hand-edited Rego when the used template is used again', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.queryByTestId('policy-definition-prefilled-hint')).toBeNull();

    change();
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));

    expect(rego().value).not.toContain('# reviewed');
    expect(name()).toHaveValue('Allow listed HTTP methods');
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();
  });
});

describe('gallery focus and detail', () => {
  const changeButton = () => screen.getByTestId('policy-template-gallery-change-button');
  const search = () => screen.getByTestId('policy-template-gallery-search-input');

  it('moves focus to Change after Use, also for Allow all', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    expect(changeButton()).toHaveFocus();

    fireEvent.click(changeButton());
    await useCard('blank');
    expect(changeButton()).toHaveFocus();
  });

  it('moves focus to the selected card after Change', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.click(changeButton());
    expect(screen.getByTestId('policy-template-card-allow-http-methods')).toHaveFocus();
  });

  it('moves focus to the search after Change when no shown card is selected', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.change(await screen.findByTestId('policy-template-gallery-search-input'), {
      target: { value: 'business' },
    });
    await useCard('allow-during-business-hours');
    act(() => mockUndo.last?.());
    fireEvent.click(changeButton());
    expect(search()).toHaveFocus();
  });

  it('moves focus to the detail heading when a card is selected', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    const heading = screen.getByTestId('policy-template-gallery-detail-heading');
    expect(heading).toHaveTextContent('Allow listed HTTP methods');
    expect(heading).toHaveFocus();

    fireEvent.click(screen.getByTestId('policy-template-card-blank'));
    expect(screen.getByTestId('policy-template-gallery-detail-heading')).toHaveFocus();
  });

  it('shows no detail for a card the search hides', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(await screen.findByTestId('policy-template-gallery-detail')).toBeInTheDocument();
    fireEvent.change(search(), { target: { value: 'business' } });
    expect(screen.getByTestId('policy-template-gallery-detail')).not.toBeVisible();

    fireEvent.change(search(), { target: { value: 'no such template' } });
    expect(screen.getByText('No templates match.')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-gallery-use-button')).not.toBeVisible();
  });

  it('keeps settings typed in the detail while a search hides its card', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-methods'), {
      target: { value: 'DELETE' },
    });
    fireEvent.change(search(), { target: { value: 'zzz' } });
    expect(screen.getByTestId('policy-template-gallery-detail')).not.toBeVisible();

    fireEvent.change(search(), { target: { value: '' } });
    expect(screen.getByTestId('policy-template-gallery-detail')).toBeVisible();
    expect(screen.getByTestId('policy-template-gallery-param-methods')).toHaveValue('DELETE');
  });

  it('shows no Allow all detail while a filter hides its card', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('blank'));
    expect(screen.getByTestId('policy-template-gallery-detail')).toHaveTextContent('Allow all');

    fireEvent.click(
      within(screen.getByTestId('policy-template-gallery-categories')).getByTestId(
        'filter-chip-trust_checks'
      )
    );
    expect(screen.queryByTestId('policy-template-card-blank')).toBeNull();
    expect(screen.getByTestId('policy-template-gallery-detail')).not.toBeVisible();
    expect(screen.getByTestId('policy-template-gallery-use-button')).not.toBeVisible();
  });

  it('names Add rules from a template in its help text', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const gallery = await screen.findByTestId('policy-template-gallery');
    expect(gallery).toHaveTextContent('Add rules from a template');
    expect(gallery).not.toHaveTextContent('column on the right');
  });

  it('shows the Rego the settings render to behind a collapsed Show Rego', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    const toggle = screen.getByTestId('policy-template-gallery-show-rego');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('policy-template-gallery-rego')).toBeNull();

    fireEvent.click(toggle);
    const block = screen.getByTestId('policy-template-gallery-rego');
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(block).toHaveClass('policy-preview-block');
    expect(block).toHaveTextContent('allow if input.http.method in {"GET"}');

    fireEvent.change(screen.getByTestId('policy-template-gallery-param-methods'), {
      target: { value: 'DELETE' },
    });
    expect(screen.getByTestId('policy-template-gallery-rego')).toHaveTextContent(
      'allow if input.http.method in {"DELETE"}'
    );
  });

  it('shows the Allow all Rego behind Show Rego', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('blank'));
    expect(screen.queryByTestId('policy-template-gallery-rego')).toBeNull();
    fireEvent.click(screen.getByTestId('policy-template-gallery-show-rego'));
    expect(screen.getByTestId('policy-template-gallery-rego')).toHaveTextContent(
      'default allow = true'
    );
  });

  it('says there is no Rego while a setting is invalid', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('at-least-n-trust-checks-pass'));
    fireEvent.click(screen.getByTestId('policy-template-gallery-show-rego'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-min_passing'), {
      target: { value: '0' },
    });
    expect(screen.getByTestId('policy-template-gallery-rego')).toHaveTextContent(
      'Fix the settings above to see the Rego.'
    );
  });
});

describe('template settings in the gallery', () => {
  it('fills a setting into the Rego when the template is used', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('at-least-n-trust-checks-pass'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-min_passing'), {
      target: { value: '3' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));

    expect(rego().value).toContain('count(passing) >= 3');
  });

  it('refuses a setting outside its range', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('at-least-n-trust-checks-pass'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-min_passing'), {
      target: { value: '0' },
    });

    expect(screen.getByText('Enter a whole number from 1 to 20.')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-gallery-use-button')).toBeDisabled();
  });

  it('fills a single-value setting into the Rego as a string', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-during-business-hours'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-time_zone'), {
      target: { value: 'Asia/Singapore' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('time.clock([now, "Asia/Singapore"])');
  });

  it('refuses business hours that end before they start', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-during-business-hours'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-end_hour'), {
      target: { value: '8' },
    });
    expect(screen.getByText('Must be later than From hour.')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-gallery-use-button')).toBeDisabled();
  });
});

describe('templates panel', () => {
  it('always offers Add rules in the templates column, with no close button', () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const column = screen.getByTestId('policy-templates-column');
    expect(within(column).getByTestId('policy-templates-panel')).toHaveTextContent(
      'Add rules from a template'
    );
    expect(within(column).queryByTestId('policy-templates-close-button')).toBeNull();
    expect(within(column).queryByTestId('policy-templates-use-button')).toBeNull();
  });

  it('adds a rule to a new policy with no allow-default warning', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(rego().value).toContain('allow if input.http.method in {"GET"}');
    expect(screen.queryByTestId('policy-rules-allow-default-warning')).toBeNull();
  });

  it('focuses the column search from Add rules from a template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(screen.getByTestId('policy-templates-insert-button'));
    await waitFor(() => expect(screen.getByTestId('policy-templates-search-input')).toHaveFocus());
  });

  it('keeps the dry-run under the editor, apart from the templates column', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    const simulate = await screen.findByTestId('policy-simulate-panel');
    const column = screen.getByTestId('policy-templates-column');
    expect(column).not.toContainElement(simulate);
    expect(
      column.compareDocumentPosition(simulate) & Node.DOCUMENT_POSITION_PRECEDING
    ).toBeTruthy();
  });

  it('has no templates column without policies.edit', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByTestId('policy-editor-section');
    expect(screen.queryByTestId('policy-templates-column')).toBeNull();
  });

  it('clears the chosen template when the Type changes', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    fireEvent.change(screen.getByDisplayValue('Agent Surfaces'), { target: { value: 'gateway' } });

    expect(await screen.findByTestId('policy-templates-other-type-note')).toHaveTextContent(
      'for Agent Surface policies only'
    );
    expect(screen.queryByTestId('policy-templates-preview')).toBeNull();
  });

  it('filters by category', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(
      within(await screen.findByTestId('policy-templates-categories')).getByTestId(
        'filter-chip-trust_checks'
      )
    );

    const rows = screen.getAllByTestId(/^policy-templates-row-/);
    expect(rows.map(r => r.textContent)).toEqual([
      expect.stringContaining('Require Trust Registry recognition'),
      expect.stringContaining('Require verified credential subject'),
      expect.stringContaining('All trust checks pass'),
      expect.stringContaining('At least N trust checks pass'),
    ]);
  });

  it('offers the ticket starter templates other than rate controls', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
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
    openAdd();
    fireEvent.click(await screen.findByTestId('policy-templates-tab-organization'));
    expect(screen.getByTestId('policy-templates-organization-empty')).toBeInTheDocument();
  });
});

describe('templates for the other type and for tool bindings', () => {
  it('lists only templates of the policy type in Add rules and says how many it left out', async () => {
    renderAt('/policy-definitions/new?type=gateway');
    const note = await screen.findByTestId('policy-templates-other-type-note');
    expect(note).toHaveTextContent(/\d+ templates are for Agent Surface policies only/);
    expect(
      screen.queryByTestId('policy-templates-row-require-authentication:agent_surface')
    ).toBeNull();
    expect(
      screen.getByTestId('policy-templates-row-allow-http-methods:gateway')
    ).toBeInTheDocument();
  });

  it('refuses to add an MCP tool policy template to a policy', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await panelRow('tool-allow-by-jwt-claim'));
    expect(screen.getByTestId('policy-templates-mcp-tool-note')).toHaveTextContent(
      'bound to MCP tools'
    );
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
  });

  it('shows the template docs link with its own label in the panel', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    const link = screen.getByTestId('policy-templates-docs-link');
    expect(link).toHaveTextContent('Reference: input.trust_check_results');
    expect(link).toHaveAttribute('href', expect.stringContaining('#inputtrust_check_results'));
  });
});

describe('add rules while creating a policy', () => {
  const row = panelRow;

  it('combines the rules of several templates in one new policy', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
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
      '# Inserted from template: Allow listed HTTP methods\nallow if input.http.method in {"GET"}\n# End of template: Allow listed HTTP methods\n'
    );
    expect(screen.getByTestId('policy-template-card-deny-by-default')).toHaveAttribute(
      'aria-pressed',
      'false'
    );
  });

  it('keeps Name and Description when rules are inserted', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.change(screen.getByPlaceholderText('e.g. Require Authentication'), {
      target: { value: 'partner policy' },
    });
    openAdd();
    fireEvent.click(await row('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue(
      'partner policy'
    );
  });

  it('refuses to add a standalone template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(await row('restrict-mcp-tools-by-role'));
    expect(screen.getByTestId('policy-templates-standalone-note')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-templates-default-only-note')).toBeNull();
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
  });

  it('says Deny by default only sets the default decision', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(await row('deny-by-default'));
    expect(screen.getByTestId('policy-templates-default-only-note')).toHaveTextContent(
      'only sets the default decision, so it adds no rules to a policy. To deny by default, change default allow to false in the Rego, or pick it under Start from on a new policy.'
    );
    expect(screen.queryByTestId('policy-templates-standalone-note')).toBeNull();
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
  });

  it('says Monitor-only baseline only sets an allow default', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(await row('allow-all-monitor'));
    expect(screen.getByTestId('policy-templates-default-only-note')).toHaveTextContent(
      'change default allow to true'
    );
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeDisabled();
  });

  it('keeps the MCP tool note on a tool template that only sets the default', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    openAdd();
    fireEvent.click(await row('tool-allow-every-caller'));
    expect(screen.getByTestId('policy-templates-mcp-tool-note')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-templates-default-only-note')).toBeNull();
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
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(screen.getByTestId('policy-rules-allow-default-warning')).toBeInTheDocument();
  });

  it('hides Add rules from a template and Save as template without policies.edit', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByTestId('policy-templates-insert-button')).toBeNull();
    expect(screen.queryByTestId('policy-templates-save-as-button')).toBeNull();
  });
});

describe('read-only without policies.edit', () => {
  const title = (section: string) =>
    within(screen.getByTestId(section)).getAllByRole('heading', { level: 6 })[0].textContent;
  const titles = () => [title('policy-details-section'), title('policy-editor-section')];

  it('shows a saved policy read-only, with no Save', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.getByTestId('policy-definition-read-only-note')).toHaveTextContent(
      'You can view this policy but not change it.'
    );
    expect(rego()).toHaveAttribute('readonly');
    expect(screen.queryByTestId('policy-definition-editor-save-button')).toBeNull();
    expect(screen.getByTestId('policy-definition-name-input')).toHaveAttribute('readonly');
    expect(screen.getByTestId('policy-definition-description-input')).toHaveAttribute('readonly');
    expect(screen.getByTestId('policy-definition-enabled-switch')).toBeDisabled();
    expect(screen.getByTestId('policy-definition-type-select')).toBeDisabled();
    expect(titles()).toEqual(['Details', 'Policy']);
  });

  it('offers no dry-run', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByTestId('policy-simulate-panel')).toBeNull();
  });

  it('saves nothing on Ctrl+S', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false);
  });

  it('offers no Fix it on a package mismatch', async () => {
    mockCanEdit = false;
    mockGateway({ ...SAVED, policy: 'package gateway.policy\n\ndefault allow := false' });
    renderAt('/policy-definitions/partner-only');
    await screen.findByText(/Package mismatch/);
    expect(screen.queryByRole('button', { name: 'Fix it' })).toBeNull();
  });

  it('numbers no section on the create form', () => {
    mockCanEdit = false;
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(titles()).toEqual(['Details', 'Policy']);
    expect(screen.queryByTestId('policy-definition-editor-save-button')).toBeNull();
  });

  it('changes nothing for a user with policies.edit', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByTestId('policy-definition-read-only-note')).toBeNull();
    expect(rego()).not.toHaveAttribute('readonly');
    expect(screen.getByTestId('policy-definition-editor-save-button')).toBeInTheDocument();
    expect(screen.getByTestId('policy-definition-name-input')).not.toHaveAttribute('readonly');
    expect(screen.getByTestId('policy-definition-enabled-switch')).toBeEnabled();
  });

  it('numbers the three sections on the create form', () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect([title('policy-template-gallery'), ...titles()]).toEqual([
      '1Start from',
      '2Details',
      '3Policy',
    ]);
  });
});

describe('rules in this policy', () => {
  it('lists the rules written in the editor and those of each added template', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    const card = await screen.findByTestId('policy-editor-section');
    expect(within(card).getByTestId('policy-rules-count')).toHaveTextContent('1 rule');
    expect(within(card).getByTestId('policy-rules-group-0')).toHaveTextContent(
      'Written in the editor'
    );
    expect(within(card).getByTestId('policy-rules-group-0-rule-0')).toHaveTextContent(
      /Allows.*allow if input\.jwt\.iss == "https:\/\/login\.example".*Line 5/
    );

    fireEvent.click(screen.getByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-http-methods:agent_surface')
    );
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    const added = within(card).getByTestId('policy-rules-group-1');
    expect(added).toHaveTextContent('From template Allow listed HTTP methods');
    expect(within(added).getByTestId('policy-rules-just-added')).toBeInTheDocument();
    expect(within(card).getByTestId('policy-rules-count')).toHaveTextContent('2 rules');
  });

  it('removes the rules of an added template and keeps the rest', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface')
    );
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.change(rego(), {
      target: { value: `${rego().value}\nallow if input.http.method == "GET"\n` },
    });

    fireEvent.click(screen.getByTestId('policy-rules-group-1-remove-button'));

    expect(rego().value).not.toContain('jwt_claim_values');
    expect(rego().value).not.toContain('template');
    expect(rego().value).toContain('allow if input.jwt.iss == "https://login.example"');
    expect(rego().value).toContain('allow if input.http.method == "GET"');
    expect(screen.getByTestId('policy-rules-count')).toHaveTextContent('2 rules');
  });

  it('drops the examples card with the template whose rules were removed', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface')
    );
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(await screen.findByTestId('policy-template-examples-card')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('policy-rules-group-1-remove-button'));

    expect(screen.queryByTestId('policy-template-examples-card')).toBeNull();
  });

  it('checks the examples of a second added template that has more of them', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-http-methods:agent_surface')
    );
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    await screen.findByTestId('policy-template-examples-card');
    fireEvent.click(screen.getByTestId('policy-templates-row-allow-by-jwt-claim:agent_surface'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    const card = screen.getByTestId('policy-template-examples-card');
    await waitFor(() =>
      expect(within(card).getByTestId('policy-template-example-row-2')).toHaveTextContent(
        /Roles list with adminALLOW(ALLOW|DENY)/
      )
    );
  });

  it('selects a rule in the Rego from its line numbers', async () => {
    mockGateway({
      ...SAVED,
      policy: 'package surface.policy\n\nallow if {\n  input.x\n}\n',
    });
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-rules-group-0-rule-0-show-button'));
    expect(screen.getByTestId('policy-view-rego')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('policy-view-rules-panel')).toHaveClass('d-none');
    const { selectionStart, selectionEnd, value } = rego();
    expect(value.slice(selectionStart, selectionEnd)).toBe('allow if {\n  input.x\n}');
  });

  it('turns an allow-all policy with allow rules into deny by default', async () => {
    mockGateway({
      ...SAVED,
      policy:
        'package surface.policy\n\ndefault allow := true\n\nallow if input.http.method == "GET"',
    });
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-rules-set-default-deny-button'));
    expect(rego().value).toContain('default allow := false');
    expect(screen.queryByTestId('policy-rules-allow-default-warning')).toBeNull();
  });

  it('shows the rules without edit actions to a viewer', async () => {
    mockCanEdit = false;
    mockGateway({
      ...SAVED,
      policy: `${SAVED.policy}\n\n# Inserted from template: Allow listed HTTP methods\nallow if input.http.method in {"GET"}\n# End of template: Allow listed HTTP methods\n`,
    });
    renderAt('/policy-definitions/partner-only');
    const card = await screen.findByTestId('policy-editor-section');
    expect(within(card).getByTestId('policy-rules-group-1')).toBeInTheDocument();
    expect(within(card).queryByTestId('policy-rules-group-1-remove-button')).toBeNull();
    expect(within(card).queryByTestId('policy-templates-insert-button')).toBeNull();
  });

  it('says the rules cannot be listed while a bracket is open', async () => {
    mockGateway({ ...SAVED, policy: 'package surface.policy\n\nallow if {\n  input.x' });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-unparsed')).toBeInTheDocument();
  });
});

describe('policy section', () => {
  it('opens a saved policy on its rules and switches to the Rego', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('policy-view-rego-panel')).toHaveClass('d-none');

    fireEvent.click(screen.getByTestId('policy-view-rego'));

    expect(screen.getByTestId('policy-view-rego-panel')).not.toHaveClass('d-none');
    expect(screen.getByTestId('policy-view-rules-panel')).toHaveClass('d-none');
  });

  it('offers Add rules and Write Rego for a policy with no rules', async () => {
    mockGateway({ ...SAVED, policy: 'package surface.policy\n\ndefault allow := false\n' });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-empty')).toHaveTextContent('No rules yet');

    fireEvent.click(screen.getByTestId('policy-rules-add-button'));
    expect(await screen.findByTestId('policy-templates-panel')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('policy-rules-write-rego-button'));
    expect(screen.getByTestId('policy-view-rego')).toHaveAttribute('aria-pressed', 'true');
  });

  it('says on the Rules view when the Rego does not compile', async () => {
    (apiClient.post as jest.Mock).mockResolvedValueOnce({
      data: { valid: false, error: 'rego_parse_error' },
    });
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-rules-invalid-open-rego-button'));
    expect(screen.getByTestId('policy-view-rego')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('rego_parse_error')).toBeInTheDocument();
  });

  it('shows the policy ID and SHA of a saved policy on one line', async () => {
    mockGateway({ ...SAVED, content_hash: 'sha256:abc' } as typeof SAVED);
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-definition-id')).toHaveTextContent('partner-only');
    expect(screen.getByTestId('policy-definition-sha')).toHaveTextContent('sha256:abc');
    expect(screen.getByTestId('policy-definition-id-copy-button')).toBeInTheDocument();
  });
});

describe('editing after a template', () => {
  it('warns before adding an organisation template, whose rules are added as written', async () => {
    await savePolicyTemplate({
      name: 'Partner GETs',
      summary: 'GET only',
      category: 'routing_paths',
      policy_type: 'agent_surface',
      rego: 'package surface.policy\n\nallow if input.http.method == "GET"',
      reads: [],
      examples: [],
    });
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await screen.findByTestId('policy-templates-tab-organization'));
    fireEvent.click(screen.getByText('Partner GETs'));
    expect(screen.getByTestId('policy-templates-org-insert-warning')).toHaveTextContent(
      'combine with OR'
    );
    expect(screen.getByTestId('policy-templates-insert-rules-button')).toBeEnabled();
  });

  it('labels an empty Rego as allowing every request, as the gateway treats it', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.change(rego(), { target: { value: '' } });
    fireEvent.click(screen.getByTestId('policy-view-rules'));
    expect(screen.getByTestId('policy-editor-section')).toHaveTextContent('Default ALLOW');
    expect(screen.getByTestId('policy-rules-empty')).toHaveTextContent(
      'An empty policy allows every request.'
    );
  });

  it('keeps a typed name when the used template is used again with new settings', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.change(screen.getByPlaceholderText('e.g. Require Authentication'), {
      target: { value: 'partner reads' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-methods'), {
      target: { value: 'GET, HEAD' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue('partner reads');
    expect(rego().value).toContain('{"GET", "HEAD"}');
  });

  it('says the policy no longer follows the template once the Rego is edited by hand', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom Rego'
    );
  });

  it('has no gallery for a user without policies.edit', () => {
    mockCanEdit = false;
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(screen.queryByTestId('policy-template-gallery')).toBeNull();
  });

  it('warns when a Type change keeps rules written for the other type', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('require-authentication');
    fireEvent.change(screen.getByDisplayValue('Agent Surfaces'), { target: { value: 'gateway' } });
    expect(
      await screen.findByText(/Require authenticated caller is written for Agent Surface policies/)
    ).toBeInTheDocument();
  });
});

describe('remove one rule', () => {
  it('removes a chosen rule from the Rego and offers Undo', async () => {
    mockGateway({
      ...SAVED,
      policy: `${SAVED.policy}\n\nallow if input.http.method == "HEAD"\n`,
    });
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await screen.findByTestId('policy-rules-group-0-rule-1-remove-button'));
    expect(rego().value).not.toContain('"HEAD"');
    expect(rego().value).toContain('allow if input.jwt.iss == "https://login.example"');
    expect(screen.getByTestId('policy-rules-count')).toHaveTextContent('1 rule');

    act(() => mockUndo.last?.());
    expect(rego().value).toContain('"HEAD"');
  });

  it('refuses to remove a helper another rule still uses', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await panelRow('allow-path-prefixes'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    const group = screen.getByTestId('policy-rules-group-1');
    const helper = within(group).getByTestId('policy-rules-group-1-rule-0-remove-button');
    expect(helper).toBeDisabled();
    expect(helper).toHaveAttribute('title', expect.stringContaining('Another rule uses'));
    expect(within(group).getByTestId('policy-rules-group-1-rule-0-in-use')).toHaveTextContent(
      'Another rule uses this; remove that rule first'
    );
    const allowRule = within(group).getAllByRole('button', { name: /Remove the rule allow/ });
    expect(allowRule[0]).toBeEnabled();
    expect(within(group).queryByTestId('policy-rules-group-1-in-use')).toBeNull();
  });

  it('refuses to remove a deny rule that allow counts, and says why', async () => {
    mockGateway({
      ...SAVED,
      policy:
        'package surface.policy\n\ndefault allow := false\n\ndeny contains "no path" if not input.http.path\n\nallow if count(deny) == 0\n',
    });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-group-0-rule-0-remove-button')).toBeDisabled();
    expect(screen.getByTestId('policy-rules-group-0-rule-0')).toHaveTextContent('Helper');
    expect(screen.getByTestId('policy-rules-group-0-rule-0-in-use')).toBeVisible();
    expect(screen.queryByTestId('policy-rules-group-0-rule-1-in-use')).toBeNull();
  });

  it('refuses to remove a template whose rule a rule outside it still reads', async () => {
    mockGateway({
      ...SAVED,
      policy: `${SAVED.policy}\n\n# Inserted from template: Blocked callers\nblocked if input.x\n# End of template: Blocked callers\n\nallow if not blocked\n`,
    });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-group-1-remove-button')).toBeDisabled();
    expect(screen.getByTestId('policy-rules-group-1-in-use')).toHaveTextContent(
      'A rule outside this template uses its rules; remove that rule first'
    );
  });

  it('shows no rule Remove to a viewer', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByTestId('policy-rules-group-0-rule-0');
    expect(screen.queryByTestId('policy-rules-group-0-rule-0-remove-button')).toBeNull();
  });
});

describe('undo', () => {
  it('takes added rules back out of a saved policy, with their examples card', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    await screen.findByTestId('policy-template-examples-card');

    act(() => mockUndo.last?.());

    expect(rego().value).toBe(SAVED.policy);
    expect(screen.queryByTestId('policy-template-examples-card')).toBeNull();
    expect(screen.queryByTestId('policy-rules-just-added')).toBeNull();
  });

  it('puts removed rules back', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.click(screen.getByTestId('policy-rules-group-1-remove-button'));
    expect(rego().value).not.toContain('Allow listed HTTP methods');

    act(() => mockUndo.last?.());

    expect(rego().value).toContain('# Inserted from template: Allow listed HTTP methods');
    expect(screen.getByTestId('policy-rules-group-1')).toBeInTheDocument();
  });

  it('restores the starting template after undoing a removed rule on the create form', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await useCard('allow-http-methods');
    fireEvent.click(screen.getByTestId('policy-rules-group-0-rule-0-remove-button'));
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom Rego'
    );

    act(() => mockUndo.last?.());

    expect(rego().value).toContain('allow if input.http.method in {"GET"}');
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Allow listed HTTP methods'
    );
  });

  it('keeps the mark of a same-named group that is still in the policy', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.click(screen.getByTestId('policy-rules-group-1-remove-button'));

    expect(screen.getByTestId('policy-rules-just-added')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-examples-card')).toBeInTheDocument();
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
