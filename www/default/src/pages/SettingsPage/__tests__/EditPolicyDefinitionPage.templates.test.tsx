import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../../../context/PageTitleContext';
import { apiClient } from '../../../api';
import EditPolicyDefinitionPage from '../EditPolicyDefinitionPage';

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

/** A helper rule (line 5) that the allow rule (line 7) reads. */
const HELPER_POLICY =
  'package surface.policy\n\ndefault allow := false\n\nblocked if input.x\n\nallow if not blocked\n';

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

/** `openedByUndo` opens the page the way a discard toast's Undo does. */
function renderAt(path: string, openedByUndo = false) {
  const [pathname, search = ''] = path.split('?');
  const entry = {
    pathname,
    search: search && `?${search}`,
    state: openedByUndo ? { discardUndo: true } : null,
  };
  return render(
    <PageTitleProvider>
      <MemoryRouter initialEntries={[entry]}>
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

const customButton = () => screen.getByTestId('policy-template-gallery-create-custom-button');

/** Selects a gallery card, which shows its detail, and uses it; `blank` creates a custom policy. */
async function applyCard(id: string) {
  if (id === 'blank') {
    fireEvent.click(customButton());
    return;
  }
  fireEvent.click(await card(id));
  fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
}

/** Opens the create form and uses Deny by default, which shows Details and Policy. */
async function renderNew(type: 'agent_surface' | 'gateway' = 'agent_surface') {
  renderAt(`/policy-definitions/new?type=${type}`);
  await applyCard('deny-by-default');
}

const nameField = () => screen.queryByPlaceholderText('e.g. Require Authentication');
const column = () => screen.getByTestId('policy-templates-column');
const changeGallery = () =>
  fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));

describe('pick a template before the rest of the form', () => {
  it('selects no card and shows only Start from until a template is used', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const cards = await screen.findAllByTestId(/^policy-template-card-(?!scope)/);
    for (const c of cards) expect(c).toHaveAttribute('aria-pressed', 'false');
    expect(nameField()).toBeNull();
    expect(screen.queryByTestId('policy-editor-section')).toBeNull();
    expect(within(column()).getByTestId('policy-template-gallery-detail-empty')).toHaveTextContent(
      'Pick a template under Start from to see what it does, then use it.'
    );
    expect(screen.queryByTestId('policy-templates-panel')).toBeNull();
  });

  it('shows a card in the templates column without filling the form until Use', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('all-trust-checks-pass'));
    expect(screen.getByTestId('policy-template-card-all-trust-checks-pass')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(within(column()).getByTestId('policy-template-gallery-detail')).toHaveTextContent(
      'All trust checks pass'
    );
    expect(screen.getByTestId('policy-template-gallery')).not.toContainElement(
      screen.getByTestId('policy-template-gallery-detail')
    );
    expect(screen.queryByTestId('policy-template-gallery-detail-empty')).toBeNull();
    expect(nameField()).toBeNull();
    expect(screen.queryByTestId('policy-editor-section')).toBeNull();
  });

  it('shows Details, the Rules view and Add rules once a template is used', async () => {
    await renderNew();
    expect(nameField()).toHaveValue('Deny by default');
    expect(screen.getByPlaceholderText('What does this policy do?').tagName).toBe('TEXTAREA');
    expect(rego().value).toBe('package surface.policy\n\ndefault allow := false\n');
    expect(screen.getByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
    expect(within(column()).getByTestId('policy-templates-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-template-gallery-detail-panel')).toBeNull();
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Deny by default'
    );
  });

  it('hides Create until a template is used, and Cmd+S saves nothing before then', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    expect(screen.queryByTestId('policy-definition-editor-save-button')).toBeNull();
    fireEvent.keyDown(document, { key: 's', metaKey: true });
    expect(screen.queryByText('Name is required')).toBeNull();

    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(screen.getByTestId('policy-definition-editor-save-button')).toBeInTheDocument();
  });

  it('shows the rest of the form once a custom policy is created', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await screen.findAllByTestId(/^policy-template-card-(?!scope)/);
    await applyCard('blank');
    expect(nameField()).toBeInTheDocument();
    expect(rego().value).toContain('default allow = true');
    expect(screen.getByTestId('policy-templates-panel')).toBeInTheDocument();
  });

  it('puts Create custom policy under the templates list', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await screen.findAllByTestId(/^policy-template-card-(?!scope)/);
    expect(screen.queryByTestId('policy-template-card-blank')).toBeNull();
    const cards = screen.getAllByTestId(/^policy-template-card-(?!scope)/);
    expect(
      cards[cards.length - 1].compareDocumentPosition(customButton()) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(customButton()).toHaveTextContent('Create custom policy');
  });

  it('creates a custom policy at once, with no question, before the templates have loaded', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(customButton());
    expect(screen.queryByTestId('policy-template-gallery-replace-confirm')).toBeNull();
    expect(rego().value).toContain('default allow = true');
    expect(nameField()).toBeInTheDocument();
    await screen.findAllByTestId(/^policy-templates-row-/);
  });

  it('hides the rest of the form again when the first Use is undone', async () => {
    await renderNew();
    act(() => mockUndo.last?.());
    expect(nameField()).toBeNull();
    expect(screen.queryByTestId('policy-editor-section')).toBeNull();
    expect(customButton()).toBeInTheDocument();
    expect(screen.queryByTestId('policy-template-gallery-summary')).toBeNull();
    expect(screen.getByTestId('policy-template-gallery-detail-panel')).toBeInTheDocument();
  });

  it('hides the Type set by the Define button and names it in the header', async () => {
    await renderNew('agent_surface');
    expect(screen.queryByTestId('policy-definition-type-select')).toBeNull();
    expect(screen.getByText('Create Agent Surface Policy')).toBeInTheDocument();
  });

  it('hides the Type of a Gateway policy too', async () => {
    await renderNew('gateway');
    expect(screen.queryByTestId('policy-definition-type-select')).toBeNull();
    expect(screen.getByText('Create Gateway Policy')).toBeInTheDocument();
  });

  it('shows the Type, locked, when the page was opened without a Define button', async () => {
    renderAt('/policy-definitions/new');
    await applyCard('deny-by-default');
    const type = await screen.findByTestId('policy-definition-type-select');
    expect(type).toHaveValue('gateway');
    expect(type).toBeDisabled();
    expect(screen.getByText('Create Policy')).toBeInTheDocument();
  });

  it('closes a reopened gallery with Cancel and brings back Add rules', async () => {
    await renderNew();
    expect(screen.queryByTestId('policy-template-gallery-cancel-button')).toBeNull();
    changeGallery();
    expect(screen.queryByTestId('policy-templates-panel')).toBeNull();
    expect(within(column()).getByTestId('policy-template-gallery-detail')).toHaveTextContent(
      'Deny by default'
    );

    fireEvent.click(screen.getByTestId('policy-template-gallery-cancel-button'));

    expect(screen.getByTestId('policy-template-gallery-summary')).toBeInTheDocument();
    expect(within(column()).getByTestId('policy-templates-panel')).toBeInTheDocument();
    expect(rego().value).toBe('package surface.policy\n\ndefault allow := false\n');
    expect(screen.getByTestId('policy-template-gallery-change-button')).toHaveFocus();
  });

  it('offers no Cancel before a template is used', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await screen.findAllByTestId(/^policy-template-card-(?!blank)/);
    expect(screen.queryByTestId('policy-template-gallery-cancel-button')).toBeNull();
  });

  it('shows the sections of a saved policy straight away', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-editor-section')).toBeInTheDocument();
    expect(nameField()).toHaveValue('partner-only');
    expect(screen.queryByTestId('policy-template-gallery')).toBeNull();
    expect(screen.getByTestId('policy-templates-panel')).toBeInTheDocument();
  });
});

describe('start a policy from the gallery', () => {
  it('fills Name, Description and Rego from the used template and shows its rules', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('all-trust-checks-pass');

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
    await applyCard('allow-http-methods');
    expect(screen.queryByTestId('policy-template-gallery-create-custom-button')).toBeNull();

    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));

    expect(customButton()).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-card-allow-http-methods')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
  });

  it('keeps a chosen template past the first six in view when the gallery reopens', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-all-monitor');
    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));
    expect(screen.getByTestId('policy-template-card-allow-all-monitor')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
  });

  const galleryCards = () => screen.getAllByTestId(/^policy-template-card-(?!blank|scope)/);

  it('shows six templates until Show all, with no search or category filters', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await screen.findAllByTestId(/^policy-template-card-(?!blank|scope)/);
    expect(galleryCards()).toHaveLength(6);
    expect(screen.queryByTestId('policy-template-gallery-search-input')).toBeNull();
    expect(screen.queryByTestId('policy-template-gallery-categories')).toBeNull();

    fireEvent.click(screen.getByTestId('policy-template-gallery-show-all'));
    expect(galleryCards().length).toBeGreaterThan(6);
  });

  it('lists only templates that serve Gateway policies on a Gateway policy', async () => {
    await renderNew('gateway');
    changeGallery();
    await card('allow-http-methods');

    expect(
      screen.queryByTestId('policy-template-card-require-trust-registry-recognition')
    ).toBeNull();
    expect(screen.queryByTestId('policy-template-card-tool-allow-by-jwt-claim')).toBeNull();
    expect(screen.queryByTestId('policy-template-card-scope')).toBeNull();
    expect(customButton()).toBeInTheDocument();
  });

  it('marks Agent Surface only templates with a note on an Agent Surface policy', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(
      within(await card('require-trust-registry-recognition')).getByTestId(
        'policy-template-card-scope'
      )
    ).toHaveTextContent('Agent surface only');
    expect(
      within(await card('allow-http-methods')).queryByTestId('policy-template-card-scope')
    ).toBeNull();
  });

  it('undoes only the fields the template filled', async () => {
    await renderNew();
    changeGallery();
    await applyCard('all-trust-checks-pass');
    fireEvent.click(screen.getByLabelText('Enabled'));

    act(() => mockUndo.last?.());

    expect(screen.getByPlaceholderText('e.g. Require Authentication')).toHaveValue(
      'Deny by default'
    );
    expect(rego().value).toBe('package surface.policy\n\ndefault allow := false\n');
    expect(screen.getByLabelText('Enabled')).not.toBeChecked();
  });

  it('uses the Gateway variant of a shared template on a Gateway policy', async () => {
    await renderNew('gateway');
    changeGallery();
    await applyCard('allow-http-methods');

    expect(screen.getByText('Create Gateway Policy')).toBeInTheDocument();
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
    await applyCard('blank');
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

  it('fills Name from Deny by default when it is used', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(await card('deny-by-default')).toHaveAttribute('aria-pressed', 'false');
    await applyCard('deny-by-default');

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
    renderAt('/policy-definitions/new?type=agent_surface', true);
    await waitFor(() => expect(rego().value).toBe(restored));
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom Rego'
    );

    changeGallery();
    expect(await card('deny-by-default')).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByTestId('policy-template-gallery-detail-empty')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-template-gallery-use-button')).toBeNull();
  });

  it('starts fresh, dropping a left draft, when Create Policy is opened again without Undo', async () => {
    window.sessionStorage.setItem(
      'policy-draft:new',
      JSON.stringify({ ...SAVED, id: '', name: 'draft', policy: `${SAVED.policy}\n` })
    );
    renderAt('/policy-definitions/new?type=agent_surface');
    const cards = await screen.findAllByTestId(/^policy-template-card-(?!scope)/);
    for (const c of cards) expect(c).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByTestId('policy-template-gallery-detail-empty')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-template-gallery-summary')).toBeNull();
    expect(screen.queryByPlaceholderText('e.g. Require Authentication')).toBeNull();
    expect(screen.queryByTestId('policy-editor-section')).toBeNull();
    expect(window.sessionStorage.getItem('policy-draft:new')).toBeNull();
  });

  it('no longer says Pre-filled once a Use is undone', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('all-trust-checks-pass');
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();

    act(() => mockUndo.last?.());

    expect(screen.queryByTestId('policy-definition-prefilled-hint')).toBeNull();
  });

  it('says Custom Rego once Rego started from Allow all is edited by hand', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('blank');
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom Rego'
    );
  });

  it('replaces hand-edited Rego when the used template is used again', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.queryByTestId('policy-definition-prefilled-hint')).toBeNull();

    change();
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('# reviewed');
    fireEvent.click(screen.getByTestId('policy-template-gallery-replace-button'));

    expect(rego().value).not.toContain('# reviewed');
    expect(name()).toHaveValue('Allow listed HTTP methods');
    expect(screen.getByTestId('policy-definition-prefilled-hint')).toBeInTheDocument();
  });
});

describe('gallery focus and detail', () => {
  const changeButton = () => screen.getByTestId('policy-template-gallery-change-button');

  it('moves focus to Change after Use, also for Allow all', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    expect(changeButton()).toHaveFocus();

    fireEvent.click(changeButton());
    await applyCard('blank');
    expect(changeButton()).toHaveFocus();
  });

  it('moves focus to the selected card after Change', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    fireEvent.click(changeButton());
    expect(screen.getByTestId('policy-template-card-allow-http-methods')).toHaveFocus();
  });

  it('moves focus to the first card after Change when no card is selected', async () => {
    window.sessionStorage.setItem(
      'policy-draft:new',
      JSON.stringify({ ...SAVED, id: '', name: 'draft', policy: `${SAVED.policy}\n` })
    );
    renderAt('/policy-definitions/new?type=agent_surface', true);
    await waitFor(() => expect(changeButton()).toBeInTheDocument());
    await screen.findAllByTestId(/^policy-templates-row-/);
    fireEvent.click(changeButton());
    expect(screen.getByTestId('policy-template-card-deny-by-default')).toHaveFocus();
  });

  it('moves focus to the detail heading when a card is selected', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('allow-http-methods'));
    const heading = screen.getByTestId('policy-template-gallery-detail-heading');
    expect(heading).toHaveTextContent('Allow listed HTTP methods');
    expect(heading).toHaveFocus();
  });

  it('names Add rules from a template in its help text', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const gallery = await screen.findByTestId('policy-template-gallery');
    expect(gallery).toHaveTextContent('Add rules from a template');
    expect(gallery).not.toHaveTextContent('on the right');
  });

  it('moves focus to the first card Show all brings into view', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const shown = await screen.findAllByTestId(/^policy-template-card-(?!scope)/);
    fireEvent.click(screen.getByTestId('policy-template-gallery-show-all'));
    const cards = screen.getAllByTestId(/^policy-template-card-(?!scope)/);
    expect(cards.length).toBeGreaterThan(shown.length);
    expect(screen.queryByTestId('policy-template-gallery-show-all')).toBeNull();
    expect(cards[shown.length]).toHaveFocus();
  });

  it('shows the Add rules panel with its search focused after Use, Change and Add rules', async () => {
    await renderNew();
    changeGallery();
    expect(screen.getByTestId('policy-template-gallery-detail-panel')).toBeInTheDocument();
    openAdd();
    expect(within(column()).getByTestId('policy-templates-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-template-gallery-detail-panel')).toBeNull();
    await waitFor(() => expect(screen.getByTestId('policy-templates-search-input')).toHaveFocus());
    expect(screen.getByTestId('policy-template-gallery-summary')).toBeInTheDocument();
  });

  it('moves focus to Change after Use', async () => {
    await renderNew();
    expect(changeButton()).toHaveFocus();
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

  it('shows the custom policy detail, focused, with its Rego, before it replaces edits', async () => {
    await renderNew();
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    changeGallery();
    fireEvent.click(customButton());
    expect(customButton()).toHaveAttribute('aria-pressed', 'true');
    const heading = screen.getByTestId('policy-template-gallery-detail-heading');
    expect(heading).toHaveTextContent('Custom policy');
    expect(heading).toHaveFocus();
    expect(screen.getByTestId('policy-template-gallery-use-button')).toHaveTextContent(
      'Create custom policy'
    );
    expect(rego().value).toContain('# reviewed');
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
    fireEvent.click(await card('business-hours-access-window'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-time_zone'), {
      target: { value: 'Asia/Singapore' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('time.clock([time.now_ns(), "Asia/Singapore"])');
  });

  it('picks allow or deny inside the business-hours window from a select', async () => {
    renderAt('/policy-definitions/new?type=gateway');
    fireEvent.click(await card('business-hours-access-window'));
    const mode = screen.getByTestId('policy-template-gallery-param-mode');
    expect(mode.tagName).toBe('SELECT');
    expect(mode).toHaveValue('allow');
    fireEvent.change(mode, { target: { value: 'deny' } });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('allow if not in_access_window');
  });

  it('takes the window as HH:MM, crossing midnight, on every day when Days is empty', async () => {
    renderAt('/policy-definitions/new?type=gateway');
    fireEvent.click(await card('business-hours-access-window'));
    const from = screen.getByTestId('policy-template-gallery-param-start_time');
    expect(from).toHaveAttribute('type', 'time');
    expect(from).toHaveValue('09:00');
    fireEvent.change(from, { target: { value: '22:00' } });
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-end_time'), {
      target: { value: '06:30' },
    });
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-days'), {
      target: { value: '' },
    });
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(rego().value).toContain('1320 > 390');
    expect(rego().value).toContain('access_day if count(set()) == 0');
  });

  it('refuses a business-hours window that ends when it starts', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    fireEvent.click(await card('business-hours-access-window'));
    fireEvent.change(screen.getByTestId('policy-template-gallery-param-end_time'), {
      target: { value: '09:00' },
    });
    expect(screen.getByText('Must differ from From.')).toBeInTheDocument();
    expect(screen.getByTestId('policy-template-gallery-use-button')).toBeDisabled();
  });
});

describe('templates panel', () => {
  it('offers Add rules in the templates column once a template is used, with no close button', async () => {
    await renderNew();
    const column = screen.getByTestId('policy-templates-column');
    expect(within(column).getByTestId('policy-templates-panel')).toHaveTextContent(
      'Add rules from a template'
    );
    expect(within(column).queryByTestId('policy-templates-close-button')).toBeNull();
    expect(within(column).queryByTestId('policy-templates-use-button')).toBeNull();
  });

  it('adds a rule to a new policy with no allow-default warning', async () => {
    await renderNew();
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(rego().value).toContain('allow if input.http.method in {"GET"}');
    expect(screen.queryByTestId('policy-rules-allow-default-warning')).toBeNull();
  });

  it('scrolls the preview into view and keeps focus on the picked row', async () => {
    const original = Element.prototype.scrollIntoView;
    const scrollIntoView = jest.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    try {
      await renderNew();
      const row = await panelRow('allow-http-methods');
      row.focus();
      scrollIntoView.mockClear();
      fireEvent.click(row);
      const heading = screen.getByTestId('policy-templates-preview-heading');
      expect(heading).toHaveTextContent('Allow listed HTTP methods');
      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', behavior: 'smooth' });
      expect(scrollIntoView.mock.instances).toContain(heading);
      expect(row).toHaveFocus();
      expect(heading).not.toHaveFocus();
    } finally {
      Element.prototype.scrollIntoView = original;
    }
  });

  it('shows no preview while the search hides the picked template', async () => {
    await renderNew();
    fireEvent.click(await panelRow('allow-http-methods'));
    expect(screen.getByTestId('policy-templates-preview')).toBeInTheDocument();
    const search = screen.getByTestId('policy-templates-search-input');

    fireEvent.change(search, { target: { value: 'no template is called this' } });
    expect(screen.getByText('No templates match.')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-templates-preview')).toBeNull();
    expect(screen.queryByTestId('policy-templates-insert-rules-button')).toBeNull();
    expect(screen.getByTestId('policy-templates-preview-empty')).toBeInTheDocument();

    fireEvent.change(search, { target: { value: '' } });
    expect(screen.getByTestId('policy-templates-preview-heading')).toHaveTextContent(
      'Allow listed HTTP methods'
    );
  });

  it('focuses the column search from Add rules from a template', async () => {
    await renderNew();
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

  it('filters by category', async () => {
    await renderNew();
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
    await renderNew();
    openAdd();
    const names = (await screen.findAllByTestId(/^policy-templates-row-/)).map(
      r => r.textContent ?? ''
    );
    for (const name of [
      'Require authenticated caller',
      'Allow by JWT claim or role',
      'Allow by JWT issuer and audience',
      'Require Trust Registry recognition',
      'Require verified credential subject',
      'All trust checks pass',
    ]) {
      expect(names.some(n => n.startsWith(name))).toBe(true);
    }
    expect(names.some(n => /rate/i.test(n))).toBe(false);
  });

  it('lists only templates that add rules, each labelled Adds rules', async () => {
    await renderNew();
    const rows = await screen.findAllByTestId(/^policy-templates-row-/);
    for (const row of rows) {
      expect(within(row).getByTestId('policy-template-role-badge')).toHaveTextContent('Adds rules');
    }
    for (const id of [
      'deny-by-default',
      'allow-all-monitor',
      'restrict-mcp-tools-by-role',
      'allowlist-outbound-destinations',
      'business-hours-access-window',
      'tool-allow-by-jwt-claim',
      'tool-allow-every-caller',
    ]) {
      expect(screen.queryByTestId(`policy-templates-row-${id}:agent_surface`)).toBeNull();
    }
  });

  it('lists the built-in templates in one list, with no tabs', async () => {
    await renderNew();
    const panel = await screen.findByTestId('policy-templates-panel');
    expect(within(panel).queryAllByRole('tab')).toHaveLength(0);
    expect(
      within(panel).getByTestId('policy-templates-row-allow-http-methods:agent_surface')
    ).toBeInTheDocument();
  });
});

describe('templates for the other type and for tool bindings', () => {
  it('lists only templates of the policy type in Add rules and says how many it left out', async () => {
    await renderNew('gateway');
    expect(await screen.findByTestId('policy-templates-left-out-note')).toHaveTextContent(
      '17 templates left out: 3 are whole policies, 14 are for Agent Surface policies. Pick a whole policy under Start from.'
    );
    expect(
      screen.queryByTestId('policy-templates-row-require-authentication:agent_surface')
    ).toBeNull();
    expect(
      screen.getByTestId('policy-templates-row-allow-http-methods:gateway')
    ).toBeInTheDocument();
  });

  it('leaves out MCP tool policy templates as whole policies', async () => {
    await renderNew();
    expect(await screen.findByTestId('policy-templates-left-out-note')).toHaveTextContent(
      /^9 templates left out: 9 are whole policies\. Pick a whole policy under Start from\.$/
    );
    expect(
      screen.queryByTestId('policy-templates-row-tool-allow-by-jwt-claim:agent_surface')
    ).toBeNull();
  });

  it('shows the template docs link with its own label in the panel', async () => {
    await renderNew();
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    const link = screen.getByTestId('policy-templates-docs-link');
    expect(link).toHaveTextContent('Reference: input.trust_check_results');
    expect(link).toHaveAttribute('href', expect.stringContaining('#inputtrust_check_results'));
  });
});

describe('add rules while creating a policy', () => {
  const row = panelRow;

  it('combines the rules of several templates in one new policy', async () => {
    await renderNew();
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
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Deny by default · 2 templates added'
    );
  });

  it('keeps Name and Description when rules are inserted', async () => {
    await renderNew();
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

  it('says the rules change nothing while the policy allows by default', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('blank');
    fireEvent.click(await row('allow-http-methods'));
    expect(screen.getByTestId('policy-templates-allow-default-note')).toHaveTextContent(
      'This policy allows every request by default, so these rules change nothing until you choose Deny by default.'
    );
  });

  it('has no allow-default note while the policy denies by default', async () => {
    await renderNew();
    fireEvent.click(await row('allow-http-methods'));
    expect(screen.getByTestId('policy-templates-insert-preview')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-templates-allow-default-note')).toBeNull();
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

  it('says whole policies are offered only when creating a policy', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-templates-left-out-note')).toHaveTextContent(
      '9 templates left out: 9 are whole policies. Whole policies are offered only when creating a policy.'
    );
    expect(
      screen.queryByTestId('policy-templates-row-restrict-mcp-tools-by-role:agent_surface')
    ).toBeNull();
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

  it('hides Add rules from a template without policies.edit', async () => {
    mockCanEdit = false;
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByTestId('policy-templates-insert-button')).toBeNull();
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

  it('titles the three sections on the create form without step numbers', async () => {
    await renderNew();
    expect([title('policy-template-gallery'), ...titles()]).toEqual([
      'Start from',
      'Details',
      'Policy',
    ]);
  });
});

describe('rules in this policy', () => {
  it('lists the rules written in the editor and those of each added template', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    const card = await screen.findByTestId('policy-editor-section');
    expect(within(card).getByTestId('policy-rules-count')).toHaveTextContent('1 rule');
    expect(within(card).getByTestId('policy-rules-group-0')).toHaveTextContent('Your rules');
    expect(within(card).getByTestId('policy-rules-group-0-rule-0')).toHaveTextContent(
      /Allows.*allow if input\.jwt\.iss == "https:\/\/login\.example".*5/
    );

    fireEvent.click(screen.getByTestId('policy-templates-insert-button'));
    fireEvent.click(
      await screen.findByTestId('policy-templates-row-allow-http-methods:agent_surface')
    );
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));

    const added = within(card).getByTestId('policy-rules-group-1');
    expect(added).toHaveTextContent('From template: Allow listed HTTP methods');
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
        /Roles list with admin.*ALLOW(ALLOW|DENY)/
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

  it('shows the view switch as one joined control with the active half filled', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    const rules = await screen.findByTestId('policy-view-rules');
    const rego = screen.getByTestId('policy-view-rego');
    expect(screen.getByRole('group', { name: 'Policy view' })).toHaveClass(
      'btn-group',
      'policy-view-switch'
    );
    expect(rules).toHaveClass('btn-primary');
    expect(rego).toHaveClass('app-button-secondary');
    expect(rego).toHaveAttribute('aria-pressed', 'false');

    fireEvent.click(rego);

    expect(rego).toHaveClass('btn-primary');
    expect(rego).toHaveAttribute('aria-pressed', 'true');
    expect(rules).toHaveClass('app-button-secondary');
    expect(rules).not.toHaveClass('btn-primary');
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
  it('labels an empty Rego as allowing every request, as the gateway treats it', async () => {
    await renderNew();
    fireEvent.change(rego(), { target: { value: '' } });
    fireEvent.click(screen.getByTestId('policy-view-rules'));
    expect(screen.getByTestId('policy-editor-section')).toHaveTextContent('Default ALLOW');
    expect(screen.getByTestId('policy-rules-empty')).toHaveTextContent(
      'An empty policy allows every request.'
    );
  });

  it('keeps a typed name when the used template is used again with new settings', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
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
    await applyCard('allow-http-methods');
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

  it('marks pasted rules written for the other Type and blocks Create until they are removed', async () => {
    const view = renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('deny-by-default');
    fireEvent.click(await panelRow('require-authentication'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    const surfaceRego = rego().value;
    view.unmount();

    await renderNew('gateway');
    fireEvent.change(rego(), {
      target: { value: surfaceRego.replace('package surface.policy', 'package gateway.policy') },
    });
    const save = screen.getByTestId('policy-definition-editor-save-button');

    expect(screen.getByTestId('policy-rules-group-0-other-type')).toHaveTextContent(
      "Written for Agent Surface policies. It reads input Gateway policies don't get. Remove it to create this policy."
    );
    expect(screen.getByTestId('policy-rules-other-type-banner')).toBeInTheDocument();
    expect(save).toBeDisabled();
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);

    fireEvent.click(screen.getByTestId('policy-rules-group-0-remove-button'));

    expect(screen.queryByTestId('policy-rules-other-type-banner')).toBeNull();
    expect(save).toBeEnabled();
  });
});

describe('gallery cards', () => {
  it('show no role or default decision badges, on a card or in its detail', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    for (const id of ['deny-by-default', 'allow-http-methods']) {
      const c = await card(id);
      expect(within(c).queryByTestId('policy-template-role-badge')).toBeNull();
      expect(c).not.toHaveTextContent(/Default (ALLOW|DENY)/);
    }

    fireEvent.click(await card('allow-http-methods'));
    const detail = screen.getByTestId('policy-template-gallery-detail');
    expect(within(detail).queryByTestId('policy-template-role-badge')).toBeNull();
    expect(detail).not.toHaveTextContent(/Default (ALLOW|DENY)/);
  });
});

describe('Use over rules already in the policy', () => {
  const name = () => screen.getByPlaceholderText('e.g. Require Authentication');
  const confirm = () => screen.queryByTestId('policy-template-gallery-replace-confirm');

  async function withAddedRules() {
    await renderNew();
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));
    fireEvent.click(await card('all-trust-checks-pass'));
  }

  it('asks in place first, with the focus on Cancel, and Cancel keeps the rules', async () => {
    await withAddedRules();
    const use = screen.getByTestId('policy-template-gallery-use-button');
    fireEvent.click(use);

    expect(confirm()).toHaveTextContent('This replaces the 1 rule in the Policy section.');
    expect(rego().value).toContain('Allow listed HTTP methods');
    const cancel = screen.getByTestId('policy-template-gallery-replace-cancel-button');
    expect(cancel).toHaveFocus();

    fireEvent.click(cancel);
    expect(confirm()).toBeNull();
    expect(use).toHaveFocus();
    expect(rego().value).toContain('Allow listed HTTP methods');
    expect(name()).toHaveValue('Deny by default');
  });

  it('closes on Escape and returns the focus to Use', async () => {
    await withAddedRules();
    const use = screen.getByTestId('policy-template-gallery-use-button');
    fireEvent.click(use);
    fireEvent.keyDown(screen.getByTestId('policy-template-gallery-replace-cancel-button'), {
      key: 'Escape',
    });
    expect(confirm()).toBeNull();
    expect(use).toHaveFocus();
  });

  it('replaces the rules on Replace, with Undo', async () => {
    await withAddedRules();
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    fireEvent.click(screen.getByTestId('policy-template-gallery-replace-button'));

    expect(rego().value).not.toContain('Allow listed HTTP methods');
    expect(rego().value).toContain('every r in input.trust_check_results.target { r.ok }');
    expect(name()).toHaveValue('All trust checks pass');
    act(() => mockUndo.last?.());
    expect(rego().value).toContain('Allow listed HTTP methods');
  });

  it('closes the question when another card is picked', async () => {
    await withAddedRules();
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    fireEvent.click(await card('allow-http-methods'));
    expect(confirm()).toBeNull();
  });

  it('asks before a custom policy replaces the rules too, and creates it on Replace', async () => {
    await withAddedRules();
    fireEvent.click(customButton());
    expect(rego().value).toContain('Allow listed HTTP methods');
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(confirm()).toBeInTheDocument();
    expect(rego().value).toContain('Allow listed HTTP methods');

    fireEvent.click(screen.getByTestId('policy-template-gallery-replace-button'));
    expect(rego().value).toContain('default allow = true');
    expect(screen.getByTestId('policy-template-gallery-summary')).toHaveTextContent(
      'Started from Custom policy'
    );
  });

  it('names your edits when the hand-edited Rego cannot be read', async () => {
    await renderNew();
    fireEvent.change(rego(), { target: { value: 'package surface.policy\n\nallow if {' } });
    changeGallery();
    fireEvent.click(await card('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
    expect(confirm()).toHaveTextContent('This replaces your edits in the Policy section.');
  });

  it('applies at once over an untouched start', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    expect(confirm()).toBeNull();
    expect(rego().value).toContain('allow if input.http.method in {"GET"}');
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
    mockGateway({ ...SAVED, policy: HELPER_POLICY });
    renderAt('/policy-definitions/partner-only');
    const group = await screen.findByTestId('policy-rules-group-0');
    const helper = within(group).getByTestId('policy-rules-group-0-rule-0-remove-button');
    expect(helper).toBeDisabled();
    expect(helper).toHaveAttribute('title', expect.stringContaining('Another rule uses'));
    expect(within(group).getByTestId('policy-rules-group-0-rule-0-in-use')).toHaveTextContent(
      /^Another rule uses this \(allow, line \d+\); remove that rule first\.$/
    );
    expect(within(group).getByRole('button', { name: /Remove the rule allow/ })).toBeEnabled();
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
      'A rule outside this template uses its rules (allow, line 11); remove that rule first.'
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
    await applyCard('allow-http-methods');
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

  it('clears the used template name on Create custom policy and restores it on Undo', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    const description = () => screen.getByPlaceholderText('What does this policy do?');
    const filledDescription = (description() as HTMLTextAreaElement).value;
    expect(nameField()).toHaveValue('Allow listed HTTP methods');
    changeGallery();
    fireEvent.click(customButton());

    expect(rego().value).toContain('default allow = true');
    expect(nameField()).toHaveValue('');
    expect(description()).toHaveValue('');
    expect(mockUndo.message).toContain('Undo restores the form from before this change.');

    act(() => mockUndo.last?.());

    expect(nameField()).toHaveValue('Allow listed HTTP methods');
    expect(description()).toHaveValue(filledDescription);
    expect(rego().value).toContain('allow if input.http.method in {"GET"}');
  });

  it('keeps a typed name on Create custom policy', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    fireEvent.change(nameField()!, { target: { value: 'Read-only partners' } });
    changeGallery();
    fireEvent.click(customButton());

    expect(rego().value).toContain('default allow = true');
    expect(nameField()).toHaveValue('Read-only partners');
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

describe('the start after rules are added', () => {
  const summary = () => screen.getByTestId('policy-template-gallery-summary');

  it('keeps the start and counts the templates added', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    openAdd();
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(summary()).toHaveTextContent(
      'Started from Allow listed HTTP methods · 1 template added'
    );

    fireEvent.click(await panelRow('require-trust-registry-recognition'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(summary()).toHaveTextContent(
      'Started from Allow listed HTTP methods · 2 templates added'
    );
  });

  it('says Custom Rego once a rule is typed inside an added template', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('blank');
    openAdd();
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(summary()).toHaveTextContent('Started from Custom policy · 1 template added');

    fireEvent.change(rego(), {
      target: {
        value: rego().value.replace(
          '# End of template: Allow listed HTTP methods',
          'allow if { true }\n# End of template: Allow listed HTTP methods'
        ),
      },
    });
    expect(summary()).toHaveTextContent('Started from Custom Rego');

    act(() => mockUndo.last?.());
    expect(summary()).toHaveTextContent('Started from Custom policy');
  });

  it('says Custom Rego when rules are added after a hand edit', async () => {
    await renderNew();
    fireEvent.change(rego(), { target: { value: `${rego().value}\nallow if input.x` } });
    openAdd();
    fireEvent.click(await panelRow('allow-http-methods'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(summary()).toHaveTextContent('Started from Custom Rego');
  });

  it('keeps Deny by default as the start when rules are added to it', async () => {
    await renderNew();
    openAdd();
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    expect(summary()).toHaveTextContent('Started from Deny by default · 1 template added');
    expect(screen.getByTestId('policy-template-gallery-change-button')).not.toHaveFocus();

    fireEvent.click(screen.getByTestId('policy-template-gallery-change-button'));
    expect(await card('deny-by-default')).toHaveAttribute('aria-pressed', 'true');
  });

  it('says Custom Rego once the Rego is edited by hand after rules were added', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    openAdd();
    fireEvent.click(await panelRow('all-trust-checks-pass'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    fireEvent.change(rego(), { target: { value: rego().value.replace('"GET"', '"PUT"') } });
    expect(summary()).toHaveTextContent('Started from Custom Rego');
  });

  it('titles the rules from Use with the template they started from', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    await applyCard('allow-http-methods');
    expect(screen.getByTestId('policy-rules-group-0')).toHaveTextContent(
      'Your rules · started from Allow listed HTTP methods'
    );
    fireEvent.change(rego(), { target: { value: `${rego().value}\n# reviewed` } });
    expect(screen.getByTestId('policy-rules-group-0')).toHaveTextContent('Your rules');
    expect(screen.getByTestId('policy-rules-group-0')).not.toHaveTextContent('started from');
  });
});

describe('why a rule cannot be removed', () => {
  it('names the rule that reads a helper', async () => {
    mockGateway({ ...SAVED, policy: HELPER_POLICY });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-group-0-rule-0-in-use')).toHaveTextContent(
      'Another rule uses this (allow, line 7); remove that rule first.'
    );
  });

  it('gives the whole-document read its own reason', async () => {
    mockGateway({
      ...SAVED,
      policy:
        'package surface.policy\n\ndefault allow := false\n\nblocked if input.x\n\nallow if not data.surface.policy["blocked"]\n',
    });
    renderAt('/policy-definitions/partner-only');
    expect(await screen.findByTestId('policy-rules-group-0-rule-0-in-use')).toHaveTextContent(
      'The Rego reads the policy as a whole document; remove rules in the Rego view.'
    );
  });
});

describe('template examples that differ', () => {
  it('explains a differing example and loads its input in Test', async () => {
    mockGateway();
    fetchMock.mockImplementation(async (url: string) => {
      if (url.endsWith('/simulate')) {
        return jsonResponse({
          allow: true,
          policy_type: 'agent_surface',
          content_hash: 'sha256:x',
          query: 'data.surface.policy.allow',
        });
      }
      if (url.includes('/versions')) return jsonResponse([]);
      return jsonResponse(SAVED);
    });
    renderAt('/policy-definitions/partner-only');
    fireEvent.click(await panelRow('allow-by-jwt-claim'));
    fireEvent.click(screen.getByTestId('policy-templates-insert-rules-button'));
    const card = await screen.findByTestId('policy-template-examples-card');
    await waitFor(() =>
      expect(within(card).getByTestId('policy-template-example-row-1')).toHaveTextContent('Differs')
    );
    expect(within(card).getByTestId('policy-template-example-row-0')).toHaveTextContent('Matches');
    expect(within(card).getByTestId('policy-template-example-row-1-why')).toHaveTextContent(
      'Allow rules combine with OR'
    );

    const before = (screen.getByTestId('policy-simulate-input') as HTMLTextAreaElement).value;
    fireEvent.click(within(card).getByTestId('policy-template-example-row-1-load-button'));
    const input = JSON.parse(
      (screen.getByTestId('policy-simulate-input') as HTMLTextAreaElement).value
    );
    expect(input.source_auth.claims.role).toBe('viewer');
    expect(mockUndo.message).toBe(
      'Loaded Role viewer into Test (dry-run). Undo restores the sample input from before.'
    );

    act(() => mockUndo.last?.());
    expect(screen.getByTestId('policy-simulate-input')).toHaveValue(before);
  });
});

describe('built-in template badges', () => {
  it('shows each card its category and no storage badge', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    const allowMethods = await card('allow-http-methods');
    expect(allowMethods).toHaveTextContent('Routing & paths');
    expect(allowMethods).not.toHaveTextContent('This tab only');
    expect(allowMethods).not.toHaveTextContent('Organization template');
  });

  it('has no Save as template on a saved policy', async () => {
    mockGateway();
    renderAt('/policy-definitions/partner-only');
    await screen.findByText('Edit Policy: partner-only');
    expect(screen.queryByText('Save as template')).toBeNull();
  });

  it('marks no built-in as recommended', async () => {
    renderAt('/policy-definitions/new?type=agent_surface');
    expect(await card('require-authentication')).not.toHaveTextContent('Recommended');
    expect(await card('allow-by-jwt-claim')).not.toHaveTextContent('Recommended');
    await applyCard('deny-by-default');
    expect(await panelRow('require-authentication')).not.toHaveTextContent('Recommended');
  });
});
