import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../../../context/PageTitleContext';
import EditPolicyDefinitionPage from '../EditPolicyDefinitionPage';

// The page only talks to the backend via `apiClient`; stub it so the create
// form renders without network access.
jest.mock('../../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
    post: jest.fn().mockResolvedValue({ data: { valid: true } }),
  },
}));

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));

beforeEach(() => window.sessionStorage.clear());

/** Opens the create form and starts from Allow all, which shows the Details and Policy sections. */
async function renderCreateForm() {
  const view = render(
    <PageTitleProvider>
      <MemoryRouter initialEntries={['/policy-definitions/new']}>
        <Routes>
          <Route path="/policy-definitions/new" element={<EditPolicyDefinitionPage />} />
        </Routes>
      </MemoryRouter>
    </PageTitleProvider>
  );
  await screen.findByTestId('policy-template-card-deny-by-default');
  fireEvent.click(screen.getByTestId('policy-template-card-blank'));
  fireEvent.click(screen.getByTestId('policy-template-gallery-use-button'));
  return view;
}

describe('EditPolicyDefinitionPage — policy type selector', () => {
  it('offers exactly Gateway and Agent Surfaces', async () => {
    await renderCreateForm();
    const optionLabels = screen.getAllByRole('option').map(o => o.textContent);
    expect(optionLabels).toEqual(['Gateway', 'Agent Surfaces']);
  });

  it('does not offer a legacy Channel option', async () => {
    await renderCreateForm();
    expect(screen.queryByRole('option', { name: /channel/i })).toBeNull();
  });
});

describe('EditPolicyDefinitionPage — package/type mismatch', () => {
  it('blocks save when the declared package does not match the selected type', async () => {
    await renderCreateForm();
    // The create form defaults to Type=Gateway. Declaring a surface package is a
    // mismatch that must block the save.
    const editor = screen.getByPlaceholderText('...add policy here...');
    fireEvent.change(editor, {
      target: { value: 'package surface.policy\ndefault allow = true' },
    });

    expect(await screen.findByText(/Package mismatch:/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Create/i })).toBeDisabled();
  });

  it('the "Fix it" action rewrites the package to the canonical one and re-enables save', async () => {
    await renderCreateForm();
    const editor = screen.getByPlaceholderText('...add policy here...') as HTMLTextAreaElement;
    fireEvent.change(editor, {
      target: { value: 'package surface.policy\ndefault allow = true' },
    });
    await screen.findByText(/Package mismatch:/i);

    fireEvent.click(screen.getByRole('button', { name: /Fix it/i }));

    await waitFor(() => expect(screen.queryByText(/Package mismatch:/i)).toBeNull());
    expect(editor.value).toContain('package gateway.policy');
    expect(screen.getByRole('button', { name: /Create/i })).toBeEnabled();
  });
});

describe('EditPolicyDefinitionPage — instructions panel', () => {
  const toggle = () => screen.getByTestId('policy-instructions-toggle');
  const body = () => screen.getByTestId('policy-instructions-body');

  it('starts collapsed', async () => {
    await renderCreateForm();
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
    expect(body()).not.toHaveClass('show');
  });

  it('expands and collapses when the title is clicked', async () => {
    await renderCreateForm();

    fireEvent.click(screen.getByText('Rego reference'));
    expect(toggle()).toHaveAttribute('aria-expanded', 'true');
    expect(body()).toHaveClass('show');

    fireEvent.click(screen.getByText('Rego reference'));
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
    expect(body()).not.toHaveClass('show');
  });

  it('toggles when the arrow is clicked', async () => {
    await renderCreateForm();
    fireEvent.click(screen.getByTestId('policy-instructions-chevron'));
    expect(body()).toHaveClass('show');
  });

  it('keeps the title a heading that holds the toggle button', async () => {
    await renderCreateForm();
    const heading = screen.getByRole('heading', { name: /Rego reference/i });
    expect(heading).toContainElement(toggle());
    expect(screen.getByRole('button', { name: /Rego reference/i })).toBe(toggle());
  });

  it('points the toggle at the body it expands', async () => {
    await renderCreateForm();
    expect(toggle()).toHaveAttribute('aria-controls', body().id);
  });

  it('flips the arrow to match the state', async () => {
    await renderCreateForm();
    const chevron = () => screen.getByTestId('policy-instructions-chevron');
    expect(chevron()).toHaveClass('fa-chevron-down');

    fireEvent.click(toggle());
    expect(chevron()).toHaveClass('fa-chevron-up');
    expect(chevron()).not.toHaveClass('fa-chevron-down');
  });

  it('toggles from the keyboard with Enter and Space only', async () => {
    const user = userEvent.setup();
    await renderCreateForm();
    toggle().focus();

    await user.keyboard('{Enter}');
    expect(toggle()).toHaveAttribute('aria-expanded', 'true');

    await user.keyboard(' ');
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');

    await user.keyboard('a');
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
  });

  it('keeps the examples in the DOM for the selected policy type', async () => {
    await renderCreateForm();
    expect(body()).toHaveTextContent('package gateway.policy');
  });

  it('describes the caller context input and the MCP tool policy input apart', async () => {
    await renderCreateForm();
    const callerFields = screen.getByTestId('policy-instructions-input-fields');
    expect(callerFields).toHaveTextContent('input.source_auth.claims');
    expect(callerFields).not.toHaveTextContent('input.jwt');
    expect(screen.getByTestId('policy-instructions-tool-input-fields')).toHaveTextContent(
      'input.jwt.<claim>'
    );
  });
});
