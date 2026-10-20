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

function renderCreateForm() {
  return render(
    <PageTitleProvider>
      <MemoryRouter initialEntries={['/policy-definitions/new']}>
        <Routes>
          <Route path="/policy-definitions/new" element={<EditPolicyDefinitionPage />} />
        </Routes>
      </MemoryRouter>
    </PageTitleProvider>
  );
}

describe('EditPolicyDefinitionPage — policy type selector', () => {
  it('offers exactly Gateway and Agent Surfaces', () => {
    renderCreateForm();
    const optionLabels = screen.getAllByRole('option').map(o => o.textContent);
    expect(optionLabels).toEqual(['Gateway', 'Agent Surfaces']);
  });

  it('does not offer a legacy Channel option', () => {
    renderCreateForm();
    expect(screen.queryByRole('option', { name: /channel/i })).toBeNull();
  });
});

describe('EditPolicyDefinitionPage — package/type mismatch', () => {
  it('blocks save when the declared package does not match the selected type', async () => {
    renderCreateForm();
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
    renderCreateForm();
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

  it('starts collapsed', () => {
    renderCreateForm();
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
    expect(body()).not.toHaveClass('show');
  });

  it('expands and collapses when the title is clicked', () => {
    renderCreateForm();

    fireEvent.click(screen.getByText('Policy Instructions & Examples'));
    expect(toggle()).toHaveAttribute('aria-expanded', 'true');
    expect(body()).toHaveClass('show');

    fireEvent.click(screen.getByText('Policy Instructions & Examples'));
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
    expect(body()).not.toHaveClass('show');
  });

  it('toggles when the arrow is clicked', () => {
    renderCreateForm();
    fireEvent.click(screen.getByTestId('policy-instructions-chevron'));
    expect(body()).toHaveClass('show');
  });

  it('keeps the title a heading that holds the toggle button', () => {
    renderCreateForm();
    const heading = screen.getByRole('heading', { name: /Policy Instructions & Examples/i });
    expect(heading).toContainElement(toggle());
    expect(screen.getByRole('button', { name: /Policy Instructions & Examples/i })).toBe(toggle());
  });

  it('points the toggle at the body it expands', () => {
    renderCreateForm();
    expect(toggle()).toHaveAttribute('aria-controls', body().id);
  });

  it('flips the arrow to match the state', () => {
    renderCreateForm();
    const chevron = () => screen.getByTestId('policy-instructions-chevron');
    expect(chevron()).toHaveClass('fa-chevron-down');

    fireEvent.click(toggle());
    expect(chevron()).toHaveClass('fa-chevron-up');
    expect(chevron()).not.toHaveClass('fa-chevron-down');
  });

  it('toggles from the keyboard with Enter and Space only', async () => {
    const user = userEvent.setup();
    renderCreateForm();
    toggle().focus();

    await user.keyboard('{Enter}');
    expect(toggle()).toHaveAttribute('aria-expanded', 'true');

    await user.keyboard(' ');
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');

    await user.keyboard('a');
    expect(toggle()).toHaveAttribute('aria-expanded', 'false');
  });

  it('keeps the examples in the DOM for the selected policy type', () => {
    renderCreateForm();
    expect(body()).toHaveTextContent('package gateway.policy');
  });
});
