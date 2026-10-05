import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
