import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditAuthorityPage from '../EditAuthorityPage';
import { ApiError, apiClient } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../api', () => {
  const actual = jest.requireActual('../../api');
  return {
    ApiError: actual.ApiError,
    apiClient: {
      get: jest.fn(),
      deleteAuthority: jest.fn(),
      listTrustRegistries: jest.fn(),
    },
  };
});
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../../utils/authoritiesCache', () => ({ clearAuthoritiesCache: jest.fn() }));

const AUTHORITY = {
  id: 'auth-1',
  name: 'Acme Authority',
  did: 'did:web:acme.example.com',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-01T10:00:00Z',
};

async function deleteAuthority() {
  render(
    <MemoryRouter initialEntries={['/authorities/auth-1']}>
      <Routes>
        <Route path="/authorities/:id" element={<EditAuthorityPage />} />
      </Routes>
    </MemoryRouter>
  );
  const button = await screen.findByTestId('authority-editor-delete-button');
  fireEvent.click(button);
  fireEvent.click(button);
}

describe('EditAuthorityPage — delete', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.get as jest.Mock).mockResolvedValue({ data: AUTHORITY });
    (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([]);
  });

  it('opens the in-use dialog on a 409 with references, without a toast', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockRejectedValue(
      new ApiError(
        'in use (409)',
        409,
        undefined,
        JSON.stringify({
          references: [
            {
              kind: 'surface',
              id: 'surface-1',
              name: 'Orders',
              uses: [
                {
                  element: 'trust_check',
                  id: 'tc-1',
                  placement: 'transit_point',
                  transit_point: 'partner',
                },
              ],
            },
          ],
          hidden_references: 1,
        })
      )
    );

    await deleteAuthority();

    const dialog = await screen.findByTestId('authority-in-use-dialog');
    expect(apiClient.deleteAuthority).toHaveBeenCalledWith('auth-1');
    expect(dialog).toHaveTextContent('Acme Authority is used by Trust Checks');
    expect(dialog).toHaveTextContent('Trust Check on Transit Point partner');
    expect(screen.getByTestId('authority-in-use-dialog-hidden')).toHaveTextContent(
      "1 more you can't view."
    );
    expect(showToast).not.toHaveBeenCalled();
  });

  it('keeps the error toast for any other failure', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockRejectedValue(
      new ApiError('Authority not found (404)', 404, undefined, '{"message":"Authority not found"}')
    );

    await deleteAuthority();

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', 'Authority not found (404)')
    );
    expect(screen.queryByTestId('authority-in-use-dialog')).toBeNull();
  });
});
