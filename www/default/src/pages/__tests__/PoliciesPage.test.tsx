import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import PoliciesPage from '../PoliciesPage';

// Both PoliciesPage and its PolicyListTab children fetch via `apiClient`;
// stub it so the tabs render with empty policy lists.
jest.mock('../../api', () => ({
  apiClient: {
    fetch: jest.fn().mockResolvedValue({ ok: true, json: async () => [] }),
  },
}));

describe('PoliciesPage — policy tabs', () => {
  it('shows Gateway and Agent Surfaces tabs but no Channel or Paywall tab', () => {
    render(
      <MemoryRouter initialEntries={['/policies']}>
        <PoliciesPage />
      </MemoryRouter>
    );

    expect(screen.getByRole('tab', { name: /gateway/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /agent surfaces/i })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: /paywall/i })).toBeNull();
    expect(screen.queryByRole('tab', { name: /channel/i })).toBeNull();
  });
});
