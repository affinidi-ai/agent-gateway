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
  it('shows Gateway, Agent Surfaces and Paywall tabs but no Channel tab', () => {
    render(
      <MemoryRouter initialEntries={['/policies']}>
        <PoliciesPage />
      </MemoryRouter>
    );

    expect(screen.getByRole('tab', { name: /gateway/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /agent surfaces/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /paywall/i })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: /channel/i })).toBeNull();
  });
});
