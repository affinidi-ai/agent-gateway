import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../api';
import CredentialAuditTab from '../CredentialAuditTab';

jest.mock('../../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
  },
}));

const auditPage = (caller: Record<string, string>) => ({
  events: [
    {
      timestamp: '2026-11-04T10:00:00Z',
      event: 'token_injected',
      provider_id: 'github',
      via_fabric: false,
      caller: { auth_method: 'jwt_bearer', iss: 'https://login.example.com', ...caller },
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
  total_pages: 1,
});

const renderWith = (caller: Record<string, string>) => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(auditPage(caller)),
  });
  render(
    <MemoryRouter>
      <CredentialAuditTab />
    </MemoryRouter>
  );
};

const renderPage = (page: Record<string, unknown>) => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(page),
  });
  render(
    <MemoryRouter>
      <CredentialAuditTab />
    </MemoryRouter>
  );
};

describe('CredentialAuditTab counts', () => {
  it('shows the total of a partial read as a lower bound', async () => {
    renderPage({ ...auditPage({ sub: 'alice' }), total: 12, truncated: true });

    expect(await screen.findByLabelText('12+ audit events')).toBeInTheDocument();
  });

  it('shows the total as a lower bound when the read met records it could not read', async () => {
    renderPage({ ...auditPage({ sub: 'alice' }), total: 12, dropped_records: 1 });

    expect(await screen.findByLabelText('12+ audit events')).toBeInTheDocument();
  });

  it('shows the total of a complete read as it is', async () => {
    renderPage({ ...auditPage({ sub: 'alice' }), total: 12, dropped_records: 0 });

    expect(await screen.findByLabelText('12 audit events')).toBeInTheDocument();
  });
});

describe('CredentialAuditTab caller', () => {
  it("shows the principal a caller's grants are keyed by beside the token's sub", async () => {
    renderWith({ sub: 'pairwise-sub', principal: 'person-1' });
    fireEvent.click(await screen.findByTestId('credential-audit-row-0'));

    const principal = screen.getByTestId('credential-audit-caller-principal');
    expect(within(principal).getByText('Principal')).toBeInTheDocument();
    expect(within(principal).getByText('person-1')).toBeInTheDocument();
    expect(screen.getByText('pairwise-sub')).toBeInTheDocument();
  });

  it('shows no principal row for a caller named by sub', async () => {
    renderWith({ sub: 'alice' });
    fireEvent.click(await screen.findByTestId('credential-audit-row-0'));

    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-audit-caller-principal')).not.toBeInTheDocument();
  });
});
