import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import CredentialsPage from '../CredentialsPage';

const mockHasPermission = jest.fn();
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission, loading: false }),
}));
jest.mock('../SettingsPage/StrategiesTab', () => () => null);
jest.mock('../SettingsPage/CredentialProvidersTab', () => () => null);
jest.mock('../CredentialsPage/StsClientsTab', () => () => null);
jest.mock(
  '../CredentialsPage/CredentialTokensTab',
  () => (props: { onViewActivity?: (userHash: string) => void }) => (
    <button
      type="button"
      data-testid="stub-view-activity"
      disabled={!props.onViewActivity}
      onClick={() => props.onViewActivity?.('user-hash-1')}
    />
  )
);
jest.mock(
  '../CredentialsPage/DelegatedAccessTab',
  () => (props: { onViewHistory?: () => void }) => (
    <button
      type="button"
      data-testid="stub-view-history"
      disabled={!props.onViewHistory}
      onClick={() => props.onViewHistory?.()}
    />
  )
);
jest.mock(
  '../CredentialsPage/CredentialAuditTab',
  () => (props: { externalSearchTerm?: string }) => (
    <div data-testid="stub-audit-search">{props.externalSearchTerm}</div>
  )
);

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/credentials?tab=credential-tokens']}>
      <CredentialsPage />
    </MemoryRouter>
  );

describe('CredentialsPage delegated access', () => {
  beforeEach(() => jest.clearAllMocks());

  it('keeps the Credential Tokens tab and adds Delegated Access beside it', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();

    expect(
      screen.getAllByRole('tab').map(tab => tab.textContent?.replace(/\s+/g, ' ').trim())
    ).toEqual([
      'JWT Verification',
      'Credential Providers',
      'Credential Tokens',
      'Delegated Access',
      'STS Clients',
      'Credential Delegation Audit',
    ]);
    expect(screen.getByTestId('credentials-credential-tokens-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
  });

  it('opens the delegation audit as the history of delegated access', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();
    fireEvent.click(screen.getByTestId('credentials-delegated-access-tab-trigger'));

    fireEvent.click(screen.getByTestId('stub-view-history'));

    expect(screen.getByTestId('credentials-credential-audit-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
    expect(screen.getByTestId('credentials-search-input')).toHaveValue('');
  });

  it('opens a user audit from the Credential Tokens tab', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();

    fireEvent.click(screen.getByTestId('stub-view-activity'));

    expect(screen.getByTestId('credentials-credential-audit-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
    expect(screen.getByTestId('stub-audit-search')).toHaveTextContent('user-hash-1');
    expect(screen.getByTestId('credentials-search-input')).toHaveValue('user-hash-1');
  });

  it('offers no audit link to a user who may not read the audit', () => {
    mockHasPermission.mockImplementation((permission: string) => permission !== 'audit.view');
    renderPage();

    expect(screen.getByTestId('stub-view-activity')).toBeDisabled();
    expect(screen.getByTestId('stub-view-history')).toBeDisabled();
    expect(
      screen.queryByTestId('credentials-credential-audit-tab-trigger')
    ).not.toBeInTheDocument();
  });
});
