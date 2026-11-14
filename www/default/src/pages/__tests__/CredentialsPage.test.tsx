import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
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
      onClick={() => props.onViewActivity?.('sha256:user-1')}
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

const DELEGATION =
  'token_injected%2Ctoken_refreshed%2Crefresh_failed%2Ctoken_not_found%2Cconsent_granted' +
  '%2Cconsent_required%2Cconsent_expired%2Ctoken_revoked%2Cuser_tokens_revoked';

const AuditLog: React.FC = () => {
  const location = useLocation();
  return <div data-testid="audit-log">{location.pathname + location.search}</div>;
};

const renderPage = (address = '/credentials?tab=credential-tokens') =>
  render(
    <MemoryRouter initialEntries={[address]}>
      <Routes>
        <Route path="/credentials" element={<CredentialsPage />} />
        <Route path="/audit" element={<AuditLog />} />
      </Routes>
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

  it('opens the Audit Log on the records of ended access as the history', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage('/credentials?tab=delegated-access');

    fireEvent.click(screen.getByTestId('stub-view-history'));

    expect(screen.getByTestId('audit-log')).toHaveTextContent(
      '/audit?category=consent_expired%2Ctoken_revoked%2Cuser_tokens_revoked'
    );
  });

  it("opens the Audit Log on a user's delegation records from the Credential Tokens tab", () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();

    fireEvent.click(screen.getByTestId('stub-view-activity'));

    expect(screen.getByTestId('audit-log')).toHaveTextContent(
      `/audit?filter=sha256%3Auser-1&category=${DELEGATION}`
    );
  });

  it('opens the Audit Log on every delegation record from the Credential Delegation Audit tab', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();

    fireEvent.click(screen.getByTestId('credentials-credential-audit-tab-trigger'));

    expect(screen.getByTestId('audit-log')).toHaveTextContent(`/audit?category=${DELEGATION}`);
  });

  it('leads a stored address of the audit tab to the Audit Log', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage('/credentials?tab=credential-audit');

    expect(screen.getByTestId('audit-log')).toHaveTextContent(`/audit?category=${DELEGATION}`);
  });

  it('offers no way into the audit to a user who may not read it', () => {
    mockHasPermission.mockImplementation((permission: string) => permission !== 'audit.view');
    renderPage('/credentials?tab=credential-audit');

    expect(screen.queryByTestId('audit-log')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-jwt-verification-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
    expect(screen.getByTestId('stub-view-activity')).toBeDisabled();
    expect(screen.getByTestId('stub-view-history')).toBeDisabled();
    expect(
      screen.queryByTestId('credentials-credential-audit-tab-trigger')
    ).not.toBeInTheDocument();
  });
});
