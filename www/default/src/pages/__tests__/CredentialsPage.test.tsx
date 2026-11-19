import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import CredentialsPage from '../CredentialsPage';

const mockHasPermission = jest.fn();
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission, loading: false }),
}));
const mockVault = { tokens: [], providers: {}, loading: false, vaultError: null };
const mockVaultsGiven: Record<string, unknown> = {};
jest.mock('../CredentialsPage/useDelegationVault', () => ({
  useDelegationVault: () => mockVault,
}));
jest.mock('../SettingsPage/StrategiesTab', () => () => null);
jest.mock('../SettingsPage/CredentialProvidersTab', () => () => null);
jest.mock('../CredentialsPage/StsClientsTab', () => () => null);
jest.mock(
  '../CredentialsPage/CredentialTokensTab',
  () => (props: { vault: unknown; onViewActivity?: (userHash: string) => void }) => {
    mockVaultsGiven.credentialTokens = props.vault;
    return (
      <button
        type="button"
        data-testid="stub-view-activity"
        disabled={!props.onViewActivity}
        onClick={() => props.onViewActivity?.('sha256:user-1')}
      />
    );
  }
);
jest.mock(
  '../CredentialsPage/DelegatedAccessTab',
  () => (props: { vault: unknown; onViewHistory?: () => void }) => {
    mockVaultsGiven.delegatedAccess = props.vault;
    return (
      <button
        type="button"
        data-testid="stub-view-history"
        disabled={!props.onViewHistory}
        onClick={() => props.onViewHistory?.()}
      />
    );
  }
);

const DELEGATION =
  'consent_granted%2Cconsent_expired%2Cconsent_limited%2Ctoken_revoked%2Cuser_tokens_revoked';

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

  it('keeps the Credential Tokens tab, has Delegated Access beside it and no audit tab', () => {
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
    ]);
    expect(screen.getByTestId('credentials-credential-tokens-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
    expect(
      screen.queryByTestId('credentials-credential-audit-tab-trigger')
    ).not.toBeInTheDocument();
  });

  it('hands both delegation tabs the one vault it loaded', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage();

    expect(mockVaultsGiven.credentialTokens).toBe(mockVault);
    expect(mockVaultsGiven.delegatedAccess).toBe(mockVault);
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

  it('opens its first tab, not the Audit Log, for a stored address of the removed audit tab', () => {
    mockHasPermission.mockReturnValue(true);
    renderPage('/credentials?tab=credential-audit');

    expect(screen.queryByTestId('audit-log')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-jwt-verification-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
  });

  it('offers no way into the audit to a user who may not read it', () => {
    mockHasPermission.mockImplementation((permission: string) => permission !== 'audit.view');
    renderPage();

    expect(screen.queryByTestId('audit-log')).not.toBeInTheDocument();
    expect(screen.getByTestId('stub-view-activity')).toBeDisabled();
    expect(screen.getByTestId('stub-view-history')).toBeDisabled();
  });
});
