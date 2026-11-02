import React, { useEffect, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import StrategiesTab from './SettingsPage/StrategiesTab';
import CredentialProvidersTab from './SettingsPage/CredentialProvidersTab';
import CredentialTokensTab from './CredentialsPage/CredentialTokensTab';
import DelegatedAccessTab from './CredentialsPage/DelegatedAccessTab';
import StsClientsTab from './CredentialsPage/StsClientsTab';
import { useDelegationVault } from './CredentialsPage/useDelegationVault';
import { usePermissions } from '../context/PermissionsContext';
import {
  DELEGATION_CATEGORIES,
  DELEGATION_ENDED_CATEGORIES,
  auditLogPath,
} from './AuditPage/auditHelpers';

type TabKey =
  | 'jwt-verification'
  | 'credential-providers'
  | 'credential-tokens'
  | 'delegated-access'
  | 'sts-clients';
const VALID_TABS: TabKey[] = [
  'jwt-verification',
  'credential-providers',
  'credential-tokens',
  'delegated-access',
  'sts-clients',
];
const SETTINGS_TABS: TabKey[] = ['jwt-verification', 'credential-tokens', 'delegated-access'];

const CredentialsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canViewProviders = !permissionsLoading && hasPermission('credential_providers.view');
  const canViewSettingsTabs = !permissionsLoading && hasPermission('settings.view');
  const defaultTab: TabKey = canViewSettingsTabs ? 'jwt-verification' : 'credential-providers';
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : defaultTab;
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');
  const canViewAudit = !permissionsLoading && hasPermission('audit.view');
  const canViewSts = !permissionsLoading && hasPermission('sts_clients.view');
  const vault = useDelegationVault();

  const [strategiesCount, setStrategiesCount] = useState(0);
  const [providersCount, setProvidersCount] = useState(0);
  const [tokensCount, setTokensCount] = useState(0);
  const [delegationsCount, setDelegationsCount] = useState(0);
  const [stsClientsCount, setStsClientsCount] = useState(0);

  useEffect(() => {
    if (permissionsLoading) return;
    const hidden =
      (activeTab === 'sts-clients' && !canViewSts) ||
      (activeTab === 'credential-providers' && !canViewProviders) ||
      (SETTINGS_TABS.includes(activeTab) && !canViewSettingsTabs);
    if (hidden) {
      const fallback: TabKey = canViewSettingsTabs ? 'jwt-verification' : 'credential-providers';
      setActiveTab(fallback);
      setSearchParams({ tab: fallback }, { replace: true });
    }
  }, [
    activeTab,
    canViewSts,
    canViewProviders,
    canViewSettingsTabs,
    permissionsLoading,
    setSearchParams,
  ]);

  const viewHistory = () => navigate(auditLogPath(DELEGATION_ENDED_CATEGORIES));
  const viewActivity = (userHash: string) =>
    navigate(auditLogPath(DELEGATION_CATEGORIES, userHash));

  const filterActive = searchTerm.trim().length > 0;
  const tabBadge = (count: number) => {
    if (!filterActive) return null;
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    );
  };

  return (
    <div className="container-fluid" data-testid="page-credentials">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            data-testid="credentials-search-input"
            placeholder="Filter JWT Verification, Providers, Tokens, Access..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'jwt-verification';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-3 custom-channel-tabs"
      >
        {canViewSettingsTabs && (
          <Tab
            eventKey="jwt-verification"
            tabAttrs={{ 'data-testid': 'credentials-jwt-verification-tab-trigger' }}
            title={
              <>
                <i className="fas fa-id-badge"></i> JWT Verification {tabBadge(strategiesCount)}
              </>
            }
          >
            <StrategiesTab
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setStrategiesCount}
            />
          </Tab>
        )}

        {canViewProviders && (
          <Tab
            eventKey="credential-providers"
            tabAttrs={{ 'data-testid': 'credentials-credential-providers-tab-trigger' }}
            title={
              <>
                <i className="fas fa-id-card"></i> Credential Providers {tabBadge(providersCount)}
              </>
            }
          >
            <CredentialProvidersTab
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setProvidersCount}
              onProvidersChange={vault.refresh}
            />
          </Tab>
        )}

        {canViewSettingsTabs && (
          <Tab
            eventKey="credential-tokens"
            tabAttrs={{ 'data-testid': 'credentials-credential-tokens-tab-trigger' }}
            title={
              <>
                <i className="fas fa-lock"></i> Credential Tokens {tabBadge(tokensCount)}
              </>
            }
          >
            <CredentialTokensTab
              vault={vault}
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setTokensCount}
              onViewActivity={canViewAudit ? viewActivity : undefined}
            />
          </Tab>
        )}

        {canViewSettingsTabs && (
          <Tab
            eventKey="delegated-access"
            tabAttrs={{ 'data-testid': 'credentials-delegated-access-tab-trigger' }}
            title={
              <>
                <i className="fas fa-user-check"></i> Delegated Access {tabBadge(delegationsCount)}
              </>
            }
          >
            <DelegatedAccessTab
              vault={vault}
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setDelegationsCount}
              onViewHistory={canViewAudit ? viewHistory : undefined}
            />
          </Tab>
        )}

        {canViewSts && (
          <Tab
            eventKey="sts-clients"
            tabAttrs={{ 'data-testid': 'credentials-sts-clients-tab-trigger' }}
            title={
              <>
                <i className="fas fa-right-left"></i> STS Clients {tabBadge(stsClientsCount)}
              </>
            }
          >
            <StsClientsTab
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setStsClientsCount}
            />
          </Tab>
        )}
      </Tabs>
    </div>
  );
};

export default CredentialsPage;
