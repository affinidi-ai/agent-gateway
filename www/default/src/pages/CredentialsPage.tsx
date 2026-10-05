import React, { useEffect, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import StrategiesTab from './SettingsPage/StrategiesTab';
import CredentialProvidersTab from './SettingsPage/CredentialProvidersTab';
import CredentialTokensTab from './CredentialsPage/CredentialTokensTab';
import CredentialAuditTab from './CredentialsPage/CredentialAuditTab';
import StsClientsTab from './CredentialsPage/StsClientsTab';
import { usePermissions } from '../context/PermissionsContext';

type TabKey =
  | 'jwt-verification'
  | 'credential-providers'
  | 'credential-tokens'
  | 'credential-audit'
  | 'sts-clients';
const VALID_TABS: TabKey[] = [
  'jwt-verification',
  'credential-providers',
  'credential-tokens',
  'credential-audit',
  'sts-clients',
];

const CredentialsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'jwt-verification';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canViewAudit = !permissionsLoading && hasPermission('audit.view');
  const canViewSts = !permissionsLoading && hasPermission('sts_clients.view');

  const [strategiesCount, setStrategiesCount] = useState(0);
  const [providersCount, setProvidersCount] = useState(0);
  const [tokensCount, setTokensCount] = useState(0);
  const [auditCount, setAuditCount] = useState(0);
  const [stsClientsCount, setStsClientsCount] = useState(0);

  useEffect(() => {
    if (!permissionsLoading && !canViewAudit && activeTab === 'credential-audit') {
      setActiveTab('jwt-verification');
      setSearchParams({ tab: 'jwt-verification' }, { replace: true });
    } else if (!permissionsLoading && !canViewSts && activeTab === 'sts-clients') {
      setActiveTab('jwt-verification');
      setSearchParams({ tab: 'jwt-verification' }, { replace: true });
    }
  }, [activeTab, canViewAudit, canViewSts, permissionsLoading, setSearchParams]);

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
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter JWT Verification, Providers, Tokens, Audit..."
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
        <Tab
          eventKey="jwt-verification"
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

        <Tab
          eventKey="credential-providers"
          title={
            <>
              <i className="fas fa-id-card"></i> Credential Providers {tabBadge(providersCount)}
            </>
          }
        >
          <CredentialProvidersTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setProvidersCount}
          />
        </Tab>

        <Tab
          eventKey="credential-tokens"
          title={
            <>
              <i className="fas fa-lock"></i> Credential Tokens {tabBadge(tokensCount)}
            </>
          }
        >
          <CredentialTokensTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setTokensCount}
          />
        </Tab>

        {canViewSts && (
          <Tab
            eventKey="sts-clients"
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

        {canViewAudit && (
          <Tab
            eventKey="credential-audit"
            title={
              <>
                <i className="fas fa-clipboard-list"></i> Credential Delegation Audit{' '}
                {tabBadge(auditCount)}
              </>
            }
          >
            <CredentialAuditTab
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setAuditCount}
            />
          </Tab>
        )}
      </Tabs>
    </div>
  );
};

export default CredentialsPage;
