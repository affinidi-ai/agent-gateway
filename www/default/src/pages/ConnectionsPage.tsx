import React, { useCallback, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import { usePermissions } from '../context/PermissionsContext';
import { useAgentPayFlag } from '../utils/featureFlags';
import GatewaysPage from './GatewaysPage';
import MediatorsPage from './MediatorsPage';
import PaymentGatewaysPage from './PaymentGatewaysPage';
import TrustAgentsPage from './TrustAgentsPage';
import TrustRegistriesPage from './TrustRegistriesPage';
import { KeyManagementPanel } from './VtaConnectionsPage/KeyManagementPanel';

type TabKey =
  | 'gateways'
  | 'payment-gateways'
  | 'mediators'
  | 'trust-registries'
  | 'trust-agents'
  | 'key-management';

interface TabCount {
  filtered: number;
  total: number;
}

const ALL_TABS: TabKey[] = [
  'gateways',
  'payment-gateways',
  'mediators',
  'trust-registries',
  'trust-agents',
  'key-management',
];

const ConnectionsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { hasPermission } = usePermissions();
  const showGateways = hasPermission('gateways.view');
  const { enabled: agentPayOn } = useAgentPayFlag();
  const showPaymentGateways = agentPayOn && hasPermission('payment_gateways.view');
  const showMediators = hasPermission('mediators.view');
  const showRegistries = hasPermission('trust_registries.view');
  const showTrustAgents = hasPermission('vta_connections.view');
  const validTabs = ALL_TABS.filter(
    tab =>
      (tab !== 'gateways' || showGateways) &&
      (tab !== 'payment-gateways' || showPaymentGateways) &&
      (tab !== 'mediators' || showMediators) &&
      (tab !== 'trust-registries' || showRegistries) &&
      ((tab !== 'trust-agents' && tab !== 'key-management') || showTrustAgents)
  );
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  // The tab follows the URL, so a link to another tab of this page switches it.
  const activeTab: TabKey =
    tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : (validTabs[0] ?? 'gateways');
  const [searchTerm, setSearchTerm] = useState('');
  // Pinned to DOM via ref callback so the embedded pages can portal
  // their action buttons into the tab banner.
  const [actionsContainer, setActionsContainer] = useState<HTMLDivElement | null>(null);
  const [counts, setCounts] = useState<Record<TabKey, TabCount>>({
    gateways: { filtered: 0, total: 0 },
    'payment-gateways': { filtered: 0, total: 0 },
    mediators: { filtered: 0, total: 0 },
    'trust-registries': { filtered: 0, total: 0 },
    'trust-agents': { filtered: 0, total: 0 },
    'key-management': { filtered: 0, total: 0 },
  });

  // Stable per-tab count setters so the embedded pages' useEffect deps
  // don't churn on every parent render.
  const setGatewaysCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev.gateways.filtered === filtered && prev.gateways.total === total
        ? prev
        : { ...prev, gateways: { filtered, total } }
    );
  }, []);
  const setPaymentGatewaysCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev['payment-gateways'].filtered === filtered && prev['payment-gateways'].total === total
        ? prev
        : { ...prev, 'payment-gateways': { filtered, total } }
    );
  }, []);
  const setMediatorsCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev.mediators.filtered === filtered && prev.mediators.total === total
        ? prev
        : { ...prev, mediators: { filtered, total } }
    );
  }, []);
  const setTrustRegistriesCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev['trust-registries'].filtered === filtered && prev['trust-registries'].total === total
        ? prev
        : { ...prev, 'trust-registries': { filtered, total } }
    );
  }, []);

  const setTrustAgentsCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev['trust-agents'].filtered === filtered && prev['trust-agents'].total === total
        ? prev
        : { ...prev, 'trust-agents': { filtered, total } }
    );
  }, []);

  const filterActive = searchTerm.trim().length > 0;

  const tabBadge = (key: TabKey) => {
    if (!filterActive) return null;
    const c = counts[key];
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {c.filtered}
      </span>
    );
  };

  return (
    <div className="container-fluid" data-testid="page-connections">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            data-testid="connections-search-input"
            placeholder="Filter Connections..."
          />
        </div>
      </div>

      <div style={{ position: 'relative' }}>
        <div
          ref={setActionsContainer}
          className="connections-tab-actions"
          style={{
            position: 'absolute',
            right: 0,
            top: 0,
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            zIndex: 1,
          }}
        />
        <Tabs
          activeKey={activeTab}
          onSelect={k => {
            setSearchParams({ tab: (k as TabKey) || validTabs[0] }, { replace: true });
          }}
          className="mb-3 custom-channel-tabs"
        >
          {showGateways && (
            <Tab
              eventKey="gateways"
              tabAttrs={{ 'data-testid': 'connections-gateways-tab-trigger' }}
              title={
                <>
                  <i className="fas fa-server"></i> Gateways {tabBadge('gateways')}
                </>
              }
            >
              <GatewaysPage
                externalSearchTerm={searchTerm}
                onCountChange={setGatewaysCount}
                actionsContainer={activeTab === 'gateways' ? actionsContainer : null}
              />
            </Tab>
          )}

          {showPaymentGateways && (
            <Tab
              eventKey="payment-gateways"
              tabAttrs={{ 'data-testid': 'connections-tab-payment-gateways' }}
              title={
                <>
                  <i className="fas fa-credit-card"></i> Payment Gateways{' '}
                  {tabBadge('payment-gateways')}
                </>
              }
            >
              <PaymentGatewaysPage
                externalSearchTerm={searchTerm}
                onCountChange={setPaymentGatewaysCount}
                actionsContainer={activeTab === 'payment-gateways' ? actionsContainer : null}
              />
            </Tab>
          )}

          {showMediators && (
            <Tab
              eventKey="mediators"
              tabAttrs={{ 'data-testid': 'connections-mediators-tab-trigger' }}
              title={
                <>
                  <i className="fas fa-exchange-alt"></i> Mediators {tabBadge('mediators')}
                </>
              }
            >
              <MediatorsPage externalSearchTerm={searchTerm} onCountChange={setMediatorsCount} />
            </Tab>
          )}

          {showRegistries && (
            <Tab
              eventKey="trust-registries"
              tabAttrs={{ 'data-testid': 'connections-trust-registries-tab-trigger' }}
              title={
                <>
                  <i className="fas fa-shield-alt"></i> Registries {tabBadge('trust-registries')}
                </>
              }
            >
              <TrustRegistriesPage
                externalSearchTerm={searchTerm}
                onCountChange={setTrustRegistriesCount}
              />
            </Tab>
          )}

          {showTrustAgents && (
            <Tab
              eventKey="trust-agents"
              tabAttrs={{ 'data-testid': 'connections-tab-trust-agents' }}
              title={
                <>
                  <i className="fas fa-robot"></i> Trust Agents {tabBadge('trust-agents')}
                </>
              }
            >
              <TrustAgentsPage
                externalSearchTerm={searchTerm}
                onCountChange={setTrustAgentsCount}
                actionsContainer={activeTab === 'trust-agents' ? actionsContainer : null}
              />
            </Tab>
          )}

          {showTrustAgents && (
            <Tab
              eventKey="key-management"
              tabAttrs={{ 'data-testid': 'connections-tab-key-management' }}
              title={
                <>
                  <i className="fas fa-key"></i> Key Management
                </>
              }
            >
              {activeTab === 'key-management' && <KeyManagementPanel />}
            </Tab>
          )}
        </Tabs>
      </div>
    </div>
  );
};

export default ConnectionsPage;
