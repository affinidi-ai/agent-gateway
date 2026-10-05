import React, { useCallback, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import GatewaysPage from './GatewaysPage';
import MediatorsPage from './MediatorsPage';
import TrustRegistriesPage from './TrustRegistriesPage';

type TabKey = 'gateways' | 'mediators' | 'trust-registries';

interface TabCount {
  filtered: number;
  total: number;
}

const VALID_TABS: TabKey[] = ['gateways', 'mediators', 'trust-registries'];

const ConnectionsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'gateways';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');
  // Pinned to DOM via ref callback so the embedded pages can portal
  // their action buttons into the tab banner.
  const [actionsContainer, setActionsContainer] = useState<HTMLDivElement | null>(null);
  const [counts, setCounts] = useState<Record<TabKey, TabCount>>({
    gateways: { filtered: 0, total: 0 },
    mediators: { filtered: 0, total: 0 },
    'trust-registries': { filtered: 0, total: 0 },
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
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
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
            const next = (k as TabKey) || 'gateways';
            setActiveTab(next);
            setSearchParams({ tab: next }, { replace: true });
          }}
          className="mb-3 custom-channel-tabs"
        >
          <Tab
            eventKey="gateways"
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

          <Tab
            eventKey="mediators"
            title={
              <>
                <i className="fas fa-exchange-alt"></i> Mediators {tabBadge('mediators')}
              </>
            }
          >
            <MediatorsPage externalSearchTerm={searchTerm} onCountChange={setMediatorsCount} />
          </Tab>

          <Tab
            eventKey="trust-registries"
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
        </Tabs>
      </div>
    </div>
  );
};

export default ConnectionsPage;
