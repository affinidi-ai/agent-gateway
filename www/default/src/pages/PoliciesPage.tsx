import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import PolicyListTab from './PoliciesPage/PolicyListTab';
import PaywallPoliciesTab from './PoliciesPage/PaywallPoliciesTab';

type TabKey = 'gateway' | 'agent_surface' | 'paywall';

const PoliciesPage: React.FC = () => {
  const validTabs: TabKey[] = ['gateway', 'agent_surface', 'paywall'];

  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey = tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : 'gateway';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');

  const [gatewayCount, setGatewayCount] = useState(0);
  const [agentSurfaceCount, setAgentSurfaceCount] = useState(0);
  const [paywallCount, setPaywallCount] = useState(0);

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
            placeholder="Filter Gateway, Agent Surfaces, Paywall policies..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'gateway';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-3 custom-channel-tabs"
      >
        <Tab
          eventKey="gateway"
          title={
            <>
              <i className="fas fa-shield-alt"></i> Gateway {tabBadge(gatewayCount)}
            </>
          }
        >
          <PolicyListTab
            policyType="gateway"
            label="Gateway"
            icon="fa-shield-alt"
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setGatewayCount}
          />
        </Tab>

        <Tab
          eventKey="agent_surface"
          title={
            <>
              <i className="fas fa-exchange-alt"></i> Agent Surfaces
              {tabBadge(agentSurfaceCount)}
            </>
          }
        >
          <PolicyListTab
            policyType="agent_surface"
            label="Agent Surface"
            icon="fa-exchange-alt"
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setAgentSurfaceCount}
          />
        </Tab>

        <Tab
          eventKey="paywall"
          title={
            <>
              <i className="fas fa-credit-card"></i> Paywall {tabBadge(paywallCount)}
            </>
          }
        >
          <PaywallPoliciesTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setPaywallCount}
          />
        </Tab>
      </Tabs>
    </div>
  );
};

export default PoliciesPage;
