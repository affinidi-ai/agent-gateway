import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import PolicyListTab from './PoliciesPage/PolicyListTab';
import type { PolicyType } from '../types';

const PoliciesPage: React.FC = () => {
  const validTabs: PolicyType[] = ['gateway', 'agent_surface'];

  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as PolicyType | null;
  const initialTab: PolicyType =
    tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : 'gateway';
  const [activeTab, setActiveTab] = useState<PolicyType>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');

  return (
    <div className="container-fluid" data-testid="page-policies">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            data-testid="policies-search-input"
            placeholder="Filter Gateway and Agent Surface policies..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as PolicyType) || 'gateway';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-3 custom-channel-tabs"
      >
        <Tab
          eventKey="gateway"
          tabAttrs={{ 'data-testid': 'policies-gateway-tab-trigger' }}
          title={
            <>
              <i className="fas fa-shield-alt"></i> Gateway
            </>
          }
        >
          <PolicyListTab
            policyType="gateway"
            label="Gateway"
            icon="fa-shield-alt"
            externalSearchTerm={searchTerm}
          />
        </Tab>

        <Tab
          eventKey="agent_surface"
          tabAttrs={{ 'data-testid': 'policies-agent-surface-tab-trigger' }}
          title={
            <>
              <i className="fas fa-exchange-alt"></i> Agent Surfaces
            </>
          }
        >
          <PolicyListTab
            policyType="agent_surface"
            label="Agent Surface"
            icon="fa-exchange-alt"
            externalSearchTerm={searchTerm}
          />
        </Tab>
      </Tabs>
    </div>
  );
};

export default PoliciesPage;
