import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../../components/shared/SearchInput';
import IntegrationsTab from './IntegrationsTab';
import { useIntegrationDefinitions } from './useIntegrationDefinitions';

type TabKey = 'integrations';
const VALID_TABS: TabKey[] = ['integrations'];

/** Integrations, and the endpoints and event sets they join. */
const IntegrationsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const [activeTab, setActiveTab] = useState<TabKey>(
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'integrations'
  );
  const [searchTerm, setSearchTerm] = useState('');
  const { integrations, endpoints, eventSets, loading, error, reload } =
    useIntegrationDefinitions();
  const definitions = { integrations, endpoints, eventSets };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter integrations, endpoints and event sets..."
          width="384px"
        />
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}

      {loading ? (
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: '60vh' }}
        >
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading integrations</span>
          </div>
        </div>
      ) : (
        <Tabs
          activeKey={activeTab}
          onSelect={key => {
            const next = (key as TabKey) || 'integrations';
            setActiveTab(next);
            setSearchParams({ tab: next }, { replace: true });
          }}
          className="mb-3 custom-channel-tabs"
        >
          <Tab
            eventKey="integrations"
            title={
              <>
                <i className="fas fa-bell" aria-hidden="true"></i> Integrations
              </>
            }
          >
            <IntegrationsTab {...definitions} searchTerm={searchTerm} onChanged={reload} />
          </Tab>
        </Tabs>
      )}
    </div>
  );
};

export default IntegrationsPage;
