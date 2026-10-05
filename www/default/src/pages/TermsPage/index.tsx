import { CustomerTermsSection } from './CustomerTermsSection';
import React from 'react';
import { Alert, Spinner } from 'react-bootstrap';
import { usePermissions } from '../../context/PermissionsContext';
import { AffinidiTermsSection, TermsHistorySection } from './sections';
import { useTermsManager } from './useTermsManager';

const TermsPage: React.FC = () => {
  const { hasPermission } = usePermissions();
  const manager = useTermsManager();

  if (!manager.definitions && !manager.error) {
    return (
      <div className="text-center py-5" data-testid="page-terms-manager">
        <Spinner animation="border" variant="primary" />
      </div>
    );
  }

  return (
    <div data-testid="page-terms-manager">
      {manager.error && <Alert variant="danger">{manager.error}</Alert>}
      {manager.notice && <Alert variant="success">{manager.notice}</Alert>}

      <AffinidiTermsSection
        affinidi={manager.definitions?.affinidi}
        affinidiProvider={manager.definitions?.affinidi_provider}
      />
      <CustomerTermsSection
        current={manager.current}
        draft={manager.draft}
        setDraft={manager.setDraft}
        versionAlreadyPublished={manager.versionAlreadyPublished}
        canEdit={hasPermission('terms.edit')}
        saving={manager.saving}
        onPublish={manager.publish}
        onDeactivate={manager.deactivate}
      />
      <TermsHistorySection versions={manager.definitions?.customer.versions ?? []} />
    </div>
  );
};

export default TermsPage;
