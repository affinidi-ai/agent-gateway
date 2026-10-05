import React from 'react';
import { Alert } from 'react-bootstrap';
import { EmptyState } from '../../components/shared/EmptyState';
import { Link } from '../../components/shared/Link';
import { TermsDefinitions, TermsVersion } from '../../termsApi';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';

interface AffinidiTermsSectionProps {
  affinidi: TermsDefinitions['affinidi'];
  affinidiProvider?: TermsDefinitions['affinidi_provider'];
}

export const AffinidiTermsSection: React.FC<AffinidiTermsSectionProps> = ({
  affinidi,
  affinidiProvider,
}) => (
  <div className="card shadow mb-4">
    <div className="card-header py-3">
      <h6 className="m-0 font-weight-bold text-primary">Affinidi Terms</h6>
    </div>
    <div className="card-body">
      {affinidiProvider?.state === 'degraded' && (
        <Alert variant="warning">
          The latest metadata could not be refreshed. Using cached metadata.
        </Alert>
      )}
      {affinidiProvider?.state === 'unavailable' && (
        <Alert variant="danger">Affinidi Terms metadata is unavailable.</Alert>
      )}
      {affinidiProvider?.last_successful_refresh && (
        <p
          className="small text-muted"
          title={formatDateTime(affinidiProvider.last_successful_refresh, true)}
        >
          Last successful refresh: {timeAgo(affinidiProvider.last_successful_refresh)}
        </p>
      )}
      {affinidi ? (
        <p className="mb-0">
          <strong>{affinidi.title}</strong> · version {affinidi.version} ·{' '}
          <Link href={affinidi.url} external variant="inline" testId="terms-affinidi-link">
            View Terms
          </Link>
        </p>
      ) : (
        <p className="text-muted mb-0">No Affinidi Terms metadata is available.</p>
      )}
    </div>
  </div>
);

export const TermsHistorySection: React.FC<{ versions: TermsVersion[] }> = ({ versions }) => (
  <div className="card shadow mb-4">
    <div className="card-header py-3">
      <h6 className="m-0 font-weight-bold text-primary">Published history</h6>
    </div>
    <div className="card-body">
      {versions.length ? (
        <div className="table-responsive">
          <table className="table table-sm table-hover">
            <thead>
              <tr>
                <th>Title</th>
                <th>Version</th>
                <th>Re-consent</th>
                <th>Document</th>
              </tr>
            </thead>
            <tbody>
              {[...versions].reverse().map(version => (
                <tr key={version.version_id} data-testid={`terms-row-${version.version_id}`}>
                  <td>{version.title}</td>
                  <td>{version.version}</td>
                  <td>{version.requires_reconsent ? 'Required' : 'Not required'}</td>
                  <td>
                    <Link
                      href={version.url}
                      external
                      variant="inline"
                      testId={`terms-history-${version.version_id}-link`}
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div data-testid="terms-empty-state">
          <EmptyState
            icon="fa-file-contract"
            title="No Customer T&C published"
            body="Save and publish a draft to require Customer T&C acceptance."
          />
        </div>
      )}
    </div>
  </div>
);
