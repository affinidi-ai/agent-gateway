import React from 'react';

interface RemoteSurface {
  config_id: string;
  name: string;
  description?: string;
  listen_address: string;
  protocol: string;
}

interface RemoteTabProps {
  remoteSurfaces: RemoteSurface[];
  loadingSurfaces: boolean;
  surfacesError: string;
  fetchRemoteSurfaces: (forceRefresh: boolean) => void;
}

const RemoteTab: React.FC<RemoteTabProps> = ({
  remoteSurfaces = [],
  loadingSurfaces,
  surfacesError,
  fetchRemoteSurfaces,
}) => {
  return (
    <>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-network-wired"></i> Available Surfaces from Remote Gateway{' '}
              <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
                {remoteSurfaces.length}
              </span>
            </h6>
            <button
              className="btn btn-sm btn-outline-primary"
              onClick={() => fetchRemoteSurfaces(true)}
              disabled={loadingSurfaces}
            >
              <i className={`fas ${loadingSurfaces ? 'fa-spinner fa-spin' : 'fa-sync-alt'}`}></i>
              {loadingSurfaces ? ' Refreshing...' : ' Refresh'}
            </button>
          </div>
        </div>
        <div className="card-body">
          {surfacesError && (
            <div className="alert alert-warning" role="alert">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {surfacesError}
            </div>
          )}

          {loadingSurfaces && !remoteSurfaces.length ? (
            <div className="text-center py-4">
              <div className="spinner-border" role="status">
                <span className="visually-hidden"></span>
              </div>
              <p className="text-muted mt-2">Querying remote gateway for available surfaces...</p>
            </div>
          ) : remoteSurfaces.length === 0 ? (
            <div className="alert alert-info mb-0">
              <i className="fas fa-info-circle me-2"></i>
              No surfaces available from this gateway. Click "Refresh Surfaces" to query the remote
              gateway.
            </div>
          ) : (
            <>
              <p className="text-muted mb-3">
                <i className="fas fa-info-circle me-2"></i> This Gateway exposes{' '}
                <strong>{remoteSurfaces.length}</strong> surface
                {remoteSurfaces.length !== 1 ? 's' : ''}
                that can be used for routing requests.
              </p>
              <div className="table-responsive">
                <table className="table table-sm table-hover">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>Protocol</th>
                      <th>Listen Address</th>
                      <th>Surface ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {remoteSurfaces.map(surface => (
                      <tr key={surface.config_id}>
                        <td>
                          <strong>{surface.name}</strong>
                        </td>
                        <td>
                          <small className="text-muted">{surface.description || '-'}</small>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              surface.protocol === 'a2a'
                                ? 'text-bg-primary'
                                : surface.protocol === 'ap2'
                                  ? 'text-bg-info'
                                  : surface.protocol === 'mcp'
                                    ? 'text-bg-success'
                                    : 'text-bg-secondary'
                            }`}
                          >
                            {surface.protocol.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <code style={{ fontSize: '0.85rem' }}>{surface.listen_address}</code>
                        </td>
                        <td>
                          <code className="text-muted" style={{ fontSize: '0.75rem' }}>
                            {surface.config_id}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="mt-3 pt-3 border-top">
                <small className="text-muted">
                  <i className="fas fa-clock me-2"></i> Surface information is cached - click
                  "Refresh Surfaces" to get the latest list of surfaces.
                </small>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default RemoteTab;
