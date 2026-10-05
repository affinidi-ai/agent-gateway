import React from 'react';
import { Alert, Form } from 'react-bootstrap';
import HeaderMetadataMappingEditor from '../_shared/HeaderMetadataMappingEditor';
import type { HeaderMetadataMappingConfig } from '../_shared/headerMetadataMapping';
import type { ConfigPanelProps } from '../types';

function isTransitPointType(type: string | undefined): boolean {
  return typeof type === 'string' && type.startsWith('transit-point-');
}

function transitPointProtocol(type: string | undefined): string | null {
  if (!type) return null;
  const match = type.match(/^transit-point-(.+)$/);
  return match ? match[1] : null;
}

const MetadataExtractionPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  protocol,
  allNodes,
  openFullscreenEditor,
  closeFullscreenEditor,
  hasAttemptedSave,
}) => {
  const parentNode = node.parentId ? allNodes?.find(n => n.id === node.parentId) : undefined;
  const parentIsTransitPoint = isTransitPointType(parentNode?.type);
  const tpProtocol = transitPointProtocol(parentNode?.type);
  const isTransitA2aLike = parentIsTransitPoint && (tpProtocol === 'a2a' || tpProtocol === 'ap2');
  const isSurfaceA2aLike = protocol === 'a2a' || protocol === 'ap2';
  const isRequest = (node.direction ?? 'request') === 'request';
  const showHeaderMapping =
    isRequest && (isTransitA2aLike || (!parentIsTransitPoint && isSurfaceA2aLike));
  const headerMetadataMapping: HeaderMetadataMappingConfig | undefined =
    config.header_metadata_mapping && typeof config.header_metadata_mapping === 'object'
      ? config.header_metadata_mapping
      : undefined;
  const headerMappingHeaderCount = Array.isArray(headerMetadataMapping?.headers)
    ? headerMetadataMapping.headers.filter(row => row?.header || row?.field).length
    : 0;
  const isFullscreenEditor = !!closeFullscreenEditor;
  const title = 'Metadata Extraction';
  const helpText = isTransitA2aLike
    ? 'Header values received from the managed agent on this Transit Point endpoint are written to A2A metadata before identity, policy, Trust Check, Workload Binding, and forwarding controls run.'
    : 'Header values received at the Access Point are written to protocol metadata before identity, policy, Trust Check, and forwarding controls run.';

  if (isFullscreenEditor) {
    return (
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-table-list me-1" /> {title}
            </h6>
            <div className="d-flex align-items-center gap-2">
              <span className="badge text-bg-info">
                {headerMappingHeaderCount} {headerMappingHeaderCount === 1 ? 'header' : 'headers'}{' '}
                configured
              </span>
              {closeFullscreenEditor && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={closeFullscreenEditor}
                  data-testid="metadata-extraction-close-tab"
                >
                  <i className="fas fa-times me-1" /> Close tab
                </button>
              )}
            </div>
          </div>
        </div>
        <div className="card-body">
          {showHeaderMapping ? (
            <HeaderMetadataMappingEditor
              idPrefix={`metadata-extraction-${node.id}`}
              testIdPrefix="metadata-extraction-header-mapping"
              mapping={headerMetadataMapping}
              helpText={helpText}
              onChange={mapping => updateField('header_metadata_mapping', mapping)}
              hasAttemptedSave={hasAttemptedSave}
            />
          ) : (
            <Alert variant="secondary" className="mb-0">
              Header Metadata Mapping is not available for this Metadata Extraction placement.
            </Alert>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="config-section" data-testid="metadata-extraction-section">
      <label>{title}</label>
      <div className="py-2" data-testid="metadata-extraction-summary">
        <div className="fw-semibold small mb-1">
          <i
            className="fas fa-table-list me-2 text-muted"
            style={{ opacity: 0.6 }}
            aria-hidden="true"
          />
          {headerMappingHeaderCount === 0
            ? 'No headers configured'
            : `${headerMappingHeaderCount} header${headerMappingHeaderCount === 1 ? '' : 's'} configured`}
        </div>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '11px' }}>
          {isTransitA2aLike
            ? 'Managed-agent request headers can be normalized into A2A metadata before identity and policy controls run.'
            : 'Request headers can be normalized into protocol metadata before identity and policy controls run.'}
        </Form.Text>
      </div>
      <button
        type="button"
        className="btn btn-primary btn-sm w-100"
        onClick={() => openFullscreenEditor?.()}
        disabled={!openFullscreenEditor || !showHeaderMapping}
        data-testid="metadata-extraction-configure"
      >
        <i className="fas fa-pen-to-square me-1" /> Configure Header Mapping…
      </button>
      {!showHeaderMapping && (
        <Alert variant="secondary" className="py-2 mt-2 mb-0" style={{ fontSize: '11px' }}>
          Header Metadata Mapping is not available for this Metadata Extraction placement.
        </Alert>
      )}
    </div>
  );
};

export default MetadataExtractionPanel;
