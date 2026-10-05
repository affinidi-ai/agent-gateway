import React, { useEffect, useState } from 'react';
import { useApp } from '../../../../context/AppContext';
import { generateSchemaFromPayload } from '../../../../utils/schemaUtils';
import { formatTime } from '../../../../utils/stringUtils';
import { useFabricResolver } from '../../../../utils/useFabricResolver';
import type { AgentSurface } from '../../../../api';
import CaptureDetailsModal from './CaptureDetailsModal';
import CaptureHistoryTable from './CaptureHistoryTable';
import CapturePipelineView from './CapturePipelineView';
import CaptureSchemaModal from './CaptureSchemaModal';
import { CapturedPayload } from './types';
import { useSurfaceCaptureStream } from './useSurfaceCaptureStream';

export interface SurfaceCapturePanelProps {
  surfaceId: string;
  surface: AgentSurface | null;
  onClose: () => void;
}

const buildRouteDisplay = (surface: AgentSurface | null): string => {
  if (!surface) return '';
  const addr = surface.access_point?.listen_address || '';
  const route = surface.access_point?.route || '';
  return `${addr}${route}`;
};

const SurfaceCapturePanel: React.FC<SurfaceCapturePanelProps> = ({
  surfaceId,
  surface,
  onClose,
}) => {
  const { state, actions } = useApp();
  const stream = useSurfaceCaptureStream(surfaceId);

  const [selectedCapture, setSelectedCapture] = useState<CapturedPayload | null>(null);
  const [schemaModal, setSchemaModal] = useState<{
    title: string;
    schema: string;
    source: any;
  } | null>(null);

  useEffect(() => {
    // Keep the WebSocket alive while the capture panel is open so events are
    // not missed when the user switches to another browser tab.
    actions.setWsKeepAlive(true);
    return () => {
      actions.setWsKeepAlive(false);
      document.body.classList.remove('modal-open');
    };
  }, []);

  const targetEndpoint = surface?.target?.endpoint || '';
  const isFabric = targetEndpoint.startsWith('fabric://');
  const fullRoute = buildRouteDisplay(surface);
  const { formatFabric } = useFabricResolver([targetEndpoint]);
  const fabricFormatted = isFabric ? formatFabric(targetEndpoint) : null;
  const targetDisplay = fabricFormatted?.display || targetEndpoint;
  const protocol = surface?.access_point?.protocol;
  const identityFieldName =
    protocol === 'mcp'
      ? surface?.target?.agent_identity?.meta_field || 'agentIdentity'
      : 'agentIdentity';

  const openCapture = (capture: CapturedPayload) => {
    setSelectedCapture(capture);
    document.body.classList.add('modal-open');
  };
  const closeCapture = () => {
    setSelectedCapture(null);
    document.body.classList.remove('modal-open');
  };
  const openSchema = (payload: any, title: string) => {
    setSchemaModal({ title, schema: generateSchemaFromPayload(payload), source: payload });
    document.body.classList.add('modal-open');
  };
  const closeSchema = () => {
    setSchemaModal(null);
    document.body.classList.remove('modal-open');
  };

  const copyRoute = async (e: React.MouseEvent<HTMLButtonElement>) => {
    navigator.clipboard.writeText(fullRoute);
    const btn = e.currentTarget;
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => {
      btn.innerHTML = original;
    }, 2000);
  };

  const copyAllStages = async () => {
    if (!stream.latestInboundRequest) return;
    try {
      const text = [
        '=== Inbound Request (from source agent) ===',
        stream.latestInboundRequest,
        stream.latestOutboundRequest ? '\n=== Outbound (to target) ===' : '',
        stream.latestOutboundRequest,
        stream.latestInboundResponse ? '\n=== Inbound Response (from target) ===' : '',
        stream.latestInboundResponse,
        stream.latestOutboundResponse ? '\n=== Outbound Result (to source agent) ===' : '',
        stream.latestOutboundResponse,
      ]
        .filter(Boolean)
        .join('\n');
      await navigator.clipboard.writeText(text);
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
    }
  };

  const openLatest = () => {
    if (stream.captured.length > 0) openCapture(stream.captured[0]);
  };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <button className="btn btn-sm btn-secondary" onClick={onClose}>
          <i className="fas fa-arrow-left"></i> Back to Monitoring
        </button>
        <div className="d-flex gap-2">
          <button
            className={`btn btn-sm ${stream.isPaused ? 'btn-success' : 'btn-warning'}`}
            onClick={() => stream.setPaused(!stream.isPaused)}
            title={stream.isPaused ? 'Resume live capture' : 'Pause live capture'}
          >
            <i className={`fas ${stream.isPaused ? 'fa-play' : 'fa-pause'}`}></i>{' '}
            {stream.isPaused ? 'Resume' : 'Pause'}
          </button>
          <button
            className="btn btn-sm btn-warning"
            onClick={stream.clear}
            disabled={stream.count === 0}
          >
            <i className="fas fa-trash"></i> Clear Payloads
          </button>
          <button
            className="btn btn-sm btn-outline-secondary"
            onClick={copyAllStages}
            disabled={!stream.latestInboundRequest}
            title="Copy all stages to clipboard"
          >
            <i className="fas fa-copy"></i> Copy All Stages
          </button>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-eye"></i> Surface Payload Capture
          </h6>
        </div>
        <div className="card-body">
          {fullRoute && (
            <div className="alert alert-success mb-3" style={{ fontSize: '14px' }}>
              <i className="fas fa-info-circle me-2"></i>
              <strong>Surface Route:</strong> {fullRoute}
              <button
                type="button"
                className="btn btn-xs ms-2"
                style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
                onClick={copyRoute}
                title="Copy to clipboard"
              >
                <i className="fas fa-copy"></i>
              </button>
            </div>
          )}
          {targetEndpoint && (
            <div className="alert alert-info mb-3" style={{ fontSize: '14px' }}>
              <i className="fas fa-route me-2"></i>
              <strong>Target: </strong> {targetDisplay}
              {isFabric && fabricFormatted && fabricFormatted.display !== targetEndpoint && (
                <small className="text-muted ms-2" title={targetEndpoint}>
                  <code>{targetEndpoint}</code>
                </small>
              )}
            </div>
          )}
          <div className="row">
            <div className="col-md-4">
              <strong>Status:</strong>
              <span
                className={`badge ms-2 ${stream.isPaused ? 'text-bg-warning' : 'text-bg-success'}`}
              >
                {stream.isPaused ? (
                  <>
                    <i className="fas fa-pause-circle"></i> Paused
                  </>
                ) : (
                  <>
                    <i className="fas fa-circle pulse-icon"></i> Live Capturing
                  </>
                )}
              </span>
            </div>
            <div className="col-md-4">
              <strong>Payloads Captured:</strong>
              <span className="badge text-bg-info ms-2">{stream.count}</span>
            </div>
            <div className="col-md-4">
              <strong>WebSocket:</strong>
              <span
                className={`badge ms-2 ${state.wsStatus === 'CONNECTED' ? 'text-bg-success' : 'text-bg-warning'}`}
              >
                {state.wsStatus}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <div className="d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center">
              <h6 className="m-0 font-weight-bold text-success me-3">
                <i className="fas fa-file-code"></i>{' '}
                {stream.displayedCapture
                  ? `${stream.displayedCapture.channel} - ${formatTime(stream.displayedCapture.timestamp)}`
                  : 'Most Recent Agent Payload'}
                {stream.isPaused && stream.displayedCapture && (
                  <span className="badge text-bg-warning ms-2">Historical</span>
                )}
              </h6>
              {stream.latestInboundRequest && (
                <span
                  className={`badge rounded-pill cursor-pointer ${
                    stream.latestValidationStatus === 'success'
                      ? 'text-bg-success'
                      : stream.latestValidationStatus === 'Failed Validation'
                        ? 'text-bg-danger'
                        : 'text-bg-info'
                  }`}
                  onClick={openLatest}
                  title="Click to view details"
                  style={{ cursor: 'pointer' }}
                >
                  {stream.latestValidationStatus === 'success' ? (
                    <>
                      <i className="fas fa-check-circle"></i> Validation OK
                    </>
                  ) : stream.latestValidationStatus === 'Failed Validation' ? (
                    <>
                      <i className="fas fa-exclamation-triangle"></i> Failed Validation
                    </>
                  ) : (
                    <>
                      <i className="fas fa-info-circle"></i> {stream.latestValidationStatus}
                    </>
                  )}
                </span>
              )}
            </div>
            {stream.captured.length > 0 && (
              <small className="text-muted">
                Last updated: {formatTime(stream.captured[0].timestamp)}
              </small>
            )}
          </div>
        </div>
        <div className="card-body">
          <CapturePipelineView
            inboundRequest={stream.latestInboundRequest}
            outboundRequest={stream.latestOutboundRequest}
            inboundResponse={stream.latestInboundResponse}
            outboundResponse={stream.latestOutboundResponse}
            validationStatus={stream.latestValidationStatus}
            validationError={stream.latestValidationError}
            isFabric={isFabric}
            targetEndpoint={targetEndpoint}
            targetDisplay={targetDisplay}
            onGenerateSchema={openSchema}
          />
        </div>
      </div>

      <CaptureHistoryTable captured={stream.captured} onSelectRow={stream.loadCapture} />

      {selectedCapture && <CaptureDetailsModal capture={selectedCapture} onClose={closeCapture} />}
      {schemaModal && (
        <CaptureSchemaModal
          title={schemaModal.title}
          schema={schemaModal.schema}
          sourcePayload={schemaModal.source}
          identityFieldName={identityFieldName}
          protocol={protocol}
          onClose={closeSchema}
        />
      )}
    </div>
  );
};

export default SurfaceCapturePanel;
