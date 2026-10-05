import React from 'react';

interface StageProps {
  title: string;
  subtitle: string;
  value: string;
  borderClass: string;
  inputClass?: string;
  iconClass: string;
  titleColor: string;
  buttonColor: string;
  onGenerateSchema: () => void;
}

const Stage: React.FC<StageProps> = ({
  title,
  subtitle,
  value,
  borderClass,
  inputClass = '',
  iconClass,
  titleColor,
  buttonColor,
  onGenerateSchema,
}) => (
  <div>
    <div className="d-flex justify-content-between align-items-center mb-2">
      <h6 className={`mb-0 ${titleColor}`}>
        <i className={`fas ${iconClass}`}></i> {title}
      </h6>
      <button
        className={`btn btn-sm btn-outline-${buttonColor}`}
        onClick={onGenerateSchema}
        disabled={!value}
        title="Generate JSON schema from this payload"
      >
        <i className="fas fa-file-code"></i> Generate Schema
      </button>
    </div>
    <small className="text-muted d-block mb-2">{subtitle}</small>
    <div className={`schema-property-card ${borderClass}`}>
      <textarea
        className={`form-control schema-raw-json ${inputClass}`}
        style={{
          minHeight: '300px',
          resize: 'vertical',
          fontFamily: 'monospace',
          fontSize: '12px',
        }}
        value={value}
        readOnly
        placeholder=""
      />
    </div>
  </div>
);

const Arrow: React.FC<{ caption?: string }> = ({ caption }) => (
  <div className="text-center">
    <i className="fas fa-arrow-down fa-2x text-muted"></i>
    {caption && <small className="d-block text-muted">{caption}</small>}
  </div>
);

const EndpointCard: React.FC<{
  isFabric: boolean;
  targetEndpoint: string;
  targetDisplay: string;
}> = ({ isFabric, targetEndpoint, targetDisplay }) => {
  if (isFabric) {
    return (
      <div>
        <h6 className="mb-2 text-purple">
          <i className="fas fa-network-wired"></i> Fabric Gateway
        </h6>
        <small className="text-muted d-block mb-2">
          Request forwarded through gateway fabric protocol
        </small>
        <div className="schema-property-card border-purple bg-light">
          <div className="p-3 text-center">
            <i className="fas fa-project-diagram fa-2x mb-2 text-purple"></i>
            <div>
              <strong>Target:</strong> <code title={targetEndpoint}>{targetDisplay}</code>
            </div>
            {targetDisplay !== targetEndpoint && (
              <small className="text-muted d-block mt-1">
                <code>{targetEndpoint}</code>
              </small>
            )}
            <small className="text-muted">DIDComm ForwardRequest protocol</small>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div>
      <h6 className="mb-2 text-dark">
        <i className="fas fa-globe"></i> Direct URL
      </h6>
      <small className="text-muted d-block mb-2">Request sent directly to HTTP endpoint</small>
      <div className="schema-property-card border-dark bg-light">
        <div className="p-3 text-center">
          <i className="fas fa-link fa-2x mb-2 text-dark"></i>
          <div>
            <strong>Endpoint:</strong> <code>{targetEndpoint}</code>
          </div>
          <small className="text-muted">Direct HTTP/HTTPS connection</small>
        </div>
      </div>
    </div>
  );
};

const AgentCard: React.FC<{ position: 'top' | 'bottom' }> = ({ position }) => (
  <div>
    <h6 className="mb-2 text-secondary">
      <i className="fas fa-user"></i> Source Agent
    </h6>
    <small className="text-muted d-block mb-2">
      {position === 'top'
        ? 'The agent/client initiating the request'
        : 'The agent/client receives the response'}
    </small>
    <div className="schema-property-card border-secondary bg-light">
      <div className="p-3 text-center text-muted">
        <i className="fas fa-robot fa-2x mb-2"></i>
        <div>
          <strong>External Agent</strong>
        </div>
        <small>
          {position === 'top' ? 'Sends request to gateway' : 'Receives response from gateway'}
        </small>
      </div>
    </div>
  </div>
);

export interface CapturePipelineViewProps {
  inboundRequest: string;
  outboundRequest: string;
  inboundResponse: string;
  outboundResponse: string;
  validationStatus: string;
  validationError?: string;
  isFabric: boolean;
  targetEndpoint: string;
  targetDisplay: string;
  onGenerateSchema: (payload: any, title: string) => void;
}

const CapturePipelineView: React.FC<CapturePipelineViewProps> = ({
  inboundRequest,
  outboundRequest,
  inboundResponse,
  outboundResponse,
  validationStatus,
  validationError,
  isFabric,
  targetEndpoint,
  targetDisplay,
  onGenerateSchema,
}) => {
  if (!inboundRequest) {
    return (
      <div className="text-center text-muted py-5">
        <i className="fas fa-hourglass-half fa-3x mb-3"></i>
        <p>Waiting for agent requests...</p>
        <small>Make a request to this surface to see the payload here in real-time.</small>
      </div>
    );
  }

  const inboundBorder =
    validationStatus === 'success'
      ? 'border-success'
      : validationStatus === 'Failed Validation'
        ? 'border-danger'
        : 'border-info';
  const inboundInput =
    validationStatus === 'success'
      ? 'is-valid'
      : validationStatus === 'Failed Validation'
        ? 'is-invalid'
        : '';

  const safeParse = (s: string) => {
    try {
      return JSON.parse(s);
    } catch {
      return s;
    }
  };

  return (
    <div>
      {validationError && (
        <div className="alert alert-danger mb-3">
          <h6>
            <i className="fas fa-exclamation-circle"></i> Validation Error
          </h6>
          <small className="font-monospace">{validationError}</small>
        </div>
      )}
      <div className="d-flex flex-column gap-3">
        <AgentCard position="top" />
        <Arrow />
        <Stage
          title="1. Inbound Request (from source agent)"
          subtitle="Original payload received from the calling agent"
          value={inboundRequest}
          borderClass={inboundBorder}
          inputClass={inboundInput}
          iconClass="fa-arrow-down"
          titleColor="text-primary"
          buttonColor="primary"
          onGenerateSchema={() =>
            onGenerateSchema(safeParse(inboundRequest), 'Inbound Request Schema')
          }
        />
        {outboundRequest && <Arrow caption="Gateway processes & transforms" />}
        {outboundRequest && (
          <Stage
            title="2. Outbound (to target)"
            subtitle="Transformed payload sent to target (includes VP, custom metadata, etc.)"
            value={outboundRequest}
            borderClass="border-info"
            iconClass="fa-arrow-up"
            titleColor="text-info"
            buttonColor="info"
            onGenerateSchema={() =>
              onGenerateSchema(safeParse(outboundRequest), 'Outbound Request Schema')
            }
          />
        )}
        <Arrow caption="Sent to target" />
        <EndpointCard
          isFabric={isFabric}
          targetEndpoint={targetEndpoint}
          targetDisplay={targetDisplay}
        />
        {inboundResponse && <Arrow caption="Target responds" />}
        {inboundResponse && (
          <Stage
            title="3. Inbound Response (from target)"
            subtitle="Raw response received from the target endpoint"
            value={inboundResponse}
            borderClass="border-warning"
            iconClass="fa-arrow-down"
            titleColor="text-warning"
            buttonColor="warning"
            onGenerateSchema={() =>
              onGenerateSchema(safeParse(inboundResponse), 'Inbound Response Schema')
            }
          />
        )}
        {outboundResponse && <Arrow caption="Gateway processes response" />}
        {outboundResponse && (
          <Stage
            title="4. Outbound Result (to source agent)"
            subtitle="Final response returned to the calling agent"
            value={outboundResponse}
            borderClass="border-success"
            iconClass="fa-arrow-up"
            titleColor="text-success"
            buttonColor="success"
            onGenerateSchema={() =>
              onGenerateSchema(safeParse(outboundResponse), 'Outbound Response Schema')
            }
          />
        )}
        {outboundResponse && <Arrow />}
        {outboundResponse && <AgentCard position="bottom" />}
      </div>
    </div>
  );
};

export default CapturePipelineView;
