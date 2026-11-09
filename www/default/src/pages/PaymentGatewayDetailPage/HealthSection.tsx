import React, { useState } from 'react';
import {
  pingPaymentGateway,
  type PingResult,
} from '../../components/payment-gateways/pingPaymentGateway';
import { AppButton } from '../../components/shared/AppButton';
import { ConnectionHealthBadge, PeerLastSeen } from '../../utils/connectionHealth';
import type { GatewayListItem } from '../../utils/gateways';

/** The connection's health, when agent-pay was last heard from, and a ping. */
const HealthSection: React.FC<{ gateway: GatewayListItem; canPing: boolean }> = ({
  gateway,
  canPing,
}) => {
  const [pinging, setPinging] = useState(false);
  const [result, setResult] = useState<PingResult | null>(null);

  const ping = async () => {
    setPinging(true);
    setResult(await pingPaymentGateway(gateway.id, gateway.name));
    setPinging(false);
  };

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-heartbeat" aria-hidden="true"></i> Health
        </h6>
      </div>
      <div className="card-body">
        <dl className="row mb-3">
          <dt className="col-sm-3">Connection</dt>
          <dd className="col-sm-9">
            {gateway.runtime_status ? (
              <ConnectionHealthBadge runtime={gateway.runtime_status} />
            ) : (
              <span className="text-muted">No runtime status yet</span>
            )}
          </dd>
          <dt className="col-sm-3">Last contact</dt>
          <dd className="col-sm-9">
            <PeerLastSeen gatewayId={gateway.id} peerLastSeenAt={gateway.peer_last_seen_at} />
          </dd>
        </dl>
        {canPing && (
          <AppButton
            variant="secondary"
            size="sm"
            onClick={ping}
            loading={pinging}
            loadingLabel="Pinging"
            iconStart={<i className="fas fa-heartbeat me-1" aria-hidden="true" />}
            data-testid="payment-gateway-ping-button"
          >
            Ping
          </AppButton>
        )}
        {result && (
          <div
            className={`alert ${result.ok ? 'alert-success' : 'alert-danger'} mt-3 mb-0`}
            role="status"
            data-testid="payment-gateway-ping-result"
          >
            {result.message}
          </div>
        )}
      </div>
    </div>
  );
};

export default HealthSection;
