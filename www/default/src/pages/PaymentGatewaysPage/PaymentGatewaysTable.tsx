import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { DeleteButton } from '../../components/shared/DeleteButton';
import GatewayStatusCell from '../../components/gateways/GatewayStatusCell';
import { isGatewayPending, type GatewayListItem } from '../../utils/gateways';
import PaymentGatewayOfferCell from './PaymentGatewayOfferCell';

interface PaymentGatewaysTableProps {
  gateways: GatewayListItem[];
  canEdit: boolean;
  canDelete: boolean;
  pinging: Record<string, boolean>;
  onOpen: (id: string) => void;
  onResume: (id: string) => void;
  onPing: (gateway: GatewayListItem) => void;
  onDelete: (gateway: GatewayListItem) => Promise<void>;
}

const stop = (handler: () => void) => (event: React.MouseEvent) => {
  event.stopPropagation();
  handler();
};

const PaymentGatewaysTable: React.FC<PaymentGatewaysTableProps> = ({
  gateways,
  canEdit,
  canDelete,
  pinging,
  onOpen,
  onResume,
  onPing,
  onDelete,
}) => (
  <div className="table-responsive">
    <table className="table table-hover table-sm" data-testid="payment-gateways-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>Offers</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {gateways.map(gateway => {
          const pending = isGatewayPending(gateway);
          return (
            <tr
              key={gateway.id}
              onClick={() => onOpen(gateway.id)}
              style={{ cursor: 'pointer' }}
              data-testid={`payment-gateways-row-${gateway.id}`}
            >
              <td>
                <div className="fw-bold">{gateway.name}</div>
                {gateway.description && <small className="text-muted">{gateway.description}</small>}
              </td>
              <td>
                <GatewayStatusCell gateway={gateway} />
              </td>
              <td>
                <PaymentGatewayOfferCell gateway={gateway} />
              </td>
              <td className="align-middle">
                <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                  {canEdit && pending && (
                    <AppButton
                      variant="warning"
                      size="sm"
                      title="Verify the connection and finish setting it up"
                      aria-label={`Verify payment gateway ${gateway.name}`}
                      onClick={stop(() => onResume(gateway.id))}
                      data-testid={`payment-gateways-verify-button-${gateway.id}`}
                      iconStart={<i className="fas fa-check-double me-1" aria-hidden="true" />}
                    >
                      Verify
                    </AppButton>
                  )}
                  <AppButton
                    variant="outline-primary"
                    size="sm"
                    title="Open payment gateway"
                    aria-label={`Open payment gateway ${gateway.name}`}
                    onClick={stop(() => onOpen(gateway.id))}
                    data-testid={`payment-gateways-open-button-${gateway.id}`}
                  >
                    <i className="fas fa-arrow-right" aria-hidden="true"></i>
                  </AppButton>
                  {canEdit && !pending && (
                    <AppButton
                      variant="secondary"
                      size="sm"
                      title="Ping payment gateway - test connectivity"
                      aria-label={`Ping payment gateway ${gateway.name}`}
                      onClick={stop(() => onPing(gateway))}
                      loading={pinging[gateway.id]}
                      loadingLabel=""
                      data-testid={`payment-gateways-ping-button-${gateway.id}`}
                    >
                      <i className="fas fa-heartbeat" aria-hidden="true"></i>
                    </AppButton>
                  )}
                  {canDelete && (
                    <DeleteButton
                      onDelete={() => onDelete(gateway)}
                      className="btn-sm"
                      title="Delete payment gateway"
                      aria-label={`Delete payment gateway ${gateway.name}`}
                      data-testid={`payment-gateways-delete-button-${gateway.id}`}
                    />
                  )}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

export default PaymentGatewaysTable;
