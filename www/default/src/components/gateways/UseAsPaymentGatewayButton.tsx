import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { useAgentPayFlag } from '../../utils/featureFlags';
import { getErrorMessage } from '../../utils/apiError';
import type { GatewayRecord } from '../../utils/gateways';
import { showToast } from '../../utils/toaster';
import { AppButton } from '../shared/AppButton';

/** Only an active remote peer can become a payment gateway. */
export const canBecomePaymentGateway = (gateway: GatewayRecord): boolean =>
  gateway.gateway_type === 'remote' && gateway.status === 'active' && gateway.role !== 'payment';

export const paymentRoleConfirmText = (name: string): string =>
  `Use "${name}" as a payment gateway?\n\n` +
  'It moves to Connections → Payment Gateways, where surfaces can charge through it. ' +
  "It stops reaching this gateway's surfaces over Fabric and can no longer be a Managed Agent or Transit Point route.";

interface UseAsPaymentGatewayButtonProps {
  gateway: GatewayRecord;
  onError: (message: string) => void;
  testId: string;
  /** Renders only the icon, with the label as the title. */
  iconOnly?: boolean;
  className?: string;
}

/**
 * Turns an active remote peer into a payment gateway, after a confirm, and
 * opens the Payment Gateways tab. Needs `agent_pay_delegation` on and both
 * `gateways.edit` and `payment_gateways.edit`.
 */
const UseAsPaymentGatewayButton: React.FC<UseAsPaymentGatewayButtonProps> = ({
  gateway,
  onError,
  testId,
  iconOnly = false,
  className,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const { enabled: agentPayOn } = useAgentPayFlag();
  const [busy, setBusy] = useState(false);

  if (
    !agentPayOn ||
    !canBecomePaymentGateway(gateway) ||
    !hasPermission('gateways.edit') ||
    !hasPermission('payment_gateways.edit')
  ) {
    return null;
  }

  const handleClick = async (event: React.MouseEvent) => {
    event.stopPropagation();
    if (!window.confirm(paymentRoleConfirmText(gateway.name || gateway.id))) return;
    setBusy(true);
    try {
      await apiClient.setGatewayPaymentRole(gateway.id);
      showToast('success', `${gateway.name || gateway.id} is now a payment gateway`);
      navigate('/connections?tab=payment-gateways');
    } catch (err) {
      onError(getErrorMessage(err, 'Failed to make this gateway a payment gateway'));
      setBusy(false);
    }
  };

  return (
    <AppButton
      variant="outline-secondary"
      size="sm"
      className={className}
      onClick={handleClick}
      loading={busy}
      title="Use as payment gateway"
      aria-label={`Use ${gateway.name || gateway.id} as a payment gateway`}
      data-testid={testId}
      iconStart={
        <i className={`fas fa-credit-card${iconOnly ? '' : ' me-1'}`} aria-hidden="true" />
      }
    >
      {iconOnly ? null : 'Use as payment gateway'}
    </AppButton>
  );
};

export default UseAsPaymentGatewayButton;
