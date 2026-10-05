import React from 'react';
import type { ConfigPanelProps } from '../types';
import PaymentX402Fullscreen from './PaymentX402Fullscreen';
import PaymentMppFullscreen from './PaymentMppFullscreen';

/**
 * Dispatches the Payment element's fullscreen editor to the x402 or MPP
 * implementation based on the node's `payment_kind`, since a single node
 * type carries either protocol.
 */
const PaymentFullscreen: React.FC<ConfigPanelProps> = props => {
  const kind: 'x402' | 'mpp' = props.config?.payment_kind === 'mpp' ? 'mpp' : 'x402';
  return kind === 'mpp' ? (
    <PaymentMppFullscreen {...props} />
  ) : (
    <PaymentX402Fullscreen {...props} />
  );
};

export default PaymentFullscreen;
