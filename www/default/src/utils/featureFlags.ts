import { useApp } from '../context/AppContext';
import type { Settings } from '../types';

/** Whether the agent-pay UI is shown: `feature_flags.agent_pay_delegation`, off unless `true`. */
export const agentPayEnabled = (settings: Settings | null | undefined): boolean =>
  settings?.feature_flags?.agent_pay_delegation === true;

/**
 * `agent_pay_delegation` from the loaded settings, and whether they have loaded
 * yet: before they have, the flag reads off.
 */
export function useAgentPayFlag(): { enabled: boolean; loaded: boolean } {
  const { state } = useApp();
  return { enabled: agentPayEnabled(state.settings), loaded: state.settings !== null };
}

/** Permissions any one of which opens Connections: a payment-gateways-only caller only while agent-pay is on. */
export const connectionsPermissions = (agentPayOn: boolean): readonly string[] =>
  agentPayOn ? ['gateways.view', 'payment_gateways.view'] : ['gateways.view'];
