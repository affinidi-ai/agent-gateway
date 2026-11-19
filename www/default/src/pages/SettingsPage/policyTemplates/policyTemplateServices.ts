import { createContext, useContext } from 'react';
import { showUndoToast } from '../../../utils/toaster';
import { simulatePolicy } from '../simulatePolicy';
import type { PolicyType } from './types';

/** A dry-run decision of a policy for one input. */
export interface SimulatedDecision {
  allow: boolean;
  reason?: string;
}

/**
 * What the policy template feature needs from the app around it. The dashboard's services are
 * the default; another app provides its own through `PolicyTemplateServicesContext.Provider`.
 * `simulate` is an effect dependency, so pass a stable value (a module constant or a `useMemo`
 * result), not an object built on every render.
 */
export interface PolicyTemplateServices {
  /** Shows `message` with an Undo action that calls `onUndo`. */
  notifyUndo: (options: { message: string; onUndo: () => void }) => void;
  /** Runs `policy` against `input` in place of the saved policy `policyId`'s Rego. */
  simulate: (
    policyId: string,
    policyType: PolicyType,
    policy: string,
    input: unknown
  ) => Promise<SimulatedDecision>;
}

export const PolicyTemplateServicesContext = createContext<PolicyTemplateServices>({
  notifyUndo: showUndoToast,
  simulate: simulatePolicy,
});

export const usePolicyTemplateServices = (): PolicyTemplateServices =>
  useContext(PolicyTemplateServicesContext);
