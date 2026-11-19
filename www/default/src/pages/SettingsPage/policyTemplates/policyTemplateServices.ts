import { createContext, useContext } from 'react';
import { showUndoToast } from '../../../utils/toaster';
import { simulatePolicy } from '../simulatePolicy';
import { BUILTIN_POLICY_TEMPLATES } from './builtinPolicyTemplates';
import { createSessionPolicyTemplateStore, type PolicyTemplateStore } from './policyTemplateStore';
import type { PolicyType } from './types';

/** A dry-run decision of a policy for one input. */
export interface SimulatedDecision {
  allow: boolean;
  reason?: string;
}

/** The dashboard's store: the built-in catalogue plus this tab's organisation templates. */
export const sessionPolicyTemplateStore =
  createSessionPolicyTemplateStore(BUILTIN_POLICY_TEMPLATES);

/**
 * What the policy template feature needs from the app around it. The dashboard's services are
 * the default; another app provides its own through `PolicyTemplateServicesContext.Provider`.
 * `store` and `simulate` are effect dependencies, so pass a stable value (a module constant or
 * a `useMemo` result), not an object built on every render.
 */
export interface PolicyTemplateServices {
  store: PolicyTemplateStore;
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
  store: sessionPolicyTemplateStore,
  notifyUndo: showUndoToast,
  simulate: simulatePolicy,
});

export const usePolicyTemplateServices = (): PolicyTemplateServices =>
  useContext(PolicyTemplateServicesContext);
