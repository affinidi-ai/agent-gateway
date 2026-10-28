export const WIZARD_STEPS = ['Backend', 'Transport', 'Pair', 'Verify', 'Done'] as const;

export type WizardStep = (typeof WIZARD_STEPS)[number];
