export const WIZARD_STEPS = ['Transport', 'Pair', 'Verify', 'Done'] as const;

export type WizardStep = (typeof WIZARD_STEPS)[number];
