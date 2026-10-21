import { Integration } from '../../integrationsApi';

/** Error toasts stay until dismissed, so the reason can be read. */
export const STICKY_ERROR = { autoRemove: false };

/** Whether any of `texts` contains the lower-cased filter `term`. */
export const matches = (term: string, ...texts: (string | undefined)[]): boolean =>
  texts.some(text => text?.toLowerCase().includes(term));

/** The names of the integrations `uses` picks, for "used by" columns and delete guards. */
export const namesOfIntegrations = (
  integrations: Integration[],
  uses: (integration: Integration) => boolean
): string[] => integrations.filter(uses).map(integration => integration.name);

/** "Not used", "1 integration" or "N integrations". */
export const usedByLabel = (count: number): string =>
  count === 0 ? 'Not used' : `${count} integration${count === 1 ? '' : 's'}`;
