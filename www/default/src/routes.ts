/** Centralized route path constants */
export const ROUTES = {
  DASHBOARD: '/',
  CLI_CONSENT: '/cli-consent',
  ACCESS_TOKEN_NEW: '/access-tokens/new',
  INTEGRATIONS: '/integrations',
  INTEGRATION_NEW: '/integrations/new',
} as const;

/** The editor of one integration. */
export const integrationPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/${encodeURIComponent(id)}`;
