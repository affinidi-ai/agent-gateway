/** Centralized route path constants */
export const ROUTES = {
  DASHBOARD: '/',
  CLI_CONSENT: '/cli-consent',
  ACCESS_TOKEN_NEW: '/access-tokens/new',
  INTEGRATIONS: '/integrations',
  INTEGRATION_NEW: '/integrations/new',
  ENDPOINT_NEW: '/integrations/endpoints/new',
  EVENT_SET_NEW: '/integrations/event-sets/new',
} as const;

/** The editor of one integration. */
export const integrationPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/${encodeURIComponent(id)}`;

/** The editor of one integration endpoint. */
export const endpointPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/endpoints/${encodeURIComponent(id)}`;

/** The editor of one event set. */
export const eventSetPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/event-sets/${encodeURIComponent(id)}`;
