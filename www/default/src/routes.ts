/** Centralized route path constants */
export const ROUTES = {
  DASHBOARD: '/',
  CLI_CONSENT: '/cli-consent',
  ACCESS_TOKEN_NEW: '/access-tokens/new',
  INTEGRATIONS: '/integrations',
  INTEGRATION_NEW: '/integrations/new',
  ENDPOINT_NEW: '/integrations/endpoints/new',
  EVENT_SET_NEW: '/integrations/event-sets/new',
  PAYMENT_GATEWAY_CONNECT: '/payment-gateways/connect',
  PAYMENT_GATEWAYS_TAB: '/connections?tab=payment-gateways',
  TRUST_AGENT_CONNECT: '/connections/trust-agents/connect',
  TRUST_AGENTS_TAB: '/connections?tab=trust-agents',
  KEY_MANAGEMENT_TAB: '/connections?tab=key-management',
} as const;

/** The connect wizard, resumed at the grant step of a trust agent connection that was created. */
export const trustAgentResumePath = (id: string): string =>
  `${ROUTES.TRUST_AGENT_CONNECT}?id=${encodeURIComponent(id)}`;

/** The detail page of one payment gateway. */
export const paymentGatewayPath = (id: string): string =>
  `/payment-gateways/${encodeURIComponent(id)}`;

/** The connect wizard, resumed at the approval and verify steps of a created payment gateway. */
export const paymentGatewayResumePath = (id: string): string =>
  `${ROUTES.PAYMENT_GATEWAY_CONNECT}?id=${encodeURIComponent(id)}`;

/** The editor of one integration. */
export const integrationPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/${encodeURIComponent(id)}`;

/** The editor of one integration endpoint. */
export const endpointPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/endpoints/${encodeURIComponent(id)}`;

/** The editor of one event set. */
export const eventSetPath = (id: string): string =>
  `${ROUTES.INTEGRATIONS}/event-sets/${encodeURIComponent(id)}`;
