/**
 * Canonical deep-links for "Add <thing you're missing>" shortcuts. All URLs are absolute paths
 * inside the dashboard app so `<AddResourceLink>` can open them in a new tab
 * without losing the caller's in-progress form / wizard state.
 *
 * Add entries here. Keep the map
 * flat and typed so downstream tests can assert exact URLs.
 */

import { CertificateKind } from '../types';

export const deepLinks = {
  agentSurface: '/surfaces/new',
  remoteGateway: '/gateways/connect',
  secret: '/secrets/new',
  apiKey: '/secrets?tab=api-keys',
  certificate: (kind?: CertificateKind): string =>
    kind ? `/secrets?tab=certificates&kind=${kind}` : '/secrets?tab=certificates',
  trustRegistry: '/trust-registries/wizard',
  issuer: '/issuers/new',
  authority: '/authorities/new',
  mediator: '/mediators/wizard',
  jwtVerificationStrategy: '/jwt-verification-strategies/new',
  policyDefinition: (type?: 'gateway' | 'surface' | 'response' | 'mcp_tool'): string =>
    type ? `/policy-definitions/new?type=${type}` : '/policy-definitions/new',
  mcpProxy: '/mcp-proxies/wizard',
  credentialProvider: '/credential-providers/new',
  policies: '/policies',
  integration: '/integrations/integrations/wizard',
  oidcProvider: '/oidc-providers/new',
  a2aProxy: '/proxies/a2a-proxies/new',
} as const;
