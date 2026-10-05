// Permanent catalog redirect links (docs.affinidi.com/catalog/) survive page moves/restructuring.
const catalogUrl = (kb: string) => `https://docs.affinidi.com/catalog?t=docs&kb=${kb}&lang=en_US`;

export const DOCS_URL = {
  home: catalogUrl('1066'),
  createFirstSurface: catalogUrl('1094'),
  identity: catalogUrl('1098'),
  credentials: catalogUrl('1072'),
  credentialDelegation: catalogUrl('1112'),
  connections: catalogUrl('1070'),
  integrations: catalogUrl('1121'),
  payments: catalogUrl('1077'),
  surfaces: catalogUrl('1085'),
  policies: catalogUrl('1076'),
  mcpProxy: catalogUrl('1130'),
  secrets: catalogUrl('1083'),
  jwtStrategies: catalogUrl('1118'),
  // Direct doc-site links (no catalog redirect exists yet for these pages).
  proxies:
    'https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/reference/proxies/',
  // Surface Builder canvas element reference pages (docs.affinidi.com/catalog/ "Reference > Surfaces").
  accessPointElement: catalogUrl('1131'),
  callerContextElement: catalogUrl('1144'),
  identityElement: catalogUrl('1145'),
  managedAgentElement: catalogUrl('1146'),
  mcpToolsElement: catalogUrl('1147'),
  metadataElements: catalogUrl('1148'),
  networkingElements: catalogUrl('1149'),
  outboundBindingElements: catalogUrl('1150'),
  paymentElement: catalogUrl('1151'),
  protocolExtensionElements: catalogUrl('1152'),
  opaPoliciesReference: catalogUrl('1132'),
  surfaceReference: catalogUrl('1133'),
  transitPoints: catalogUrl('1135'),
  trustElements: catalogUrl('1136'),
  variantsElement: catalogUrl('1137'),
  auditLog: catalogUrl('1142'),
} as const;
