/**
 * Long-identifier list fixtures for the laptop layout spec.
 *
 * A fresh test-mode gateway has empty lists, and an empty list renders its
 * empty state instead of the table, so the row actions never appear. These
 * `page.route` handlers answer the list requests of those pages with rows
 * whose DIDs, URLs and names run past 80 characters. Every other request
 * reaches the real gateway; nothing is written through the API.
 *
 * Bodies use the dashboard's own types where they are exported from a module
 * that compiles on its own; the rest mirror the page-local interfaces the
 * pages parse the response into.
 */

import type {Page, Route} from '@playwright/test';
import type {
    AccessTokenMeta,
    Authority,
    CertificateKind,
    DidWebVhIdentity,
    Issuer,
    TrustRegistry,
} from '../../www/default/src/types';
import type {AuditEntry, AuditResponse} from '../../www/default/src/pages/AuditPage/types';
import type {A2aProxy} from '../../www/default/src/pages/A2aProxyPage/types';

/** Fixed ids so the inventory can name row test ids. */
export const FIXTURE_ID = {
    surface: 'layout-surface-1',
    mcpProxy: 'layout-mcp-proxy-1',
    a2aProxy: 'layout-a2a-proxy-1',
    jwtStrategy: 'layout-jwt-strategy-1',
    credentialProvider: 'layout-credential-provider-1',
    delegationToken: 'layout-delegation-token-1',
    stsClient: 'layout-sts-client-1',
    gatewayPolicy: 'layout-gateway-policy-1',
    surfacePolicy: 'layout-surface-policy-1',
    secret: 'layout-secret-1',
    apiKey: 'layout-api-key-1',
    certificate: 'layout-certificate-1',
    accessToken: 'layout-access-token-1',
    issuer: 'layout-issuer-1',
    authority: 'layout-authority-1',
    payment: '0x7d3f9b2c41e8a6d05f1c9e3b7a2d4f6081c3e5a7b9d1f3e5c7a9b1d3f5e7c9a1b3d5f7e9c1a3b5d7f9e1c3a5b7d9f1e3',
    mediator: 'layout-mediator-1',
    connectionPoint: 'layout-connection-point-1',
    trustRegistry: 'layout-trust-registry-1',
    integration: 'layout-integration-1',
    metricsChannel: 'layout-surface-1',
} as const;

const DOMAIN = 'agents.layout-fixture.enterprise-operations.example.com';
export const LONG_DID = `did:web:${DOMAIN}:tenants:procurement:agents:purchase-order-reconciliation-assistant-0001`;
const LONG_DID_2 = `did:web:${DOMAIN}:tenants:finance:agents:quarterly-ledger-close-and-variance-review-0002`;
const LONG_URL = `https://${DOMAIN}/api/v1/procurement/purchase-orders/reconciliation/agent-endpoint`;
const LONG_NAME = 'Enterprise Procurement Purchase Order Reconciliation Assistant (EMEA Production Tenant)';
const LONG_DESCRIPTION =
    'Reconciles purchase orders against supplier invoices and goods receipts across every EMEA business unit and flags variances.';
const LONG_TAG = 'cost-centre:emea-procurement-operations-shared-services-reconciliation-and-audit-team';

const NOW = Date.UTC(2026, 9, 20, 9, 30, 0);
const iso = (minutesAgo: number) => new Date(NOW - minutesAgo * 60_000).toISOString();
const unix = (minutesAgo: number) => Math.floor((NOW - minutesAgo * 60_000) / 1000);

/** Mirrors the dashboard's `AgentSurface` (`www/default/src/api.ts`), list fields only. */
interface SurfaceFixture {
    surface_id: string;
    name: string;
    description: string;
    status: 'active' | 'disabled';
    tags: string[];
    access_point: {listen_address: string; route: string; protocol: 'a2a' | 'ap2' | 'mcp'};
    target: {endpoint: string};
    transit?: {points: unknown[]};
}

/** Mirrors `McpProxy` in `www/default/src/pages/ProxiesPage.tsx`. */
interface McpProxyFixture {
    id: string;
    name: string;
    description: string;
    channel_prefix: string;
    base_url: string;
    status: string;
    direct_access?: boolean;
    managed_by?: string | null;
    created_at: string;
}

/** Mirrors `JwtVerificationStrategy` in `www/default/src/pages/SettingsPage/StrategiesTab.tsx`. */
interface JwtStrategyFixture {
    id: string;
    name: string;
    expected_issuer: string;
    jwks_source: {type: 'remote' | 'static'; jwks_uri?: string};
    created_at: string;
    updated_at: string;
}

/** Mirrors `CredentialProviderListItem` in `www/default/src/pages/SettingsPage/CredentialProvidersTab.tsx`. */
interface CredentialProviderFixture {
    id: string;
    name: string;
    provider_id: string;
    provider_type: 'oauth2_authorization_code' | 'oauth2_client_credentials' | 'api_key';
    token_endpoint?: string;
    default_scopes: string[];
    token_refresh_enabled: boolean;
    description?: string;
    created_at: string;
    updated_at: string;
}

/** Mirrors `DelegationToken` in `www/default/src/pages/CredentialsPage/CredentialTokensTab.tsx`. */
interface DelegationTokenFixture {
    id: string;
    agent_did: string;
    user_identity_hash: string;
    credential_provider_id: string;
    provider_id: string;
    token_type: string;
    scopes: string[];
    expires_at: string | null;
    consent_granted_at: string;
    last_used_at: string | null;
    created_at: string;
    updated_at: string;
    is_expired: boolean;
    can_refresh: boolean;
}

/** Mirrors `StsClient` in `www/default/src/pages/CredentialsPage/StsClientsTab.tsx`. */
interface StsClientFixture {
    id: string;
    client_id: string;
    name: string;
    client_secret_ref?: string | null;
    allowed_audiences: string[];
    allowed_scopes: string[];
    allowed_subject_token_types: string[];
    allow_impersonation: boolean;
    max_ttl_secs?: number | null;
    issue_id_jag: boolean;
    created_at: string;
    updated_at: string;
}

/** Mirrors `AuditEvent` / `AuditLogPage` in `www/default/src/pages/CredentialsPage/CredentialAuditTab.tsx`. */
interface DelegationAuditEventFixture {
    timestamp: string;
    event: string;
    agent_did?: string;
    user_identity_hash?: string;
    provider_id?: string;
    provider_name?: string;
    channel_id?: string;
    channel_name?: string;
    target_endpoint?: string;
    protocol?: string;
    scopes?: string[];
    via_fabric: boolean;
    caller?: {auth_method: string; iss?: string; sub?: string; email?: string};
}

interface DelegationAuditPageFixture {
    events: DelegationAuditEventFixture[];
    total: number;
    page: number;
    page_size: number;
    total_pages: number;
}

/** Mirrors `PolicyDefinition` in `www/default/src/pages/PoliciesPage/PolicyListTab.tsx`. */
interface PolicyDefinitionFixture {
    id: string;
    name: string;
    description: string;
    policy_type: 'gateway' | 'agent_surface';
    policy: string;
    enabled: boolean;
    created_at: string;
    updated_at?: string;
    content_hash?: string;
}

/** Mirrors `Secret` in `www/default/src/pages/SecretsPage.tsx`. */
interface SecretFixture {
    id: string;
    name: string;
    secret_id: string;
    description?: string;
    secret_type?: string;
    tags: string[];
    created_at: string;
    updated_at: string;
}

/** Mirrors the dashboard's `ApiKeyMeta` (`www/default/src/api.ts`). */
interface ApiKeyFixture {
    key_id: string;
    agent_id: string;
    client_id: string;
    prefix: string;
    status: 'active' | 'revoked';
    labels: Record<string, string>;
    created_at: string;
    created_by: string;
    use_count: number;
}

/** Mirrors `Certificate` in `www/default/src/pages/SecretsPage.tsx`. */
interface CertificateFixture {
    id: string;
    name: string;
    certificate_id: string;
    description?: string;
    tags: string[];
    created_at: string;
    updated_at: string;
    expires_at?: string;
    active: boolean;
    kind?: CertificateKind;
}

/** One raw x402 payment record as `PaymentsPage` groups them. */
interface PaymentRecordFixture {
    id: string;
    type: 'verification' | 'settlement';
    status: string;
    tx_hash: string;
    channel_id: string;
    channel_name: string;
    resource_path?: string;
    network: string;
    network_name: string;
    amount: string;
    decimals: number;
    asset: string;
    recipient: string;
    recipient_name: string;
    tx_explorer_url: string;
    correlation_id: string;
    created_at: number;
    completed_at?: number;
    verification_mode?: string;
    settlement_method?: string;
    sync_status?: string;
}

/** Mirrors `Mediator` in `www/default/src/pages/MediatorsPage.tsx`. */
interface MediatorFixture {
    id: string;
    name: string;
    description: string;
    did: string;
    status: 'active' | 'disabled';
    created_at: string;
    updated_at: string;
}

/** Mirrors `ConnectionPoint` in `www/default/src/pages/GatewaysPage.tsx`. */
interface ConnectionPointFixture {
    id: string;
    gateway_id: string;
    mediator_id: string;
    name: string;
    description: string;
    oob_url: string;
    use_count: number;
    created_at: string;
    last_used_at?: string;
    expires_at?: string;
    cp_type?: 'user' | 'system';
    secret?: string;
    enabled?: boolean;
    did_method?: string;
}

/** Mirrors `Integration` in `www/default/src/pages/IntegrationsPage.tsx`. */
interface IntegrationFixture {
    id: string;
    name: string;
    description: string;
    type: string;
    category?: string;
    configuration: Record<string, unknown>;
    content: Record<string, unknown>;
    status: string;
    created_at: string;
}

/** Mirrors `HierarchicalMetrics` in `www/default/src/pages/MetricsPage.tsx`. */
interface HierarchicalMetricsFixture {
    connections: Record<
        string,
        {
            sources: Record<
                string,
                Record<string, Record<string, Array<{timestamp: string; status: 'success'; latency_ms: number; direction: 'request'}>>>
            >;
            rule_triggers: Array<{timestamp: string; accepted: boolean}>;
        }
    >;
}

const surfaces: SurfaceFixture[] = [
    {
        surface_id: FIXTURE_ID.surface,
        name: LONG_NAME,
        description: LONG_DESCRIPTION,
        status: 'active',
        tags: [LONG_TAG, 'system:onboarding'],
        access_point: {
            listen_address: '0.0.0.0:8711',
            route: '/a2a/enterprise-procurement/purchase-order-reconciliation-assistant/emea-production',
            protocol: 'a2a',
        },
        target: {endpoint: LONG_URL},
        transit: {points: []},
    },
];

const mcpProxies: McpProxyFixture[] = [
    {
        id: FIXTURE_ID.mcpProxy,
        name: `${LONG_NAME} MCP Proxy`,
        description: LONG_DESCRIPTION,
        channel_prefix: 'enterprise-procurement-purchase-order-reconciliation-assistant-emea-production',
        base_url: LONG_URL,
        status: 'active',
        direct_access: false,
        managed_by: 'procurement-automation-platform-terraform-pipeline-emea-production-workspace',
        created_at: iso(120),
    },
];

const a2aProxies: A2aProxy[] = [
    {
        id: FIXTURE_ID.a2aProxy,
        name: `${LONG_NAME} A2A Proxy`,
        description: LONG_DESCRIPTION,
        status: 'active',
        backend: {
            kind: 'copilot_direct_line',
            secret_id: 'copilot-direct-line-secret-for-enterprise-procurement-reconciliation-emea-prod',
            credential_mode: 'secret',
            base_url: LONG_URL,
            timeout_secs: 30,
            poll_interval_ms: 500,
            max_poll_attempts: 20,
        },
        created_at: iso(240),
        updated_at: iso(30),
    },
];

const jwtStrategies: JwtStrategyFixture[] = [
    {
        id: FIXTURE_ID.jwtStrategy,
        name: `${LONG_NAME} Workforce Identity`,
        expected_issuer: `https://login.${DOMAIN}/tenants/procurement-emea-production/v2.0`,
        jwks_source: {type: 'remote', jwks_uri: `https://login.${DOMAIN}/tenants/procurement/discovery/v2.0/keys`},
        created_at: iso(600),
        updated_at: iso(60),
    },
];

const credentialProviders: CredentialProviderFixture[] = [
    {
        id: FIXTURE_ID.credentialProvider,
        name: `${LONG_NAME} Supplier Portal OAuth`,
        provider_id: 'supplier-portal-oauth-client-for-enterprise-procurement-reconciliation-emea-production',
        provider_type: 'oauth2_authorization_code',
        token_endpoint: `https://auth.${DOMAIN}/oauth2/v2/token`,
        default_scopes: ['purchase-orders.read', 'supplier-invoices.read', 'goods-receipts.read'],
        token_refresh_enabled: true,
        description: LONG_DESCRIPTION,
        created_at: iso(900),
        updated_at: iso(90),
    },
];

const delegationTokens: DelegationTokenFixture[] = [
    {
        id: FIXTURE_ID.delegationToken,
        agent_did: LONG_DID,
        user_identity_hash: 'sha256:9f2c7a4e1b8d3f6a0c5e9b2d7f4a1c8e3b6d9f2a5c8e1b4d7f0a3c6e9b2d5f8a',
        credential_provider_id: FIXTURE_ID.credentialProvider,
        provider_id: 'supplier-portal-oauth-client-for-enterprise-procurement-reconciliation-emea-production',
        token_type: 'Bearer',
        scopes: ['purchase-orders.read', 'supplier-invoices.read', 'goods-receipts.read'],
        expires_at: iso(-60),
        consent_granted_at: iso(300),
        last_used_at: iso(5),
        created_at: iso(300),
        updated_at: iso(5),
        is_expired: false,
        can_refresh: true,
    },
];

const stsClients: StsClientFixture[] = [
    {
        id: FIXTURE_ID.stsClient,
        client_id: 'sts-client-enterprise-procurement-purchase-order-reconciliation-assistant-emea-prod',
        name: `${LONG_NAME} Token Exchange`,
        client_secret_ref: 'secret:sts-client-enterprise-procurement-reconciliation-emea-production',
        allowed_audiences: [LONG_URL],
        allowed_scopes: ['purchase-orders.read'],
        allowed_subject_token_types: ['urn:ietf:params:oauth:token-type:jwt'],
        allow_impersonation: false,
        max_ttl_secs: 900,
        issue_id_jag: true,
        created_at: iso(800),
        updated_at: iso(80),
    },
];

const delegationAudit: DelegationAuditPageFixture = {
    events: ['token_injected', 'consent_granted'].map((event, i) => ({
        timestamp: iso(10 + i),
        event,
        agent_did: LONG_DID,
        user_identity_hash: 'sha256:9f2c7a4e1b8d3f6a0c5e9b2d7f4a1c8e3b6d9f2a5c8e1b4d7f0a3c6e9b2d5f8a',
        provider_id: FIXTURE_ID.credentialProvider,
        provider_name: `${LONG_NAME} Supplier Portal OAuth`,
        channel_id: FIXTURE_ID.surface,
        channel_name: LONG_NAME,
        target_endpoint: LONG_URL,
        protocol: 'a2a',
        scopes: ['purchase-orders.read', 'supplier-invoices.read'],
        via_fabric: false,
        caller: {
            auth_method: 'jwt_bearer',
            iss: `https://login.${DOMAIN}/tenants/procurement-emea-production/v2.0`,
            sub: 'procurement.reconciliation.service-account@enterprise-operations.example.com',
            email: 'procurement.reconciliation.service-account@enterprise-operations.example.com',
        },
    })),
    total: 2,
    page: 1,
    page_size: 25,
    total_pages: 1,
};

const policyDefinitions: PolicyDefinitionFixture[] = [
    {
        id: FIXTURE_ID.gatewayPolicy,
        name: `${LONG_NAME} Gateway Guardrail`,
        description: LONG_DESCRIPTION,
        policy_type: 'gateway',
        policy: 'package gateway.policy\n\ndefault allow := true\n',
        enabled: true,
        created_at: iso(700),
        updated_at: iso(70),
        content_hash: 'sha256:4b1d8f3a9c2e7b5d0f6a1c8e3b9d4f7a2c5e0b8d3f6a9c1e4b7d2f5a8c0e3b6d',
    },
    {
        id: FIXTURE_ID.surfacePolicy,
        name: `${LONG_NAME} Surface Guardrail`,
        description: LONG_DESCRIPTION,
        policy_type: 'agent_surface',
        policy: 'package surface.policy\n\ndefault allow := true\n',
        enabled: true,
        created_at: iso(700),
        updated_at: iso(70),
        content_hash: 'sha256:7e2a5c9f1b4d8e3a6c0f2b5d9e1a4c7f3b6d0e8a2c5f9b1d4e7a0c3f6b9d2e5a',
    },
];

const secrets: SecretFixture[] = [
    {
        id: FIXTURE_ID.secret,
        name: `${LONG_NAME} Supplier Portal Client Secret`,
        secret_id: 'supplier-portal-client-secret-enterprise-procurement-reconciliation-emea-production',
        description: LONG_DESCRIPTION,
        secret_type: 'oauth_client_secret',
        tags: [LONG_TAG],
        created_at: iso(1000),
        updated_at: iso(100),
    },
];

const apiKeys: ApiKeyFixture[] = [
    {
        key_id: FIXTURE_ID.apiKey,
        agent_id: FIXTURE_ID.surface,
        client_id: 'procurement-reconciliation-batch-runner-emea-production-scheduler-worker-pool-0001',
        prefix: 'agk_layout',
        status: 'active',
        labels: {},
        created_at: iso(1100),
        created_by: 'test-user',
        use_count: 42,
    },
];

const certificates: CertificateFixture[] = [
    {
        id: FIXTURE_ID.certificate,
        name: `${LONG_NAME} Client Certificate`,
        certificate_id: 'mtls-client-certificate-enterprise-procurement-reconciliation-assistant-emea-prod',
        description: LONG_DESCRIPTION,
        tags: [LONG_TAG],
        created_at: iso(1200),
        updated_at: iso(120),
        expires_at: iso(-60 * 24 * 300),
        active: true,
        kind: 'client_leaf',
    },
];

const accessTokens: {access_tokens: AccessTokenMeta[]} = {
    access_tokens: [
        {
            id: FIXTURE_ID.accessToken,
            name: `${LONG_NAME} Automation Token`,
            description: LONG_DESCRIPTION,
            user_id: 'test-user-001',
            scopes: ['surfaces.view', 'audit.view', 'logs.view'],
            resource_pattern: `surfaces/enterprise-procurement-purchase-order-reconciliation-assistant-emea-production/*`,
            required_headers: [],
            created_by: 'test-user',
            created_at: iso(1300),
            last_used_at: iso(3),
            expires_at: iso(-60 * 24 * 30),
            rotation_generation: 0,
            active: true,
        },
    ],
};

const identities: {identities: DidWebVhIdentity[]; count: number} = {
    identities: [
        {
            id: 'layout-identity-1',
            did: LONG_DID,
            uuid: 'layout-identity-uuid-1',
            scid: 'QmLayoutFixtureSelfCertifyingIdentifierForProcurementReconciliationAssistant',
            version: 3,
            status: 'active',
            controller: LONG_DID_2,
            created_at: iso(5000),
            updated_at: iso(50),
            metadata: {name: LONG_NAME, description: LONG_DESCRIPTION, team: LONG_TAG},
        },
    ],
    count: 1,
};

const issuers: Issuer[] = [
    {
        id: FIXTURE_ID.issuer,
        name: `${LONG_NAME} Issuer`,
        description: LONG_DESCRIPTION,
        did: LONG_DID_2,
        trust_registry_did: `did:web:registry.${DOMAIN}:ecosystems:procurement-trust-network`,
        tr_registered: true,
        created_at: iso(6000),
        updated_at: iso(60),
    },
];

const authorities: Authority[] = [
    {
        id: FIXTURE_ID.authority,
        name: `${LONG_NAME} Authority`,
        description: LONG_DESCRIPTION,
        did: `did:web:authority.${DOMAIN}:ecosystems:procurement-trust-network:governance-authority`,
        created_at: iso(6100),
        updated_at: iso(61),
    },
];

const paymentRecords: PaymentRecordFixture[] = [
    {
        id: 'layout-payment-verification-1',
        type: 'verification',
        status: 'verified',
        tx_hash: FIXTURE_ID.payment,
        channel_id: FIXTURE_ID.surface,
        channel_name: LONG_NAME,
        resource_path: '/a2a/enterprise-procurement/purchase-order-reconciliation-assistant/emea-production/tasks',
        network: 'base-sepolia',
        network_name: 'Base Sepolia Testnet',
        amount: '125000',
        decimals: 6,
        asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
        recipient: '0x9a4c1f7e3b8d2a6c0e5f9b1d4a7c3e8f2b6d0a5c',
        recipient_name: `${LONG_NAME} Treasury Wallet`,
        tx_explorer_url: `https://sepolia.basescan.org/tx/${FIXTURE_ID.payment}`,
        correlation_id: 'layout-payment-correlation-1',
        created_at: unix(20),
        completed_at: unix(19),
        verification_mode: 'Local',
    },
    {
        id: 'layout-payment-settlement-1',
        type: 'settlement',
        status: 'settled',
        tx_hash: FIXTURE_ID.payment,
        channel_id: FIXTURE_ID.surface,
        channel_name: LONG_NAME,
        network: 'base-sepolia',
        network_name: 'Base Sepolia Testnet',
        amount: '125000',
        decimals: 6,
        asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
        recipient: '0x9a4c1f7e3b8d2a6c0e5f9b1d4a7c3e8f2b6d0a5c',
        recipient_name: `${LONG_NAME} Treasury Wallet`,
        tx_explorer_url: `https://sepolia.basescan.org/tx/${FIXTURE_ID.payment}`,
        correlation_id: 'layout-payment-correlation-1',
        created_at: unix(18),
        completed_at: unix(17),
        settlement_method: 'ExternalFacilitator',
        sync_status: 'local',
    },
];

const mediators: MediatorFixture[] = [
    {
        id: FIXTURE_ID.mediator,
        name: `${LONG_NAME} Mediator`,
        description: LONG_DESCRIPTION,
        did: `did:web:mediator.${DOMAIN}:regions:eu-west-1:clusters:procurement-messaging-0001`,
        status: 'active',
        created_at: iso(7000),
        updated_at: iso(70),
    },
];

const connectionPoints: ConnectionPointFixture[] = [
    {
        id: FIXTURE_ID.connectionPoint,
        gateway_id: 'layout-gateway-self',
        mediator_id: FIXTURE_ID.mediator,
        name: `${LONG_NAME} Partner Link`,
        description: LONG_DESCRIPTION,
        oob_url: `https://${DOMAIN}/oob/invitations/enterprise-procurement-reconciliation-partner-link-0001`,
        use_count: 3,
        created_at: iso(7100),
        last_used_at: iso(15),
        expires_at: iso(-60 * 24 * 14),
        cp_type: 'user',
        secret: 'layout-fixture-connection-point-secret-0001',
        enabled: true,
        did_method: 'webvh',
    },
];

const trustRegistries: TrustRegistry[] = [
    {
        id: FIXTURE_ID.trustRegistry,
        name: `${LONG_NAME} Trust Registry`,
        description: LONG_DESCRIPTION,
        oob_url: `https://registry.${DOMAIN}/oob/invitations/procurement-trust-network-0001`,
        registry_did: `did:web:registry.${DOMAIN}:ecosystems:procurement-trust-network`,
        connection_status: 'connected',
        status: 'active',
        created_at: iso(7200),
        updated_at: iso(72),
    },
];

const integrations: IntegrationFixture[] = [
    {
        id: FIXTURE_ID.integration,
        name: `${LONG_NAME} Operations Webhook`,
        description: LONG_DESCRIPTION,
        type: 'webhook',
        category: 'notification',
        configuration: {url: LONG_URL},
        content: {},
        status: 'active',
        created_at: iso(7300),
    },
];

const hierarchicalMetrics: HierarchicalMetricsFixture = {
    connections: {
        [FIXTURE_ID.metricsChannel]: {
            sources: {
                [LONG_DID_2]: {
                    [LONG_DID]: {
                        [LONG_URL]: [{timestamp: iso(2), status: 'success', latency_ms: 84, direction: 'request'}],
                    },
                },
            },
            rule_triggers: [{timestamp: iso(2), accepted: true}],
        },
    },
};

/** A full Audit Log page: `PAGE_LIMIT` (50) entries and a `total` above it so pagination shows. */
export const AUDIT_PAGE_LIMIT = 50;

function auditEntry(i: number): AuditEntry {
    const allow = i % 3 !== 0;
    return {
        id: `layout-audit-${i}`,
        timestamp: iso(i),
        event: {
            policy_decision: {
                scope: i % 2 === 0 ? 'gateway' : 'surface',
                flow: 'access_point',
                policy_id: `layout-policy-${i}`,
                policy_name: `${LONG_NAME} Guardrail ${i}`,
                decision: allow ? 'allow' : 'deny',
                deny_reason: allow ? null : `caller ${LONG_DID_2} is not on the procurement allow list`,
                surface_id: FIXTURE_ID.surface,
                caller_did: LONG_DID_2,
                http_method: 'POST',
                http_path: '/a2a/enterprise-procurement/purchase-order-reconciliation-assistant/emea-production',
                policy_version: 3,
                policy_content_hash: 'sha256:4b1d8f3a9c2e7b5d0f6a1c8e3b9d4f7a2c5e0b8d3f6a9c1e4b7d2f5a8c0e3b6d',
            },
        },
        caller: {
            did: LONG_DID_2,
            auth_method: 'jwt_bearer',
            email: 'procurement.reconciliation.service-account@enterprise-operations.example.com',
        },
        surface_id: FIXTURE_ID.surface,
        channel_name: LONG_NAME,
        provider_name: `${LONG_NAME} Supplier Portal OAuth`,
        protocol: 'a2a',
        agent_did: LONG_DID,
        trace_id: `layout-trace-${String(i).padStart(4, '0')}-procurement-reconciliation-emea-production`,
    };
}

const auditPage: AuditResponse = {
    events: Array.from({length: AUDIT_PAGE_LIMIT}, (_, i) => auditEntry(i)),
    total: AUDIT_PAGE_LIMIT * 3 + 7,
    page: 1,
    limit: AUDIT_PAGE_LIMIT,
    category_counts: {policy: AUDIT_PAGE_LIMIT * 3 + 7},
};

type Body = object;

/** Answers GET requests whose path (without the query) is exactly one of these. */
const API_FIXTURES: Record<string, Body> = {
    '/api/v1/surfaces': surfaces,
    '/api/v1/mcp-proxies': mcpProxies,
    '/api/v1/a2a-proxies': a2aProxies,
    '/api/v1/jwt-verification-strategies': jwtStrategies,
    '/api/v1/credential-providers': credentialProviders,
    '/api/v1/delegation-vault': delegationTokens,
    '/api/v1/sts/clients': stsClients,
    '/api/v1/delegation-audit': delegationAudit,
    '/api/v1/policy-definitions': policyDefinitions,
    '/api/v1/secrets/': secrets,
    '/api/v1/api-keys': apiKeys,
    '/api/v1/certificates/': certificates,
    '/api/v1/access-tokens': accessTokens,
    '/api/v1/identities': identities,
    '/api/v1/issuers': issuers,
    '/api/v1/authorities': authorities,
    '/api/v1/mediators': mediators,
    '/api/v1/mediators/compatible': mediators,
    '/api/v1/connection-points': connectionPoints,
    '/api/v1/trust-registries': trustRegistries,
    '/api/v1/integrations': integrations,
    '/api/v1/dashboard/metrics/hierarchical': hierarchicalMetrics,
    '/api/v1/audit': auditPage,
    '/api/admin/x402/payments/all': {payments: paymentRecords, total: paymentRecords.length, chart_data: []},
    '/api/admin/mpp/transactions': {transactions: [], total: 0},
};

/** Install the list fixtures on a page before its first navigation. */
export async function installLayoutFixtures(page: Page): Promise<void> {
    await page.route(
        url => url.pathname in API_FIXTURES,
        async (route: Route) => {
            if (route.request().method() !== 'GET') {
                await route.fallback();
                return;
            }
            const body = API_FIXTURES[new URL(route.request().url()).pathname];
            await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(body)});
        },
    );
}
