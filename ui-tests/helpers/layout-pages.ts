/**
 * Page inventory for the laptop layout spec: every sidebar destination and
 * each of its tabs, the profile page, every create or wizard route without a
 * record id, and the Audit Log with an entry selected.
 *
 * `testIds` must be attached once the page has loaded; the first one is the
 * page root and the rest mark the fixture data. `actions` are the primary
 * actions a user needs without opening a menu; they must be attached too.
 * An id ending in `*` matches the first element whose test id starts with
 * the part before it (rows keyed by a server-generated id).
 */

import type {Page} from '@playwright/test';
import {FIXTURE_ID, LONG_DID} from './layout-fixtures';

export interface LayoutPage {
    /** Kebab-case id, used in test titles and screenshot names. */
    readonly id: string;
    readonly route: string;
    readonly testIds: readonly string[];
    readonly actions: readonly string[];
    /** Brings the page into the state under test after the root renders. */
    readonly setup?: (page: Page) => Promise<void>;
    /** Also save a full-page screenshot. */
    readonly fullPageScreenshot?: boolean;
}

const click = (testId: string) => async (page: Page) => {
    await page.getByTestId(testId).click();
};

const tabs = (prefix: string, keys: readonly string[]) => keys.map(key => `${prefix}-${key}-tab-trigger`);

const DASHBOARD_ACTIONS = [
    'dashboard-stat-identities',
    'dashboard-stat-channels',
    'dashboard-stat-connections',
    'dashboard-bucket-select',
    'dashboard-chart-pie-button',
    'dashboard-chart-bar-button',
    'dashboard-chart-connections-button',
    'dashboard-metrics-delete-button',
    'dashboard-logs-button',
    'dashboard-settings-button',
];

const CREDENTIALS_TABS = tabs('credentials', [
    'jwt-verification',
    'credential-providers',
    'credential-tokens',
    'sts-clients',
    'credential-audit',
]);
const CREDENTIALS = ['credentials-search-input', ...CREDENTIALS_TABS];

const POLICIES = ['policies-search-input', ...tabs('policies', ['gateway', 'agent-surface', 'paywall'])];

const SECRETS = ['secrets-search-input', ...tabs('secrets', ['secrets', 'api-keys', 'certificates', 'access-tokens'])];

const IDENTITIES = ['identities-search-input', ...tabs('identities', ['identities', 'issuers', 'authorities'])];

const CONNECTIONS = ['connections-search-input', ...tabs('connections', ['gateways', 'mediators', 'trust-registries'])];

const INTEGRATIONS = [
    'integrations-search-input',
    ...['integrations', 'endpoints', 'event-sets'].map(key => `integrations-tab-${key}`),
];

const SETTINGS_TABS = tabs('settings', [
    'system-settings',
    'user-settings',
    'admin',
    'networking',
    'security',
    'limits',
    'users',
]);

const AUDIT_FILTERS = [
    'audit-search',
    'filter-overflow-trigger-category',
    'filter-chip-allow',
    'filter-chip-deny',
    'filter-overflow-trigger-flow',
    'filter-overflow-trigger-type',
];

const TEST_USER_ID = 'test-user-001';

const SIDEBAR_PAGES: LayoutPage[] = [
    {
        id: 'dashboard',
        route: '/',
        testIds: ['page-dashboard'],
        actions: DASHBOARD_ACTIONS,
    },
    {
        id: 'dashboard-chart-bar',
        route: '/',
        testIds: ['page-dashboard'],
        actions: DASHBOARD_ACTIONS,
        setup: click('dashboard-chart-bar-button'),
    },
    {
        id: 'dashboard-chart-connections',
        route: '/',
        testIds: ['page-dashboard'],
        actions: DASHBOARD_ACTIONS,
        setup: click('dashboard-chart-connections-button'),
    },
    {
        id: 'surfaces',
        route: '/surfaces',
        testIds: ['page-surfaces', `surfaces-row-${FIXTURE_ID.surface}`],
        actions: ['surfaces-search-input', 'surfaces-recent-toggle', 'surfaces-add-button', `surfaces-row-${FIXTURE_ID.surface}`],
    },
    {
        id: 'proxies',
        route: '/proxies',
        testIds: ['page-proxies', `mcp-proxy-row-${FIXTURE_ID.mcpProxy}`, `a2a-proxy-row-${FIXTURE_ID.a2aProxy}`],
        actions: [
            'proxies-search-input',
            'mcp-proxies-add-button',
            `mcp-proxy-edit-button-${FIXTURE_ID.mcpProxy}`,
            `mcp-proxy-delete-button-${FIXTURE_ID.mcpProxy}`,
            'a2a-proxies-add-button',
            `a2a-proxy-edit-button-${FIXTURE_ID.a2aProxy}`,
            `a2a-proxy-delete-button-${FIXTURE_ID.a2aProxy}`,
        ],
    },
    {
        id: 'credentials',
        route: '/credentials',
        testIds: ['page-credentials', `jwt-strategy-row-${FIXTURE_ID.jwtStrategy}`],
        actions: [
            ...CREDENTIALS,
            'jwt-strategies-add-button',
            `jwt-strategy-edit-button-${FIXTURE_ID.jwtStrategy}`,
            `jwt-strategy-delete-button-${FIXTURE_ID.jwtStrategy}`,
        ],
    },
    {
        id: 'credentials-credential-providers',
        route: '/credentials?tab=credential-providers',
        testIds: ['page-credentials', `credential-provider-row-${FIXTURE_ID.credentialProvider}`],
        actions: [
            ...CREDENTIALS,
            'credential-providers-add-button',
            `credential-provider-delete-button-${FIXTURE_ID.credentialProvider}`,
        ],
    },
    {
        id: 'credentials-credential-tokens',
        route: '/credentials?tab=credential-tokens',
        testIds: ['page-credentials', `credential-token-row-${FIXTURE_ID.delegationToken}`],
        actions: [
            ...CREDENTIALS,
            `credential-token-revoke-user-button-${FIXTURE_ID.delegationToken}`,
            `credential-token-revoke-button-${FIXTURE_ID.delegationToken}`,
        ],
    },
    {
        id: 'credentials-sts-clients',
        route: '/credentials?tab=sts-clients',
        testIds: ['page-credentials', `sts-client-row-${FIXTURE_ID.stsClient}`],
        actions: [
            ...CREDENTIALS,
            'sts-clients-add-button',
            `sts-client-edit-button-${FIXTURE_ID.stsClient}`,
            `sts-client-delete-button-${FIXTURE_ID.stsClient}`,
        ],
    },
    {
        id: 'credentials-credential-audit',
        route: '/credentials?tab=credential-audit',
        testIds: ['page-credentials', 'credential-audit-row-0'],
        actions: [
            ...CREDENTIALS,
            'credential-audit-event-filter',
            'credential-audit-refresh-button',
            'credential-audit-row-0',
            'credential-audit-provider-link-0',
        ],
    },
    {
        id: 'policies',
        route: '/policies',
        testIds: ['page-policies', `policies-gateway-row-${FIXTURE_ID.gatewayPolicy}`],
        actions: [
            ...POLICIES,
            'policies-gateway-add-button',
            `policies-gateway-global-toggle-${FIXTURE_ID.gatewayPolicy}`,
            `policies-gateway-delete-button-${FIXTURE_ID.gatewayPolicy}`,
        ],
    },
    {
        id: 'policies-agent-surface',
        route: '/policies?tab=agent_surface',
        testIds: ['page-policies', `policies-agent_surface-row-${FIXTURE_ID.surfacePolicy}`],
        actions: [
            ...POLICIES,
            'policies-agent_surface-add-button',
            `policies-agent_surface-global-toggle-${FIXTURE_ID.surfacePolicy}`,
            `policies-agent_surface-delete-button-${FIXTURE_ID.surfacePolicy}`,
        ],
    },
    {
        id: 'policies-paywall',
        route: '/policies?tab=paywall',
        testIds: ['page-policies'],
        actions: [...POLICIES, 'paywall-policies-add-surface-button'],
    },
    {
        id: 'secrets',
        route: '/secrets',
        testIds: ['page-secrets', `secrets-row-${FIXTURE_ID.secret}`],
        actions: [...SECRETS, 'secrets-add-button', `secrets-delete-button-${FIXTURE_ID.secret}`],
    },
    {
        id: 'secrets-api-keys',
        route: '/secrets?tab=api-keys',
        testIds: ['page-secrets', `api-keys-row-${FIXTURE_ID.apiKey}`],
        actions: [
            ...SECRETS,
            'api-keys-add-button',
            `api-keys-revoke-button-${FIXTURE_ID.apiKey}`,
            `api-keys-rotate-button-${FIXTURE_ID.apiKey}`,
            `api-keys-delete-button-${FIXTURE_ID.apiKey}`,
        ],
    },
    {
        id: 'secrets-certificates',
        route: '/secrets?tab=certificates',
        testIds: ['page-secrets', `certificates-row-${FIXTURE_ID.certificate}`],
        actions: [
            ...SECRETS,
            'certificates-kind-filter',
            'certificates-add-button',
            `certificates-delete-button-${FIXTURE_ID.certificate}`,
        ],
    },
    {
        id: 'secrets-access-tokens',
        route: '/secrets?tab=access-tokens',
        testIds: ['page-secrets', `access-token-row-${FIXTURE_ID.accessToken}`],
        actions: [
            ...SECRETS,
            'access-token-show-revoked',
            'access-token-new-button',
            `access-token-revoke-${FIXTURE_ID.accessToken}`,
        ],
    },
    {
        id: 'identities',
        route: '/identities',
        testIds: ['page-identities', `identities-row-${LONG_DID}`],
        actions: [
            ...IDENTITIES,
            `identities-row-${LONG_DID}`,
            `identities-history-button-${LONG_DID}`,
            `identities-policy-button-${LONG_DID}`,
            `identities-copy-link-button-${LONG_DID}`,
        ],
    },
    {
        id: 'identities-issuers',
        route: '/identities?tab=issuers',
        testIds: ['page-identities', `issuers-row-${FIXTURE_ID.issuer}`],
        actions: [
            ...IDENTITIES,
            'issuers-add-button',
            `issuers-edit-button-${FIXTURE_ID.issuer}`,
            `issuers-delete-button-${FIXTURE_ID.issuer}`,
        ],
    },
    {
        id: 'identities-authorities',
        route: '/identities?tab=authorities',
        testIds: ['page-identities', `authorities-row-${FIXTURE_ID.authority}`],
        actions: [
            ...IDENTITIES,
            'authorities-add-button',
            `authorities-edit-button-${FIXTURE_ID.authority}`,
            `authorities-delete-button-${FIXTURE_ID.authority}`,
        ],
    },
    {
        id: 'payments',
        route: '/x402payments',
        testIds: ['page-payments', `payments-row-${FIXTURE_ID.payment}`],
        actions: [
            'payments-search-input',
            'payments-refresh-button',
            'payments-bucket-select',
            'payments-overview-context-toggle',
            `payments-details-button-${FIXTURE_ID.payment}`,
            `payments-delete-button-${FIXTURE_ID.payment}`,
        ],
    },
    {
        id: 'connections',
        route: '/connections',
        testIds: ['page-connections', 'gateways-row-*', `connection-points-row-${FIXTURE_ID.connectionPoint}`],
        actions: [
            ...CONNECTIONS,
            'gateways-add-button',
            'gateways-edit-button-*',
            'connection-points-add-button',
            `connection-points-edit-button-${FIXTURE_ID.connectionPoint}`,
            `connection-points-copy-link-button-${FIXTURE_ID.connectionPoint}`,
            `connection-points-copy-secret-button-${FIXTURE_ID.connectionPoint}`,
            `connection-points-delete-button-${FIXTURE_ID.connectionPoint}`,
        ],
    },
    {
        id: 'connections-mediators',
        route: '/connections?tab=mediators',
        testIds: ['page-connections', `mediators-row-${FIXTURE_ID.mediator}`],
        actions: [
            ...CONNECTIONS,
            'mediators-add-button',
            `mediators-trust-ping-button-${FIXTURE_ID.mediator}`,
            `mediators-edit-button-${FIXTURE_ID.mediator}`,
            `mediators-delete-button-${FIXTURE_ID.mediator}`,
        ],
    },
    {
        id: 'connections-trust-registries',
        route: '/connections?tab=trust-registries',
        testIds: ['page-connections', `trust-registries-row-${FIXTURE_ID.trustRegistry}`],
        actions: [
            ...CONNECTIONS,
            'trust-registries-add-button',
            `trust-registries-ping-button-${FIXTURE_ID.trustRegistry}`,
            `trust-registries-edit-button-${FIXTURE_ID.trustRegistry}`,
            `trust-registries-delete-button-${FIXTURE_ID.trustRegistry}`,
        ],
    },
    {
        id: 'integrations',
        route: '/integrations',
        testIds: ['page-integrations', `integration-row-${FIXTURE_ID.integration}`],
        actions: [
            ...INTEGRATIONS,
            'integrations-add-button',
            'integration-test-button',
            'integration-edit-button',
            'integration-delete-button',
        ],
    },
    {
        id: 'integrations-endpoints',
        route: '/integrations?tab=endpoints',
        testIds: ['page-integrations', `endpoint-row-${FIXTURE_ID.endpoint}`],
        actions: [
            ...INTEGRATIONS,
            'endpoints-add-button',
            'endpoint-test-button',
            'endpoint-edit-button',
            'endpoint-delete-button',
        ],
    },
    {
        id: 'integrations-event-sets',
        route: '/integrations?tab=event-sets',
        testIds: ['page-integrations', `event-set-row-${FIXTURE_ID.eventSet}`],
        actions: [...INTEGRATIONS, 'event-sets-add-button', 'event-set-edit-button', 'event-set-delete-button'],
    },
    {
        id: 'settings',
        route: '/settings',
        testIds: ['page-settings'],
        actions: [...SETTINGS_TABS, 'settings-appliance-id-input', 'settings-system-save-button', 'settings-system-reset-button'],
    },
    {
        id: 'settings-user-settings',
        route: '/settings?tab=user-settings',
        testIds: ['page-settings'],
        actions: [...SETTINGS_TABS, 'settings-user-save-button', 'settings-user-reset-button'],
    },
    {
        id: 'settings-admin',
        route: '/settings?tab=admin',
        testIds: ['page-settings'],
        actions: [
            ...SETTINGS_TABS,
            'settings-admin-truncate-metrics-button',
            'settings-admin-truncate-logs-button',
            'settings-admin-export-button',
            'settings-admin-backup-button',
            'settings-admin-restore-button',
        ],
    },
    {
        id: 'settings-networking',
        route: '/settings?tab=networking',
        testIds: ['page-settings'],
        actions: [
            ...SETTINGS_TABS,
            'field-help-direct-tls-mode',
            'field-help-trusted-proxy-cidrs',
            'field-help-forwarded-header-format',
        ],
    },
    {
        id: 'settings-security',
        route: '/settings?tab=security',
        testIds: ['page-settings'],
        actions: [...SETTINGS_TABS, 'vp-audit-enabled-toggle', 'vp-audit-save-button'],
    },
    {
        id: 'settings-limits',
        route: '/settings?tab=limits',
        testIds: ['page-settings', 'limits-row-*'],
        actions: SETTINGS_TABS,
    },
    {
        id: 'settings-users',
        route: '/settings?tab=users',
        testIds: ['page-settings', `users-row-${TEST_USER_ID}`],
        actions: [
            ...SETTINGS_TABS,
            'users-search-input',
            'users-role-filter',
            'users-status-filter',
            `users-edit-button-${TEST_USER_ID}`,
        ],
    },
    {
        id: 'metrics',
        route: '/metrics',
        testIds: ['page-metrics', `metrics-channel-${FIXTURE_ID.metricsChannel}`],
        actions: [
            'metrics-configure-button',
            'metrics-live-toggle-button',
            'metrics-refresh-button',
            `metrics-channel-${FIXTURE_ID.metricsChannel}`,
            'metrics-grafana-setup-button',
            'metrics-cloudwatch-setup-button',
        ],
    },
    {
        id: 'logs',
        route: '/logs',
        testIds: ['page-logs', 'logs-filter-bar'],
        actions: [
            'logs-download-button',
            'logs-clear-button',
            'logs-pause-button',
            'logs-refresh-button',
            'logs-search-input',
            'logs-problems-button',
        ],
    },
    {
        id: 'audit',
        route: '/audit',
        testIds: ['page-audit', 'audit-list', 'audit-pagination'],
        actions: [
            ...AUDIT_FILTERS,
            'audit-forward-button',
            'audit-refresh',
            'audit-about-toggle',
            'audit-item-0',
            'audit-page-prev',
            'audit-page-next',
        ],
        fullPageScreenshot: true,
    },
    {
        id: 'audit-selected',
        route: '/audit',
        testIds: ['page-audit', 'audit-list', 'audit-pagination', 'audit-detail-panel'],
        actions: [...AUDIT_FILTERS, 'audit-forward-button', 'audit-refresh', 'audit-item-0', 'audit-detail-title'],
        setup: click('audit-item-0'),
        fullPageScreenshot: true,
    },
    {
        id: 'system-metrics',
        route: '/system-metrics',
        testIds: ['page-system-metrics'],
        actions: [
            'system-metrics-range-select',
            'system-metrics-interval-select',
            'system-metrics-live-toggle-button',
            'system-metrics-refresh-button',
        ],
    },
    {
        id: 'tasks',
        route: '/tasks',
        testIds: ['page-tasks'],
        actions: ['tasks-refresh-button'],
    },
];

const PROFILE_PAGE: LayoutPage = {
    id: 'profile',
    route: '/profile',
    testIds: ['page-profile'],
    actions: ['profile-back-button', 'profile-avatar-upload-button', 'profile-cancel-button', 'profile-save-button'],
};

const CREATE_PAGES: LayoutPage[] = [
    {
        id: 'surface-new',
        route: '/surfaces/new',
        testIds: ['page-add-surface', 'surface-template-row-*'],
        actions: ['surface-template-use-button-*', 'add-surface-cancel-button'],
    },
    {
        id: 'gateway-new',
        route: '/gateways/new',
        testIds: ['page-gateway-editor'],
        actions: ['gateway-editor-back-button', 'gateway-editor-overview-tab-trigger'],
    },
    {
        id: 'gateway-publish',
        route: '/gateways/publish',
        testIds: ['page-gateway-publish'],
        actions: ['connection-point-mediator-select', 'wizard-cancel', 'wizard-next'],
    },
    {
        id: 'gateway-connect',
        route: '/gateways/connect',
        testIds: ['page-gateway-connect'],
        actions: ['wizard-cancel', 'wizard-next'],
    },
    {
        id: 'mediator-wizard',
        route: '/mediators/wizard',
        testIds: ['page-mediator-wizard'],
        actions: ['wizard-mediator-did-input', 'wizard-cancel', 'wizard-next'],
    },
    {
        id: 'mediator-new',
        route: '/mediators/new',
        testIds: ['page-mediator-editor'],
        actions: ['mediator-editor-back-button', 'mediator-editor-cancel-button', 'mediator-editor-save-button'],
    },
    {
        id: 'mcp-proxy-wizard',
        route: '/proxies/mcp-proxies/wizard',
        testIds: ['page-mcp-proxy-wizard'],
        actions: ['mcp-proxy-wizard-back-button', 'wizard-cancel', 'wizard-next'],
    },
    {
        id: 'a2a-proxy-new',
        route: '/proxies/a2a-proxies/new',
        testIds: ['page-a2a-proxy-editor'],
        actions: [
            'a2a-proxy-back-button',
            'a2a-proxy-save-button',
            ...tabs('a2a-proxy-editor', ['overview', 'backend', 'agent-card']),
        ],
    },
    {
        id: 'integration-new',
        route: '/integrations/new',
        testIds: ['page-integration-editor'],
        actions: ['integration-test-button', 'integration-cancel-button', 'integration-save-button'],
    },
    {
        id: 'endpoint-new',
        route: '/integrations/endpoints/new',
        testIds: ['page-endpoint-editor'],
        actions: ['endpoint-cancel-button', 'endpoint-save-button'],
    },
    {
        id: 'event-set-new',
        route: '/integrations/event-sets/new',
        testIds: ['page-event-set-editor'],
        actions: ['event-set-cancel-button', 'event-set-save-button'],
    },
    {
        id: 'trust-registry-wizard',
        route: '/trust-registries/wizard',
        testIds: ['page-trust-registry-wizard'],
        actions: ['wizard-cancel', 'wizard-next'],
    },
    {
        id: 'issuer-new',
        route: '/identities?tab=issuers&issuer=new',
        testIds: ['page-identities', 'page-issuer-editor'],
        actions: [...IDENTITIES, 'issuer-editor-back-button', 'issuer-editor-save-button'],
    },
    {
        id: 'authority-new',
        route: '/identities?tab=authorities&authority=new',
        testIds: ['page-identities', 'page-authority-editor'],
        actions: [...IDENTITIES, 'authority-editor-back-button', 'authority-editor-save-button'],
    },
    {
        id: 'access-token-new',
        route: '/access-tokens/new',
        testIds: ['page-access-token'],
        actions: [
            'access-token-back-button',
            'access-token-save-button',
            'access-token-name',
            'access-token-never-expires',
            'access-token-form-save-button',
        ],
    },
    {
        id: 'secret-new',
        route: '/secrets/new',
        testIds: ['page-secret-editor'],
        actions: [
            'secret-editor-back-button',
            'secret-editor-generate-button',
            'secret-editor-add-tag-button',
            'secret-save-button',
        ],
    },
    {
        id: 'api-key-new',
        route: '/apikeys/new',
        testIds: ['page-api-key-editor'],
        actions: [
            'api-key-editor-back-button',
            'api-key-editor-create-button',
            'api-key-editor-submit-button',
            'api-key-editor-cancel-button',
        ],
    },
    {
        id: 'certificate-new',
        route: '/certificates/new',
        testIds: ['page-certificate-editor'],
        actions: [
            'certificate-editor-back-button',
            'certificate-editor-header-save-button',
            'certificate-editor-upload-button',
            'certificate-editor-add-tag-button',
            'certificate-editor-save-button',
        ],
    },
    {
        id: 'credential-provider-new',
        route: '/credential-providers/new',
        testIds: ['page-credential-provider-editor'],
        actions: [
            'credential-provider-editor-back-button',
            'credential-provider-editor-save-button',
            'credential-provider-editor-cancel-button',
        ],
    },
    {
        id: 'oidc-provider-new',
        route: '/oidc-providers/new',
        testIds: ['page-oidc-provider-editor'],
        actions: [
            'oidc-provider-editor-back-button',
            'oidc-provider-editor-save-button',
            'oidc-provider-editor-cancel-button',
        ],
    },
    {
        id: 'notification-new',
        route: '/notifications/new',
        testIds: ['page-notification-editor'],
        actions: [
            'notification-editor-back-button',
            'notification-editor-save-button',
            'notification-editor-cancel-button',
        ],
    },
    {
        id: 'policy-definition-new',
        route: '/policy-definitions/new?type=gateway',
        testIds: ['page-policy-definition-editor'],
        actions: [
            'policy-definition-editor-back-button',
            'policy-definition-editor-save-button',
            'policy-instructions-toggle',
        ],
    },
    {
        id: 'jwt-strategy-new',
        route: '/jwt-verification-strategies/new',
        testIds: ['page-jwt-strategy-editor'],
        actions: [
            'jwt-strategy-editor-back-button',
            'jwt-strategy-editor-check-jwks-button',
            'jwt-strategy-editor-save-button',
            'jwt-strategy-editor-cancel-button',
        ],
    },
    {
        id: 'sts-client-new',
        route: '/sts-clients/new',
        testIds: ['page-sts-client-editor'],
        actions: ['sts-client-editor-back-button', 'sts-client-editor-save-button', 'sts-client-editor-cancel-button'],
    },
];

export const LAYOUT_PAGES: readonly LayoutPage[] = [...SIDEBAR_PAGES, PROFILE_PAGE, ...CREATE_PAGES];
