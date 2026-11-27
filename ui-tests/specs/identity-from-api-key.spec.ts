/**
 * Identity "From API Key" tests
 *
 * Asserts the inbound Identity panel shows no API key picker, because each
 * caller is identified by the key it presents, while the protected (Managed
 * Agent) Identity panel keeps the picker. A Transit Point's Identity offers From API Key, with
 * no picker, only while that Transit Point's caller authentication is an API key; From JWT
 * Claims only behind JWT Bearer; and From mTLS certificate, with no certificate picker, only
 * behind mTLS.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-identity-from-api-key';

const SURFACE_FIXTURE = {
    surface_id: SURFACE_ID,
    name: 'Identity from API key fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-identity-from-api-key',
        protocol: 'a2a',
        caller_authentication: {
            methods: [
                {
                    type: 'api_key_provider',
                    extraction: {source: 'http_header', field: 'Authorization'},
                    agent_id: SURFACE_ID,
                },
            ],
        },
        publish_to_did_document: false,
        terminate_trace_id: false,
    },
    target: {
        endpoint: 'http://localhost:9999',
        mcp_tool_policies_enabled: false,
        identity_injection: {inject_vp: false},
        mpp_auto_pay: false,
    },
    identity_slots: {
        inbound: {type: 'from_api_key'},
        protected: {type: 'from_api_key', api_key_id: 'atgk_ui_test_agent'},
    },
};

const API_KEYS_FIXTURE = [
    {key_id: 'atgk_ui_test_agent', agent_id: SURFACE_ID, client_id: 'client-1', status: 'active'},
];

async function openSurface(page: Page) {
    await page.route(new RegExp(`/api/v1/api-keys/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: API_KEYS_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: SURFACE_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
}

test.describe('Identity — From API Key', () => {
    test('inbound Identity shows the per-caller line and no key picker', async ({page}) => {
        await openSurface(page);
        await page.locator('[data-node-id="identity-inbound"]').click();

        await expect(page.getByTestId('identity-panel-inbound-api-key-note')).toHaveText(
            'Each caller is identified by the API key it presents.',
        );
        await expect(page.getByTestId('identity-panel-api-key-select')).toHaveCount(0);
    });

    test('protected Identity keeps the key picker', async ({page}) => {
        await openSurface(page);
        await page.locator('[data-node-id="identity-protected"]').click();

        const picker = page.getByTestId('identity-panel-api-key-select');
        await expect(picker).toBeVisible();
        await expect(picker).toHaveValue('atgk_ui_test_agent');
        await expect(page.getByTestId('identity-panel-inbound-api-key-note')).toHaveCount(0);
    });
});

const TP_SURFACE_ID = 'ui-test-identity-from-api-key-tp';

const API_KEY_CALLER = {
    type: 'api_key',
    extraction: {source: 'http_header', field: 'X-API-Key'},
    secret_id: 'agents',
};

const JWT_CALLER = {
    type: 'jwt_bearer',
    jwt_verification_strategy_id: 'strategy-1',
    audiences: ['tr1'],
    token_header: 'Authorization',
    token_scheme: 'Bearer',
    forward_header: false,
};

function transitPointSurface(sourceAuth: Record<string, unknown>) {
    return {
        ...SURFACE_FIXTURE,
        surface_id: TP_SURFACE_ID,
        access_point: {...SURFACE_FIXTURE.access_point, route: `/${TP_SURFACE_ID}`},
        identity_slots: {inbound: {type: 'from_api_key'}},
        transit: {
            points: [
                {
                    id: 'tp-1',
                    alias: 'tr1',
                    protocol: 'a2a',
                    listen_address: '0.0.0.0:0',
                    target_endpoint: 'https://delta.example.com',
                    require_transit_token: false,
                    source_auth: sourceAuth,
                    managed_identity: {type: 'from_payload'},
                },
            ],
        },
    };
}

async function openTransitPointIdentity(page: Page, sourceAuth: Record<string, unknown>, saved: Request[]) {
    let current: Record<string, unknown> = transitPointSurface(sourceAuth);
    await page.route('**/api/v1/secrets/', route => route.fulfill({json: []}));
    await page.route('**/api/v1/config/surface-routing', route =>
        route.fulfill({
            json: {
                available_listen_addresses: ['0.0.0.0:0'],
                available_outbound_listen_addresses: ['0.0.0.0:0'],
                channel_path_prefix: [],
            },
        }),
    );
    await page.route(new RegExp(`/api/v1/surfaces/${TP_SURFACE_ID}(\\?.*)?$`), async (route) => {
        const request = route.request();
        if (request.method() === 'PUT') {
            saved.push(request);
            current = {...request.postDataJSON(), surface_id: TP_SURFACE_ID};
            await route.fulfill({json: current});
        } else if (request.method() === 'GET') {
            await route.fulfill({json: current});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${TP_SURFACE_ID}`);
    await page.locator('[data-node-id^="identity-transit-point-a2a"]').click();
}

const extractionType = (page: Page) => page.getByLabel('Identity Extraction Type');

test.describe('Transit Point Identity — From API Key', () => {
    test('picks From API Key behind API key caller authentication and saves it without a key', async ({page}) => {
        const saved: Request[] = [];
        await openTransitPointIdentity(page, API_KEY_CALLER, saved);

        await extractionType(page).selectOption('from_api_key');
        await expect(page.getByTestId('identity-panel-transit-api-key-note')).toHaveText(
            'Each caller is identified by the API key it presents to this Transit Point.',
        );
        await expect(page.getByTestId('identity-panel-api-key-select')).toHaveCount(0);

        await page.locator('button.btn-primary:has(.fa-save)').click();
        await expect.poll(() => saved.length).toBe(1);
        const points = (saved[0].postDataJSON().transit as {points: Array<Record<string, unknown>>}).points;
        expect(points[0].managed_identity).toEqual({type: 'from_api_key'});
    });

    test('does not offer From API Key behind JWT Bearer caller authentication', async ({page}) => {
        await openTransitPointIdentity(page, JWT_CALLER, []);

        await expect(extractionType(page).locator('option[value="from_api_key"]')).toBeDisabled();
        await expect(page.getByTestId('identity-panel-transit-api-key-unavailable')).toHaveText(
            "From API Key needs this Transit Point's caller authentication to be an API key.",
        );
    });
});

const MTLS_CALLER = {
    type: 'mtls',
    trust: {type: 'pinned', certificate_ids: ['agents-ca']},
};

const savedManagedIdentity = (saved: Request[]) =>
    (saved[0].postDataJSON().transit as {points: Array<Record<string, unknown>>}).points[0].managed_identity;

test.describe('Transit Point Identity — From JWT Claims', () => {
    test('picks From JWT Claims behind JWT Bearer caller authentication and saves its claims', async ({page}) => {
        const saved: Request[] = [];
        await openTransitPointIdentity(page, JWT_CALLER, saved);

        await extractionType(page).selectOption('from_jwt_claim');
        await page.getByPlaceholder('oid').fill('oid');
        await page.getByPlaceholder('iss, tid').fill('tid');

        await page.locator('button.btn-primary:has(.fa-save)').click();
        await expect.poll(() => saved.length).toBe(1);
        expect(savedManagedIdentity(saved)).toEqual({
            type: 'from_jwt_claim',
            claim: 'oid',
            namespace_claims: ['tid'],
        });
    });

    test('does not offer From JWT Claims behind API key caller authentication', async ({page}) => {
        await openTransitPointIdentity(page, API_KEY_CALLER, []);

        await expect(extractionType(page).locator('option[value="from_jwt_claim"]')).toBeDisabled();
        await expect(page.getByTestId('identity-panel-transit-jwt-claim-unavailable')).toHaveText(
            "From JWT Claims needs this Transit Point's caller authentication to be JWT Bearer.",
        );
    });
});

test.describe('Transit Point Identity — From mTLS certificate', () => {
    test('picks From mTLS certificate behind mTLS caller authentication and saves it without a certificate', async ({page}) => {
        const saved: Request[] = [];
        await openTransitPointIdentity(page, MTLS_CALLER, saved);

        await extractionType(page).selectOption('from_mtls');
        await expect(page.getByTestId('identity-panel-transit-mtls-note')).toHaveText(
            'Each caller is identified by the client certificate it presents to this Transit Point.',
        );

        await page.locator('button.btn-primary:has(.fa-save)').click();
        await expect.poll(() => saved.length).toBe(1);
        expect(savedManagedIdentity(saved)).toEqual({type: 'from_mtls'});
    });

    test('does not offer From mTLS certificate behind JWT Bearer caller authentication', async ({page}) => {
        await openTransitPointIdentity(page, JWT_CALLER, []);

        await expect(extractionType(page).locator('option[value="from_mtls"]')).toBeDisabled();
        await expect(page.getByTestId('identity-panel-transit-mtls-unavailable')).toHaveText(
            "From mTLS certificate needs this Transit Point's caller authentication to be mTLS, set through the API.",
        );
    });
});
