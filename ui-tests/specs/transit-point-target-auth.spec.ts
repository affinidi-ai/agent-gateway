/**
 * Transit Point Target authentication tests
 *
 * Covers the Target authentication of a Transit Point (an agent-initiated outbound route): a
 * reserved header name shown next to the field and blocking Save, a Target that is not https
 * and a Transit Point that authenticates no caller shown as advisories that allow Save, scopes
 * written and cleared, and a Transit Point left unopened keeping its stored `target_auth`,
 * whatever its method, through a save.
 *
 * The gateway API is mocked with `page.route`.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-tp-target-auth';

type Json = Record<string, unknown>;

const staticSecret = (headerName: string): Json => ({
    method: {static_secret: {secret_id: 'partner-key', header_name: headerName, header_format: '{value}'}},
    auth_type: 'custom',
    fallback: 'reject',
});

function surfaceFixture(point: Json = {}): Json {
    return {
        surface_id: SURFACE_ID,
        name: 'Transit Point auth fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: `/${SURFACE_ID}`,
            protocol: 'a2a',
            caller_authentication: {
                methods: [
                    {
                        type: 'api_key',
                        secret_id: 'caller-key',
                        extraction: {source: 'http_header', field: 'X-Api-Key'},
                    },
                ],
            },
            publish_to_did_document: false,
            terminate_trace_id: false,
        },
        target: {
            endpoint: 'https://agent.example.com',
            mcp_tool_policies_enabled: false,
            identity_injection: {inject_vp: false},
            mpp_auto_pay: false,
        },
        transit: {
            points: [
                {
                    id: 'tp-1',
                    alias: 'partner',
                    protocol: 'a2a',
                    listen_address: '0.0.0.0:0',
                    target_endpoint: 'https://partner.example.com',
                    require_transit_token: true,
                    ...point,
                },
            ],
        },
    };
}

async function mockSurface(page: Page, initial: Json, saved: Request[]) {
    let current = initial;
    await page.route(/\/api\/v1\/credential-providers\/?$/, route => route.fulfill({json: []}));
    await page.route('**/api/v1/secrets/', route => route.fulfill({json: []}));
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async route => {
        const request = route.request();
        if (request.method() === 'PUT') {
            saved.push(request);
            current = {...request.postDataJSON(), surface_id: SURFACE_ID};
            await route.fulfill({json: current});
        } else if (request.method() === 'GET') {
            await route.fulfill({json: current});
        } else {
            await route.fallback();
        }
    });
}

const providerAuth = (scopes: string[]): Json => ({
    method: {
        credential_provider: {
            provider_id: 'prov-1',
            header_name: 'Authorization',
            header_format: 'Bearer {value}',
            scopes,
        },
    },
    fallback: 'reject',
});

const PROVIDER = {
    id: 'prov-1',
    name: 'Partner provider',
    provider_id: 'partner',
    provider_type: 'oauth2_client_credentials',
    default_scopes: [],
};

/** Opens the Transit Point and chooses the stored provider again, which shows the Scopes input. */
async function chooseStoredProvider(page: Page) {
    await page.route(/\/api\/v1\/credential-providers\/?$/, route => route.fulfill({json: [PROVIDER]}));
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await transitPoint(page).click();
    await page.getByTestId('transit-point-target-auth-type').selectOption('credential_provider');
    await page.getByTestId('transit-point-target-auth-provider').selectOption('prov-1');
}

const savedProvider = (request: Request): Json =>
    (request.postDataJSON().transit as {points: Array<{target_auth: {method: {credential_provider: Json}}}>})
        .points[0].target_auth.method.credential_provider;

const saveButton = (page: Page) => page.locator('button.btn-primary:has(.fa-save)');

/** Waits for the toast a blocked Save shows, so a later request count is read after the click was handled. */
async function expectSaveBlocked(page: Page, reason: string) {
    await expect(page.locator('#app-toast')).toContainText(reason);
}
const transitPoint = (page: Page) => page.getByTestId('surface-node-transit-point-a2a');

test.describe('Transit Point Target authentication', () => {
    test('a reserved header name is refused next to the field and blocks Save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture({target_auth: staticSecret('X-Partner-Key')}), saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await transitPoint(page).click();
        await page.getByTestId('transit-point-target-auth-type').selectOption('custom_header');
        await page.getByPlaceholder('secret-name').fill('partner-key');

        await page.getByPlaceholder('X-Auth').fill('Host');
        await expect(page.getByTestId('transit-point-target-auth-errors')).toContainText(
            'Header name must not be the reserved header Host',
        );
        await expect(page.getByPlaceholder('X-Auth')).toHaveAttribute('aria-invalid', 'true');
        await expect(page.getByPlaceholder('X-Auth')).toHaveAttribute(
            'aria-describedby',
            'transit-point-target-auth-errors',
        );
        await saveButton(page).click();
        await expectSaveBlocked(page, 'Header name must not be the reserved header Host');
        expect(saved).toHaveLength(0);

        await page.getByPlaceholder('X-Auth').fill('X-Partner-Key');
        await expect(page.getByTestId('transit-point-target-auth-errors')).toHaveCount(0);
    });

    test('a Transit Point credential on a Target that is not https shows an advisory and still saves', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(
            page,
            surfaceFixture({target_endpoint: 'http://partner.example.com', target_auth: staticSecret('X-Partner-Key')}),
            saved,
        );
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await transitPoint(page).click();

        await expect(page.getByTestId('transit-point-target-auth-advisories')).toContainText(
            'its Target must be an https URL. Save is allowed',
        );
        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
    });

    test('a Transit Point credential on a Transit Point that authenticates no caller shows an advisory and still saves', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(
            page,
            surfaceFixture({
                require_transit_token: false,
                allow_unauthenticated_callers: true,
                target_auth: staticSecret('X-Partner-Key'),
            }),
            saved,
        );
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await transitPoint(page).click();

        await expect(page.getByTestId('transit-point-target-auth-advisories')).toContainText(
            'it needs a Transit Point that authenticates its callers',
        );
        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
    });

    test('a Transit Point that authenticates its callers over an https Target shows no advisory', async ({page}) => {
        await mockSurface(page, surfaceFixture({target_auth: staticSecret('X-Partner-Key')}), []);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await transitPoint(page).click();

        await expect(page.getByTestId('transit-point-target-auth-advisories')).toHaveCount(0);
        await expect(page.getByTestId('transit-point-target-auth-errors')).toHaveCount(0);
    });

    test('an unopened Transit Point saves its stored target_auth unchanged', async ({page}) => {
        const saved: Request[] = [];
        const stored = {...staticSecret('X-Partner-Key'), future_field: {keep: true}};
        await mockSurface(page, surfaceFixture({target_auth: stored}), saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await expect(page.getByTestId('surface-node-target')).toBeVisible();

        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        const points = (saved[0].postDataJSON().transit as {points: Array<{target_auth: Json}>}).points;
        expect(points[0].target_auth).toEqual(stored);
    });

    test('a stored reserved header on an unopened Transit Point blocks Save, as the gateway refuses it on every save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture({target_auth: staticSecret('Host')}), saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await expect(page.getByTestId('surface-node-target')).toBeVisible();

        await saveButton(page).click();
        await expectSaveBlocked(page, 'Header name must not be the reserved header Host');
        expect(saved).toHaveLength(0);
    });

    test('the scopes an operator types on a Transit Point are saved', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture({target_auth: providerAuth(['read'])}), saved);
        await chooseStoredProvider(page);

        await page.getByTestId('transit-point-target-auth-provider-scopes').fill('read write');
        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        expect(savedProvider(saved[0]).scopes).toEqual(['read', 'write']);
    });

    test('emptying the scopes of a Transit Point clears the stored ones', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture({target_auth: providerAuth(['read'])}), saved);
        await chooseStoredProvider(page);

        const scopes = page.getByTestId('transit-point-target-auth-provider-scopes');
        await scopes.fill('write');
        await scopes.fill('');
        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        expect(savedProvider(saved[0])).not.toHaveProperty('scopes');
        expect(savedProvider(saved[0]).provider_id).toBe('prov-1');
    });

    test('an unopened Transit Point saves a stored method the panel cannot show unchanged', async ({page}) => {
        const saved: Request[] = [];
        const stored = {method: {credential_lookup: {target_identifier: 'partner'}}, fallback: 'reject'};
        await mockSurface(page, surfaceFixture({target_auth: stored}), saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await expect(page.getByTestId('surface-node-target')).toBeVisible();

        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        const points = (saved[0].postDataJSON().transit as {points: Array<{target_auth: Json}>}).points;
        expect(points[0].target_auth).toEqual(stored);
    });
});
