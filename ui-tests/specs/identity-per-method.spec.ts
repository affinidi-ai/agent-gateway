/**
 * Caller identity per method tests
 *
 * Asserts that on a surface with several Caller Context methods the inbound
 * Identity panel lists every method with its caller identity, shows a method's
 * stored identity, says which methods' callers are refused, and lets a method
 * set its own identity.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-identity-per-method';

const JWT_METHOD = {
    type: 'jwt_bearer',
    id: 'users-jwt',
    jwt_verification_strategy_id: 'idp',
    audiences: ['api://agent'],
    token_header: 'Authorization',
    token_scheme: 'Bearer',
    forward_header: false,
};

const API_KEY_METHOD = {
    type: 'api_key',
    id: 'partner-key',
    extraction: {source: 'http_header', field: 'X-API-Key'},
    secret_id: 'partner-keys',
};

const surfaceFixture = (identitySlots: Record<string, unknown>, methods: unknown[]) => ({
    surface_id: SURFACE_ID,
    name: 'Identity per method fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-identity-per-method',
        protocol: 'a2a',
        caller_authentication: {methods},
        publish_to_did_document: false,
        terminate_trace_id: false,
    },
    target: {
        endpoint: 'http://localhost:9999',
        mcp_tool_policies_enabled: false,
        identity_injection: {inject_vp: false},
        mpp_auto_pay: false,
    },
    identity_slots: identitySlots,
});

async function openSurface(
    page: Page,
    identitySlots: Record<string, unknown>,
    methods: unknown[] = [JWT_METHOD, API_KEY_METHOD],
) {
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: surfaceFixture(identitySlots, methods)});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await page.locator('[data-node-id="identity-inbound"]').click();
}

const row = (page: Page, position: number) => page.getByTestId(`identity-panel-method-identity-${position}`);

test.describe('Identity — caller identity per method', () => {
    test('lists every method and says whose callers this Identity cannot identify', async ({page}) => {
        await openSurface(page, {inbound: {type: 'from_jwt_claim', claim: 'oid'}});

        await expect(row(page, 0)).toContainText("Method 1: JWT, reads the 'authorization' header");
        await expect(page.getByTestId('identity-panel-method-identity-0-status')).toHaveText('Uses this Identity');
        await expect(row(page, 1)).toContainText("Method 2: API Key, reads the 'x-api-key' header");
        await expect(page.getByTestId('identity-panel-method-identity-1-status')).toContainText(
            'Callers of this method are refused',
        );
    });

    test('shows a method identity stored on the method', async ({page}) => {
        await openSurface(page, {inbound: {type: 'from_jwt_claim', claim: 'oid'}}, [
            JWT_METHOD,
            {...API_KEY_METHOD, identity: {type: 'from_api_key'}},
        ]);

        await expect(page.getByTestId('identity-panel-method-identity-1-select')).toHaveValue('from_api_key');
        await expect(page.getByTestId('identity-panel-method-identity-1-status')).toHaveCount(0);
    });

    test('lets a method identify its own callers', async ({page}) => {
        await openSurface(page, {inbound: {type: 'from_jwt_claim', claim: 'oid'}});

        await page.getByTestId('identity-panel-method-identity-1-select').selectOption('from_api_key');

        await expect(page.getByTestId('identity-panel-method-identity-1-status')).toHaveCount(0);
    });

    test('opens the new surface page without a page error', async ({page}) => {
        const errors: string[] = [];
        page.on('pageerror', (error) => errors.push(error.message));

        await page.goto(`${BASE_URL}/surfaces/new`);
        await page.waitForLoadState('networkidle');

        await expect(page.locator('#root')).not.toBeEmpty();
        expect(errors).toEqual([]);
    });
});
