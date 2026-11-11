/**
 * Identity source method tests
 *
 * Asserts that on a surface with several Caller Context methods the inbound
 * Identity panel offers the methods its type can read, shows the stored
 * choice, and pre-selects the first matching method when the type changes.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-identity-source-method';

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

const surfaceFixture = (identitySlots: Record<string, unknown>) => ({
    surface_id: SURFACE_ID,
    name: 'Identity source method fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-identity-source-method',
        protocol: 'a2a',
        caller_authentication: {methods: [JWT_METHOD, API_KEY_METHOD]},
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

async function openSurface(page: Page, identitySlots: Record<string, unknown>) {
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: surfaceFixture(identitySlots)});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await page.locator('[data-node-id="identity-inbound"]').click();
}

test.describe('Identity — source method', () => {
    test('shows the stored method and lists only the methods the type can read', async ({page}) => {
        await openSurface(page, {
            inbound: {type: 'from_jwt_claim', claim: 'oid'},
            inbound_source_method: 'users-jwt',
        });

        const select = page.getByTestId('identity-panel-source-method-select');
        await expect(select).toBeVisible();
        await expect(select).toHaveValue('users-jwt');
        await expect(select.locator('option')).toHaveText([
            "Method 1: JWT, reads the 'authorization' header",
        ]);
    });

    test('pre-selects the API key method when From API Key is chosen', async ({page}) => {
        await openSurface(page, {
            inbound: {type: 'from_jwt_claim', claim: 'oid'},
            inbound_source_method: 'users-jwt',
        });

        await page.getByLabel('Identity Extraction Type').selectOption('from_api_key');

        const select = page.getByTestId('identity-panel-source-method-select');
        await expect(select).toHaveValue('partner-key');
        await expect(select.locator('option')).toHaveText([
            "Method 2: API Key, reads the 'x-api-key' header",
        ]);
    });
});
