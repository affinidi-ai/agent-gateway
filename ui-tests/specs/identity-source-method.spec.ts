/**
 * Identity source method tests
 *
 * Asserts that on a surface with several Caller Context methods the inbound
 * Identity panel offers the methods its type can read, shows the stored
 * choice, selects the first matching method beside methods it cannot all read,
 * and offers Any while every method is of the kind it reads.
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

const SECOND_JWT_METHOD = {
    ...JWT_METHOD,
    id: 'service-jwt',
    token_header: 'X-Service-Token',
};

const surfaceFixture = (identitySlots: Record<string, unknown>, methods: unknown[]) => ({
    surface_id: SURFACE_ID,
    name: 'Identity source method fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-identity-source-method',
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

    test('selects the first API key method when From API Key is chosen beside a JWT method', async ({page}) => {
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

    test('selects the first JWT method when no method is stored beside an API key method', async ({page}) => {
        await openSurface(
            page,
            {inbound: {type: 'from_jwt_claim', claim: 'oid'}},
            [API_KEY_METHOD, JWT_METHOD],
        );

        await expect(page.getByTestId('identity-panel-source-method-select')).toHaveValue('users-jwt');
    });

    test('offers Any JWT Bearer method while every method is a JWT method', async ({page}) => {
        await openSurface(
            page,
            {inbound: {type: 'from_jwt_claim', claim: 'oid'}},
            [JWT_METHOD, SECOND_JWT_METHOD],
        );

        const select = page.getByTestId('identity-panel-source-method-select');
        await expect(select).toHaveValue('');
        await expect(select.locator('option').first()).toHaveText('Any JWT Bearer method');
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
