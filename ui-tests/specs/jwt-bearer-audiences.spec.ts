/**
 * JWT Bearer audiences in the Caller Context editor
 *
 * A JWT Bearer method stored without audiences shows a warning that a new one
 * cannot be saved without one. The Audience Claim select switches the method
 * to the client a token was issued to, with a warning that its callers get no
 * per-user delegated credentials, and Save stays blocked until a client is
 * listed.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-jwt-bearer-audiences';
const STRATEGY_ID = 'ui-test-idp';

const SURFACE_FIXTURE = {
    surface_id: SURFACE_ID,
    name: 'JWT Bearer audiences fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-jwt-bearer-audiences',
        protocol: 'a2a',
        caller_authentication: {
            methods: [
                {
                    type: 'jwt_bearer',
                    jwt_verification_strategy_id: STRATEGY_ID,
                    audiences: [],
                    token_header: 'Authorization',
                    token_scheme: 'Bearer',
                    forward_header: false,
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
};

const STRATEGIES_FIXTURE = [{id: STRATEGY_ID, name: 'UI test identity provider'}];

async function openJwtMethod(page: Page) {
    await page.route(/\/api\/v1\/jwt-verification-strategies(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: STRATEGIES_FIXTURE});
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
    await page.locator('[data-node-id="caller-auth"]').click();
    await page.getByTestId('caller-auth-panel-method-0-configure-button').click();
    await expect(page.getByTestId('caller-auth-editor-method-settings')).toBeVisible();
}

test.describe('Caller Context — JWT Bearer audiences', () => {
    test('a method stored without audiences warns and checks aud', async ({page}) => {
        await openJwtMethod(page);

        await expect(page.getByTestId('caller-auth-audiences-missing-warning')).toContainText(
            'A new method cannot be saved without one',
        );
        await expect(page.getByTestId('caller-auth-jwt-audience-claim')).toHaveValue('aud');
        await expect(page.getByTestId('caller-auth-jwt-audience-claim-warning')).toHaveCount(0);
    });

    test('checking client_id warns that grants are withheld and needs a listed client', async ({page}) => {
        await openJwtMethod(page);

        await page.getByTestId('caller-auth-jwt-audience-claim').selectOption('client_id');

        await expect(page.getByTestId('caller-auth-jwt-audience-claim-warning')).toContainText(
            'these callers get no per-user delegated credentials',
        );
        await expect(page.getByTestId('caller-auth-audiences-missing-warning')).toHaveCount(0);
        await expect(page.getByTestId('caller-auth-editor-method-0-status')).toHaveAttribute(
            'aria-label',
            'List the client_id values this method accepts',
        );
    });
});
