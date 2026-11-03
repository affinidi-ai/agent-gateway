/**
 * Identity "From API Key" tests
 *
 * Asserts the inbound Identity panel shows no API key picker, because each
 * caller is identified by the key it presents, while the protected (Managed
 * Agent) Identity panel keeps the picker.
 */

import type {Page} from '@playwright/test';
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
    {key_id: 'atgk_ui_test_agent', agent_id: 'agent-1', client_id: 'client-1', status: 'active'},
];

async function openSurface(page: Page) {
    await page.route(/\/api\/v1\/api-keys(\?.*)?$/, async (route) => {
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
