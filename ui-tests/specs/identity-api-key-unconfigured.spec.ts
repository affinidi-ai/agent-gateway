/**
 * Unconfigured Identity tests
 *
 * Asserts a protected From API Key Identity whose stored key the surface
 * response reports as revoked or deleted, and so blocking
 * (`api_key_references`), gets the red
 * canvas ring, a short reason under the node, a labelled picker entry with a
 * warning in its panel, and a Save error; choosing an active key clears the
 * ring and warning, and an active stored key shows neither.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-identity-api-key-unconfigured';
const STORED_KEY = 'atgk_ui_test_stored';
const ACTIVE_KEY = 'atgk_ui_test_active';

type ReferenceStatus = 'active' | 'revoked' | 'missing';

function surfaceFixture(storedKey: string, status: ReferenceStatus) {
    return {
        surface_id: SURFACE_ID,
        name: 'Unconfigured Identity fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: '/ui-test-identity-api-key-unconfigured',
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
            protected: {type: 'from_api_key', api_key_id: storedKey},
        },
        api_key_references: [{key_id: storedKey, status, blocking: status !== 'active'}],
    };
}

const API_KEYS_FIXTURE = [
    {key_id: STORED_KEY, agent_id: SURFACE_ID, client_id: 'stored-client', status: 'revoked'},
    {key_id: ACTIVE_KEY, agent_id: SURFACE_ID, client_id: 'active-client', status: 'active'},
];

async function openSurface(page: Page, storedKey: string, status: ReferenceStatus) {
    await page.route(new RegExp(`/api/v1/api-keys/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: API_KEYS_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: surfaceFixture(storedKey, status)});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
}

const identityNode = (page: Page) => page.locator('[data-node-id="identity-protected"]');

const CASES = [
    {
        status: 'revoked' as const,
        reason: 'API key revoked',
        label: 'stored-client (revoked)',
        warning:
            'The API key this Identity uses was revoked. Select an active API key of this surface.',
    },
    {
        status: 'missing' as const,
        reason: 'API key deleted',
        label: `${STORED_KEY} (deleted)`,
        warning:
            'The API key this Identity uses was deleted. Select an active API key of this surface.',
    },
];

test.describe('Identity — unconfigured API key', () => {
    for (const {status, reason, label, warning} of CASES) {
        test(`a ${status} stored key rings the Identity until an active key is chosen`, async ({
            page,
        }) => {
            await openSurface(page, STORED_KEY, status);
            const node = identityNode(page);
            const ring = node.locator('.unconfigured-ring');
            await expect(ring).toHaveCount(1);
            await expect(ring).toHaveAttribute('stroke', '#e74a3b');
            await expect(node.locator('.node-incomplete-reason')).toHaveText(reason);

            await node.click();
            const picker = page.getByTestId('identity-panel-api-key-select');
            await expect(picker).toHaveValue(STORED_KEY);
            await expect(picker.locator('option:checked')).toHaveText(label);
            await expect(picker.locator('option:checked')).toBeDisabled();
            await expect(page.getByTestId('identity-api-key-revoked-warning')).toHaveText(warning);

            await page.getByTestId('surface-save-button').click();
            await expect(page.getByText(`Identity: ${warning}`, {exact: true})).toBeVisible();

            await picker.selectOption(ACTIVE_KEY);
            await expect(page.getByTestId('identity-api-key-revoked-warning')).toHaveCount(0);
            await expect(ring).toHaveCount(0);
            await expect(node.locator('.node-incomplete-reason')).toHaveCount(0);
        });
    }

    test('an active stored key shows no ring or warning', async ({page}) => {
        await openSurface(page, ACTIVE_KEY, 'active');
        const node = identityNode(page);
        await expect(node).toBeVisible();
        await expect(node.locator('.unconfigured-ring')).toHaveCount(0);
        await expect(node.locator('.node-incomplete-reason')).toHaveCount(0);

        await node.click();
        await expect(page.getByTestId('identity-panel-api-key-select')).toHaveValue(ACTIVE_KEY);
        await expect(page.getByTestId('identity-api-key-revoked-warning')).toHaveCount(0);
    });
});
