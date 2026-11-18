/**
 * Response Authentication tests
 *
 * Asserts the Managed Agent panel's Response Authentication section saves each
 * method as `target.response_auth`, keeps it on reopen, and sends `null` once
 * it is switched off.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-response-authentication';
const T = 'managed-agent-response-auth';

function surfaceFixture(responseAuth?: Record<string, unknown>) {
    return {
        surface_id: SURFACE_ID,
        name: 'Response authentication fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: '/ui-test-response-authentication',
            protocol: 'a2a',
            publish_to_did_document: false,
            terminate_trace_id: false,
        },
        target: {
            endpoint: 'https://agent.example/a2a',
            mcp_tool_policies_enabled: false,
            identity_injection: {inject_vp: false},
            ...(responseAuth ? {response_auth: responseAuth} : {}),
        },
    };
}

/** Serves the surface from a store that each save replaces, as the gateway does. */
async function serveSurface(page: Page, responseAuth?: Record<string, unknown>) {
    let stored: Record<string, unknown> = surfaceFixture(responseAuth);
    await page.route(/\/api\/v1\/secrets\/?(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: [{id: 'bravo-key', name: 'Bravo key', secret_type: 'ApiKey'}]});
        } else {
            await route.fallback();
        }
    });
    await page.route(/\/api\/v1\/certificates(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                json: [
                    {id: 'bravo-cert', name: 'Bravo server', kind: 'client_leaf', active: true},
                    {id: 'bravo-ca', name: 'Bravo CA', kind: 'ca', active: true},
                    {id: 'gateway-cert', name: 'Gateway client', kind: 'client_leaf', active: true},
                ],
            });
        } else {
            await route.fallback();
        }
    });
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        const method = route.request().method();
        if (method === 'GET') {
            await route.fulfill({json: stored});
        } else if (method === 'PUT') {
            const body = route.request().postDataJSON();
            const target = {...body.target};
            if (target.response_auth === null) delete target.response_auth;
            stored = {...body, target};
            await route.fulfill({json: stored});
        } else {
            await route.fallback();
        }
    });
}

async function openManagedAgent(page: Page) {
    await page.getByTestId('surface-node-target').click();
    await expect(page.getByTestId(`${T}-method`)).toBeVisible();
}

function isSurfaceSave(request: Request) {
    return request.method() === 'PUT' && request.url().includes(`/api/v1/surfaces/${SURFACE_ID}`);
}

async function save(page: Page) {
    const saved = page.waitForRequest(isSurfaceSave);
    await page.getByTestId('surface-save-button').click();
    return (await saved).postDataJSON().target.response_auth;
}

test.describe('Managed Agent — Response Authentication', () => {
    test('saves an API key and shows it on reopen', async ({page}) => {
        await serveSurface(page);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await openManagedAgent(page);

        await page.getByTestId(`${T}-method`).selectOption('api_key');
        await page.getByTestId(`${T}-header`).fill('X-Bravo-Key');
        await page.getByTestId(`${T}-secret`).selectOption('bravo-key');
        expect(await save(page)).toEqual({api_key: {header_name: 'X-Bravo-Key', secret_id: 'bravo-key'}});

        await page.reload();
        await openManagedAgent(page);
        await expect(page.getByTestId(`${T}-method`)).toHaveValue('api_key');
        await expect(page.getByTestId(`${T}-header`)).toHaveValue('X-Bravo-Key');
        await expect(page.getByTestId(`${T}-secret`)).toHaveValue('bravo-key');
    });

    test('saves mTLS with a pinned certificate and a client certificate and shows it on reopen', async ({page}) => {
        await serveSurface(page);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await openManagedAgent(page);

        await page.getByTestId(`${T}-method`).selectOption('mtls');
        await expect(page.getByTestId(`${T}-trust-cert-bravo-ca`)).toHaveCount(0);
        await page.getByTestId(`${T}-trust-cert-bravo-cert`).check();
        await page.getByTestId(`${T}-client-cert`).selectOption('gateway-cert');
        expect(await save(page)).toEqual({
            mtls: {
                server_trust: {type: 'pinned', certificate_ids: ['bravo-cert']},
                client_certificate_id: 'gateway-cert',
            },
        });

        await page.reload();
        await openManagedAgent(page);
        await expect(page.getByTestId(`${T}-method`)).toHaveValue('mtls');
        await expect(page.getByTestId(`${T}-trust-mode`)).toHaveValue('pinned');
        await expect(page.getByTestId(`${T}-trust-cert-bravo-cert`)).toBeChecked();
        await expect(page.getByTestId(`${T}-client-cert`)).toHaveValue('gateway-cert');
    });

    test('saves mTLS with a CA and shows it on reopen', async ({page}) => {
        await serveSurface(page);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await openManagedAgent(page);

        await page.getByTestId(`${T}-method`).selectOption('mtls');
        await page.getByTestId(`${T}-trust-mode`).selectOption('ca');
        await page.getByTestId(`${T}-trust-cert-bravo-ca`).check();
        expect(await save(page)).toEqual({
            mtls: {server_trust: {type: 'ca', ca_certificate_ids: ['bravo-ca']}},
        });

        await page.reload();
        await openManagedAgent(page);
        await expect(page.getByTestId(`${T}-trust-mode`)).toHaveValue('ca');
        await expect(page.getByTestId(`${T}-trust-cert-bravo-ca`)).toBeChecked();
    });

    test('keeps a stored setting it did not edit, and sends null once switched off', async ({page}) => {
        const stored = {api_key: {header_name: 'X-Agent-Key', secret_id: 'bravo-key'}};
        await serveSurface(page, stored);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await openManagedAgent(page);

        await page.locator('#inject-identity-vp').click();
        expect(await save(page)).toEqual(stored);

        await page.getByTestId(`${T}-method`).selectOption('off');
        expect(await save(page)).toBeNull();

        await page.reload();
        await openManagedAgent(page);
        await expect(page.getByTestId(`${T}-method`)).toHaveValue('off');
    });
});
