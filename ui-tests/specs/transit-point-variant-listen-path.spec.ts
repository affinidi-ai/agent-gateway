/**
 * A base Transit Point's Listen Path edit reaching its variants
 *
 * The gateway builds a variant's routes from the base Transit Point's path, so a variant
 * copy left on the base's old path is served nowhere and refused as
 * `listen_path_variant_unserved`. Editing the base path, switching to a variant and saving
 * must send that variant the new path, and the reloaded variant must show it.
 *
 * The gateway API is mocked with `page.route`.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-tp-variant-listen-path';
const LISTENER = 'https://gateway.example.com:9443';

type Json = Record<string, unknown>;

const point = (listenPath: string): Json => ({
    id: 'tp-1',
    alias: 'partner',
    protocol: 'a2a',
    listen_address: LISTENER,
    listen_path: listenPath,
    target_endpoint: 'https://partner.example.com',
    require_transit_token: true,
});

function surfaceFixture(): Json {
    return {
        surface_id: SURFACE_ID,
        name: 'Variant Listen Path fixture',
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
        transit: {points: [point('/agents/old')]},
        variants: [
            {
                id: 'variant-beta',
                alias: 'beta',
                name: 'Beta',
                enabled: true,
                overrides: {transit: {points: [point('/agents/old')]}},
            },
        ],
    };
}

async function mockGateway(page: Page, saved: Request[]) {
    let current = surfaceFixture();
    await page.route(/\/api\/v1\/credential-providers\/?$/, route => route.fulfill({json: []}));
    await page.route('**/api/v1/secrets/', route => route.fulfill({json: []}));
    await page.route(/\/api\/v1\/config\/surface-routing(\?.*)?$/, route =>
        route.fulfill({
            json: {
                available_listen_addresses: ['https://gateway.example.com'],
                available_outbound_listen_addresses: [LISTENER],
                shared_hostname_outbound_addresses: [],
                channel_path_prefix: [{id: 'agents', name: 'agents', prefix: '/agents'}],
            },
        }),
    );
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

const saveButton = (page: Page) => page.locator('button.btn-primary:has(.fa-save)');
const transitPoint = (page: Page) => page.getByTestId('surface-node-transit-point-a2a');
const customPath = (page: Page) => page.getByPlaceholder('my-agent/v1');

async function switchVariant(page: Page, name: string) {
    await page.locator('.surface-variants-widget').click();
    await page.getByRole('menuitem', {name}).click();
}

test.describe('A base Transit Point Listen Path edit', () => {
    test('reaches a variant that held the old path, through a save and a reload', async ({page}) => {
        const saved: Request[] = [];
        await mockGateway(page, saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await transitPoint(page).click();
        await expect(customPath(page)).toHaveValue('old');
        await customPath(page).fill('new');

        await switchVariant(page, 'Beta');
        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);

        const body = saved[0].postDataJSON() as {
            transit: {points: Array<{listen_path?: string}>};
            variants: Array<{overrides?: {transit?: {points?: Array<{listen_path?: string}>}}}>;
        };
        expect(body.transit.points[0].listen_path).toBe('/agents/new');
        // A variant equal to its base may send no override at all; one it sends holds the new path.
        for (const variantPoint of body.variants[0].overrides?.transit?.points ?? []) {
            expect(variantPoint.listen_path ?? '/agents/new').toBe('/agents/new');
        }

        await page.reload();
        await switchVariant(page, 'Beta');
        await transitPoint(page).click();
        await expect(customPath(page)).toHaveValue('new');
    });
});
