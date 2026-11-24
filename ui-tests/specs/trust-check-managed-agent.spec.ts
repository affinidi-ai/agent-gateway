/**
 * Transit Point Trust Check — managed agent subject
 *
 * Asserts the Trust Check editor of a Transit Point saves a query that checks
 * the managed agent calling out as `subject: "managed_agent"` with a blank
 * entity, which the gateway fills in with the agent's DID.
 */

import type {Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-trust-check-managed-agent';
const OUTBOUND_LISTENER = '127.0.0.1:0';
const AUTHORITY = {id: 'authority-a', name: 'Authority A', did: 'did:web:authority-a.example', created_at: '2026-01-01T00:00:00Z'};

const fixture = {
    surface_id: SURFACE_ID,
    name: 'Trust Check managed agent fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-trust-check-managed-agent',
        protocol: 'a2a',
        publish_to_did_document: false,
        terminate_trace_id: false,
    },
    target: {
        endpoint: 'http://localhost:9999',
        mcp_tool_policies_enabled: false,
        identity_injection: {inject_vp: false},
        mpp_auto_pay: false,
    },
    trust_check_split: true,
    transit: {
        points: [
            {
                id: 'tp-fixture',
                alias: 'partner',
                name: 'partner',
                target_endpoint: 'https://partner.example',
                protocol: 'a2a',
                listen_address: OUTBOUND_LISTENER,
                require_transit_token: true,
                trust_check_list: [
                    {
                        id: 'q-1',
                        trust_registry_id: 'tr-fixture',
                        query_type: 'recognition',
                        authority_source: 'authority',
                        query: {authority_id: AUTHORITY.did, entity_id: '{{ input.agent.did }}'},
                    },
                ],
            },
        ],
    },
};

function isSurfaceSave(request: Request) {
    return request.method() === 'PUT' && request.url().includes(`/api/v1/surfaces/${SURFACE_ID}`);
}

test.describe('Transit Point Trust Check — managed agent', () => {
    test('saves a query that checks the managed agent calling out', async ({page}) => {
        await page.route('**/api/v1/config/surface-routing', async (route) => {
            const response = await route.fetch();
            const routing = await response.json();
            await route.fulfill({
                response,
                json: {
                    ...routing,
                    available_outbound_listen_addresses: [
                        ...(routing.available_outbound_listen_addresses ?? []),
                        OUTBOUND_LISTENER,
                    ],
                },
            });
        });
        await page.route(/\/api\/v1\/authorities(\?.*)?$/, async (route) => {
            if (route.request().method() === 'GET') {
                await route.fulfill({json: [AUTHORITY]});
            } else {
                await route.fallback();
            }
        });
        await page.route(/\/api\/v1\/issuers(\?.*)?$/, async (route) => {
            if (route.request().method() === 'GET') {
                await route.fulfill({json: []});
            } else {
                await route.fallback();
            }
        });
        await page.route(/\/api\/v1\/trust-registries(\?.*)?$/, async (route) => {
            if (route.request().method() === 'GET') {
                await route.fulfill({json: [{id: 'tr-fixture', name: 'Fixture registry'}]});
            } else {
                await route.fallback();
            }
        });
        await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
            const method = route.request().method();
            if (method === 'GET') {
                await route.fulfill({json: fixture});
            } else if (method === 'PUT') {
                await route.fulfill({json: route.request().postDataJSON()});
            } else {
                await route.fallback();
            }
        });

        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await page.getByTestId('surface-node-trust-check').first().click();
        await page.getByTestId('trust-check-panel-configure').click();
        await expect(page.getByTestId('trust-check-query-0-subject')).toContainText('Destination agent');

        await page.getByTestId('trust-check-query-0-subject').click();
        await page.getByText("This surface's managed agent").click();
        await expect(page.getByTestId('trust-check-query-0-entity-managed-agent')).toBeVisible();
        await captureFullPage(page, 'trust-check-managed-agent');
        await page.getByTestId('trust-check-save').click();

        const saved = page.waitForRequest(isSurfaceSave);
        await page.getByTestId('surface-save-button').click();
        const [point] = (await saved).postDataJSON().transit.points;
        expect(point.trust_check_list).toHaveLength(1);
        expect(point.trust_check_list[0].subject).toBe('managed_agent');
        expect(point.trust_check_list[0].query.entity_id).toBe('');
        expect(point.trust_check_list[0].query.authority_id).toBe(AUTHORITY.did);
    });
});
