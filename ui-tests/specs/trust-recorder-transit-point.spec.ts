/**
 * Transit Point Trust Recorder
 *
 * Asserts a Transit Point's own Trust Recorder sits on the Managed Agent →
 * Transit Point arrow and saves to `transit.points[].trust_recorder`, never to
 * the surface's `access_point.trust_recorder`.
 */

import type {Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-trust-recorder-transit-point';
const OUTBOUND_LISTENER = '127.0.0.1:0';
const SURFACE_ISSUER_TEMPLATE = '{{ surface.issuer_did }}';
const AUTHORITY = {id: 'authority-a', name: 'Authority A', did: 'did:web:authority-a.example', created_at: '2026-01-01T00:00:00Z'};

const fixture = {
    surface_id: SURFACE_ID,
    name: 'Transit Point recorder fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-trust-recorder-transit-point',
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
                trust_recorder: {
                    entries: [
                        {
                            trust_registry_id: 'tr-fixture',
                            issuer_did: 'did:web:issuer.example',
                            authority_did: AUTHORITY.did,
                            authority_source: 'authority',
                            include_owned_agent: true,
                        },
                    ],
                },
            },
        ],
    },
};

function isSurfaceSave(request: Request) {
    return request.method() === 'PUT' && request.url().includes(`/api/v1/surfaces/${SURFACE_ID}`);
}

test.describe('Trust Recorder — Transit Point', () => {
    test('saves an edited Transit Point recorder to its Transit Point', async ({page}) => {
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
        await page.getByTestId('surface-node-trust-recorder').click();
        await expect(page.getByTestId('trust-recorder-panel-results-ref')).toContainText(
            'request leg (Managed Agent → Transit Point)',
        );
        await page.getByTestId('trust-recorder-panel-configure').click();
        await page.getByTestId('trust-recorder-entry-0-authority-mode-surface-issuer-radio').check();
        await captureFullPage(page, 'trust-recorder-transit-point');
        await page.getByTestId('trust-recorder-save').click();

        const saved = page.waitForRequest(isSurfaceSave);
        await page.getByTestId('surface-save-button').click();
        const body = (await saved).postDataJSON();
        expect(body.access_point.trust_recorder).toBeUndefined();
        const [entry] = body.transit.points[0].trust_recorder.entries;
        expect(body.transit.points[0].trust_recorder.entries).toHaveLength(1);
        expect(entry.trust_registry_id).toBe('tr-fixture');
        expect(entry.authority_did).toBe(SURFACE_ISSUER_TEMPLATE);
        expect(entry.include_owned_agent).toBe(true);
    });
});
