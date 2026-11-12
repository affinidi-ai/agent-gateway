/**
 * Trust Check authority list tests
 *
 * Asserts the Trust Check editor saves a query that names several Authorities
 * as `query.authority_ids` with `authority_sources`, and stops adding
 * Authorities at the gateway's limit.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-trust-check-authority-lists';
const AUTHORITY_A = {id: 'authority-a', name: 'Authority A', did: 'did:web:authority-a.example', created_at: '2026-01-01T00:00:00Z'};
const AUTHORITY_B = {id: 'authority-b', name: 'Authority B', did: 'did:web:authority-b.example', created_at: '2026-01-01T00:00:00Z'};
const TRUST_CHECK_AUTHORITIES_MAX = 25;

function trustCheck(query: Record<string, unknown>, sources: Record<string, unknown>) {
    return {
        id: 'q-1',
        trust_registry_id: 'tr-fixture',
        query_type: 'recognition',
        ...sources,
        query: {...query, entity_id: '{{ input.agent.did }}'},
    };
}

function surfaceFixture(check: Record<string, unknown>) {
    return {
        surface_id: SURFACE_ID,
        name: 'Trust Check authority list fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: '/ui-test-trust-check-authority-lists',
            protocol: 'a2a',
            trust_check_list: [check],
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
}

async function openTrustCheckEditor(page: Page, check: Record<string, unknown>) {
    const fixture = surfaceFixture(check);
    await page.route(/\/api\/v1\/authorities(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: [AUTHORITY_A, AUTHORITY_B]});
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
    await expect(page.getByTestId('trust-check-query-0-form')).toBeVisible();
}

function isSurfaceSave(request: Request) {
    return request.method() === 'PUT' && request.url().includes(`/api/v1/surfaces/${SURFACE_ID}`);
}

test.describe('Trust Check — several Authorities in one query', () => {
    test('saves two picked Authorities as authority_ids with their sources', async ({page}) => {
        await openTrustCheckEditor(
            page,
            trustCheck({authority_id: AUTHORITY_A.did}, {authority_source: 'authority'}),
        );

        await page.getByTestId('trust-check-query-0-add-authority').click();
        await page.getByTestId('trust-check-query-0-authority-1').click();
        await page.getByText(AUTHORITY_B.name, {exact: true}).click();
        await captureFullPage(page, 'trust-check-two-authorities');
        await page.getByTestId('trust-check-save').click();

        const saved = page.waitForRequest(isSurfaceSave);
        await page.getByTestId('surface-save-button').click();
        const [check] = (await saved).postDataJSON().access_point.trust_check_list;
        expect(check.query.authority_ids).toEqual([AUTHORITY_A.did, AUTHORITY_B.did]);
        expect(check.query).not.toHaveProperty('authority_id');
        expect(check.authority_sources).toEqual({
            [AUTHORITY_A.did]: 'authority',
            [AUTHORITY_B.did]: 'authority',
        });
        expect(check).not.toHaveProperty('authority_source');
    });

    test('disables Add Authority once the query names the most Authorities a Trust Check checks', async ({page}) => {
        const authorities = Array.from({length: TRUST_CHECK_AUTHORITIES_MAX}, (_, i) => `did:web:authority-${i}.example`);
        await openTrustCheckEditor(page, trustCheck({authority_ids: authorities}, {}));

        await expect(page.getByTestId('trust-check-query-0-add-authority')).toBeDisabled();
        await expect(page.getByTestId('trust-check-add-query')).toBeDisabled();
        await captureFullPage(page, 'trust-check-authority-limit');
    });
});
