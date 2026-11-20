/**
 * Self recognition check tests
 *
 * Asserts the Transit Point panel's Self Recognition Check switch is disabled with a note while
 * the surface has no Trust Recorder that records the owned agent, and saves
 * `transit.points[].self_recognition_check` once it can run.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-self-recognition-check';

function surfaceFixture(options: {withRecorder: boolean}) {
    return {
        surface_id: SURFACE_ID,
        name: 'Self recognition check fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: '/ui-test-self-recognition-check',
            protocol: 'a2a',
            ...(options.withRecorder
                ? {
                      trust_recorder: {
                          entries: [
                              {
                                  trust_registry_id: 'tr-fixture',
                                  issuer_did: 'did:web:issuer.example',
                                  authority_did: 'did:web:authority.example',
                                  include_owned_agent: true,
                              },
                          ],
                      },
                  }
                : {}),
            publish_to_did_document: false,
            terminate_trace_id: false,
        },
        target: {
            endpoint: 'http://localhost:9999',
            mcp_tool_policies_enabled: false,
            identity_injection: {inject_vp: false},
            mpp_auto_pay: false,
        },
        transit: {
            points: [
                {
                    id: 'tp-fixture',
                    alias: 'partner',
                    name: 'partner',
                    target_endpoint: 'https://partner.example',
                    protocol: 'a2a',
                    require_transit_token: true,
                    managed_identity: {type: 'static', did: 'did:web:tp.example'},
                },
            ],
        },
    };
}

async function openTransitPointPanel(page: Page, options: {withRecorder: boolean}) {
    const fixture = surfaceFixture(options);
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
    await page.getByTestId('surface-node-transit-point-a2a').click();
    await expect(page.getByTestId('transit-point-self-recognition-check-switch')).toBeVisible();
}

function isSurfaceSave(request: Request) {
    return request.method() === 'PUT' && request.url().includes(`/api/v1/surfaces/${SURFACE_ID}`);
}

test.describe('Transit Point — self recognition check', () => {
    test('is disabled with a note while the surface has no Trust Recorder', async ({page}) => {
        await openTransitPointPanel(page, {withRecorder: false});

        await expect(page.getByTestId('transit-point-self-recognition-check-switch')).toBeDisabled();
        await expect(page.getByTestId('transit-point-self-recognition-check-note')).toContainText(
            'Requires a Trust Recorder that records the owned agent',
        );
        await captureFullPage(page, 'self-recognition-check-needs-recorder');
    });

    test('saves the trust registry picked once the surface records the owned agent', async ({page}) => {
        await openTransitPointPanel(page, {withRecorder: true});

        const toggle = page.getByTestId('transit-point-self-recognition-check-switch');
        await expect(toggle).toBeEnabled();
        await expect(page.getByTestId('transit-point-self-recognition-check-note')).toBeHidden();
        await toggle.check();

        const registry = page.getByTestId('transit-point-self-recognition-check-registry-tr-fixture');
        await expect(registry).not.toBeChecked();
        await expect(page.getByTestId('transit-point-self-recognition-check-registry-required')).toBeVisible();
        await registry.check();
        await expect(page.getByTestId('transit-point-self-recognition-check-registry-required')).toBeHidden();
        await captureFullPage(page, 'self-recognition-check-on');

        const saved = page.waitForRequest(isSurfaceSave);
        await page.getByTestId('surface-save-button').click();
        const [point] = (await saved).postDataJSON().transit.points;
        expect(point.self_recognition_check).toEqual({trust_registry_ids: ['tr-fixture']});
    });
});
