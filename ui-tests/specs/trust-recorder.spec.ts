/**
 * Trust Recorder tests
 *
 * Asserts the recorder warns when its entries rely on the surface Issuer but
 * the surface has none selected or its Issuer no longer exists, and explains how
 * Issuer, Authority and Entity relate.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-trust-recorder';
const SURFACE_ISSUER_TEMPLATE = '{{ surface.issuer_did }}';

function surfaceFixture(options: {issuerId?: string; authority: string}) {
    return {
        surface_id: SURFACE_ID,
        name: 'Trust recorder fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        ...(options.issuerId ? {issuer_id: options.issuerId} : {}),
        access_point: {
            listen_address: '0.0.0.0:0',
            route: '/ui-test-trust-recorder',
            protocol: 'a2a',
            trust_recorder: {
                entries: [
                    {
                        trust_registry_id: 'tr-fixture',
                        issuer_did: 'did:web:issuer.example',
                        authority_did: options.authority,
                        include_owned_agent: true,
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
}

const ISSUER_FIXTURE = {
    id: 'issuer-1',
    name: 'Issuer One',
    did: 'did:web:issuer-one.example',
    created_at: '2026-01-01T00:00:00Z',
};

async function openRecorderPanel(
    page: Page,
    options: {issuerId?: string; authority: string; issuers?: Array<typeof ISSUER_FIXTURE>},
) {
    const fixture = surfaceFixture(options);
    await page.route(/\/api\/v1\/issuers(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: options.issuers ?? []});
        } else {
            await route.fallback();
        }
    });
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: fixture});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await page.getByTestId('surface-node-trust-recorder').click();
    await expect(page.getByTestId('trust-recorder-panel-configure')).toBeVisible();
}

test.describe('Trust Recorder — surface Issuer warning', () => {
    test('warns in the panel and in the entry when the surface has no Issuer', async ({page}) => {
        await openRecorderPanel(page, {authority: SURFACE_ISSUER_TEMPLATE});

        const panelWarning = page.getByTestId('trust-recorder-panel-no-surface-issuer-warning');
        await expect(panelWarning).toBeVisible();
        await expect(panelWarning).toContainText('No Issuer is selected for this surface');
        await expect(panelWarning).toContainText('no records are written');
        await captureFullPage(page, 'trust-recorder-panel-no-surface-issuer');

        await page.getByTestId('trust-recorder-panel-configure').click();
        const entryWarning = page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning');
        await expect(entryWarning).toBeVisible();
        await expect(entryWarning).toContainText('This entry uses the surface Issuer as its Authority');
        await captureFullPage(page, 'trust-recorder-entry-no-surface-issuer');
    });

    test('does not warn when the surface has an Issuer that exists', async ({page}) => {
        await openRecorderPanel(page, {
            authority: SURFACE_ISSUER_TEMPLATE,
            issuerId: 'issuer-1',
            issuers: [ISSUER_FIXTURE],
        });
        await expect(page.getByTestId('trust-recorder-panel-configure')).toBeVisible();
        await expect(page.getByTestId('trust-recorder-panel-no-surface-issuer-warning')).toBeHidden();

        await page.getByTestId('trust-recorder-panel-configure').click();
        await expect(page.getByTestId('trust-recorder-entry-0-form')).toBeVisible();
        await expect(page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning')).toBeHidden();
    });

    test('warns when the surface still points at an Issuer that was deleted', async ({page}) => {
        await openRecorderPanel(page, {
            authority: SURFACE_ISSUER_TEMPLATE,
            issuerId: 'issuer-deleted',
            issuers: [ISSUER_FIXTURE],
        });

        const panelWarning = page.getByTestId('trust-recorder-panel-no-surface-issuer-warning');
        await expect(panelWarning).toBeVisible();
        await expect(panelWarning).toContainText("This surface's Issuer no longer exists");
        await expect(panelWarning).toContainText('no records are written');
        await captureFullPage(page, 'trust-recorder-panel-deleted-surface-issuer');

        await page.getByTestId('trust-recorder-panel-configure').click();
        await expect(page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning')).toContainText(
            "This surface's Issuer no longer exists",
        );
    });

    test('does not warn when the entry names an explicit Authority', async ({page}) => {
        await openRecorderPanel(page, {authority: 'did:web:authority.example'});
        await expect(page.getByTestId('trust-recorder-panel-no-surface-issuer-warning')).toBeHidden();

        await page.getByTestId('trust-recorder-panel-configure').click();
        await expect(page.getByTestId('trust-recorder-entry-0-form')).toBeVisible();
        await expect(page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning')).toBeHidden();
    });

    test('hides the entry warning when the operator switches to an explicit Authority', async ({page}) => {
        await openRecorderPanel(page, {authority: SURFACE_ISSUER_TEMPLATE});
        await page.getByTestId('trust-recorder-panel-configure').click();
        await expect(page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning')).toBeVisible();

        await page.getByTestId('trust-recorder-entry-0-authority-mode-explicit-radio').check();
        await expect(page.getByTestId('trust-recorder-entry-0-authority')).toBeVisible();
        await expect(page.getByTestId('trust-recorder-entry-0-no-surface-issuer-warning')).toBeHidden();
    });
});

test.describe('Trust Recorder — Issuer, Authority and Entity explainer', () => {
    test('is collapsed by default, explains each term and links to the guide', async ({page}) => {
        await openRecorderPanel(page, {authority: 'did:web:authority.example'});
        await page.getByTestId('trust-recorder-panel-configure').click();

        const toggle = page.getByTestId('trust-recorder-fullscreen-context-toggle');
        await expect(toggle).toHaveAttribute('aria-expanded', 'false');
        await expect(page.getByTestId('trust-recorder-fullscreen-context-body')).toBeHidden();

        await toggle.click();
        const body = page.getByTestId('trust-recorder-fullscreen-context-body');
        await expect(body).toBeVisible();
        for (const term of ['Authority', 'Entity', 'Issuer (this entry)', 'Surface Issuer']) {
            await expect(body).toContainText(term);
        }
        await expect(body).toContainText('does not sign records');

        const guide = page.getByTestId('trust-recorder-fullscreen-context-doclink');
        await expect(guide).toHaveAttribute('target', '_blank');
        await expect(guide).toHaveAttribute('rel', /noopener/);
        await expect(guide).toHaveAttribute('href', /^https:\/\//);
        await captureFullPage(page, 'trust-recorder-explainer-open');
    });
});
