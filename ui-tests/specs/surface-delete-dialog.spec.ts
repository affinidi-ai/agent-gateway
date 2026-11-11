/**
 * Surface delete confirmation tests
 *
 * Asserts deleting a surface opens a dialog that names the surface and says the
 * delete is permanent, sends nothing until the operator confirms with Delete
 * surface, and then sends one DELETE and returns to the surfaces list;
 * cancelling sends none and keeps the surface open.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-surface-delete';
const SURFACE_NAME = 'Surface delete fixture';

const SURFACE_FIXTURE = {
    surface_id: SURFACE_ID,
    name: SURFACE_NAME,
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-surface-delete',
        protocol: 'a2a',
        public: true,
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

async function openSurface(page: Page): Promise<Request[]> {
    const deletes: Request[] = [];
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        const method = route.request().method();
        if (method === 'GET') {
            await route.fulfill({json: SURFACE_FIXTURE});
        } else if (method === 'DELETE') {
            deletes.push(route.request());
            await route.fulfill({
                json: {success: true, message: `Surface '${SURFACE_ID}' deleted`, warnings: []},
            });
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    return deletes;
}

test.describe('Surface delete confirmation', () => {
    test('deletes only after confirming in the dialog, then returns to the list', async ({page}) => {
        const deletes = await openSurface(page);

        await page.getByTestId('surface-delete-button').click();

        const dialog = page.getByTestId('surface-delete-dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog.locator('.modal-title')).toHaveText('Delete Surface?');
        await expect(
            dialog.locator('.modal-title i.fa-triangle-exclamation.text-danger'),
        ).toBeVisible();
        await expect(dialog.locator('.modal-body p')).toHaveText([
            `You are about to permanently delete ${SURFACE_NAME} and all associated configuration. ` +
                'This action cannot be undone.',
            'Are you sure you want to continue?',
        ]);
        await expect(dialog.locator('.modal-body strong')).toHaveText(SURFACE_NAME);
        const confirm = page.getByTestId('surface-delete-dialog-confirm');
        await expect(confirm).toHaveText('Delete surface');
        await expect(confirm).toBeEnabled();
        expect(deletes).toHaveLength(0);

        await confirm.click();

        await expect(page).toHaveURL(`${BASE_URL}/surfaces`);
        await expect(dialog).toHaveCount(0);
        expect(deletes.map((request) => request.url())).toEqual([
            `${BASE_URL}/api/v1/surfaces/${SURFACE_ID}`,
        ]);
    });

    test('cancelling deletes nothing and keeps the surface open', async ({page}) => {
        const deletes = await openSurface(page);

        await page.getByTestId('surface-delete-button').click();
        const dialog = page.getByTestId('surface-delete-dialog');
        await expect(dialog).toBeVisible();
        await dialog.getByRole('button', {name: 'Cancel'}).click();

        await expect(dialog).toHaveCount(0);
        await expect(page).toHaveURL(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await expect(page.getByTestId('surface-delete-button')).toBeEnabled();
        expect(deletes).toHaveLength(0);
    });
});
