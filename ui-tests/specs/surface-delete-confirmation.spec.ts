/**
 * Surface delete confirmation tests
 *
 * Asserts the surface page's delete button sends nothing and opens a
 * confirmation naming the surface with focus on Cancel, that Cancel sends no
 * DELETE and returns focus to the delete button, and that Delete sends one and
 * returns to the surface list.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-surface-delete';

const SURFACE_FIXTURE = {
    surface_id: SURFACE_ID,
    name: 'Surface delete fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-surface-delete',
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
};

async function openSurface(page: Page): Promise<Request[]> {
    const deletes: Request[] = [];
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        const method = route.request().method();
        if (method === 'GET') {
            await route.fulfill({json: SURFACE_FIXTURE});
        } else if (method === 'DELETE') {
            deletes.push(route.request());
            await route.fulfill({status: 204, body: ''});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await expect(page.getByTestId('surface-delete-button')).toBeVisible();
    return deletes;
}

test.describe('Surface delete confirmation', () => {
    test('asks before deleting and deletes nothing on Cancel', async ({page}) => {
        const deletes = await openSurface(page);

        await page.getByTestId('surface-delete-button').click();

        const confirmation = page.getByTestId('surface-delete-confirm');
        await expect(confirmation).toBeVisible();
        await expect(page.getByTestId('surface-delete-confirm-name')).toHaveText(
            'Delete Surface delete fixture?',
        );
        await expect(confirmation).toContainText(
            'You are about to permanently delete this surface and all associated configuration. This action cannot be undone.',
        );
        await expect(confirmation).toContainText('Are you sure you want to continue?');
        await expect(page.getByTestId('surface-delete-confirm-confirm')).toHaveText('Delete');
        await expect(page.getByTestId('surface-delete-confirm-cancel')).toBeFocused();

        await page.keyboard.press('Enter');

        await expect(confirmation).toBeHidden();
        await expect(page.getByTestId('surface-delete-button')).toBeFocused();
        await expect(page).toHaveURL(new RegExp(`/surfaces/${SURFACE_ID}$`));
        expect(deletes).toHaveLength(0);
    });

    test('deletes the surface once and returns to the list on Delete', async ({page}) => {
        const deletes = await openSurface(page);

        await page.getByTestId('surface-delete-button').click();
        await page.getByTestId('surface-delete-confirm-confirm').click();

        await expect(page).toHaveURL(/\/surfaces$/);
        expect(deletes).toHaveLength(1);
    });
});
