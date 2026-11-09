/**
 * API key delete confirmation tests
 *
 * Asserts deleting an API key opens a dialog that says surfaces using the key
 * stop serving, sends nothing until the operator confirms with Delete API key,
 * and then sends one plain DELETE; cancelling sends none.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const OWNER = 'ui-test-key-delete-owner';
const KEY_ID = 'atgk_ui_test_key_delete';

const KEYS_FIXTURE = [
    {
        key_id: KEY_ID,
        agent_id: OWNER,
        client_id: 'delete-client',
        status: 'active',
        created_at: '2026-07-01T10:00:00Z',
        labels: {},
        issuer: {actor: 'admin', method: 'api'},
    },
];

async function mockKeys(page: Page): Promise<Request[]> {
    const deletes: Request[] = [];
    await page.route(/\/api\/v1\/api-keys(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: KEYS_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.route(new RegExp(`/api/v1/api-keys/${OWNER}/${KEY_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() !== 'DELETE') {
            await route.fallback();
            return;
        }
        deletes.push(route.request());
        await route.fulfill({status: 204, body: ''});
    });
    return deletes;
}

test.describe('API key delete confirmation', () => {
    test('deletes only after a second confirmation in the dialog', async ({page}) => {
        const deletes = await mockKeys(page);
        await page.goto(`${BASE_URL}/secrets?tab=api-keys`);

        await page.getByTestId(`api-keys-delete-button-${KEY_ID}`).click();

        const dialog = page.getByTestId('api-key-delete-dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog.locator('.modal-title')).toHaveText('Delete API key');
        await expect(
            dialog.locator('.modal-title i.fa-triangle-exclamation.text-danger'),
        ).toBeVisible();
        await expect(dialog).toContainText('delete-client');
        await expect(dialog).toContainText('Surfaces that use it will stop working');
        const confirm = page.getByTestId('api-key-delete-dialog-confirm');
        await expect(confirm).toBeEnabled();
        expect(deletes).toHaveLength(0);

        await confirm.click();

        await expect(dialog).toHaveCount(0);
        expect(deletes.map((request) => request.url())).toEqual([
            `${BASE_URL}/api/v1/api-keys/${OWNER}/${KEY_ID}`,
        ]);
    });

    test('cancelling deletes nothing', async ({page}) => {
        const deletes = await mockKeys(page);
        await page.goto(`${BASE_URL}/secrets?tab=api-keys`);

        await page.getByTestId(`api-keys-delete-button-${KEY_ID}`).click();
        const dialog = page.getByTestId('api-key-delete-dialog');
        await expect(dialog).toBeVisible();
        await dialog.getByRole('button', {name: 'Cancel'}).click();

        await expect(dialog).toHaveCount(0);
        expect(deletes).toHaveLength(0);
    });
});
