/**
 * API key revoke confirmation tests
 *
 * Asserts revoking an API key opens a dialog that says surfaces using the key
 * stop serving, the key can't be restored and a new key gives the surface a new
 * DID, sends nothing until the operator confirms with Revoke API key, and then
 * sends one revoke; cancelling or closing sends none, and a failed revoke shows
 * an error toast.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const OWNER = 'ui-test-key-revoke-owner';
const KEY_ID = 'atgk_ui_test_key_revoke';

const KEYS_FIXTURE = [
    {
        key_id: KEY_ID,
        agent_id: OWNER,
        client_id: 'revoke-client',
        status: 'active',
        created_at: '2026-07-01T10:00:00Z',
        labels: {},
        issuer: {actor: 'admin', method: 'api'},
    },
];

async function mockKeys(page: Page, revokeStatus = 204): Promise<Request[]> {
    const revokes: Request[] = [];
    await page.route(/\/api\/v1\/api-keys(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: KEYS_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.route(
        new RegExp(`/api/v1/api-keys/${OWNER}/${KEY_ID}/revoke(\\?.*)?$`),
        async (route) => {
            if (route.request().method() !== 'POST') {
                await route.fallback();
                return;
            }
            revokes.push(route.request());
            if (revokeStatus === 204) {
                await route.fulfill({status: 204, body: ''});
            } else {
                await route.fulfill({status: revokeStatus, json: {message: 'Revoke refused'}});
            }
        },
    );
    return revokes;
}

async function openDialog(page: Page) {
    await page.goto(`${BASE_URL}/secrets?tab=api-keys`);
    await page.getByTestId(`api-keys-revoke-button-${KEY_ID}`).click();
    const dialog = page.getByTestId('api-key-revoke-dialog');
    await expect(dialog).toBeVisible();
    return dialog;
}

test.describe('API key revoke confirmation', () => {
    test('revokes only after a second confirmation in the dialog', async ({page}) => {
        const revokes = await mockKeys(page);
        const dialog = await openDialog(page);

        await expect(dialog.locator('.modal-title')).toHaveText('Revoke API key');
        await expect(
            dialog.locator('.modal-title i.fa-triangle-exclamation.text-danger'),
        ).toBeVisible();
        await expect(dialog).toContainText('revoke-client');
        await expect(dialog).toContainText('Surfaces that use this key will stop serving');
        await expect(dialog).toContainText("A revoked key can't be restored");
        await expect(dialog).toContainText('gives the surface a new DID');
        const confirm = page.getByTestId('api-key-revoke-dialog-confirm');
        await expect(confirm).toBeEnabled();
        expect(revokes).toHaveLength(0);

        await confirm.click();

        await expect(dialog).toHaveCount(0);
        expect(revokes.map((request) => request.url())).toEqual([
            `${BASE_URL}/api/v1/api-keys/${OWNER}/${KEY_ID}/revoke`,
        ]);
    });

    test('cancelling revokes nothing', async ({page}) => {
        const revokes = await mockKeys(page);
        const dialog = await openDialog(page);

        await dialog.getByRole('button', {name: 'Cancel'}).click();

        await expect(dialog).toHaveCount(0);
        expect(revokes).toHaveLength(0);
    });

    test('closing revokes nothing', async ({page}) => {
        const revokes = await mockKeys(page);
        const dialog = await openDialog(page);

        await dialog.getByRole('button', {name: 'Close'}).click();

        await expect(dialog).toHaveCount(0);
        expect(revokes).toHaveLength(0);
    });

    test('a failed revoke shows an error toast', async ({page}) => {
        const revokes = await mockKeys(page, 500);
        await openDialog(page);

        await page.getByTestId('api-key-revoke-dialog-confirm').click();

        await expect(page.getByText(/^Revoke failed: /)).toBeVisible();
        expect(revokes).toHaveLength(1);
    });
});
