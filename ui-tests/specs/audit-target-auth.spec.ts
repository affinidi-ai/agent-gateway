/**
 * Audit Log: Target credential failure records
 *
 * A `target_auth_failed` record shows how the request ended (refused, or forwarded without the
 * credential when the fallback is passthrough), the credential outcome and the token endpoint's
 * OAuth error code. The audit API is mocked with `page.route`.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

type Json = Record<string, unknown>;

function record(targetAuth: Json | null): Json {
    return {
        id: 'evt-1',
        timestamp: '2026-11-02T10:00:00Z',
        channel_name: 'Orders',
        surface_id: 'orders',
        event: {
            request_rejected: {
                stage: 'forward',
                reason: 'target_auth_failed',
                http_status: 502,
                ...(targetAuth ? {target_auth: targetAuth} : {}),
            },
        },
    };
}

async function openAudit(page: Page, entry: Json) {
    await page.route(/\/api\/v1\/audit(\?.*)?$/, route =>
        route.fulfill({json: {events: [entry], total: 1, page: 1, limit: 25, category_counts: {}}}),
    );
    await page.goto(`${BASE_URL}/audit`);
    await page.getByTestId('audit-item-0').click();
    await expect(page.getByTestId('audit-detail-panel')).toBeVisible();
}

test.describe('Audit Log: Target credential failures', () => {
    test('a passthrough record is titled Forwarded without Target credential', async ({page}) => {
        await openAudit(page, record({outcome: 'passthrough'}));

        await expect(page.getByTestId('audit-item-0')).toContainText('Forwarded without Target credential');
        await expect(page.getByTestId('audit-detail-title')).toContainText(
            'Forwarded without Target credential',
        );
        await expect(page.getByTestId('audit-fields')).toContainText('Credential outcome');
        await expect(page.getByTestId('audit-fields')).toContainText('passthrough');
    });

    test('a rejected record is titled Request refused and shows the OAuth error', async ({page}) => {
        await openAudit(page, record({outcome: 'rejected', oauth_error: 'invalid_client'}));

        await expect(page.getByTestId('audit-item-0')).toContainText('Request refused');
        await expect(page.getByTestId('audit-item-0')).not.toContainText('Forwarded without');
        await expect(page.getByTestId('audit-fields')).toContainText('Credential outcome');
        await expect(page.getByTestId('audit-fields')).toContainText('OAuth error');
        await expect(page.getByTestId('audit-fields')).toContainText('invalid_client');
    });

    test('a record without target_auth shows no credential rows', async ({page}) => {
        await openAudit(page, record(null));

        await expect(page.getByTestId('audit-fields')).not.toContainText('Credential outcome');
        await expect(page.getByTestId('audit-fields')).not.toContainText('OAuth error');
    });
});
