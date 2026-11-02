/**
 * Credential provider tests
 *
 * Covers the JWT Bearer provider form (Subject is required), the read-only editor shown to a
 * user who may view but not edit credential providers, and the redirect from the retired
 * OIDC Providers pages to the Credential providers tab.
 *
 * The gateway API is mocked with `page.route`, so the tests need no stored providers or secrets.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

const SECRETS = [
    {id: 'sec-key', name: 'Service account key', secret_id: 'SA_KEY', tenant_id: null},
];

const STORED_PROVIDER = {
    id: 'prov-1',
    name: 'Calendar provider',
    provider_id: 'calendar',
    provider_type: 'oauth2_jwt_bearer',
    token_endpoint: 'https://oauth2.googleapis.com/token',
    jwt_issuer: 'sa@project.iam.gserviceaccount.com',
    jwt_subject: 'user@example.com',
    jwt_signing_key_secret_ref: 'SA_KEY',
    default_scopes: [],
    token_refresh_enabled: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

async function mockProviderApis(page: Page, posted: Request[] = []) {
    await page.route('**/api/v1/secrets/', route => route.fulfill({json: SECRETS}));
    await page.route('**/api/v1/config/surface-routing', route =>
        route.fulfill({json: {available_listen_addresses: [], oauth_callback_route: '/oauth'}}),
    );
    await page.route('**/api/v1/credential-providers/prov-1', route =>
        route.fulfill({json: STORED_PROVIDER}),
    );
    await page.route(/\/api\/v1\/credential-providers\/?$/, async route => {
        if (route.request().method() === 'POST') {
            posted.push(route.request());
            await route.fulfill({status: 201, json: {...STORED_PROVIDER, id: 'prov-new'}});
        } else {
            await route.fulfill({json: [STORED_PROVIDER]});
        }
    });
}

test.describe('Credential providers: JWT Bearer form', () => {
    test('requires a Subject before it saves, then saves it', async ({page}) => {
        const posted: Request[] = [];
        await mockProviderApis(page, posted);
        await page.goto(`${BASE_URL}/credential-providers/new`);

        await page.getByTestId('credential-provider-type-select').selectOption('oauth2_jwt_bearer');
        await page.locator('#name').fill('Calendar provider');
        await page.locator('#provider_id').fill('calendar');
        await page.locator('#token_endpoint').fill('https://oauth2.googleapis.com/token');
        await page
            .getByTestId('credential-provider-jwt-issuer-input')
            .fill('sa@project.iam.gserviceaccount.com');
        await page.getByTestId('credential-provider-jwt_signing_key_secret_ref-select').selectOption('SA_KEY');

        await expect(page.getByTestId('credential-provider-jwt-subject-input')).toBeVisible();
        await page.getByTestId('credential-provider-editor-save-button').click();
        await expect(page.locator('.alert-danger')).toContainText(
            'Subject is required for JWT Bearer providers.',
        );
        expect(posted).toHaveLength(0);

        await page.getByTestId('credential-provider-jwt-subject-input').fill('user@example.com');
        await page.getByTestId('credential-provider-editor-save-button').click();
        await expect.poll(() => posted.length).toBe(1);
        expect(posted[0].postDataJSON()).toMatchObject({
            provider_type: 'oauth2_jwt_bearer',
            provider_id: 'calendar',
            jwt_issuer: 'sa@project.iam.gserviceaccount.com',
            jwt_subject: 'user@example.com',
            jwt_signing_key_secret_ref: 'SA_KEY',
        });
    });
});

test.describe('Credential providers: read-only view', () => {
    // The test login always signs in as an administrator, so the permissions the dashboard
    // loads are mocked to a user who may view credential providers but not edit them.
    test('opens the editor read-only without edit permission', async ({page}) => {
        await mockProviderApis(page);
        await page.route('**/api/v1/permissions', route =>
            route.fulfill({
                json: {
                    'dashboard.view': true,
                    'credential_providers.view': true,
                    'credential_providers.edit': false,
                    'credential_providers.delete': false,
                },
            }),
        );
        await page.goto(`${BASE_URL}/credential-providers/prov-1`);

        await expect(page.getByTestId('credential-provider-editor-read-only-notice')).toBeVisible();
        await expect(page.getByTestId('credential-provider-editor-save-button')).toHaveCount(0);
        await expect(page.locator('#name')).toBeDisabled();
        await expect(page.getByTestId('credential-provider-jwt-subject-input')).toBeDisabled();
    });

    test('shows Save and editable fields with edit permission', async ({page}) => {
        await mockProviderApis(page);
        await page.goto(`${BASE_URL}/credential-providers/prov-1`);

        await expect(page.getByTestId('credential-provider-editor-save-button')).toBeEnabled();
        await expect(page.getByTestId('credential-provider-editor-read-only-notice')).toHaveCount(0);
        await expect(page.locator('#name')).toBeEnabled();
    });
});

test.describe('Credential providers: retired OIDC Providers pages', () => {
    for (const path of ['/oidc-providers', '/oidc-providers/abc']) {
        test(`${path} lands on the Credential providers tab`, async ({page}) => {
            await mockProviderApis(page);
            await page.goto(`${BASE_URL}${path}`);

            await expect(page).toHaveURL(/\/credentials\?tab=credential-providers$/);
            await expect(
                page.getByTestId('credentials-credential-providers-tab-trigger'),
            ).toHaveAttribute('aria-selected', 'true');
        });
    }
});
