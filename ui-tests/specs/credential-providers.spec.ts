/**
 * Credential provider tests
 *
 * Covers the JWT Bearer provider form (Subject is required), the read-only editor shown to a
 * user who may view but not edit credential providers, and the redirect from the retired
 * OIDC Providers pages to the Credential providers tab, and deleting a secret that is in use.
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

test.describe('Secrets: delete a secret that is in use', () => {
    const IN_USE = {
        message: 'The secret is in use; remove its references first, or delete it with force=true',
        references: [
            {kind: 'surface', id: 'surf-1', name: 'Billing surface'},
            {kind: 'credential_provider', id: 'prov-1', name: 'Calendar provider'},
        ],
        hidden_references: 2,
    };

    async function mockSecrets(page: Page, deletes: string[]) {
        let gone = false;
        await page.route(/\/api\/v1\/secrets\/?$/, route =>
            route.fulfill({
                json: gone
                    ? []
                    : [{...SECRETS[0], tags: [], created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z'}],
            }),
        );
        await page.route(/\/api\/v1\/secrets\/sec-key(\?.*)?$/, async route => {
            if (route.request().method() !== 'DELETE') {
                await route.fallback();
                return;
            }
            deletes.push(route.request().url());
            if (route.request().url().includes('force=true')) {
                gone = true;
                await route.fulfill({status: 204});
            } else {
                await route.fulfill({status: 409, json: IN_USE});
            }
        });
    }

    async function clickDelete(page: Page) {
        const remove = page.getByTestId('secrets-delete-button-sec-key');
        await remove.click();
        await remove.click();
    }

    test('names the references, and Cancel deletes nothing', async ({page}) => {
        const deletes: string[] = [];
        await mockSecrets(page, deletes);
        await page.goto(`${BASE_URL}/secrets`);
        await clickDelete(page);

        const references = page.getByTestId('confirm-delete-secret-references');
        await expect(references).toContainText('Surface: Billing surface');
        await expect(references).toContainText('Credential provider: Calendar provider');
        await expect(page.getByTestId('confirm-delete-secret-references-hidden')).toHaveText(
            'and 2 more you cannot view',
        );

        await page.getByTestId('confirm-delete-secret-cancel').click();
        await expect(page.getByTestId('confirm-delete-secret-modal')).toHaveCount(0);
        expect(deletes).toHaveLength(1);
        await expect(page.getByTestId('secrets-delete-button-sec-key')).toBeVisible();
    });

    test('Delete secret anyway sends force=true and removes the secret', async ({page}) => {
        const deletes: string[] = [];
        await mockSecrets(page, deletes);
        await page.goto(`${BASE_URL}/secrets`);
        await clickDelete(page);
        await page.getByTestId('confirm-delete-secret-confirm').click();

        await expect.poll(() => deletes.length).toBe(2);
        expect(deletes[1]).toContain('force=true');
        await expect(page.getByTestId('secrets-delete-button-sec-key')).toHaveCount(0);
    });
});

