/**
 * Credential Provider Tests
 *
 * Covers creating a JWT bearer provider through the dashboard against the
 * real gateway:
 * - The form shows the signing fields only for the JWT Bearer type
 * - Client-side validation names the missing signing key
 * - The saved provider nests its assertion settings under jwt_bearer and the
 *   gateway never returns the key itself
 * - A rejected token endpoint is shown inline and nothing is stored
 * - A role that can view providers but not edit them sees the form read-only
 *
 * The token endpoint is a documentation address (TEST-NET-3), so the gateway
 * checks it without a DNS lookup and saving never calls it.
 */

import {generateKeyPairSync} from 'crypto';
import {expect, test} from '../helpers/fixtures';
import {GatewayApi} from '../helpers/gateway-api';
import {feature} from '../helpers/feature';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const TOKEN_ENDPOINT_HOST = '203.0.113.10';
const TOKEN_ENDPOINT = `https://${TOKEN_ENDPOINT_HOST}/token`;
const RUN_ID = `${Date.now()}`;
const KEY_SECRET_ID = `e2e-signing-key-${RUN_ID}`;
const PROVIDER_PREFIX = 'e2e-';

interface StoredProvider {
    id: string;
    provider_id: string;
    provider_type: string;
    token_endpoint?: string;
    default_scopes: string[];
    jwt_bearer?: Record<string, unknown>;
}

function signingKeyPem(): string {
    return generateKeyPairSync('ec', {namedCurve: 'P-256'})
        .privateKey.export({format: 'pem', type: 'pkcs8'})
        .toString();
}

async function deleteProviders(api: GatewayApi): Promise<void> {
    const listed = await api.get<StoredProvider[]>('/api/v1/credential-providers');
    for (const provider of Array.isArray(listed.body) ? listed.body : []) {
        if (provider.provider_id.startsWith(PROVIDER_PREFIX)) {
            await api.delete(`/api/v1/credential-providers/${provider.id}`);
        }
    }
}

async function findProvider(api: GatewayApi, providerId: string): Promise<StoredProvider | undefined> {
    const listed = await api.get<StoredProvider[]>('/api/v1/credential-providers');
    return listed.body.find(provider => provider.provider_id === providerId);
}

test.describe('JWT bearer credential provider', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    let secretRecordId: string;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        const secret = await api.post<{id: string}>('/api/v1/secrets/new', {
            name: `E2E signing key ${RUN_ID}`,
            secret_id: KEY_SECRET_ID,
            value: signingKeyPem(),
            secret_type: 'General',
        });
        expect(secret.status).toBe(201);
        secretRecordId = secret.body.id;
    });

    test.beforeEach(() => feature('target-authentication-dashboard'));

    test.afterEach(async () => {
        await deleteProviders(api);
    });

    test.afterAll(async () => {
        await api.delete(`/api/v1/secrets/${secretRecordId}`);
        await api.dispose();
    });

    test('shows the signing fields only for the JWT Bearer type', async ({page}) => {
        await page.goto(`${BASE_URL}/credential-providers/new`);
        await expect(page.getByTestId('jwt-bearer-section')).toHaveCount(0);

        await page.getByTestId('provider-type').selectOption('oauth2_jwt_bearer');

        await expect(page.getByTestId('jwt-bearer-section')).toBeVisible();
        await expect(page.getByTestId('jwt-bearer-encryption-banner')).toHaveAttribute('role', 'note');
        await expect(page.getByTestId('provider-signing-key-secret-ref')).toBeVisible();
        await expect(page.getByTestId('provider-assertion-issuer')).toBeVisible();
        await expect(page.getByTestId('provider-signing-algorithm')).toHaveValue('RS256');
        await expect(page.getByTestId('provider-callback-host')).toHaveCount(0);
    });

    test('names the missing signing key and does not save', async ({page}) => {
        let posted = false;
        await page.route('**/api/v1/credential-providers', async route => {
            if (route.request().method() === 'POST') posted = true;
            await route.continue();
        });
        await page.goto(`${BASE_URL}/credential-providers/new`);
        await page.getByTestId('provider-name').fill('E2E incomplete');
        await page.getByTestId('provider-type').selectOption('oauth2_jwt_bearer');
        await page.getByTestId('provider-token-endpoint').fill(TOKEN_ENDPOINT);
        await page.getByTestId('provider-save-button').click();

        await expect(page.getByTestId('provider-error')).toContainText('Signing key secret is required.');
        expect(posted).toBe(false);
    });

    test('creates the provider with its assertion settings nested under jwt_bearer', async ({page}) => {
        feature('target-authentication-dashboard', 'jwt-bearer-provider');
        const providerId = `e2e-vertex-${RUN_ID}`;
        let posted: Record<string, unknown> | null = null;
        await page.route('**/api/v1/credential-providers', async route => {
            if (route.request().method() === 'POST') posted = route.request().postDataJSON();
            await route.continue();
        });

        await page.goto(`${BASE_URL}/credential-providers/new`);
        await page.getByTestId('provider-name').fill(`E2E Vertex ${RUN_ID}`);
        await page.getByTestId('provider-type').selectOption('oauth2_jwt_bearer');
        await expect(page.getByTestId('provider-signing-key-secret-ref')).toContainText(`(${KEY_SECRET_ID})`);
        await page.getByTestId('provider-token-endpoint').fill(TOKEN_ENDPOINT);
        await page.getByTestId('provider-signing-key-secret-ref').selectOption(KEY_SECRET_ID);
        await page.getByTestId('provider-signing-algorithm').selectOption('ES256');
        await page.getByTestId('provider-assertion-issuer').fill('gateway@project.iam.gserviceaccount.com');
        await page.getByTestId('provider-key-id').fill('key-1');
        await page.getByTestId('provider-default-scopes').fill('cloud-platform');
        await page.getByTestId('provider-save-button').click();

        await expect.poll(() => posted).not.toBeNull();
        expect(posted).toMatchObject({
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: TOKEN_ENDPOINT,
            default_scopes: ['cloud-platform'],
            jwt_bearer: {
                signing_key_secret_ref: KEY_SECRET_ID,
                signing_algorithm: 'ES256',
                assertion_issuer: 'gateway@project.iam.gserviceaccount.com',
                key_id: 'key-1',
            },
        });
        expect(posted).not.toHaveProperty('signing_key_secret_ref');
        await expect(page).toHaveURL(/credentials|settings/);

        await expect.poll(async () => (await findProvider(api, providerId))?.jwt_bearer).toBeDefined();
        const stored = await findProvider(api, providerId);
        expect(stored).toMatchObject({
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: TOKEN_ENDPOINT,
            jwt_bearer: {assertion_issuer: 'gateway@project.iam.gserviceaccount.com', key_id: 'key-1'},
        });
        expect(JSON.stringify(stored)).not.toContain('PRIVATE KEY');
    });

    test('reopens a saved provider with its assertion settings filled in', async ({page}) => {
        feature('target-authentication-dashboard', 'jwt-bearer-provider');
        const providerId = `e2e-reopen-${RUN_ID}`;
        const created = await api.post<StoredProvider>('/api/v1/credential-providers', {
            name: `E2E reopen ${RUN_ID}`,
            provider_id: providerId,
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: TOKEN_ENDPOINT,
            default_scopes: ['cloud-platform'],
            token_refresh_enabled: false,
            jwt_bearer: {
                signing_key_secret_ref: KEY_SECRET_ID,
                signing_algorithm: 'ES256',
                assertion_issuer: 'gateway@project.iam.gserviceaccount.com',
                assertion_subject: 'service@project.iam.gserviceaccount.com',
                key_id: 'key-2',
            },
        });
        expect(created.status).toBe(201);

        await page.goto(`${BASE_URL}/credential-providers/${created.body.id}`);

        await expect(page.getByTestId('provider-assertion-issuer')).toHaveValue('gateway@project.iam.gserviceaccount.com');
        await expect(page.getByTestId('provider-subject')).toHaveValue('service@project.iam.gserviceaccount.com');
        await expect(page.getByTestId('provider-key-id')).toHaveValue('key-2');
        await expect(page.getByTestId('provider-signing-algorithm')).toHaveValue('ES256');
        await expect(page.getByTestId('provider-signing-key-secret-ref')).toHaveValue(KEY_SECRET_ID);
    });

    test('shows the gateway rejection inline and stores nothing when the token endpoint is not https', async ({page}) => {
        const providerId = `e2e-rejected-${RUN_ID}`;
        await page.goto(`${BASE_URL}/credential-providers/new`);
        await page.getByTestId('provider-name').fill(`E2E rejected ${RUN_ID}`);
        await page.getByTestId('provider-type').selectOption('oauth2_jwt_bearer');
        await page.getByTestId('provider-token-endpoint').fill(`http://${TOKEN_ENDPOINT_HOST}/token`);
        await page.getByTestId('provider-signing-key-secret-ref').selectOption(KEY_SECRET_ID);
        await page.getByTestId('provider-assertion-issuer').fill('gateway@example.com');
        await page.getByTestId('provider-save-button').click();

        await expect(page.getByTestId('provider-error')).toContainText('https');
        await expect(page).toHaveURL(/credential-providers\/new/);
        expect(await findProvider(api, providerId)).toBeUndefined();
    });

    test('shows a saved provider read-only, with the reason, to a role that cannot edit providers', async ({page}) => {
        const created = await api.post<StoredProvider>('/api/v1/credential-providers', {
            name: `E2E read-only ${RUN_ID}`,
            provider_id: `e2e-read-only-${RUN_ID}`,
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: TOKEN_ENDPOINT,
            default_scopes: [],
            token_refresh_enabled: false,
            jwt_bearer: {
                signing_key_secret_ref: KEY_SECRET_ID,
                signing_algorithm: 'ES256',
                assertion_issuer: 'gateway@example.com',
            },
        });
        expect(created.status).toBe(201);
        await page.route('**/api/v1/permissions', async route => {
            const response = await route.fetch();
            const permissions = await response.json();
            await route.fulfill({
                response,
                json: {...permissions, 'credential_providers.view': true, 'credential_providers.edit': false},
            });
        });

        await page.goto(`${BASE_URL}/credential-providers/${created.body.id}`);

        await expect(page.getByTestId('provider-assertion-issuer')).toHaveValue('gateway@example.com');
        await expect(page.getByTestId('provider-read-only')).toContainText(
            'Your role can view this provider but not change it.'
        );
        await expect(page.getByTestId('provider-name')).toBeDisabled();
        await expect(page.getByTestId('provider-save-button')).toHaveCount(0);
    });
});
