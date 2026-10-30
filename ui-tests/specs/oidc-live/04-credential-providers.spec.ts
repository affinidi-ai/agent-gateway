/**
 * Credential providers through the dashboard
 *
 * A client credentials provider and a JWT bearer provider are created against the live Hydra
 * instances with the secrets from the secret editor. Neither the form, the list nor the API shows
 * a secret value afterwards.
 */

import {GatewayApi} from '../../helpers/gateway-api';
import {expect, test} from '../../helpers/fixtures';
import {env} from '../../helpers/oidc-live/env';
import {Entity, ensureSecrets, listEntities} from '../../helpers/oidc-live/gateway-state';
import {names, PREFIX} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {ticket} from '../../helpers/ticket';

async function findProvider(api: GatewayApi, name: string): Promise<Entity | undefined> {
    return (await listEntities(api, '/api/v1/credential-providers')).find(provider => provider.name === name);
}

test.describe('Credential providers', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    let world: World;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        world = loadWorld();
        for (const provider of await listEntities(api, '/api/v1/credential-providers')) {
            if (provider.name?.startsWith(PREFIX)) await api.delete(`/api/v1/credential-providers/${provider.id}`);
        }
        await ensureSecrets(api, world);
    });

    test.afterAll(async () => {
        await api.dispose();
    });

    test('creates a client credentials provider for hydra-a from the stored secrets', async ({page}) => {
        ticket('FTL-30886');
        await page.goto('/credential-providers/new');
        await page.getByTestId('provider-name').fill(names.providers.clientCredentials);
        await page.getByTestId('provider-type').selectOption('oauth2_client_credentials');
        await page.getByTestId('provider-token-endpoint').fill(`${env.hydraA.issuer}oauth2/token`);
        await page.getByTestId('provider-client-id-secret-ref').selectOption(names.secrets.ccClientId);
        await page.getByTestId('provider-client-secret-secret-ref').selectOption(names.secrets.ccClientSecret);
        await page.getByTestId('provider-default-scopes').fill(names.scopes.caller);
        const saved = page.waitForResponse(
            response => response.url().endsWith('/api/v1/credential-providers') && response.request().method() === 'POST'
        );
        await page.getByTestId('provider-save-button').click();
        expect((await saved).status()).toBe(201);
        await expect(page).toHaveURL(/credentials|settings/);

        const stored = await findProvider(api, names.providers.clientCredentials);
        expect(stored).toMatchObject({
            provider_type: 'oauth2_client_credentials',
            token_endpoint: `${env.hydraA.issuer}oauth2/token`,
            default_scopes: [names.scopes.caller],
        });
        expect(JSON.stringify(stored).includes(world.good.secret), 'the provider record carries the client secret').toBe(false);
    });

    test('creates a JWT bearer provider for hydra-b with the signing key and assertion settings', async ({page}) => {
        ticket('FTL-30885', 'FTL-30888');
        await page.goto('/credential-providers/new');
        await page.getByTestId('provider-name').fill(names.providers.jwtBearer);
        await page.getByTestId('provider-type').selectOption('oauth2_jwt_bearer');
        await page.getByTestId('provider-token-endpoint').fill(`${env.hydraB.issuer}oauth2/token`);
        await page.getByTestId('provider-signing-key-secret-ref').selectOption(names.secrets.signingKey);
        await page.getByTestId('provider-signing-algorithm').selectOption('RS256');
        await page.getByTestId('provider-key-id').fill(names.assertion.kid);
        await page.getByTestId('provider-assertion-issuer').fill(names.assertion.issuer);
        await page.getByTestId('provider-subject').fill(names.assertion.subject);
        await page.getByTestId('provider-client-id-secret-ref').selectOption(names.secrets.hop2ClientId);
        await page.getByTestId('provider-client-secret-secret-ref').selectOption(names.secrets.hop2ClientSecret);
        await page.getByTestId('provider-default-scopes').fill(names.scopes.hop2);
        const saved = page.waitForResponse(
            response => response.url().endsWith('/api/v1/credential-providers') && response.request().method() === 'POST'
        );
        await page.getByTestId('provider-save-button').click();
        expect((await saved).status()).toBe(201);

        const stored = await findProvider(api, names.providers.jwtBearer);
        expect(stored).toMatchObject({
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: `${env.hydraB.issuer}oauth2/token`,
            default_scopes: [names.scopes.hop2],
            jwt_bearer: {
                signing_algorithm: 'RS256',
                key_id: names.assertion.kid,
                assertion_issuer: names.assertion.issuer,
                assertion_subject: names.assertion.subject,
            },
        });
        const record = JSON.stringify(stored);
        expect(record.includes('PRIVATE KEY'), 'the provider record carries the key').toBe(false);
        expect(record.includes(world.hop2.secret), 'the provider record carries the client secret').toBe(false);
    });

    test('lists both providers with their types', async ({page}) => {
        await page.goto('/credentials?tab=credential-providers');
        const clientCredentials = page.locator('tr', {hasText: names.providers.clientCredentials});
        const jwtBearer = page.locator('tr', {hasText: names.providers.jwtBearer});
        await expect(clientCredentials).toHaveCount(1);
        await expect(clientCredentials).toContainText('Client Credentials');
        await expect(jwtBearer).toHaveCount(1);
        await expect(jwtBearer).toContainText('JWT Bearer');
    });

    test('reopens each provider with its references and without any secret value', async ({page}) => {
        ticket('FTL-30885', 'FTL-30888');
        const jwt = (await findProvider(api, names.providers.jwtBearer)) as Entity;
        await page.goto(`/credential-providers/${jwt.id}`);
        await expect(page.getByTestId('provider-signing-key-secret-ref')).toHaveValue(names.secrets.signingKey);
        await expect(page.getByTestId('provider-assertion-issuer')).toHaveValue(names.assertion.issuer);
        await expect(page.getByTestId('provider-key-id')).toHaveValue(names.assertion.kid);
        await expect(page.getByTestId('provider-client-secret-secret-ref')).toHaveValue(names.secrets.hop2ClientSecret);
        const jwtPage = await page.content();
        expect(jwtPage.includes(world.hop2.secret), 'the provider page shows the client secret').toBe(false);
        expect(jwtPage.includes('PRIVATE KEY'), 'the provider page shows the signing key').toBe(false);

        const cc = (await findProvider(api, names.providers.clientCredentials)) as Entity;
        await page.goto(`/credential-providers/${cc.id}`);
        await expect(page.getByTestId('provider-client-secret-secret-ref')).toHaveValue(names.secrets.ccClientSecret);
        await expect(page.getByTestId('provider-token-endpoint')).toHaveValue(`${env.hydraA.issuer}oauth2/token`);
        expect((await page.content()).includes(world.good.secret), 'the provider page shows the client secret').toBe(false);
    });

    test('refuses an http token endpoint that the gateway has not been told to allow', async ({page}) => {
        ticket('FTL-30888');
        await page.goto('/credential-providers/new');
        await page.getByTestId('provider-name').fill(`${PREFIX} refused`);
        await page.getByTestId('provider-type').selectOption('oauth2_client_credentials');
        await page.getByTestId('provider-token-endpoint').fill('http://127.0.0.1:1/oauth2/token');
        await page.getByTestId('provider-client-id-secret-ref').selectOption(names.secrets.ccClientId);
        await page.getByTestId('provider-client-secret-secret-ref').selectOption(names.secrets.ccClientSecret);
        await page.getByTestId('provider-save-button').click();

        await expect(page.getByTestId('provider-error')).toBeVisible();
        expect(await findProvider(api, `${PREFIX} refused`)).toBeUndefined();
    });
});
