/**
 * Edit and delete flows through the dashboard
 *
 * Changing the issuer of a strategy a surface uses, and deleting strategies, providers, secrets and
 * surfaces. A second surface with a static-key strategy stands in for the cases where the local
 * Hydra's loopback JWKS URI would get in the way of a save.
 */

import {APIRequestContext, Page} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {callAgent} from '../../helpers/oidc-live/agent';
import {env} from '../../helpers/oidc-live/env';
import {
    Entity,
    createSecondSurface,
    createStaticStrategy,
    ensureDenyRule,
    ensureProviders,
    ensureStrategy,
    ensureSurface,
    findSurface,
    listEntities,
} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, newContext} from '../../helpers/oidc-live/hydra';
import {StaticKey, generateStaticKey, signStaticJwt} from '../../helpers/oidc-live/static-jwt';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {ticket} from '../../helpers/ticket';

const STATIC_NAME = `${names.surface} static strategy`;
const SECOND_SURFACE = `${names.surface}-static`;
const SECOND_ROUTE = `${env.routePrefix}/static`;
const SECOND_ENTRY = `${env.accessPointOrigin}${SECOND_ROUTE}`;
const OLD_ISSUER = 'https://static-issuer.oidc-e2e.example';
const NEW_ISSUER = 'https://static-issuer-2.oidc-e2e.example';

async function twoStepDelete(page: Page, title: string): Promise<void> {
    await page.locator(`button[title='${title}']`).click();
    await page.locator("button[title='Click again to confirm deletion']").click();
}

test.describe('Edit and delete', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let api: GatewayApi;
    let world: World;
    let mainSurface: Entity;
    let staticKey: StaticKey;
    let staticStrategy: Entity;
    let secondSurface: Entity;

    const staticToken = (issuer: string) => signStaticJwt(staticKey, {iss: issuer, aud: SECOND_ENTRY, sub: 'static-caller'});

    async function listedStrategies(): Promise<Entity[]> {
        return listEntities(api, '/api/v1/jwt-verification-strategies');
    }

    test.beforeAll(async () => {
        http = await newContext();
        api = await GatewayApi.connect();
        world = loadWorld();
        mainSurface = await ensureSurface(api, world);
        await ensureStrategy(api, 'b');
        staticKey = generateStaticKey('oidc-e2e-static');
    });

    test.afterAll(async () => {
        await api.dispose();
        await http.dispose();
    });

    test('deleting a strategy that no surface uses asks first and removes it', async ({page}) => {
        ticket('FTL-30890');
        await page.goto('/credentials?tab=jwt-verification');
        await page.getByTestId(`strategy-delete-button-${names.strategies.hydraB.id}`).click();
        const confirm = page.getByTestId('strategy-delete-confirm');
        await expect(confirm).toContainText(`Delete JWT verification strategy "${names.strategies.hydraB.name}"?`);
        await expect(confirm).toContainText('No surface uses it.');
        expect((await listedStrategies()).some(s => s.id === names.strategies.hydraB.id)).toBe(true);

        await page.getByTestId('strategy-delete-confirm-button').click();
        await expect(page.getByTestId(`strategy-row-${names.strategies.hydraB.id}`)).toHaveCount(0);
        expect((await listedStrategies()).some(s => s.id === names.strategies.hydraB.id)).toBe(false);
    });

    test('the delete dialog for the strategy the surface uses names the surface, and cancelling keeps it', async ({page}) => {
        ticket('FTL-30890');
        await ensureStrategy(api, 'a');
        await page.goto('/credentials?tab=jwt-verification');
        await page.getByTestId(`strategy-delete-button-${names.strategies.hydraA.id}`).click();
        const confirm = page.getByTestId('strategy-delete-confirm');
        await expect(confirm).toContainText('Used by 1 surface:');
        await expect(confirm).toContainText(names.surface);
        await expect(confirm).toContainText('A caller that presents a token is refused with 500');

        await page.getByTestId('strategy-delete-cancel-button').click();
        await expect(confirm).toHaveCount(0);
        expect((await listedStrategies()).some(s => s.id === names.strategies.hydraA.id)).toBe(true);
    });

    test('a static-key strategy and a second surface that uses it', async () => {
        ticket('FTL-30890');
        staticStrategy = await createStaticStrategy(api, {name: STATIC_NAME, issuer: OLD_ISSUER, jwk: staticKey.publicJwk});
        const {jwtBearer} = await ensureProviders(api);
        secondSurface = await createSecondSurface(api, {
            name: SECOND_SURFACE,
            route: SECOND_ROUTE,
            strategyId: staticStrategy.id,
            providerId: jwtBearer.id,
            policyId: await ensureDenyRule(api),
        });
        expect((await callAgent2(http, staticToken(OLD_ISSUER))).status).toBe(200);
    });

    test('changing the issuer of that strategy in the dashboard takes effect without a restart', async ({page}) => {
        ticket('FTL-30890');
        await page.goto(`/jwt-verification-strategies/${staticStrategy.id}`);
        await expect(page.getByTestId('strategy-issuer')).toHaveValue(OLD_ISSUER);
        await page.getByTestId('strategy-issuer').fill(NEW_ISSUER);
        const saved = page.waitForResponse(
            response => response.url().endsWith(`/jwt-verification-strategies/${staticStrategy.id}`) && response.request().method() === 'PUT'
        );
        await page.getByTestId('strategy-save-button').click();
        expect((await saved).status()).toBe(200);

        const stored = (await listedStrategies()).find(s => s.id === staticStrategy.id);
        expect(stored?.expected_issuer).toBe(NEW_ISSUER);

        const old = await callAgent2(http, staticToken(OLD_ISSUER));
        expect(old.status).toBe(403);
        expect((await callAgent2(http, staticToken(NEW_ISSUER))).status).toBe(200);
    });

    test('changing the issuer of the pinned hydra-a strategy marks the pin stale, and the gateway refuses the save', async ({page}) => {
        ticket('FTL-30890');
        await page.goto(`/jwt-verification-strategies/${names.strategies.hydraA.id}`);
        await expect(page.getByTestId('strategy-pinned-server')).toBeVisible();
        await page.getByTestId('strategy-issuer').fill(`${env.hydraA.issuer}changed`);
        await expect(page.getByTestId('strategy-pinned-stale')).toBeVisible();

        const saved = page.waitForResponse(
            response => response.url().endsWith(`/jwt-verification-strategies/${names.strategies.hydraA.id}`) && response.request().method() === 'PUT'
        );
        await page.getByTestId('strategy-save-button').click();
        expect((await saved).status()).toBe(400);
        await expect(page.getByTestId('strategy-error')).toContainText('jwks_uri rejected');

        const stored = (await listedStrategies()).find(s => s.id === names.strategies.hydraA.id);
        expect(stored?.expected_issuer).toBe(env.hydraA.issuer);
        const token = accessToken(
            await clientCredentialsToken(http, env.hydraA, world.good, {audience: env.entryPointUrl, scope: names.scopes.caller})
        );
        expect((await callAgent(http, token)).status).toBe(200);
    });

    test('deleting the strategy the second surface uses lists that surface and removes the strategy', async ({page}) => {
        ticket('FTL-30890');
        await page.goto('/credentials?tab=jwt-verification');
        await page.getByTestId(`strategy-delete-button-${staticStrategy.id}`).click();
        const confirm = page.getByTestId('strategy-delete-confirm');
        await expect(confirm).toContainText('Used by 1 surface:');
        await expect(confirm).toContainText(SECOND_SURFACE);
        await page.getByTestId('strategy-delete-confirm-button').click();
        await expect(page.getByTestId(`strategy-row-${staticStrategy.id}`)).toHaveCount(0);

        expect(await findSurfaceByName(SECOND_SURFACE)).toBeDefined();
    });

    test('callers of a surface whose strategy was deleted get 500 with a generic text and no strategy id, as the dialog says', async () => {
        ticket('FTL-30890');
        const refused = await callAgent2(http, staticToken(NEW_ISSUER));
        expect(refused.status).toBe(500);
        expect(refused.headers['www-authenticate']).toBeUndefined();
        expect(refused.text).toContain('Caller authentication is unavailable');
        expect(refused.text).not.toContain(staticStrategy.id);
        expect(refused.text).not.toContain('Auth config not found');
    });

    test('a provider that a surface uses cannot be deleted, and the dashboard says why', async ({page}) => {
        ticket('FTL-30886', 'FTL-30888');
        await page.goto('/credentials?tab=credential-providers');
        await twoStepDelete(page, `Delete "${names.providers.jwtBearer}"`);

        const error = page.getByTestId('credential-provider-delete-error');
        await expect(error).toContainText('Failed to delete provider');
        await expect(error).toContainText("A surface's Target Authentication uses this credential provider");
        const providers = await listEntities(api, '/api/v1/credential-providers');
        expect(providers.some(p => p.name === names.providers.jwtBearer)).toBe(true);
    });

    test('deleting a secret that a provider references warns first, then deletes it, and the provider keeps its reference', async ({page}) => {
        ticket('FTL-30888');
        const secret = (await listEntities(api, '/api/v1/secrets/')).find(item => item.secret_id === names.secrets.ccClientSecret);
        expect(secret).toBeDefined();
        const provider = (await listEntities(api, '/api/v1/credential-providers')).find(
            item => item.name === names.providers.clientCredentials
        ) as Entity;
        expect(provider).toBeDefined();

        await page.goto('/secrets');
        const row = page.locator('tr', {hasText: names.secrets.ccClientSecret});
        await row.locator("button[title='Delete secret']").click();
        await page.locator("button[title='Click again to confirm deletion']").click();

        const warning = page.getByTestId('secret-delete-warning');
        await expect(warning).toBeVisible();
        await expect(warning).toContainText(names.providers.clientCredentials);
        await expect(warning).toContainText('will lose');
        await expect(page.getByTestId('secret-delete-warning-provider')).toHaveCount(1);
        await expect(row).toHaveCount(1);
        expect((await listEntities(api, '/api/v1/secrets/')).some(item => item.secret_id === names.secrets.ccClientSecret)).toBe(true);

        const deleted = page.waitForResponse(
            response => response.url().endsWith(`/api/v1/secrets/${secret?.id}`) && response.request().method() === 'DELETE'
        );
        await page.getByTestId('secret-delete-warning-confirm-button').click();
        expect((await deleted).status()).toBe(204);
        await expect(page.locator('tr', {hasText: names.secrets.ccClientSecret})).toHaveCount(0);
        await expect(warning).toHaveCount(0);

        expect((await listEntities(api, '/api/v1/secrets/')).some(item => item.secret_id === names.secrets.ccClientSecret)).toBe(false);
        const stored = (await api.get<{client_secret_secret_ref?: string}>(`/api/v1/credential-providers/${provider.id}`)).body;
        expect(stored.client_secret_secret_ref).toBe(names.secrets.ccClientSecret);
    });

    test('deleting the second surface in the dashboard removes its route', async ({page}) => {
        await page.goto(`/surfaces/${secondSurface.surface_id ?? secondSurface.id}`);
        await expect(page.getByTestId('surface-node-access-point')).toBeVisible();
        await twoStepDelete(page, 'Delete this surface');
        await expect(page).toHaveURL(/\/surfaces$/);

        expect(await findSurfaceByName(SECOND_SURFACE)).toBeUndefined();
        const gone = await http.post(SECOND_ENTRY, {data: {}, failOnStatusCode: false});
        expect(gone.status()).toBe(404);
    });

    test('deleting the main surface removes its card and frees the provider and the strategy', async ({page}) => {
        ticket('FTL-30885', 'FTL-30886', 'FTL-30888', 'FTL-30890');
        await page.goto(`/surfaces/${mainSurface.surface_id ?? mainSurface.id}`);
        await expect(page.getByTestId('surface-node-access-point')).toBeVisible();
        await twoStepDelete(page, 'Delete this surface');
        await expect(page).toHaveURL(/\/surfaces$/);
        expect(await findSurface(api)).toBeUndefined();
        const card = await http.get(`${env.entryPointUrl}/.well-known/agent-card.json`, {failOnStatusCode: false});
        expect(card.status()).toBe(404);

        await page.goto('/credentials?tab=credential-providers');
        await twoStepDelete(page, `Delete "${names.providers.jwtBearer}"`);
        await expect(page.getByText(names.providers.jwtBearer)).toHaveCount(0);

        await page.goto('/credentials?tab=jwt-verification');
        await page.getByTestId(`strategy-delete-button-${names.strategies.hydraA.id}`).click();
        await expect(page.getByTestId('strategy-delete-confirm')).toContainText('No surface uses it.');
        await page.getByTestId('strategy-delete-confirm-button').click();
        await expect(page.getByTestId(`strategy-row-${names.strategies.hydraA.id}`)).toHaveCount(0);
    });

    async function findSurfaceByName(name: string): Promise<Entity | undefined> {
        return (await listEntities(api, '/api/v1/surfaces')).find(surface => surface.name === name);
    }
});

async function callAgent2(api: APIRequestContext, token: string) {
    const response = await api.post(SECOND_ENTRY, {
        headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`},
        data: {jsonrpc: '2.0', id: 1, method: 'message/send', params: {message: {role: 'user', messageId: 'oidc-e2e-2', parts: [{kind: 'text', text: 'hi'}]}}},
        failOnStatusCode: false,
    });
    return {status: response.status(), headers: response.headers(), text: await response.text()};
}
