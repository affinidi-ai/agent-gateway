/**
 * JWT verification strategies through the dashboard
 *
 * Discover from issuer runs against the live Hydra. The dashboard accepts only an https issuer and
 * the gateway refuses a loopback JWKS URI at save time, and the local Hydra is plain http on
 * loopback, so two things differ from production: the discovery request goes through the scheme
 * bridge, and the strategies for the local Hydra are written into the gateway's storage.
 */

import {generateKeyPairSync} from 'crypto';
import {Page} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {asHttpsLooking, bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {env, issuerWithoutSlash} from '../../helpers/oidc-live/env';
import {Entity, listEntities, seedStrategy, strategyRecord} from '../../helpers/oidc-live/gateway-state';
import {names, PREFIX} from '../../helpers/oidc-live/names';
import {ticket} from '../../helpers/ticket';

const DISCOVER = '**/api/v1/jwt-verification-strategies/discover';
const STRATEGIES = '**/api/v1/jwt-verification-strategies';
const STATIC_ISSUER = 'https://static-issuer.oidc-e2e.example';

function staticJwks(): string {
    const jwk = generateKeyPairSync('ec', {namedCurve: 'P-256'}).publicKey.export({format: 'jwk'});
    return JSON.stringify([{...jwk, kid: 'oidc-e2e-static', alg: 'ES256', use: 'sig'}]);
}

async function findStrategy(api: GatewayApi, name: string): Promise<Entity | undefined> {
    return (await listEntities(api, '/api/v1/jwt-verification-strategies')).find(strategy => strategy.name === name);
}

async function saveAsStatic(page: Page, name: string): Promise<void> {
    await page.getByTestId('strategy-name').fill(name);
    await page.getByTestId('strategy-jwks-source-static').check();
    await page.getByTestId('strategy-jwks').fill(staticJwks());
    await page.getByTestId('strategy-save-button').click();
    await expect(page).toHaveURL(/settings|credentials/);
}

test.describe('JWT verification strategies', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    const issuerA = asHttpsLooking(env.hydraA.issuer);

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        for (const strategy of await listEntities(api, '/api/v1/jwt-verification-strategies')) {
            if (strategy.name?.startsWith(PREFIX)) await api.delete(`/api/v1/jwt-verification-strategies/${strategy.id}`);
        }
    });

    test.afterAll(async () => {
        await api.dispose();
    });

    test('Discover from issuer fills the JWKS URI and pins the metadata Hydra publishes', async ({page}) => {
        ticket('FTL-30890');
        await bridgeLoopbackScheme(page, DISCOVER);
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-name').fill(names.strategies.hydraA.name);
        await page.getByTestId('strategy-issuer').fill(issuerA);
        const discover = page.waitForResponse(
            response => response.url().endsWith('/jwt-verification-strategies/discover') && response.request().method() === 'POST'
        );
        await page.getByTestId('strategy-discover-button').click();
        expect((await discover).status()).toBe(200);

        const card = page.getByTestId('strategy-pinned-server');
        await expect(card).toContainText(env.hydraA.issuer);
        await expect(card).toContainText(`${env.hydraA.issuer}.well-known/oauth-authorization-server`);
        await expect(card).toContainText(`${env.hydraA.issuer}oauth2/token`);
        await expect(card).toContainText(`${env.hydraA.issuer}.well-known/jwks.json`);
        await expect(page.getByTestId('strategy-jwks-uri')).toHaveValue(`${env.hydraA.issuer}.well-known/jwks.json`);
        await expect(page.getByTestId('strategy-discover-success')).toHaveAttribute('role', 'status');
        await expect(page.getByTestId('strategy-no-pin')).toHaveCount(0);
    });

    test('saving a strategy that advertises the local Hydra is refused for its loopback JWKS URI and nothing is stored', async ({page}) => {
        await bridgeLoopbackScheme(page, DISCOVER);
        await bridgeLoopbackScheme(page, STRATEGIES);
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-name').fill(names.strategies.hydraA.name);
        await page.getByTestId('strategy-issuer').fill(issuerA);
        await page.getByTestId('strategy-discover-button').click();
        await expect(page.getByTestId('strategy-pinned-server')).toBeVisible();

        const saved = page.waitForResponse(
            response => response.url().endsWith('/api/v1/jwt-verification-strategies') && response.request().method() === 'POST'
        );
        await page.getByTestId('strategy-save-button').click();
        expect((await saved).status()).toBe(400);
        await expect(page.getByTestId('strategy-error')).toContainText('jwks_uri rejected');
        expect(await findStrategy(api, names.strategies.hydraA.name)).toBeUndefined();
    });

    test('an issuer that differs only by a trailing slash fails discovery, pins nothing and cannot be saved as advertised', async ({page}) => {
        ticket('FTL-30890');
        await bridgeLoopbackScheme(page, DISCOVER);
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-issuer').fill(issuerWithoutSlash(issuerA));
        const discover = page.waitForResponse(
            response => response.url().endsWith('/jwt-verification-strategies/discover') && response.request().method() === 'POST'
        );
        await page.getByTestId('strategy-discover-button').click();

        const response = await discover;
        expect(response.status()).toBe(422);
        expect(((await response.json()) as {code: string}).code).toBe('issuer_mismatch');
        await expect(page.getByTestId('strategy-discover-error')).toContainText('Discovery failed');
        await expect(page.getByTestId('strategy-pinned-server')).toHaveCount(0);
        await expect(page.getByTestId('strategy-no-pin')).toBeVisible();

        const name = `${PREFIX} slash`;
        await saveAsStatic(page, name);
        const stored = await findStrategy(api, name);
        expect(stored?.authorization_server).toBeUndefined();
        await api.delete(`/api/v1/jwt-verification-strategies/${stored!.id}`);
    });

    test('an unreachable issuer fails discovery without naming the host and cannot be saved as advertised', async ({page}) => {
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-issuer').fill('https://127.0.0.1:1');
        const discover = page.waitForResponse(
            response => response.url().endsWith('/jwt-verification-strategies/discover') && response.request().method() === 'POST'
        );
        await page.getByTestId('strategy-discover-button').click();

        expect((await discover).status()).toBe(422);
        const alert = page.getByTestId('strategy-discover-error');
        await expect(alert).toContainText('Discovery failed');
        await expect(alert).not.toContainText('127.0.0.1');
        await expect(page.getByTestId('strategy-pinned-server')).toHaveCount(0);

        const name = `${PREFIX} unreachable`;
        await saveAsStatic(page, name);
        const stored = await findStrategy(api, name);
        expect(stored?.authorization_server).toBeUndefined();
        await api.delete(`/api/v1/jwt-verification-strategies/${stored!.id}`);
    });

    test('an http issuer is refused in the dashboard without a request and cannot be saved as advertised', async ({page}) => {
        let discoverCalls = 0;
        await page.route(DISCOVER, async route => {
            discoverCalls += 1;
            await route.continue();
        });
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-issuer').fill(env.hydraA.issuer);
        await page.getByTestId('strategy-discover-button').click();

        const alert = page.getByTestId('strategy-discover-error');
        await expect(alert).toHaveAttribute('role', 'alert');
        await expect(alert).toContainText('https');
        expect(discoverCalls).toBe(0);
        await expect(page.getByTestId('strategy-pinned-server')).toHaveCount(0);

        const name = `${PREFIX} http`;
        await saveAsStatic(page, name);
        const stored = await findStrategy(api, name);
        expect(stored?.authorization_server).toBeUndefined();
        await api.delete(`/api/v1/jwt-verification-strategies/${stored!.id}`);
    });

    test('a strategy with static keys is created in the dashboard and listed without the Discovered badge', async ({page}) => {
        await page.goto('/jwt-verification-strategies/new');
        await page.getByTestId('strategy-name').fill(`${PREFIX} static`);
        await page.getByTestId('strategy-issuer').fill(STATIC_ISSUER);
        await page.getByTestId('strategy-jwks-source-static').check();
        await page.getByTestId('strategy-jwks').fill(staticJwks());
        await page.getByTestId('strategy-save-button').click();
        await expect(page).toHaveURL(/settings|credentials/);

        const stored = await findStrategy(api, `${PREFIX} static`);
        expect(stored?.expected_issuer).toBe(STATIC_ISSUER);
        await page.goto('/credentials?tab=jwt-verification');
        const row = page.getByTestId(`strategy-row-${stored!.id}`);
        await expect(row).toBeVisible();
        await expect(row.getByTestId('strategy-discovered-badge')).toHaveCount(0);
        await api.delete(`/api/v1/jwt-verification-strategies/${stored!.id}`);
    });

    test('the strategy that advertises hydra-a is listed as Discovered and opens with Hydra metadata pinned', async ({page}) => {
        ticket('FTL-30890');
        await seedStrategy(api, strategyRecord('a'));
        await seedStrategy(api, strategyRecord('b'));

        await page.goto('/credentials?tab=jwt-verification');
        const row = page.getByTestId(`strategy-row-${names.strategies.hydraA.id}`);
        await expect(row).toContainText(names.strategies.hydraA.name);
        await expect(row.getByTestId('strategy-discovered-badge')).toHaveText('Discovered');
        await expect(page.getByTestId(`strategy-row-${names.strategies.hydraB.id}`).getByTestId('strategy-discovered-badge')).toHaveText('Discovered');

        await row.click();
        await expect(page).toHaveURL(new RegExp(`/jwt-verification-strategies/${names.strategies.hydraA.id}$`));
        const card = page.getByTestId('strategy-pinned-server');
        await expect(card).toContainText(env.hydraA.issuer);
        await expect(card).toContainText(`${env.hydraA.issuer}oauth2/token`);
        await expect(page.getByTestId('strategy-pinned-stale')).toHaveCount(0);
    });
});
