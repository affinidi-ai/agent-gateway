/**
 * JWT Verification Strategy Tests
 *
 * Covers authorization server discovery in the strategy editor and the list:
 * - Client-side https gate and the fixed failure message from the gateway
 * - Pinned metadata card and the request a discovered save sends
 * - Scope claims saved, kept and reset to the defaults on the real gateway
 * - Discovered badge and the in-page delete confirmation
 */

import {generateKeyPairSync} from 'crypto';
import {expect, test} from '../helpers/fixtures';
import {GatewayApi} from '../helpers/gateway-api';
import {feature} from '../helpers/feature';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const EDITOR_PREFIX = 'e2e-strategy-editor-';
const LIST_PREFIX = 'e2e-strategy-list-';
const ISSUER = 'https://idp.example.com';

interface StoredStrategy {
    id: string;
    name: string;
    scope_claims?: string[];
    authorization_server?: unknown;
}

const PINNED_SERVER = {
    issuer: ISSUER,
    metadata_url: `${ISSUER}/.well-known/openid-configuration`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks.json`,
};

function staticJwks(): string {
    const jwk = generateKeyPairSync('ec', {namedCurve: 'P-256'}).publicKey.export({format: 'jwk'});
    return JSON.stringify([{...jwk, kid: 'e2e-key', alg: 'ES256', use: 'sig'}]);
}

function uniqueName(prefix: string): string {
    return `${prefix}${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

async function deleteLeftovers(api: GatewayApi, prefix: string): Promise<void> {
    const listed = await api.get<StoredStrategy[]>('/api/v1/jwt-verification-strategies');
    for (const strategy of Array.isArray(listed.body) ? listed.body : []) {
        if (strategy.name.startsWith(prefix)) {
            await api.delete(`/api/v1/jwt-verification-strategies/${strategy.id}`);
        }
    }
}

async function findByName(api: GatewayApi, name: string): Promise<StoredStrategy | undefined> {
    const listed = await api.get<StoredStrategy[]>('/api/v1/jwt-verification-strategies');
    return listed.body.find(strategy => strategy.name === name);
}

test.describe('Strategy discovery', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
    });

    test.afterAll(async () => {
        await deleteLeftovers(api, EDITOR_PREFIX);
        await api.dispose();
    });

    test('refuses a non-https issuer without calling the gateway', async ({page}) => {
        feature('strategy-discovery');
        let discoverCalls = 0;
        await page.route('**/api/v1/jwt-verification-strategies/discover', async route => {
            discoverCalls += 1;
            await route.continue();
        });
        await page.goto(`${BASE_URL}/jwt-verification-strategies/new`);
        await page.getByTestId('strategy-issuer').fill('http://idp.example.com');
        await page.getByTestId('strategy-discover-button').click();

        const alert = page.getByTestId('strategy-discover-error');
        await expect(alert).toBeVisible();
        await expect(alert).toHaveAttribute('role', 'alert');
        expect(discoverCalls).toBe(0);
        await expect(page.getByTestId('strategy-pinned-server')).toHaveCount(0);
    });

    test('shows a fixed message and pins nothing when the gateway cannot discover the issuer', async ({page}) => {
        feature('strategy-discovery');
        await page.goto(`${BASE_URL}/jwt-verification-strategies/new`);
        await page.getByTestId('strategy-issuer').fill('https://127.0.0.1:1');
        const discover = page.waitForResponse(
            response =>
                response.url().endsWith('/api/v1/jwt-verification-strategies/discover') &&
                response.request().method() === 'POST'
        );
        await page.getByTestId('strategy-discover-button').click();

        expect((await discover).status()).toBe(422);
        const alert = page.getByTestId('strategy-discover-error');
        await expect(alert).toContainText('Discovery failed');
        await expect(alert).not.toContainText('127.0.0.1');
        await expect(page.getByTestId('strategy-pinned-server')).toHaveCount(0);
        await expect(page.getByTestId('strategy-no-pin')).toBeVisible();
    });

    test('pins the discovered server and saves it with discover_metadata true', async ({page}) => {
        feature('strategy-discovery');
        await page.route('**/api/v1/jwt-verification-strategies/discover', async route => {
            await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(PINNED_SERVER)});
        });
        let saved: Record<string, unknown> | null = null;
        await page.route('**/api/v1/jwt-verification-strategies', async route => {
            if (route.request().method() !== 'POST') {
                await route.continue();
                return;
            }
            saved = route.request().postDataJSON();
            await route.fulfill({
                status: 201,
                contentType: 'application/json',
                body: JSON.stringify({id: 'discovered-1', ...saved, authorization_server: PINNED_SERVER}),
            });
        });

        await page.goto(`${BASE_URL}/jwt-verification-strategies/new`);
        await page.getByTestId('strategy-name').fill(uniqueName(EDITOR_PREFIX));
        await page.getByTestId('strategy-issuer').fill(ISSUER);
        await page.getByTestId('strategy-discover-button').click();

        const card = page.getByTestId('strategy-pinned-server');
        await expect(card).toContainText(PINNED_SERVER.token_endpoint);
        await expect(card).toContainText(PINNED_SERVER.jwks_uri);
        await expect(page.getByTestId('strategy-jwks-uri')).toHaveValue(PINNED_SERVER.jwks_uri);
        await expect(page.getByTestId('strategy-discover-success')).toHaveAttribute('role', 'status');

        await page.getByTestId('strategy-save-button').click();
        await expect.poll(() => saved).not.toBeNull();
        expect(saved).toMatchObject({
            expected_issuer: ISSUER,
            discover_metadata: true,
            jwks_source: {type: 'remote', jwks_uri: PINNED_SERVER.jwks_uri},
        });
        expect(saved).not.toHaveProperty('scope_claims');
    });

    test('warns that static keys cannot be discovered and disables the Discover button', async ({page}) => {
        feature('strategy-discovery');
        await page.goto(`${BASE_URL}/jwt-verification-strategies/new`);
        await page.getByTestId('strategy-issuer').fill(ISSUER);
        await page.getByTestId('strategy-jwks-source-static').check();

        await expect(page.getByTestId('strategy-static-pin-warning')).toBeVisible();
        await expect(page.getByTestId('strategy-discover-button')).toBeDisabled();
    });

    test('saves scope claims and resets them to the defaults when cleared', async ({page}) => {
        feature('required-scopes');
        const name = uniqueName(EDITOR_PREFIX);
        await page.goto(`${BASE_URL}/jwt-verification-strategies/new`);
        await page.getByTestId('strategy-name').fill(name);
        await page.getByTestId('strategy-issuer').fill(ISSUER);
        await page.getByTestId('strategy-jwks-source-static').check();
        await page.getByTestId('strategy-jwks').fill(staticJwks());
        await page.getByTestId('strategy-scope-claims').fill('roles, scope');
        await page.getByTestId('strategy-save-button').click();
        await expect(page).toHaveURL(/credentials/);

        const created = await findByName(api, name);
        expect(created?.scope_claims).toEqual(['roles', 'scope']);

        await page.goto(`${BASE_URL}/jwt-verification-strategies/${created!.id}`);
        const scopeClaims = page.getByTestId('strategy-scope-claims');
        await expect(scopeClaims).toHaveValue('roles, scope');
        await scopeClaims.fill('');
        await page.getByTestId('strategy-save-button').click();
        await expect(page).toHaveURL(/credentials/);

        const reset = await findByName(api, name);
        expect(reset?.scope_claims).toBeUndefined();
    });
});

test.describe('Strategy list', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
    });

    test.afterAll(async () => {
        await deleteLeftovers(api, LIST_PREFIX);
        await api.dispose();
    });

    test('marks a strategy with a pinned authorization server as Discovered', async ({page}) => {
        feature('strategy-discovery');
        const name = uniqueName(LIST_PREFIX);
        await page.route('**/api/v1/jwt-verification-strategies', async route => {
            if (route.request().method() !== 'GET') {
                await route.continue();
                return;
            }
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([
                    {
                        id: 'pinned-1',
                        name,
                        expected_issuer: ISSUER,
                        jwks_source: {type: 'remote', jwks_uri: PINNED_SERVER.jwks_uri},
                        authorization_server: PINNED_SERVER,
                        created_at: '2026-10-21T10:00:00Z',
                        updated_at: '2026-10-21T10:00:00Z',
                    },
                ]),
            });
        });
        await page.goto(`${BASE_URL}/credentials?tab=jwt-verification`);

        const row = page.getByTestId('strategy-row-pinned-1');
        await expect(row.getByTestId('strategy-discovered-badge')).toHaveText('Discovered');
    });

    test('confirms a delete in the page, then removes the strategy', async ({page}) => {
        feature('strategy-discovery');
        const name = uniqueName(LIST_PREFIX);
        const created = await api.post<StoredStrategy>('/api/v1/jwt-verification-strategies', {
            name,
            expected_issuer: ISSUER,
            jwks_source: {type: 'static', jwks: JSON.parse(staticJwks())},
        });
        expect(created.status).toBe(201);
        const id = created.body.id;

        await page.goto(`${BASE_URL}/credentials?tab=jwt-verification`);
        await page.getByTestId(`strategy-delete-button-${id}`).click();

        const confirm = page.getByTestId('strategy-delete-confirm');
        await expect(confirm).toHaveAttribute('role', 'alertdialog');
        await expect(confirm).toContainText(`Delete JWT verification strategy "${name}"?`);
        await expect(confirm).toContainText('No surface uses it.');
        expect(await findByName(api, name)).toBeDefined();

        await page.getByTestId('strategy-delete-confirm-button').click();
        await expect(page.getByTestId(`strategy-row-${id}`)).toHaveCount(0);
        expect(await findByName(api, name)).toBeUndefined();
    });

    test('keeps the strategy when the delete is cancelled', async ({page}) => {
        feature('strategy-discovery');
        const name = uniqueName(LIST_PREFIX);
        const created = await api.post<StoredStrategy>('/api/v1/jwt-verification-strategies', {
            name,
            expected_issuer: ISSUER,
            jwks_source: {type: 'static', jwks: JSON.parse(staticJwks())},
        });
        const id = created.body.id;

        await page.goto(`${BASE_URL}/credentials?tab=jwt-verification`);
        await page.getByTestId(`strategy-delete-button-${id}`).click();
        await page.getByTestId('strategy-delete-cancel-button').click();

        await expect(page.getByTestId('strategy-delete-confirm')).toHaveCount(0);
        await expect(page.getByTestId(`strategy-row-${id}`)).toBeVisible();
        expect(await findByName(api, name)).toBeDefined();
    });
});
