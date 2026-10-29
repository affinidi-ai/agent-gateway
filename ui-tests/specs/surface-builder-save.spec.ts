/**
 * Surface Builder Save Path Tests
 *
 * Covers creating a surface from the A2A starter through the builder against
 * the real gateway:
 * - The saved surface carries the Managed Agent target
 * - A credential provider chosen as the Target Authentication is saved and
 *   read back by the gateway
 */

import type {Page} from '@playwright/test';
import {generateKeyPairSync} from 'crypto';
import {expect, test} from '../helpers/fixtures';
import {GatewayApi} from '../helpers/gateway-api';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const RUN_ID = `${Date.now()}`;
const STRATEGY_NAME = `e2e-builder-strategy-${RUN_ID}`;
const TARGET_URL = 'https://agent.example.org/a2a';
const A2A_STARTER_ID = '75c89fd7-d83f-4213-be48-a3777dacf2dc';

interface StoredSurface {
    surface_id: string;
    name: string;
    target: {endpoint?: string; auth?: unknown};
    access_point: {
        caller_authentication?: unknown;
    };
}

async function startFromA2aStarter(page: Page): Promise<void> {
    await page.goto(`${BASE_URL}/surfaces/new`);
    await page.getByTestId(`surface-starter-use-${A2A_STARTER_ID}`).click();
    await page.getByTestId('surface-welcome-dismiss').click();
}

async function selectNode(page: Page, nodeType: string): Promise<void> {
    const node = page.getByTestId(`surface-node-${nodeType}`);
    await expect(async () => {
        await node.click({force: true});
        await expect(node).toHaveClass(/node-single-selected/, {timeout: 1000});
    }).toPass();
}

async function dropOnPipelineEdge(page: Page, nodeType: string): Promise<void> {
    const canvas = page.getByTestId('surface-canvas');
    const canvasBox = await canvas.boundingBox();
    if (!canvasBox) throw new Error('Canvas is not visible');
    const links = page.getByTestId('canvas-link');
    const linkCount = await links.count();
    for (let index = 0; index < linkCount; index += 1) {
        const box = await links.nth(index).boundingBox();
        if (!box) continue;
        await page.getByTestId(`palette-item-${nodeType}`).dragTo(canvas, {
            targetPosition: {x: box.x + box.width / 2 - canvasBox.x, y: box.y + box.height / 2 - canvasBox.y},
        });
        if ((await page.getByTestId(`surface-node-${nodeType}`).count()) > 0) return;
    }
    throw new Error(`${nodeType} did not snap to any pipeline edge`);
}

async function addJwtCallerAuth(page: Page, strategyName: string): Promise<void> {
    await page.getByTestId('palette-section-policy').click();
    await dropOnPipelineEdge(page, 'caller-auth');
    await selectNode(page, 'caller-auth');
    await page.getByTestId('caller-auth-configure').click();
    await page.getByTestId('caller-auth-jwt-strategy').selectOption({label: strategyName});
    await page.getByTestId('caller-auth-close-button').click();
}

async function createSurface(page: Page): Promise<StoredSurface> {
    const created = page.waitForResponse(
        response => response.url().endsWith('/api/v1/surfaces') && response.request().method() === 'POST'
    );
    await page.getByTestId('surface-create-button').click();
    const response = await created;
    expect(response.status()).toBe(201);
    return (await response.json()) as StoredSurface;
}

async function fillTargetUrl(page: Page, url: string): Promise<void> {
    await selectNode(page, 'target');
    await page.getByTestId('managed-agent-endpoint-url').fill(url);
}

test.describe('Surface builder save', () => {
    test.describe.configure({mode: 'serial'});

    test.use({viewport: {width: 1600, height: 1000}});

    let api: GatewayApi;
    let strategyId: string;
    const createdSurfaceIds: string[] = [];

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        const jwk = generateKeyPairSync('ec', {namedCurve: 'P-256'}).publicKey.export({format: 'jwk'});
        const strategy = await api.post<{id: string}>('/api/v1/jwt-verification-strategies', {
            name: STRATEGY_NAME,
            expected_issuer: 'https://idp.example.com',
            jwks_source: {type: 'static', jwks: [{...jwk, kid: 'e2e-key', alg: 'ES256', use: 'sig'}]},
        });
        expect(strategy.status).toBe(201);
        strategyId = strategy.body.id;
    });

    test.afterEach(async () => {
        for (const id of createdSurfaceIds.splice(0)) {
            await api.delete(`/api/v1/surfaces/${id}`);
        }
    });

    test.afterAll(async () => {
        await api.delete(`/api/v1/jwt-verification-strategies/${strategyId}`);
        await api.dispose();
    });

    test('creates a surface from the starter with its Managed Agent target', async ({page}) => {
        await startFromA2aStarter(page);
        await fillTargetUrl(page, TARGET_URL);
        const created = await createSurface(page);
        createdSurfaceIds.push(created.surface_id);

        await expect(page).toHaveURL(/\/surfaces(\/|$)/);
        const stored = await api.get<StoredSurface>(`/api/v1/surfaces/${created.surface_id}`);
        expect(stored.status).toBe(200);
        expect(stored.body.target.endpoint).toBe(TARGET_URL);
        expect(stored.body.access_point.caller_authentication).toBeUndefined();
    });

    test('saves a credential provider as the Target Authentication', async ({page}) => {
        const providerName = `E2E target auth ${RUN_ID}`;
        const secret = await api.post<{id: string}>('/api/v1/secrets/new', {
            name: `E2E target key ${RUN_ID}`,
            secret_id: `e2e-target-key-${RUN_ID}`,
            value: 'e2e-api-key-value',
            secret_type: 'General',
        });
        expect(secret.status).toBe(201);
        const provider = await api.post<{id: string}>('/api/v1/credential-providers', {
            name: providerName,
            provider_id: `e2e-target-auth-${RUN_ID}`,
            provider_type: 'api_key',
            api_key_secret_ref: `e2e-target-key-${RUN_ID}`,
        });
        expect(provider.status).toBe(201);

        try {
            await startFromA2aStarter(page);
            await addJwtCallerAuth(page, STRATEGY_NAME);
            await fillTargetUrl(page, TARGET_URL);
            await page.getByTestId('managed-agent-auth-type').selectOption({label: 'Credential Provider'});
            await page.getByTestId('managed-agent-auth-configure').click();
            await page.getByTestId('target-auth-credential-provider-select').selectOption({label: `${providerName} (API Key)`});

            const created = await createSurface(page);
            createdSurfaceIds.push(created.surface_id);

            const stored = await api.get<StoredSurface>(`/api/v1/surfaces/${created.surface_id}`);
            expect(stored.body.target.auth).toMatchObject({
                method: {credential_provider: {credential_provider_id: provider.body.id}},
            });
        } finally {
            for (const id of createdSurfaceIds.splice(0)) {
                await api.delete(`/api/v1/surfaces/${id}`);
            }
            await api.delete(`/api/v1/credential-providers/${provider.body.id}`);
            await api.delete(`/api/v1/secrets/${secret.body.id}`);
        }
    });
});
