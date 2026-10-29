/**
 * Surface Builder Save Path Tests
 *
 * Covers creating a surface from the A2A starter through the builder against
 * the real gateway:
 * - The saved surface carries the Managed Agent target
 * - Caller authentication with a JWT strategy, required scopes and the Access
 *   Point URL as an accepted audience is saved and read back by the gateway
 * - A surface that lets failed callers through lands on its detail page with
 *   the save warnings and a deny rule to copy, and no policy is attached
 * - Add to Accepted Audiences moves focus to the status that replaces it
 * - The selected node keeps its highlight when the canvas is redrawn
 * - A credential provider chosen as the Target Authentication is saved and
 *   read back by the gateway
 * - Saving is refused, with the reason next to the field, until a provider is
 *   chosen and the custom header is not a reserved name such as Host
 *
 * The test gateway's listeners are plain http, so it reports no Access Point
 * URL; the declarations response is given one so the audience control shows.
 */

import type {Page} from '@playwright/test';
import {generateKeyPairSync} from 'crypto';
import {expect, test} from '../helpers/fixtures';
import {GatewayApi} from '../helpers/gateway-api';
import {ticket} from '../helpers/ticket';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const RUN_ID = `${Date.now()}`;
const STRATEGY_NAME = `e2e-builder-strategy-${RUN_ID}`;
const TARGET_URL = 'https://agent.example.org/a2a';
const A2A_STARTER_ID = '75c89fd7-d83f-4213-be48-a3777dacf2dc';
const REQUIRED_SCOPE = 'agent:invoke';
const ACCESS_POINT_URL = `https://gateway.example.org/e2e-builder-${RUN_ID}`;

interface StoredSurface {
    surface_id: string;
    warnings?: Array<{code: string}>;
    name: string;
    target: {endpoint?: string; auth?: unknown};
    access_point: {
        inbound_policy?: unknown;
        caller_authentication?: {
            methods: Array<{
                type: string;
                jwt_verification_strategy_id?: string;
                audiences?: string[];
                required_scopes?: string[];
            }>;
        };
    };
}

interface DeclarationsBody {
    declarations?: Array<{resource: string | null}>;
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

async function addJwtCallerAuth(page: Page, strategyName: string, scope?: string): Promise<void> {
    await page.getByTestId('palette-section-policy').click();
    await dropOnPipelineEdge(page, 'caller-auth');
    await selectNode(page, 'caller-auth');
    await page.getByTestId('caller-auth-configure').click();
    await page.getByTestId('caller-auth-jwt-strategy').selectOption({label: strategyName});
    if (scope) {
        await page.getByTestId('caller-auth-scope-input').fill(scope);
        await page.getByTestId('caller-auth-scope-add').click();
        await expect(page.getByTestId('caller-auth-scopes')).toContainText(scope);
    }
    await page.getByTestId('caller-auth-close-button').click();
}

async function reportAccessPointUrl(page: Page): Promise<void> {
    await page.route('**/api/v1/surfaces/*/declarations', async route => {
        const response = await route.fetch();
        const body = (await response.json()) as DeclarationsBody;
        const declarations = (body.declarations ?? []).map(declaration => ({
            ...declaration,
            resource: declaration.resource ?? ACCESS_POINT_URL,
        }));
        await route.fulfill({response, json: {...body, declarations}});
    });
}

async function openSavedCallerAuth(page: Page, surfaceId: string): Promise<void> {
    await expect(page).toHaveURL(new RegExp(`/surfaces/${surfaceId}$`));
    await selectNode(page, 'caller-auth');
    await page.getByTestId('caller-auth-configure').click();
    await expect(page.getByTestId('caller-auth-discovery-derived-audience')).toContainText(ACCESS_POINT_URL);
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
        ticket('FTL-30888');
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

    test('saves JWT caller authentication with scopes and the entry point audience', async ({page}) => {
        ticket('FTL-30892', 'FTL-30894');
        await reportAccessPointUrl(page);
        await startFromA2aStarter(page);
        await addJwtCallerAuth(page, STRATEGY_NAME, REQUIRED_SCOPE);
        await fillTargetUrl(page, TARGET_URL);

        const created = await createSurface(page);
        createdSurfaceIds.push(created.surface_id);
        await openSavedCallerAuth(page, created.surface_id);
        await expect(page.getByTestId('caller-auth-discovery-derived-scopes')).toHaveText(REQUIRED_SCOPE);
        await page.getByTestId('caller-auth-discovery-add-audience-button').click();
        await page.getByTestId('caller-auth-close-button').click();

        const updated = page.waitForResponse(
            response =>
                response.url().endsWith(`/api/v1/surfaces/${created.surface_id}`) && response.request().method() === 'PUT'
        );
        await page.getByTestId('surface-save-button').click();
        expect((await updated).status()).toBe(200);

        const stored = await api.get<StoredSurface>(`/api/v1/surfaces/${created.surface_id}`);
        const [method] = stored.body.access_point.caller_authentication?.methods ?? [];
        expect(method).toMatchObject({
            type: 'jwt_bearer',
            jwt_verification_strategy_id: strategyId,
            required_scopes: [REQUIRED_SCOPE],
            audiences: [ACCESS_POINT_URL],
        });
    });

    test('moves focus to the Listed status after Add to Accepted Audiences', async ({page}) => {
        ticket('FTL-30892');
        await reportAccessPointUrl(page);
        await startFromA2aStarter(page);
        await addJwtCallerAuth(page, STRATEGY_NAME, REQUIRED_SCOPE);
        await fillTargetUrl(page, TARGET_URL);

        const created = await createSurface(page);
        createdSurfaceIds.push(created.surface_id);
        await openSavedCallerAuth(page, created.surface_id);
        const add = page.getByTestId('caller-auth-discovery-add-audience-button');
        await add.focus();
        await page.keyboard.press('Enter');

        const listed = page.getByTestId('caller-auth-discovery-audience-listed');
        await expect(listed).toHaveText('Listed in Accepted Audiences.');
        await expect(listed).toBeFocused();
        await expect(add).toHaveCount(0);
        await expect(page.getByTestId('caller-auth-discovery-audience-status')).toHaveAttribute('role', 'status');
    });

    test('opens the new surface with its save warnings when failed callers are not denied', async ({page}) => {
        ticket('FTL-30893', 'FTL-30894');
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], {origin: new URL(BASE_URL).origin});
        await startFromA2aStarter(page);
        await addJwtCallerAuth(page, STRATEGY_NAME);
        await fillTargetUrl(page, TARGET_URL);

        const created = await createSurface(page);
        createdSurfaceIds.push(created.surface_id);

        expect(created.warnings?.map(warning => warning.code)).toContain('fail_open_policy');
        await expect(page).toHaveURL(new RegExp(`/surfaces/${created.surface_id}$`));
        const alert = page.getByTestId('surface-warnings-alert');
        await expect(alert).toBeVisible();
        await expect(alert).toHaveAttribute('aria-label', 'Surface warnings');
        await expect(page.getByTestId('surface-warning-fail_open_policy')).toBeVisible();

        const copyRule = page.getByTestId('surface-warnings-copy-rule');
        await copyRule.click();
        await expect(copyRule).toHaveText('Copied');
        const copied = await page.evaluate(() => navigator.clipboard.readText());
        expect(copied).toContain('package surface.policy');
        expect(copied).toContain('input.source_auth.method == "failed"');

        const stored = await api.get<StoredSurface>(`/api/v1/surfaces/${created.surface_id}`);
        expect(stored.body.access_point.inbound_policy).toBeUndefined();
    });

    test('keeps the selected node highlighted when a resize redraws the canvas', async ({page}) => {
        ticket('FTL-30895');
        await startFromA2aStarter(page);
        await selectNode(page, 'target');
        const canvas = page.getByTestId('surface-canvas');
        const widthBefore = await canvas.getAttribute('width');

        await page.setViewportSize({width: 1300, height: 900});

        await expect(canvas).not.toHaveAttribute('width', widthBefore ?? '');
        await expect(page.getByTestId('surface-node-target')).toHaveClass(/node-single-selected/);
        await expect(page.locator('.node.node-single-selected')).toHaveCount(1);
    });

    test('saves a credential provider as the Target Authentication', async ({page}) => {
        ticket('FTL-30888');
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

    test('refuses to save credential provider Target Authentication without a provider or with header Host', async ({page}) => {
        ticket('FTL-30888');
        const providerName = `E2E refused ${RUN_ID}`;
        const secret = await api.post<{id: string}>('/api/v1/secrets/new', {
            name: `E2E refused key ${RUN_ID}`,
            secret_id: `e2e-refused-key-${RUN_ID}`,
            value: 'e2e-api-key-value',
            secret_type: 'General',
        });
        expect(secret.status).toBe(201);
        const provider = await api.post<{id: string}>('/api/v1/credential-providers', {
            name: providerName,
            provider_id: `e2e-refused-${RUN_ID}`,
            provider_type: 'api_key',
            api_key_secret_ref: `e2e-refused-key-${RUN_ID}`,
        });
        expect(provider.status).toBe(201);
        const posted: string[] = [];
        page.on('request', request => {
            if (request.method() === 'POST' && request.url().endsWith('/api/v1/surfaces')) posted.push(request.url());
        });

        try {
            await startFromA2aStarter(page);
            await addJwtCallerAuth(page, STRATEGY_NAME);
            await fillTargetUrl(page, TARGET_URL);
            await page.getByTestId('managed-agent-auth-type').selectOption({label: 'Credential Provider'});
            await page.getByTestId('managed-agent-auth-configure').click();
            const save = page.getByTestId('surface-create-button');
            const error = page.getByTestId('target-auth-error');
            const providerSelect = page.getByTestId('target-auth-credential-provider-select');

            await expect(error).toHaveText('Select a credential provider.');
            await expect(providerSelect).toHaveAttribute('aria-invalid', 'true');
            await expect(save).toBeDisabled();
            await expect(save).toHaveAttribute('title', 'Fix element validation errors before saving');

            await providerSelect.selectOption({label: `${providerName} (API Key)`});
            await page.getByTestId('target-auth-inject-as').selectOption('custom_header');
            await page.getByTestId('target-auth-inject-name').fill('Host');
            await page.getByTestId('target-auth-inject-format').fill('{value}');

            await expect(error).toHaveText('Host cannot be used as the header name.');
            await expect(page.getByTestId('target-auth-inject-name')).toHaveAttribute('aria-invalid', 'true');
            await expect(save).toBeDisabled();
            expect(posted).toEqual([]);

            await page.getByTestId('target-auth-inject-name').fill('X-Gateway-Token');
            await expect(error).toHaveCount(0);
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
