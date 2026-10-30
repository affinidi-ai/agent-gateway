import {Page, expect} from '@playwright/test';
import {asHttpsLooking} from './bridge';
import {env} from './env';

const A2A_STARTER_ID = '75c89fd7-d83f-4213-be48-a3777dacf2dc';

export async function startA2aSurface(page: Page): Promise<void> {
    await page.goto('/surfaces/new');
    await page.getByTestId(`surface-starter-use-${A2A_STARTER_ID}`).click();
    await page.getByTestId('surface-welcome-dismiss').click();
}

export async function selectNode(page: Page, nodeType: string): Promise<void> {
    const node = page.getByTestId(`surface-node-${nodeType}`);
    await expect(async () => {
        await node.click({force: true});
        await expect(node).toHaveClass(/node-single-selected/, {timeout: 1000});
    }).toPass({timeout: 15_000});
}

async function clearSelection(page: Page): Promise<void> {
    await page.getByTestId('surface-canvas').click({position: {x: 8, y: 8}});
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

export async function openCallerAuth(page: Page): Promise<void> {
    if ((await page.getByTestId('surface-node-caller-auth').count()) === 0) {
        await clearSelection(page);
        await page.getByTestId('palette-section-policy').click();
        await dropOnPipelineEdge(page, 'caller-auth');
    }
    await selectNode(page, 'caller-auth');
    await page.getByTestId('caller-auth-configure').click();
}

export async function chooseStrategy(page: Page, strategyName: string): Promise<void> {
    await openCallerAuth(page);
    await page.getByTestId('caller-auth-jwt-strategy').selectOption({label: strategyName});
    await page.getByTestId('caller-auth-close-button').click();
}

export async function turnOnAuthorizationServerDiscovery(page: Page): Promise<void> {
    const toggle = page.getByTestId('caller-auth-discovery-switch');
    if (!(await toggle.isChecked())) await toggle.click();
    const resource = page.getByTestId('caller-auth-discovery-resource-input');
    await expect(resource).toHaveValue(env.entryPointUrl);
    await expect(resource).toBeFocused();
}

export async function configureCallerAuth(
    page: Page,
    options: {strategyName: string; scopes: string[]; discovery?: boolean}
): Promise<void> {
    await openCallerAuth(page);
    await page.getByTestId('caller-auth-jwt-strategy').selectOption({label: options.strategyName});
    for (const scope of options.scopes) {
        await page.getByTestId('caller-auth-scope-input').fill(scope);
        await page.getByTestId('caller-auth-scope-add').click();
        await expect(page.getByTestId('caller-auth-scopes')).toContainText(scope);
    }
    if (options.discovery) await turnOnAuthorizationServerDiscovery(page);
    await page.getByTestId('caller-auth-close-button').click();
}

export async function nameSurface(page: Page, name: string): Promise<void> {
    const field = page.locator('#surface-name');
    await expect(async () => {
        await page.getByTestId('surface-node-surface').click({force: true});
        await expect(field).toBeVisible({timeout: 1000});
    }).toPass({timeout: 15_000});
    await field.fill(name);
}

export async function routeToTheHttpsListener(page: Page): Promise<void> {
    await selectNode(page, 'access-point');
    await page.getByTestId('route-listener-listen-address').selectOption(env.accessPointOrigin);
    await page.getByTestId('route-listener-surface-prefix').selectOption(env.routePrefix);
    await page.getByTestId('route-listener-custom-path').fill(env.customPath);
    await expect(page.getByTestId('access-point-entry-point-url')).toContainText(env.entryPointUrl);
}

export async function configureTarget(
    page: Page,
    options: {url: string; providerLabel: string; scopes?: string}
): Promise<void> {
    await selectNode(page, 'target');
    await page.getByTestId('managed-agent-endpoint-url').fill(asHttpsLooking(options.url));
    await page.getByTestId('managed-agent-auth-type').selectOption({label: 'Credential Provider'});
    await page.getByTestId('managed-agent-auth-configure').click();
    await page.getByTestId('target-auth-credential-provider-select').selectOption({label: options.providerLabel});
    if (options.scopes) await page.getByTestId('target-auth-scopes').fill(options.scopes);
}

export async function openSurface(page: Page, surfaceId: string): Promise<void> {
    await page.goto(`/surfaces/${surfaceId}`);
    await expect(page.getByTestId('surface-node-access-point')).toBeVisible();
}

export async function retypeTarget(page: Page): Promise<void> {
    await selectNode(page, 'target');
    await page.getByTestId('managed-agent-endpoint-url').fill(asHttpsLooking(env.agentUrl));
}

export async function saveEdit(page: Page, timeout = 15_000): Promise<SavedSurface> {
    const saved = page.waitForResponse(
        response => /\/api\/v1\/surfaces\/[^/]+$/.test(response.url()) && response.request().method() === 'PUT',
        {timeout}
    );
    await page.getByTestId('surface-save-button').click();
    const response = await saved;
    expect(response.status()).toBe(200);
    return (await response.json()) as SavedSurface;
}

export interface SavedSurface {
    surface_id: string;
    warnings?: Array<{code: string}>;
    access_point: {
        listen_address: string;
        route: string;
        caller_authentication?: {
            methods: Array<{
                type: string;
                jwt_verification_strategy_id: string;
                audiences?: string[];
                required_scopes?: string[];
            }>;
            protected_resource?: {resource: string; authorization_servers?: string[]; scopes?: string[]} | null;
        };
        inbound_policy?: {policy_definition_id: string};
    };
    target: {
        endpoint: string;
        auth?: {method: {credential_provider?: {credential_provider_id: string}}};
        policy?: {policy_definition_id: string};
    };
}
