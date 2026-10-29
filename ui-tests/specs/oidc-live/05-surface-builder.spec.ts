/**
 * Surface builder through the dashboard
 *
 * An A2A surface in front of the mock agent: caller authentication with the hydra-a strategy and
 * Target Authentication through the JWT bearer provider.
 *
 * The dashboard accepts only an https Target for a credential provider and the mock agent is plain
 * http on loopback, so the save requests go through the scheme bridge.
 */

import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {
    configureTarget,
    nameSurface,
    openCallerAuth,
    openSurface,
    routeToTheHttpsListener,
    SavedSurface,
    startA2aSurface,
} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {
    Entity,
    ensureDenyRule,
    ensureProviders,
    ensureSecrets,
    ensureStrategy,
    listEntities,
} from '../../helpers/oidc-live/gateway-state';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld} from '../../helpers/oidc-live/world';

const SURFACES = '**/api/v1/surfaces**';

async function surfaceByName(api: GatewayApi): Promise<SavedSurface | undefined> {
    const listed = await listEntities(api, '/api/v1/surfaces');
    const found = listed.find(surface => surface.name === names.surface);
    return found ? (await api.get<SavedSurface>(`/api/v1/surfaces/${found.surface_id ?? found.id}`)).body : undefined;
}

test.describe('Surface builder', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    let jwtBearerProviderId: string;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        for (const surface of await listEntities(api, '/api/v1/surfaces')) {
            if (surface.name?.startsWith('oidc-e2e')) await api.delete(`/api/v1/surfaces/${surface.surface_id ?? surface.id}`);
        }
        await ensureSecrets(api, loadWorld());
        await ensureStrategy(api, 'a');
        jwtBearerProviderId = (await ensureProviders(api)).jwtBearer.id;
    });

    test.afterAll(async () => {
        await api.dispose();
    });

    test('creates the surface with caller authentication and Target Authentication', async ({page}) => {
        await bridgeLoopbackScheme(page, SURFACES);
        await startA2aSurface(page);
        await nameSurface(page, names.surface);
        await routeToTheHttpsListener(page);
        await openCallerAuth(page);
        await page.getByTestId('caller-auth-jwt-strategy').selectOption({label: names.strategies.hydraA.name});
        await page.getByTestId('caller-auth-close-button').click();
        await configureTarget(page, {
            url: env.agentUrl,
            providerLabel: `${names.providers.jwtBearer} (JWT Bearer)`,
        });
        const created = page.waitForResponse(
            response => response.url().endsWith('/api/v1/surfaces') && response.request().method() === 'POST'
        );
        await page.getByTestId('surface-create-button').click();
        const response = await created;
        expect(response.status()).toBe(201);
        const body = (await response.json()) as SavedSurface;

        await expect(page).toHaveURL(/\/surfaces$/);

        const stored = (await surfaceByName(api)) as SavedSurface;
        expect(stored.surface_id).toBe(body.surface_id);
        expect(stored.access_point.listen_address).toBe(env.accessPointOrigin);
        expect(stored.access_point.route).toBe(env.route);
        const [method] = stored.access_point.caller_authentication?.methods ?? [];
        expect(method).toMatchObject({
            type: 'jwt_bearer',
            jwt_verification_strategy_id: names.strategies.hydraA.id,
        });
        expect(stored.target.endpoint).toBe(env.agentUrl);
        expect(stored.target.auth?.method.credential_provider?.credential_provider_id).toBe(jwtBearerProviderId);
    });

    test('attaches the policy that denies callers whose token failed verification', async () => {
        const surface = (await surfaceByName(api)) as SavedSurface;
        const policyId = await ensureDenyRule(api);
        const patched = await api.patch(`/api/v1/surfaces/${surface.surface_id}`, {
            access_point: {inbound_policy: {policy_definition_id: policyId, require_agent_context: false}},
        });
        expect(patched.status).toBe(200);

        const stored = (await surfaceByName(api)) as SavedSurface;
        expect(stored.access_point.inbound_policy?.policy_definition_id).toBe(policyId);
    });

    test('shows the entry point URL for the saved surface', async ({page}) => {
        const surface = (await surfaceByName(api)) as SavedSurface;
        await openSurface(page, surface.surface_id);
        await expect(page.getByTestId('surface-entry-point-url')).toContainText(env.entryPointUrl);
    });
});
