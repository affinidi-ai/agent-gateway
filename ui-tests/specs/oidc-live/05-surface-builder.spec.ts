/**
 * Surface builder through the dashboard
 *
 * An A2A surface in front of the mock agent: caller authentication with the hydra-a strategy and a
 * required scope, and Target Authentication through the JWT bearer provider. Saved without
 * Authorization server discovery, the Access Point does not declare and the gateway warns that
 * failed callers reach a policy that lets them through; the dashboard only warns and offers the
 * deny rule to copy. The rule is attached to the Target policy through the API, where it also denies
 * callers arriving over Fabric. Turning on Authorization server discovery in the Caller Context
 * editor makes the Access Point declare hydra-a, after which the gateway refuses failed callers
 * itself and nothing is left to warn about. Removing the required scope keeps that refusal.
 *
 * The dashboard accepts only an https Target for a credential provider and the mock agent is plain
 * http on loopback, so the save requests go through the scheme bridge.
 */

import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {callAgent} from '../../helpers/oidc-live/agent';
import {bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {
    configureCallerAuth,
    configureTarget,
    nameSurface,
    openCallerAuth,
    openSurface,
    retypeTarget,
    routeToTheHttpsListener,
    SavedSurface,
    saveEdit,
    startA2aSurface,
    turnOnAuthorizationServerDiscovery,
} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {ensureDenyRule, ensureProviders, ensureSecrets, ensureStrategy, listEntities} from '../../helpers/oidc-live/gateway-state';
import {names} from '../../helpers/oidc-live/names';
import {newContext} from '../../helpers/oidc-live/hydra';
import {loadWorld} from '../../helpers/oidc-live/world';
import {feature} from '../../helpers/feature';

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
    let denyRuleId: string;

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

    test('creates the surface with caller authentication, a required scope and Target Authentication, and only warns', async ({page}) => {
        feature('jwt-bearer-provider', 'target-authentication-dashboard', 'a2a-signin-design');
        await bridgeLoopbackScheme(page, SURFACES);
        await startA2aSurface(page);
        await nameSurface(page, names.surface);
        await routeToTheHttpsListener(page);
        await configureCallerAuth(page, {strategyName: names.strategies.hydraA.name, scopes: [names.scopes.caller]});
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
        const codes = body.warnings?.map(warning => warning.code) ?? [];
        expect(codes).toContain('fail_open_policy');
        expect(codes).not.toContain('declaration_stripped');

        await expect(page).toHaveURL(new RegExp(`/surfaces/${body.surface_id}$`));
        await expect(page.getByTestId('surface-warnings-alert')).toBeVisible();
        await expect(page.getByTestId('surface-warning-fail_open_policy')).toBeVisible();
        await expect(page.getByTestId('surface-warnings-copy-rule')).toBeVisible();
        await expect(page.getByTestId('surface-warnings-discovery-hint')).toBeVisible();
        await expect(page.getByTestId('surface-node-policy')).toHaveCount(0);

        const stored = (await surfaceByName(api)) as SavedSurface;
        expect(stored.surface_id).toBe(body.surface_id);
        expect(stored.access_point.listen_address).toBe(env.accessPointOrigin);
        expect(stored.access_point.route).toBe(env.route);
        const [method] = stored.access_point.caller_authentication?.methods ?? [];
        expect(method).toMatchObject({
            type: 'jwt_bearer',
            jwt_verification_strategy_id: names.strategies.hydraA.id,
            required_scopes: [names.scopes.caller],
        });
        expect(method.audiences ?? []).toEqual([]);
        expect(stored.access_point.caller_authentication?.protected_resource).toBeUndefined();
        expect(stored.target.endpoint).toBe(env.agentUrl);
        expect(stored.target.auth?.method.credential_provider?.credential_provider_id).toBe(jwtBearerProviderId);
        expect(stored.access_point.inbound_policy).toBeUndefined();
        expect(stored.target.policy).toBeUndefined();
    });

    test('attaching the deny rule to the Target policy through the API clears the fail-open warning', async ({page}) => {
        feature('a2a-signin-design');
        const surface = (await surfaceByName(api)) as SavedSurface;
        denyRuleId = await ensureDenyRule(api);
        const patched = await api.patch(`/api/v1/surfaces/${surface.surface_id}`, {
            target: {policy: {policy_definition_id: denyRuleId, require_agent_context: false}},
        });
        expect(patched.status).toBe(200);
        expect(((await surfaceByName(api)) as SavedSurface).target.policy?.policy_definition_id).toBe(denyRuleId);

        await openSurface(page, surface.surface_id);
        await expect(page.getByTestId('surface-warnings-alert')).toHaveCount(0);
        await expect(page.getByTestId('surface-node-policy')).toHaveCount(1);
    });

    test('turning on Authorization server discovery in the Caller Context editor makes the Access Point declare hydra-a', async ({page}) => {
        feature('a2a-signin-design', 'signin-challenges-and-metadata', 'agent-card-signin-declaration', 'agent-card-tab-and-signin-settings');
        await bridgeLoopbackScheme(page, SURFACES);
        const surface = (await surfaceByName(api)) as SavedSurface;
        await openSurface(page, surface.surface_id);
        await openCallerAuth(page);
        await expect(page.getByTestId('caller-auth-outcome-chip').first()).toContainText('Not declared');
        await expect(page.getByTestId('caller-auth-outcome-detail').first()).toContainText(
            'Authorization server discovery is off'
        );
        await expect(page.getByTestId('caller-auth-discovery-switch')).not.toBeChecked();
        await expect(page.getByTestId('caller-auth-discovery-off-summary')).toBeVisible();

        await turnOnAuthorizationServerDiscovery(page);
        await expect(page.getByTestId('caller-auth-discovery-derived-authorization-server')).toHaveText(env.hydraA.issuer);
        await expect(page.getByTestId('caller-auth-discovery-derived-scopes')).toHaveText(names.scopes.caller);
        await expect(page.getByTestId('caller-auth-discovery-derived-audience')).toContainText(env.entryPointUrl);
        await page.getByTestId('caller-auth-close-button').click();
        await retypeTarget(page);
        const saved = await saveEdit(page);

        expect(saved.warnings ?? []).toEqual([]);
        await expect(page.getByTestId('surface-warnings-alert')).toHaveCount(0);
        const stored = (await surfaceByName(api)) as SavedSurface;
        const [method] = stored.access_point.caller_authentication?.methods ?? [];
        expect(method).toMatchObject({
            type: 'jwt_bearer',
            jwt_verification_strategy_id: names.strategies.hydraA.id,
            required_scopes: [names.scopes.caller],
        });
        expect(method.audiences ?? []).toEqual([]);
        expect(stored.access_point.caller_authentication?.protected_resource).toEqual({resource: env.entryPointUrl, scopes: []});
        expect(stored.target.policy?.policy_definition_id).toBe(denyRuleId);
    });

    test('shows the entry point URL and the Declares OAuth outcome for the saved surface', async ({page}) => {
        feature('agent-card-signin-declaration', 'agent-card-tab-and-signin-settings');
        const surface = (await surfaceByName(api)) as SavedSurface;
        await openSurface(page, surface.surface_id);
        await expect(page.getByTestId('surface-entry-point-url')).toContainText(env.entryPointUrl);
        await openCallerAuth(page);
        await expect(page.getByTestId('caller-auth-outcome-chip').first()).toContainText('Declares OAuth');
        await expect(page.getByTestId('caller-auth-discovery-switch')).toBeChecked();
        await expect(page.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(env.entryPointUrl);
        await expect(page.getByTestId('caller-auth-discovery-rules-error')).toHaveCount(0);
        await expect(page.getByTestId('surface-warnings-alert')).toHaveCount(0);
    });

    test('removing the required scope keeps the gateway refusing a caller without a token', async ({page}) => {
        feature('a2a-signin-design', 'required-scopes');
        await bridgeLoopbackScheme(page, SURFACES);
        const surface = (await surfaceByName(api)) as SavedSurface;
        await openSurface(page, surface.surface_id);
        await openCallerAuth(page);
        await page.getByRole('button', {name: `Remove scope ${names.scopes.caller}`}).click();
        await expect(page.getByTestId('caller-auth-discovery-derived-scopes')).toContainText('None required');
        await page.getByTestId('caller-auth-close-button').click();
        await retypeTarget(page);
        const removed = await saveEdit(page);
        expect(removed.warnings ?? []).toEqual([]);

        const http = await newContext();
        try {
            const refused = await callAgent(http);
            expect(refused.status).toBe(401);
            expect(refused.headers['www-authenticate']).toContain('resource_metadata="');
            expect(refused.headers['www-authenticate']).not.toContain('scope=');
        } finally {
            await http.dispose();
        }

        await openCallerAuth(page);
        await page.getByTestId('caller-auth-scope-input').fill(names.scopes.caller);
        await page.getByTestId('caller-auth-scope-add').click();
        await page.getByTestId('caller-auth-close-button').click();
        await retypeTarget(page);
        await saveEdit(page);
        const stored = (await surfaceByName(api)) as SavedSurface;
        const [method] = stored.access_point.caller_authentication?.methods ?? [];
        expect(method.required_scopes).toEqual([names.scopes.caller]);
    });
});
