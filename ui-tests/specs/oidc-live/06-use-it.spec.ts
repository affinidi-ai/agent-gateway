/**
 * Using the surface end to end
 *
 * Tokens come from the live hydra-a and the calls go to the gateway's https Access Point. The
 * Access Point declares hydra-a and the required scope in its agent card and protected resource
 * metadata, and refuses a failed caller itself with a challenge. The gateway reaches the mock agent
 * with its own token from hydra-b (JWT bearer grant).
 */

import {APIRequestContext} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {agentLog, callAgent, hydraBTokenRequests, resetAgentLog} from '../../helpers/oidc-live/agent';
import {CARD_URL, CardJson, gatewayScheme} from '../../helpers/oidc-live/agent-card';
import {openCallerAuth, openSurface} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, jwtClaims, newContext} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {feature} from '../../helpers/feature';

const PRM_URL = `${env.accessPointOrigin}/.well-known/oauth-protected-resource${env.route}`;

test.describe('Use the surface', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let world: World;
    let surfaceId: string;
    let afterFirstCall = 0;

    async function callerToken(client: 'good' | 'noScope' | 'otherAudience'): Promise<string> {
        const options =
            client === 'otherAudience'
                ? {audience: names.otherAudience, scope: names.scopes.caller}
                : client === 'good'
                  ? {audience: env.entryPointUrl, scope: names.scopes.caller}
                  : {audience: env.entryPointUrl};
        return accessToken(await clientCredentialsToken(http, env.hydraA, world[client], options));
    }

    test.beforeAll(async () => {
        http = await newContext();
        world = loadWorld();
        const api = await GatewayApi.connect();
        try {
            const surface = await ensureSurface(api, world);
            surfaceId = String(surface.surface_id ?? surface.id);
        } finally {
            await api.dispose();
        }
    });

    test.afterAll(async () => {
        await http.dispose();
    });

    test('hop 2: the card fetch and the first call reach the agent with a hydra-b token the gateway obtained', async () => {
        feature('jwt-bearer-provider', 'target-authentication-provider', 'protected-agent-card-fetch');
        await resetAgentLog(http);
        const before = await hydraBTokenRequests(http);

        const card = await http.get(CARD_URL, {failOnStatusCode: false});
        expect(card.status()).toBe(200);
        const call = await callAgent(http, await callerToken('good'));
        expect(call.status).toBe(200);
        expect(JSON.parse(call.text).result.parts[0].text).toBe('mock agent reply');

        const log = await agentLog(http);
        expect(log.filter(entry => entry.method === 'GET' && entry.authenticated && entry.client_id === names.clients.hop2)).toHaveLength(1);
        expect(log.filter(entry => entry.method === 'POST' && entry.authenticated && entry.client_id === names.clients.hop2)).toHaveLength(1);
        expect(log.filter(entry => entry.status !== 200)).toHaveLength(0);

        afterFirstCall = await hydraBTokenRequests(http);
        expect(afterFirstCall - before, 'hydra-b token requests for the gateway').toBeLessThanOrEqual(1);
    });

    test('hop 2: a second call reuses the token instead of asking hydra-b again', async () => {
        feature('jwt-bearer-provider', 'target-authentication-provider');
        const call = await callAgent(http, await callerToken('good'));
        expect(call.status).toBe(200);

        const log = await agentLog(http);
        expect(log.filter(entry => entry.method === 'POST' && entry.authenticated && entry.client_id === names.clients.hop2)).toHaveLength(2);
        expect(await hydraBTokenRequests(http)).toBe(afterFirstCall);
    });

    test("the public agent card declares hydra-a and the required scope, and drops the agent's own security and signatures", async () => {
        feature('protected-agent-card-fetch', 'agent-card-signin-declaration');
        const response = await http.get(CARD_URL);
        expect(response.status()).toBe(200);
        const card = (await response.json()) as CardJson;
        const text = JSON.stringify(card);

        expect(card.name).toBe('OIDC Demo Mock Agent');
        expect(card.url).toBe(env.entryPointUrl);
        const scheme = gatewayScheme(card);
        expect(scheme.type).toBe('oauth2');
        expect(scheme.oauth2MetadataUrl).toBe(`${env.hydraA.issuer}.well-known/oauth-authorization-server`);
        expect(scheme.flows.clientCredentials.tokenUrl).toBe(`${env.hydraA.issuer}oauth2/token`);
        expect(Object.keys(scheme.flows.clientCredentials.scopes)).toEqual([names.scopes.caller]);
        expect(card.security).toEqual([{agent_gateway: [names.scopes.caller]}]);
        expect(card).not.toHaveProperty('signatures');
        expect(text).not.toContain('agent_own_oauth');
        expect(text).not.toContain('agent-as.internal.example');
        expect(text).not.toContain(env.hydraB.issuer);
    });

    test('the dashboard reports the same outcome for the saved surface', async ({page}) => {
        feature('agent-card-signin-declaration', 'agent-card-tab-and-signin-settings');
        await openSurface(page, surfaceId);
        await openCallerAuth(page);
        await expect(page.getByTestId('caller-auth-outcome-chip').first()).toContainText('Declares OAuth');
        await expect(page.getByTestId('caller-auth-discovery-switch')).toBeChecked();
        await expect(page.getByTestId('caller-auth-discovery-derived-authorization-server')).toHaveText(env.hydraA.issuer);
        await expect(page.getByTestId('surface-warnings-alert')).toHaveCount(0);
    });

    test('the protected resource metadata names the entry point, hydra-a and the scope', async () => {
        feature('signin-challenges-and-metadata');
        const response = await http.get(PRM_URL);
        expect(response.status()).toBe(200);
        expect(await response.json()).toEqual({
            resource: env.entryPointUrl,
            authorization_servers: [env.hydraA.issuer],
            bearer_methods_supported: ['header'],
            scopes_supported: [names.scopes.caller],
        });
    });

    test('a call without a token gets 401 with a challenge that points at the metadata', async () => {
        feature('signin-challenges-and-metadata');
        const call = await callAgent(http);
        expect(call.status).toBe(401);
        const challenge = call.headers['www-authenticate'];
        expect(challenge).toMatch(/^Bearer /);
        expect(challenge).toContain(`resource_metadata="${PRM_URL}"`);
        expect(challenge).toContain(`scope="${names.scopes.caller}"`);
    });

    test("the good client gets the agent's reply", async () => {
        feature('required-scopes', 'signin-challenges-and-metadata');
        const token = await callerToken('good');
        expect(jwtClaims(token).iss).toBe(env.hydraA.issuer);
        const call = await callAgent(http, token);
        expect(call.status).toBe(200);
        expect(JSON.parse(call.text).result.parts[0].text).toBe('mock agent reply');
    });

    test('the client without the scope gets 403 with insufficient_scope', async () => {
        feature('required-scopes');
        const call = await callAgent(http, await callerToken('noScope'));
        expect(call.status).toBe(403);
        expect(call.headers['www-authenticate'] ?? '').toContain('insufficient_scope');
    });

    test('the client with a token for another audience gets 401 with a challenge', async () => {
        feature('signin-challenges-and-metadata');
        const call = await callAgent(http, await callerToken('otherAudience'));
        expect(call.status).toBe(401);
        expect(call.headers['www-authenticate']).toContain(`resource_metadata="${PRM_URL}"`);
    });

    test('a token that hydra-b issued is refused with 401 while the surface trusts hydra-a', async () => {
        feature('signin-challenges-and-metadata');
        const token = accessToken(
            await clientCredentialsToken(http, env.hydraB, world.goodOnB, {
                audience: env.entryPointUrl,
                scope: names.scopes.caller,
            })
        );
        const call = await callAgent(http, token);
        expect(call.status).toBe(401);
        expect(call.headers['www-authenticate']).toContain('error="invalid_token"');
    });
});
