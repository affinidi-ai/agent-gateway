/**
 * Using the surface end to end
 *
 * Tokens come from the live hydra-a and the calls go to the gateway's https Access Point. The
 * gateway reaches the mock agent with its own token from hydra-b (JWT bearer grant).
 */

import {APIRequestContext} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {agentLog, callAgent, hydraBTokenRequests, resetAgentLog} from '../../helpers/oidc-live/agent';
import {env} from '../../helpers/oidc-live/env';
import {ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, jwtClaims, newContext} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';

const CARD_URL = `${env.entryPointUrl}/.well-known/agent-card.json`;

test.describe('Use the surface', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let world: World;
    let afterFirstCall = 0;

    async function callerToken(): Promise<string> {
        return accessToken(
            await clientCredentialsToken(http, env.hydraA, world.good, {
                audience: env.entryPointUrl,
                scope: names.scopes.caller,
            })
        );
    }

    test.beforeAll(async () => {
        http = await newContext();
        world = loadWorld();
        const api = await GatewayApi.connect();
        try {
            await ensureSurface(api, world);
        } finally {
            await api.dispose();
        }
    });

    test.afterAll(async () => {
        await http.dispose();
    });

    test('hop 2: the card fetch and the first call reach the agent with a hydra-b token the gateway obtained', async () => {
        await resetAgentLog(http);
        const before = await hydraBTokenRequests(http);

        const card = await http.get(CARD_URL, {failOnStatusCode: false});
        expect(card.status()).toBe(200);
        const call = await callAgent(http, await callerToken());
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
        const call = await callAgent(http, await callerToken());
        expect(call.status).toBe(200);

        const log = await agentLog(http);
        expect(log.filter(entry => entry.method === 'POST' && entry.authenticated && entry.client_id === names.clients.hop2)).toHaveLength(2);
        expect(await hydraBTokenRequests(http)).toBe(afterFirstCall);
    });

    test('the good client gets the agent\'s reply', async () => {
        const token = await callerToken();
        expect(jwtClaims(token).iss).toBe(env.hydraA.issuer);
        const call = await callAgent(http, token);
        expect(call.status).toBe(200);
        expect(JSON.parse(call.text).result.parts[0].text).toBe('mock agent reply');
    });

    test('a token that hydra-b issued is not accepted while the surface trusts hydra-a', async () => {
        const token = accessToken(
            await clientCredentialsToken(http, env.hydraB, world.goodOnB, {
                audience: env.entryPointUrl,
                scope: names.scopes.caller,
            })
        );
        expect((await callAgent(http, token)).status).toBe(403);
    });
});
