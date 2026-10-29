/**
 * Strategy swap through the dashboard
 *
 * The surface that trusts hydra-a is pointed at the strategy for hydra-b in the Caller Context
 * panel. The gateway keeps running: the card and the protected resource metadata name hydra-b,
 * a token from hydra-a is refused and a token from hydra-b is accepted. Swapping back restores
 * the first behaviour.
 */

import fs from 'fs';
import path from 'path';
import {APIRequestContext, Page} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {callAgent} from '../../helpers/oidc-live/agent';
import {CARD_URL, CardJson, gatewayScheme} from '../../helpers/oidc-live/agent-card';
import {bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {chooseStrategy, openCallerAuth, openSurface, retypeTarget, saveEdit} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {ensureStrategy, ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, newContext} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {ticket} from '../../helpers/ticket';

const SURFACES = '**/api/v1/surfaces**';
const PRM_URL = `${env.accessPointOrigin}/.well-known/oauth-protected-resource${env.route}`;

function gatewayPid(): string {
    return fs.readFileSync(path.join(env.gatewayEnvDir, 'gateway.pid'), 'utf8').trim();
}

test.describe('Strategy swap', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let world: World;
    let surfaceId: string;
    let pid: string;

    async function tokenFrom(which: 'a' | 'b'): Promise<string> {
        const hydra = which === 'a' ? env.hydraA : env.hydraB;
        const client = which === 'a' ? world.good : world.goodOnB;
        return accessToken(
            await clientCredentialsToken(http, hydra, client, {audience: env.entryPointUrl, scope: names.scopes.caller})
        );
    }

    async function declaredMetadataUrl(): Promise<string> {
        const response = await http.get(CARD_URL);
        expect(response.status()).toBe(200);
        return gatewayScheme((await response.json()) as CardJson).oauth2MetadataUrl;
    }

    async function swapTo(page: Page, strategyName: string): Promise<void> {
        await bridgeLoopbackScheme(page, SURFACES);
        await openSurface(page, surfaceId);
        await chooseStrategy(page, strategyName);
        await retypeTarget(page);
        const saved = await saveEdit(page);
        const target = Object.values(names.strategies).find(strategy => strategy.name === strategyName);
        const [method] = saved.access_point.caller_authentication?.methods ?? [];
        expect(method.jwt_verification_strategy_id).toBe(target?.id);
        expect(method.audiences).toEqual([env.entryPointUrl]);
        expect(method.required_scopes).toEqual([names.scopes.caller]);
        expect(saved.warnings ?? []).toEqual([]);
    }

    test.beforeAll(async () => {
        http = await newContext();
        pid = gatewayPid();
        world = loadWorld();
        const api = await GatewayApi.connect();
        try {
            const surface = await ensureSurface(api, world);
            surfaceId = String(surface.surface_id ?? surface.id);
            await ensureStrategy(api, 'a');
            await ensureStrategy(api, 'b');
        } finally {
            await api.dispose();
        }
    });

    test.afterAll(async () => {
        await http.dispose();
    });

    test('before the swap hydra-a is declared and its tokens are accepted', async () => {
        ticket('FTL-30890', 'FTL-30894');
        expect(await declaredMetadataUrl()).toBe(`${env.hydraA.issuer}.well-known/oauth-authorization-server`);
        expect((await callAgent(http, await tokenFrom('a'))).status).toBe(200);
        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(401);
    });

    test('pointing the surface at the hydra-b strategy changes the card and the metadata, without a restart', async ({page}) => {
        ticket('FTL-30889', 'FTL-30890', 'FTL-30894');
        await swapTo(page, names.strategies.hydraB.name);

        const card = (await (await http.get(CARD_URL)).json()) as CardJson;
        const scheme = gatewayScheme(card);
        expect(scheme.oauth2MetadataUrl).toBe(`${env.hydraB.issuer}.well-known/oauth-authorization-server`);
        expect(scheme.flows.clientCredentials.tokenUrl).toBe(`${env.hydraB.issuer}oauth2/token`);
        const resource = (await (await http.get(PRM_URL)).json()) as {authorization_servers: string[]};
        expect(resource.authorization_servers).toEqual([env.hydraB.issuer]);
        expect(gatewayPid()).toBe(pid);
        expect((await http.get(`${env.gatewayUrl}/api/v1/alive`)).status()).toBe(200);
    });

    test('a token from hydra-a is now refused with a challenge and a token from hydra-b is accepted', async () => {
        ticket('FTL-30894');
        const refused = await callAgent(http, await tokenFrom('a'));
        expect(refused.status).toBe(401);
        expect(refused.headers['www-authenticate']).toContain(`resource_metadata="${PRM_URL}"`);
        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(200);
    });

    test('the dashboard reports the new authorization server for the surface', async ({page}) => {
        ticket('FTL-30889', 'FTL-30890');
        await openSurface(page, surfaceId);
        await openCallerAuth(page);
        await expect(page.getByTestId('caller-auth-jwt-strategy')).toHaveValue(names.strategies.hydraB.id);
        await expect(page.getByTestId('caller-auth-outcome-chip').first()).toContainText('Declares OAuth');
        await expect(page.getByTestId('caller-auth-discovery-derived-authorization-server')).toHaveText(env.hydraB.issuer);
        await expect(page.getByTestId('caller-auth-discovery-audience-listed')).toBeVisible();
        await expect(page.getByTestId('caller-auth-discovery-derived-notes')).toHaveCount(0);
    });

    test('swapping back restores hydra-a, still without a restart', async ({page}) => {
        ticket('FTL-30889', 'FTL-30890', 'FTL-30894');
        await swapTo(page, names.strategies.hydraA.name);

        expect(await declaredMetadataUrl()).toBe(`${env.hydraA.issuer}.well-known/oauth-authorization-server`);
        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(401);
        expect((await callAgent(http, await tokenFrom('a'))).status).toBe(200);
        expect(gatewayPid()).toBe(pid);
    });
});
