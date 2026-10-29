/**
 * Strategy swap through the dashboard
 *
 * The surface that trusts hydra-a is pointed at the strategy for hydra-b in the Caller Context
 * panel. The gateway keeps running: a token from hydra-a is refused and a token from hydra-b is
 * accepted. Swapping back restores the first behaviour.
 */

import fs from 'fs';
import path from 'path';
import {APIRequestContext, Page} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {callAgent} from '../../helpers/oidc-live/agent';
import {bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {chooseStrategy, openSurface, retypeTarget, saveEdit} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {ensureStrategy, ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, newContext} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';

const SURFACES = '**/api/v1/surfaces**';

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

    async function swapTo(page: Page, strategyName: string): Promise<void> {
        await bridgeLoopbackScheme(page, SURFACES);
        await openSurface(page, surfaceId);
        await chooseStrategy(page, strategyName);
        await retypeTarget(page);
        const saved = await saveEdit(page);
        const target = Object.values(names.strategies).find(strategy => strategy.name === strategyName);
        expect(saved.access_point.caller_authentication?.methods[0].jwt_verification_strategy_id).toBe(target?.id);
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

    test('before the swap tokens from hydra-a are accepted', async () => {
        expect((await callAgent(http, await tokenFrom('a'))).status).toBe(200);
        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(403);
    });

    test('pointing the surface at the hydra-b strategy takes effect without a restart', async ({page}) => {
        await swapTo(page, names.strategies.hydraB.name);

        expect(gatewayPid()).toBe(pid);
        expect((await http.get(`${env.gatewayUrl}/api/v1/alive`)).status()).toBe(200);
    });

    test('a token from hydra-a is now refused and a token from hydra-b is accepted', async () => {
        expect((await callAgent(http, await tokenFrom('a'))).status).toBe(403);
        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(200);
    });

    test('swapping back restores hydra-a, still without a restart', async ({page}) => {
        await swapTo(page, names.strategies.hydraA.name);

        expect((await callAgent(http, await tokenFrom('b'))).status).toBe(403);
        expect((await callAgent(http, await tokenFrom('a'))).status).toBe(200);
        expect(gatewayPid()).toBe(pid);
    });
});
