/**
 * Hop 2 when Hydra stops trusting the gateway
 *
 * The trust grant for the gateway's signing key is revoked in Hydra. A token the gateway already
 * holds keeps working until it expires. A provider with no cached token cannot get a new one and
 * the caller sees the gateway's generic error, with no detail from Hydra. The provider also waits out
 * its failure backoff, so after the grant is restored the same provider recovers within a few seconds.
 */

import {APIRequestContext, Page} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {agentLog, callAgent, resetAgentLog} from '../../helpers/oidc-live/agent';
import {bridgeLoopbackScheme} from '../../helpers/oidc-live/bridge';
import {openSurface, retypeTarget, saveEdit} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {Entity, ensureProviders, ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {
    accessToken,
    clientCredentialsToken,
    createTrustGrant,
    newContext,
    revokeTrustGrant,
    trustGrantExists,
} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, saveWorld, World} from '../../helpers/oidc-live/world';

const SURFACES = '**/api/v1/surfaces**';
const SECOND_PROVIDER = `${names.providers.jwtBearer} 2`;
const CARD_URL = `${env.entryPointUrl}/.well-known/agent-card.json`;

test.describe('Hop 2 after the trust grant is revoked', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let api: GatewayApi;
    let world: World;
    let surfaceId: string;
    let secondProvider: Entity;

    async function goodToken(): Promise<string> {
        return accessToken(
            await clientCredentialsToken(http, env.hydraA, world.good, {audience: env.entryPointUrl, scope: names.scopes.caller})
        );
    }

    async function useProvider(page: Page, label: string): Promise<void> {
        await bridgeLoopbackScheme(page, SURFACES);
        await openSurface(page, surfaceId);
        await retypeTarget(page);
        await page.getByTestId('managed-agent-auth-configure').click();
        await page.getByTestId('target-auth-credential-provider-select').selectOption({label});
        await saveEdit(page);
    }

    test.beforeAll(async () => {
        http = await newContext();
        api = await GatewayApi.connect();
        world = loadWorld();
        const surface = await ensureSurface(api, world);
        surfaceId = String(surface.surface_id ?? surface.id);
        const {clientCredentials, jwtBearer} = await ensureProviders(api);
        // The default licence allows two credential providers, so the unused one makes room.
        await api.delete(`/api/v1/credential-providers/${clientCredentials.id}`);
        const created = await api.post<Entity>('/api/v1/credential-providers', {
            name: SECOND_PROVIDER,
            provider_id: 'oidc-e2e-jwt-bearer-2',
            provider_type: 'oauth2_jwt_bearer',
            token_endpoint: `${env.hydraB.issuer}oauth2/token`,
            default_scopes: [names.scopes.hop2],
            client_id_secret_ref: names.secrets.hop2ClientId,
            client_secret_secret_ref: names.secrets.hop2ClientSecret,
            jwt_bearer: {
                signing_key_secret_ref: names.secrets.signingKey,
                signing_algorithm: 'RS256',
                key_id: names.assertion.kid,
                assertion_issuer: names.assertion.issuer,
                assertion_subject: names.assertion.subject,
            },
        });
        expect(created.status).toBe(201);
        secondProvider = created.body;
        expect(jwtBearer.id).not.toBe(secondProvider.id);
    });

    test.afterAll(async () => {
        await api.delete(`/api/v1/credential-providers/${secondProvider.id}`);
        await api.dispose();
        await http.dispose();
    });

    test('the surface works while Hydra trusts the gateway key', async () => {
        expect((await callAgent(http, await goodToken())).status).toBe(200);
        expect(await trustGrantExists(http, env.hydraB, world.grantId)).toBe(true);
    });

    test('revoking the trust grant does not take back a token the gateway already holds', async () => {
        expect(await revokeTrustGrant(http, env.hydraB, world.grantId)).toBe(204);
        expect(await trustGrantExists(http, env.hydraB, world.grantId)).toBe(false);

        expect((await callAgent(http, await goodToken())).status).toBe(200);
    });

    test('a provider that has to ask Hydra for a new token fails the call with the generic gateway error', async ({page}) => {
        await useProvider(page, `${SECOND_PROVIDER} (JWT Bearer)`);
        await resetAgentLog(http);

        const call = await callAgent(http, await goodToken());
        expect(call.status).toBe(502);
        const body = JSON.parse(call.text) as {detail: string; title: string};
        expect(body.title).toBe('Bad Gateway');
        expect(body.detail).toBe('Target authentication failed');
        for (const leak of ['invalid_grant', 'hydra', 'assertion', 'Bearer', 'eyJ', 'PRIVATE', 'client_secret', String(new URL(env.hydraB.issuer).port)]) {
            expect(call.text.includes(leak), `the error body mentions ${leak}`).toBe(false);
        }
        const card = await http.get(CARD_URL, {failOnStatusCode: false});
        expect(card.status()).toBe(502);

        expect((await agentLog(http)).filter(entry => entry.authenticated)).toHaveLength(0);
    });

    test('restoring the grant makes the same provider work again, and the original provider still works', async ({page}) => {
        world.grantId = await createTrustGrant(http, env.hydraB, {
            issuer: names.assertion.issuer,
            subject: names.assertion.subject,
            scope: [names.scopes.hop2],
            jwk: world.key.publicJwk,
        });
        saveWorld(world);

        await resetAgentLog(http);
        const token = await goodToken();
        await expect.poll(async () => (await callAgent(http, token)).status, {timeout: 30_000, intervals: [500, 1000, 2000]}).toBe(200);
        expect((await agentLog(http)).filter(entry => entry.authenticated).length).toBeGreaterThan(0);

        await useProvider(page, `${names.providers.jwtBearer} (JWT Bearer)`);
        const call = await callAgent(http, await goodToken());
        expect(call.status).toBe(200);
        expect(JSON.parse(call.text).result.parts[0].text).toBe('mock agent reply');
    });
});
