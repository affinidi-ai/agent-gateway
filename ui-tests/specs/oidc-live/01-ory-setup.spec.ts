/**
 * Ory side
 *
 * The OAuth clients, the signing key and the RFC 7523 trust grant are created in the world setup
 * through the Hydra admin API. This spec proves, against the live Hydra, that they behave the
 * way the later specs rely on.
 */

import {APIRequestContext} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {env} from '../../helpers/oidc-live/env';
import {
    accessToken,
    clientCredentialsToken,
    generateSigningKey,
    jwtBearerToken,
    jwtClaims,
    newContext,
    publicKeyMatches,
    signAssertion,
    trustGrantExists,
} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {ticket} from '../../helpers/ticket';

test.describe('Ory side', () => {
    let hydra: APIRequestContext;
    let world: World;

    test.beforeAll(async () => {
        hydra = await newContext();
        world = loadWorld();
    });

    test.afterAll(async () => {
        await hydra.dispose();
    });

    test('hydra-a advertises the issuer string the gateway must compare exactly', async () => {
        ticket('FTL-30889', 'FTL-30890');
        const metadata = await hydra.get(`${env.hydraA.issuer}.well-known/openid-configuration`);
        expect(metadata.status()).toBe(200);
        const body = (await metadata.json()) as {issuer: string; token_endpoint: string; jwks_uri: string};
        expect(body.issuer).toBe(env.hydraA.issuer);
        expect(body.issuer.endsWith('/')).toBe(true);
        expect(body.token_endpoint).toBe(`${env.hydraA.issuer}oauth2/token`);
        expect(body.jwks_uri).toBe(`${env.hydraA.issuer}.well-known/jwks.json`);
    });

    test('demo-good gets a JWT with the entry point as audience, the scope as a list and hydra-a as issuer', async () => {
        ticket('FTL-30892', 'FTL-30894');
        const response = await clientCredentialsToken(hydra, env.hydraA, world.good, {
            audience: env.entryPointUrl,
            scope: names.scopes.caller,
        });
        const claims = jwtClaims(accessToken(response));
        expect(claims.iss).toBe(env.hydraA.issuer);
        expect(claims.aud).toEqual([env.entryPointUrl]);
        expect(claims.scp).toEqual([names.scopes.caller]);
        expect(claims.client_id).toBe(names.clients.good);
    });

    test('demo-noscope gets a token without the scope', async () => {
        ticket('FTL-30892');
        const response = await clientCredentialsToken(hydra, env.hydraA, world.noScope, {audience: env.entryPointUrl});
        const claims = jwtClaims(accessToken(response));
        expect(claims.aud).toEqual([env.entryPointUrl]);
        expect(claims.scp ?? []).not.toContain(names.scopes.caller);
    });

    test('demo-noscope is refused the scope it was never registered for', async () => {
        ticket('FTL-30892');
        const response = await clientCredentialsToken(hydra, env.hydraA, world.noScope, {
            audience: env.entryPointUrl,
            scope: names.scopes.caller,
        });
        expect(response.status).toBe(400);
        expect(response.body.error).toBe('invalid_scope');
    });

    test('demo-otheraud gets a token for another audience and cannot ask for the entry point', async () => {
        ticket('FTL-30894');
        const other = await clientCredentialsToken(hydra, env.hydraA, world.otherAudience, {
            audience: names.otherAudience,
            scope: names.scopes.caller,
        });
        expect(jwtClaims(accessToken(other)).aud).toEqual([names.otherAudience]);

        const refused = await clientCredentialsToken(hydra, env.hydraA, world.otherAudience, {
            audience: env.entryPointUrl,
            scope: names.scopes.caller,
        });
        expect(refused.status).toBe(400);
    });

    test('hydra-b accepts an assertion signed by the trusted key, refuses a replay and an unknown key', async () => {
        ticket('FTL-30886');
        expect(await trustGrantExists(hydra, env.hydraB, world.grantId)).toBe(true);
        expect(publicKeyMatches(world.key)).toBe(true);
        const claims = {
            iss: names.assertion.issuer,
            sub: names.assertion.subject,
            aud: `${env.hydraB.issuer}oauth2/token`,
            scope: names.scopes.hop2,
        };

        const assertion = signAssertion(world.key, claims);
        const issued = await jwtBearerToken(hydra, env.hydraB, world.hop2, assertion, names.scopes.hop2);
        const token = jwtClaims(accessToken(issued));
        expect(token.iss).toBe(env.hydraB.issuer);
        expect(token.scp).toEqual([names.scopes.hop2]);

        const replayed = await jwtBearerToken(hydra, env.hydraB, world.hop2, assertion, names.scopes.hop2);
        expect(replayed.status).toBe(400);

        const stranger = generateSigningKey(names.assertion.kid);
        const untrusted = await jwtBearerToken(
            hydra,
            env.hydraB,
            world.hop2,
            signAssertion(stranger, claims),
            names.scopes.hop2
        );
        expect(untrusted.status).toBe(400);
    });
});
