import fs from 'fs';
import {APIRequestContext} from '@playwright/test';
import {GatewayApi} from '../gateway-api';
import {env, ensureDir} from './env';
import {
    OAuthClient,
    SigningKey,
    createTrustGrant,
    deleteClient,
    deleteTrustGrantsFor,
    generateSigningKey,
    JWT_BEARER_GRANT,
    randomSecret,
    registerClient,
} from './hydra';
import {PREFIX, names} from './names';

export interface World {
    good: OAuthClient;
    noScope: OAuthClient;
    otherAudience: OAuthClient;
    goodOnB: OAuthClient;
    hop2: OAuthClient;
    key: SigningKey;
    grantId: string;
}

export function loadWorld(): World {
    if (!fs.existsSync(env.stateFile)) {
        throw new Error(`${env.stateFile} is missing; the world-setup project creates it`);
    }
    return JSON.parse(fs.readFileSync(env.stateFile, 'utf8')) as World;
}

export function saveWorld(world: World): void {
    ensureDir(env.stateFile);
    fs.writeFileSync(env.stateFile, JSON.stringify(world), {mode: 0o600});
}

export async function createWorld(hydra: APIRequestContext): Promise<World> {
    await destroyWorld(hydra);
    const entry = env.entryPointUrl;
    const callerGrants = ['client_credentials'];
    const good = await registerClient(hydra, env.hydraA, {
        id: names.clients.good,
        secret: randomSecret(),
        grantTypes: callerGrants,
        scope: names.scopes.caller,
        audience: [entry],
    });
    const noScope = await registerClient(hydra, env.hydraA, {
        id: names.clients.noScope,
        secret: randomSecret(),
        grantTypes: callerGrants,
        scope: '',
        audience: [entry],
    });
    const otherAudience = await registerClient(hydra, env.hydraA, {
        id: names.clients.otherAudience,
        secret: randomSecret(),
        grantTypes: callerGrants,
        scope: names.scopes.caller,
        audience: [names.otherAudience],
    });
    const goodOnB = await registerClient(hydra, env.hydraB, {
        id: names.clients.good,
        secret: randomSecret(),
        grantTypes: callerGrants,
        scope: names.scopes.caller,
        audience: [entry],
    });
    const hop2 = await registerClient(hydra, env.hydraB, {
        id: names.clients.hop2,
        secret: randomSecret(),
        grantTypes: [JWT_BEARER_GRANT],
        scope: names.scopes.hop2,
        audience: [],
    });
    const key = generateSigningKey(names.assertion.kid);
    const grantId = await createTrustGrant(hydra, env.hydraB, {
        issuer: names.assertion.issuer,
        subject: names.assertion.subject,
        scope: [names.scopes.hop2],
        jwk: key.publicJwk,
    });
    const world: World = {good, noScope, otherAudience, goodOnB, hop2, key, grantId};
    saveWorld(world);
    return world;
}

export async function destroyWorld(hydra: APIRequestContext): Promise<void> {
    for (const id of [names.clients.good, names.clients.noScope, names.clients.otherAudience]) {
        await deleteClient(hydra, env.hydraA, id);
    }
    for (const id of [names.clients.good, names.clients.hop2]) {
        await deleteClient(hydra, env.hydraB, id);
    }
    await deleteTrustGrantsFor(hydra, env.hydraB, names.assertion.issuer);
}

interface Listed {
    id: string;
    name?: string;
    surface_id?: string;
    provider_id?: string;
    secret_id?: string;
}

async function list(api: GatewayApi, path: string): Promise<Listed[]> {
    const response = await api.get<Listed[] | {items?: Listed[]}>(path);
    const body = response.body;
    return Array.isArray(body) ? body : (body.items ?? []);
}

export async function cleanGateway(api: GatewayApi): Promise<void> {
    for (const surface of await list(api, '/api/v1/surfaces')) {
        if (surface.name?.startsWith(PREFIX)) await api.delete(`/api/v1/surfaces/${surface.surface_id ?? surface.id}`);
    }
    for (const provider of await list(api, '/api/v1/credential-providers')) {
        if (provider.provider_id?.startsWith(PREFIX) || provider.name?.startsWith(PREFIX)) {
            await api.delete(`/api/v1/credential-providers/${provider.id}`);
        }
    }
    for (const strategy of await list(api, '/api/v1/jwt-verification-strategies')) {
        if (strategy.name?.startsWith(PREFIX) || strategy.id.startsWith(PREFIX)) {
            await api.delete(`/api/v1/jwt-verification-strategies/${strategy.id}`);
        }
    }
    for (const definition of await list(api, '/api/v1/policy-definitions?policy_type=agent_surface')) {
        if (definition.name === 'Deny unauthenticated callers') await api.delete(`/api/v1/policy-definitions/${definition.id}`);
    }
    for (const secret of await list(api, '/api/v1/secrets/')) {
        if (secret.secret_id?.startsWith(PREFIX)) await api.delete(`/api/v1/secrets/${secret.id}`);
    }
}
