import {randomUUID} from 'crypto';
import fs from 'fs';
import path from 'path';
import {expect} from '@playwright/test';
import {GatewayApi} from '../gateway-api';
import {env} from './env';
import {names} from './names';
import {World} from './world';

export interface Entity {
    id: string;
    name?: string;
    secret_id?: string;
    provider_id?: string;
    surface_id?: string;
    authorization_server?: {issuer: string; metadata_url: string; token_endpoint: string; jwks_uri: string};
    expected_issuer?: string;
    [key: string]: unknown;
}

export interface SecretValues {
    [secretId: string]: string;
}

export function secretValues(world: World): SecretValues {
    return {
        [names.secrets.hop2ClientId]: world.hop2.id,
        [names.secrets.hop2ClientSecret]: world.hop2.secret,
        [names.secrets.signingKey]: world.key.privatePem,
        [names.secrets.ccClientId]: world.good.id,
        [names.secrets.ccClientSecret]: world.good.secret,
    };
}

export const secretLabels: Record<string, string> = {
    [names.secrets.hop2ClientId]: 'oidc-e2e hop 2 client id',
    [names.secrets.hop2ClientSecret]: 'oidc-e2e hop 2 client secret',
    [names.secrets.signingKey]: 'oidc-e2e signing key',
    [names.secrets.ccClientId]: 'oidc-e2e client credentials id',
    [names.secrets.ccClientSecret]: 'oidc-e2e client credentials secret',
};

export async function listEntities(api: GatewayApi, path: string): Promise<Entity[]> {
    const response = await api.get<Entity[] | {items?: Entity[]}>(path);
    const body = response.body;
    return Array.isArray(body) ? body : (body.items ?? []);
}

export async function ensureSecrets(api: GatewayApi, world: World): Promise<void> {
    const present = new Set((await listEntities(api, '/api/v1/secrets/')).map(secret => secret.secret_id));
    const values = secretValues(world);
    for (const [secretId, value] of Object.entries(values)) {
        if (present.has(secretId)) continue;
        const created = await api.post('/api/v1/secrets/new', {
            name: secretLabels[secretId],
            secret_id: secretId,
            value,
            secret_type: secretId === names.secrets.signingKey ? 'Certificate' : 'General',
        });
        expect(created.status, `creating secret ${secretId}`).toBe(201);
    }
}

export function strategyRecord(which: 'a' | 'b', overrides: Partial<Entity> = {}): Entity {
    const issuer = which === 'a' ? env.hydraA.issuer : env.hydraB.issuer;
    const {id, name} = which === 'a' ? names.strategies.hydraA : names.strategies.hydraB;
    const now = new Date().toISOString();
    return {
        id,
        name,
        expected_issuer: issuer,
        jwks_source: {type: 'remote', jwks_uri: `${issuer}.well-known/jwks.json`},
        authorization_server: {
            issuer,
            metadata_url: `${issuer}.well-known/oauth-authorization-server`,
            token_endpoint: `${issuer}oauth2/token`,
            jwks_uri: `${issuer}.well-known/jwks.json`,
        },
        created_at: now,
        updated_at: now,
        ...overrides,
    };
}

// The management API refuses a loopback JWKS URI at save time, and the dashboard refuses a
// non-https issuer, so a strategy for the local Hydra is written into the gateway's storage the
// way the demo harness does. The gateway picks it up on its cache refresh interval.
export async function seedStrategy(api: GatewayApi, record: Entity): Promise<void> {
    const dir = path.join(env.gatewayEnvDir, '_storage', 'jwt_verification_strategies');
    fs.mkdirSync(dir, {recursive: true});
    fs.writeFileSync(path.join(dir, `${record.id}.json`), JSON.stringify(record));
    await expect
        .poll(async () => (await listEntities(api, '/api/v1/jwt-verification-strategies')).some(s => s.id === record.id), {
            message: `the gateway picks up strategy ${record.id}`,
            timeout: 20_000,
        })
        .toBe(true);
}

export async function ensureStrategy(api: GatewayApi, which: 'a' | 'b'): Promise<Entity> {
    const record = strategyRecord(which);
    const existing = (await listEntities(api, '/api/v1/jwt-verification-strategies')).find(s => s.id === record.id);
    if (existing) return existing;
    await seedStrategy(api, record);
    return record;
}

export async function ensureProviders(api: GatewayApi): Promise<{clientCredentials: Entity; jwtBearer: Entity}> {
    const find = async (name: string) =>
        (await listEntities(api, '/api/v1/credential-providers')).find(provider => provider.name === name);
    let clientCredentials = await find(names.providers.clientCredentials);
    if (!clientCredentials) {
        const created = await api.post<Entity>('/api/v1/credential-providers', {
            name: names.providers.clientCredentials,
            provider_id: 'oidc-e2e-client-credentials',
            provider_type: 'oauth2_client_credentials',
            token_endpoint: `${env.hydraA.issuer}oauth2/token`,
            default_scopes: [names.scopes.caller],
            client_id_secret_ref: names.secrets.ccClientId,
            client_secret_secret_ref: names.secrets.ccClientSecret,
        });
        expect(created.status, 'creating the client credentials provider').toBe(201);
        clientCredentials = created.body;
    }
    let jwtBearer = await find(names.providers.jwtBearer);
    if (!jwtBearer) {
        const created = await api.post<Entity>('/api/v1/credential-providers', {
            name: names.providers.jwtBearer,
            provider_id: 'oidc-e2e-jwt-bearer',
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
        expect(created.status, 'creating the JWT bearer provider').toBe(201);
        jwtBearer = created.body;
    }
    return {clientCredentials, jwtBearer};
}

export const DENY_RULE_NAME = 'Deny unauthenticated callers';
const DENY_RULE_REGO = `package surface.policy

default allow := false

allow if not deny

deny if input.source_auth.method == "failed"
`;

export async function ensureDenyRule(api: GatewayApi): Promise<string> {
    const listed = await listEntities(api, '/api/v1/policy-definitions?policy_type=agent_surface');
    const existing = listed.find(definition => definition.policy === DENY_RULE_REGO);
    if (existing) return existing.id;
    const id = randomUUID();
    const created = await api.post('/api/v1/policy-definitions', {
        id,
        name: DENY_RULE_NAME,
        description: 'Denies requests whose caller authentication is missing, invalid or short of scope.',
        policy_type: 'agent_surface',
        policy: DENY_RULE_REGO,
        enabled: true,
        created_at: new Date().toISOString(),
    });
    expect(created.status, 'creating the deny rule').toBe(201);
    return id;
}

export async function findSurface(api: GatewayApi): Promise<Entity | undefined> {
    const listed = (await listEntities(api, '/api/v1/surfaces')).find(surface => surface.name === names.surface);
    if (!listed) return undefined;
    return (await api.get<Entity>(`/api/v1/surfaces/${listed.surface_id ?? listed.id}`)).body;
}

export async function ensureSurface(api: GatewayApi, world: World): Promise<Entity> {
    const existing = await findSurface(api);
    if (existing) {
        const declared = (existing.access_point as {caller_authentication?: {protected_resource?: {resource?: string} | null}})
            ?.caller_authentication?.protected_resource?.resource;
        if (declared === env.entryPointUrl) return existing;
        const status = await api.delete(`/api/v1/surfaces/${existing.surface_id ?? existing.id}`);
        expect(status, 'deleting the surface from an earlier run').toBeLessThan(300);
    }
    await ensureSecrets(api, world);
    await ensureStrategy(api, 'a');
    const {jwtBearer} = await ensureProviders(api);
    const policyId = await ensureDenyRule(api);
    const created = await api.post<Entity>('/api/v1/surfaces', {
        name: names.surface,
        status: 'active',
        access_point: {
            listen_address: env.accessPointOrigin,
            route: env.route,
            protocol: 'a2a',
            caller_authentication: {
                methods: [
                    {
                        type: 'jwt_bearer',
                        jwt_verification_strategy_id: names.strategies.hydraA.id,
                        audiences: [],
                        required_scopes: [names.scopes.caller],
                    },
                ],
                protected_resource: {resource: env.entryPointUrl},
            },
            inbound_policy: {policy_definition_id: policyId, require_agent_context: false},
        },
        target: {
            endpoint: env.agentUrl,
            auth: {
                method: {credential_provider: {credential_provider_id: jwtBearer.id, inject_as: {type: 'bearer_header'}}},
                fallback: 'reject',
            },
        },
    });
    expect(created.status, 'creating the surface').toBe(201);
    return created.body;
}

export async function createStaticStrategy(
    api: GatewayApi,
    spec: {name: string; issuer: string; jwk: Record<string, unknown>}
): Promise<Entity> {
    const created = await api.post<Entity>('/api/v1/jwt-verification-strategies', {
        name: spec.name,
        expected_issuer: spec.issuer,
        jwks_source: {type: 'static', jwks: [spec.jwk]},
    });
    expect(created.status, `creating strategy ${spec.name}`).toBe(201);
    return created.body;
}

export async function createSecondSurface(
    api: GatewayApi,
    spec: {name: string; route: string; strategyId: string; providerId: string; policyId: string}
): Promise<Entity> {
    const created = await api.post<Entity>('/api/v1/surfaces', {
        name: spec.name,
        status: 'active',
        access_point: {
            listen_address: env.accessPointOrigin,
            route: spec.route,
            protocol: 'a2a',
            caller_authentication: {
                methods: [
                    {
                        type: 'jwt_bearer',
                        jwt_verification_strategy_id: spec.strategyId,
                        audiences: [`${env.accessPointOrigin}${spec.route}`],
                    },
                ],
            },
            inbound_policy: {policy_definition_id: spec.policyId, require_agent_context: false},
        },
        target: {
            endpoint: env.agentUrl,
            auth: {
                method: {credential_provider: {credential_provider_id: spec.providerId, inject_as: {type: 'bearer_header'}}},
                fallback: 'reject',
            },
        },
    });
    expect(created.status, `creating surface ${spec.name}`).toBe(201);
    return created.body;
}
