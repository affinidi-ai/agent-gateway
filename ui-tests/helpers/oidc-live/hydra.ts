import {createPrivateKey, createPublicKey, createSign, generateKeyPairSync, randomBytes, randomUUID} from 'crypto';
import {APIRequestContext, expect, request} from '@playwright/test';

export const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export interface HydraServer {
    issuer: string;
    admin: string;
}

export interface OAuthClient {
    id: string;
    secret: string;
}

export interface TokenResponse {
    status: number;
    body: Record<string, unknown>;
}

export function randomSecret(): string {
    return randomBytes(24).toString('hex');
}

export async function newContext(): Promise<APIRequestContext> {
    return request.newContext();
}

export async function registerClient(
    api: APIRequestContext,
    hydra: HydraServer,
    spec: {id: string; secret: string; grantTypes: string[]; scope: string; audience: string[]}
): Promise<OAuthClient> {
    await api.delete(`${hydra.admin}/admin/clients/${spec.id}`);
    const response = await api.post(`${hydra.admin}/admin/clients`, {
        data: {
            client_id: spec.id,
            client_secret: spec.secret,
            grant_types: spec.grantTypes,
            scope: spec.scope,
            audience: spec.audience,
            token_endpoint_auth_method: 'client_secret_basic',
        },
    });
    expect(response.status(), `registering ${spec.id}`).toBe(201);
    return {id: spec.id, secret: spec.secret};
}

export async function deleteClient(api: APIRequestContext, hydra: HydraServer, id: string): Promise<void> {
    await api.delete(`${hydra.admin}/admin/clients/${id}`);
}

export async function clientCredentialsToken(
    api: APIRequestContext,
    hydra: HydraServer,
    client: OAuthClient,
    options: {audience?: string; scope?: string} = {}
): Promise<TokenResponse> {
    const form: Record<string, string> = {grant_type: 'client_credentials'};
    if (options.audience) form.audience = options.audience;
    if (options.scope) form.scope = options.scope;
    const response = await api.post(`${hydra.issuer}oauth2/token`, {
        headers: {Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`},
        form,
    });
    return {status: response.status(), body: (await response.json()) as Record<string, unknown>};
}

export function accessToken(response: TokenResponse): string {
    expect(response.status, 'token request status').toBe(200);
    return String(response.body.access_token);
}

export function jwtClaims(token: string): Record<string, unknown> {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as Record<string, unknown>;
}

export interface SigningKey {
    privatePem: string;
    publicJwk: Record<string, unknown>;
    kid: string;
}

export function generateSigningKey(kid: string): SigningKey {
    const {publicKey, privateKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
    const jwk = publicKey.export({format: 'jwk'});
    return {
        privatePem: privateKey.export({format: 'pem', type: 'pkcs8'}).toString(),
        publicJwk: {...jwk, kid, alg: 'RS256', use: 'sig'},
        kid,
    };
}

export function signAssertion(
    key: SigningKey,
    claims: {iss: string; sub: string; aud: string; scope?: string}
): string {
    const now = Math.floor(Date.now() / 1000);
    const header = {alg: 'RS256', typ: 'JWT', kid: key.kid};
    const payload: Record<string, unknown> = {
        iss: claims.iss,
        sub: claims.sub,
        aud: claims.aud,
        iat: now - 30,
        exp: now + 300,
        jti: randomUUID(),
    };
    if (claims.scope) payload.scope = claims.scope;
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${encode(header)}.${encode(payload)}`;
    const signer = createSign('RSA-SHA256');
    signer.update(input);
    return `${input}.${signer.sign(createPrivateKey(key.privatePem)).toString('base64url')}`;
}

export function publicKeyMatches(key: SigningKey): boolean {
    const derived = createPublicKey(createPrivateKey(key.privatePem)).export({format: 'jwk'});
    return derived.n === key.publicJwk.n;
}

export async function jwtBearerToken(
    api: APIRequestContext,
    hydra: HydraServer,
    client: OAuthClient,
    assertion: string,
    scope: string
): Promise<TokenResponse> {
    const response = await api.post(`${hydra.issuer}oauth2/token`, {
        headers: {Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`},
        form: {grant_type: JWT_BEARER_GRANT, assertion, scope},
    });
    return {status: response.status(), body: (await response.json()) as Record<string, unknown>};
}

export async function createTrustGrant(
    api: APIRequestContext,
    hydra: HydraServer,
    grant: {issuer: string; subject: string; scope: string[]; jwk: Record<string, unknown>}
): Promise<string> {
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
    const response = await api.post(`${hydra.admin}/admin/trust/grants/jwt-bearer/issuers`, {
        data: {issuer: grant.issuer, subject: grant.subject, scope: grant.scope, expires_at: expiresAt, jwk: grant.jwk},
    });
    expect(response.status(), 'creating the trust grant').toBe(201);
    return String(((await response.json()) as {id: string}).id);
}

export async function trustGrantExists(api: APIRequestContext, hydra: HydraServer, id: string): Promise<boolean> {
    const response = await api.get(`${hydra.admin}/admin/trust/grants/jwt-bearer/issuers/${id}`);
    return response.status() === 200;
}

export async function revokeTrustGrant(api: APIRequestContext, hydra: HydraServer, id: string): Promise<number> {
    return (await api.delete(`${hydra.admin}/admin/trust/grants/jwt-bearer/issuers/${id}`)).status();
}

export async function deleteTrustGrantsFor(api: APIRequestContext, hydra: HydraServer, issuer: string): Promise<void> {
    const response = await api.get(`${hydra.admin}/admin/trust/grants/jwt-bearer/issuers`);
    if (response.status() !== 200) return;
    for (const grant of (await response.json()) as Array<{id: string; issuer: string}>) {
        if (grant.issuer === issuer) await revokeTrustGrant(api, hydra, grant.id);
    }
}
