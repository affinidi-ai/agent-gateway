import {KeyObject, generateKeyPairSync, randomUUID, sign} from 'crypto';

export interface StaticKey {
    privateKey: KeyObject;
    publicJwk: Record<string, unknown>;
    kid: string;
}

export function generateStaticKey(kid: string): StaticKey {
    const {publicKey, privateKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
    return {privateKey, kid, publicJwk: {...publicKey.export({format: 'jwk'}), kid, alg: 'ES256', use: 'sig'}};
}

export function signStaticJwt(key: StaticKey, claims: {iss: string; aud: string; sub: string; scope?: string}): string {
    const now = Math.floor(Date.now() / 1000);
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const payload: Record<string, unknown> = {
        iss: claims.iss,
        aud: claims.aud,
        sub: claims.sub,
        iat: now - 10,
        exp: now + 300,
        jti: randomUUID(),
    };
    if (claims.scope) payload.scope = claims.scope;
    const input = `${encode({alg: 'ES256', typ: 'JWT', kid: key.kid})}.${encode(payload)}`;
    const signature = sign('sha256', Buffer.from(input), {key: key.privateKey, dsaEncoding: 'ieee-p1363'});
    return `${input}.${signature.toString('base64url')}`;
}
