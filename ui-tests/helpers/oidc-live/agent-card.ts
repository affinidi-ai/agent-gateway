import {Locator, Response, expect} from '@playwright/test';
import {env} from './env';
import {secretValues} from './gateway-state';
import {World} from './world';

export const CARD_PATH = '/.well-known/agent-card.json';
export const CARD_URL = `${env.entryPointUrl}${CARD_PATH}`;
export const SOURCE_CARD_URL = `${env.agentUrl}${CARD_PATH}`;

const TOP_LEVEL_KEYS = [
    'after',
    'after_bytes',
    'auth',
    'before',
    'before_bytes',
    'cached',
    'display_limit_bytes',
    'fetch',
    'fetched_at',
    'generated',
    'last_caller_fetch',
    'outcome',
    'payment_required',
    'served_url',
    'source_url',
    'source_url_query_hidden',
    'supported',
    'surface_id',
    'unsupported_reason',
    'variant',
];

const AUTH_KEYS = ['failure', 'kind', 'provider_name', 'result', 'token_expires_at'];
const FETCH_KEYS = ['cause', 'duration_ms', 'http_status', 'status'];

const SECRET_KEY_NAMES = /^(token|access_token|id_token|refresh_token|secret|client_secret|secret_id|secret_ref|password|authorization|credential|api_key)$/i;
const SECRET_SHAPES = [
    /Bearer\s+[A-Za-z0-9._~+/-]{16,}/,
    /Basic\s+[A-Za-z0-9+/=]{16,}/,
    /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    /ory_(?:at|rt|ac)_[A-Za-z0-9_.-]{8,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

export function isCardRoute(response: Response, suffix: '' | '/refresh', method: 'GET' | 'POST'): boolean {
    return response.request().method() === method && new URL(response.url()).pathname.endsWith(`/agent-card${suffix}`);
}

function secretFragments(world: World): string[] {
    const values = [
        ...Object.values(secretValues(world)),
        ...[world.good, world.noScope, world.otherAudience, world.goodOnB, world.hop2].map(client => client.secret),
    ];
    const fragments: string[] = [];
    for (const value of values) {
        if (value.includes('PRIVATE KEY')) {
            fragments.push(...value.split('\n').filter(line => line.length >= 12 && !line.startsWith('-----')));
        } else if (value.length >= 8) {
            fragments.push(value);
        }
    }
    return fragments;
}

/**
 * True when the text holds one of the run's secrets or the shape of a token, an Authorization
 * value or a private key. The result is a boolean so that a failing assertion cannot print the
 * secret into the report.
 */
export function holdsSecretMaterial(text: string, world: World): boolean {
    return secretFragments(world).some(fragment => text.includes(fragment)) || SECRET_SHAPES.some(shape => shape.test(text));
}

/** Checks the visible text and the markup of one area of the page, such as the Agent Cards tab. */
export async function expectNoSecretIn(area: Locator, world: World): Promise<void> {
    const text = await area.evaluate(element => `${(element as HTMLElement).innerText}\n${element.outerHTML}`);
    expect(holdsSecretMaterial(text, world), 'the area shows no secret material').toBe(false);
}

function secretKeysIn(value: unknown, trail = ''): string[] {
    if (Array.isArray(value)) return value.flatMap((item, index) => secretKeysIn(item, `${trail}[${index}]`));
    if (value === null || typeof value !== 'object') return [];
    return Object.entries(value).flatMap(([key, child]) => [
        ...(SECRET_KEY_NAMES.test(key) ? [`${trail}.${key}`] : []),
        ...secretKeysIn(child, `${trail}.${key}`),
    ]);
}

export type CardJson = Record<string, unknown>;

export interface CardPreviewBody {
    surface_id: string;
    supported: boolean;
    unsupported_reason: string | null;
    variant: string | null;
    generated: boolean;
    served_url: string | null;
    source_url: string | null;
    source_url_query_hidden: boolean;
    fetched_at: string | null;
    cached: boolean;
    fetch: {status: string; cause: string | null; http_status: number | null; duration_ms: number};
    auth: {kind: string; result: string; provider_name: string | null; token_expires_at: string | null; failure: string | null};
    payment_required: boolean;
    outcome: {variant: string | null; outcome: string; reason: string | null; resource: string | null} | null;
    before: CardJson | null;
    after: CardJson | null;
    before_bytes: number | null;
    after_bytes: number | null;
    display_limit_bytes: number;
    last_caller_fetch: {status: string; cause: string | null; http_status: number | null; at: string} | null;
}

/**
 * Checks the shape the dashboard parses and that the body leaks nothing: only the documented keys,
 * no key named like a credential outside the cards themselves, and none of the run's secrets.
 */
export async function readPreviewBody(response: Response, world: World): Promise<CardPreviewBody> {
    const text = await response.text();
    expect(holdsSecretMaterial(text, world), 'the agent card API body holds no secret material').toBe(false);
    const body = JSON.parse(text) as CardPreviewBody;
    expect(Object.keys(body).sort()).toEqual(TOP_LEVEL_KEYS);
    expect(Object.keys(body.fetch).sort()).toEqual(FETCH_KEYS);
    expect(Object.keys(body.auth).sort()).toEqual(AUTH_KEYS);
    const {before: _before, after: _after, ...rest} = body;
    expect(secretKeysIn(rest), 'keys named like a credential in the agent card API body').toEqual([]);
    return body;
}

export interface GatewayScheme {
    type?: string;
    oauth2MetadataUrl: string;
    flows: {clientCredentials: {tokenUrl: string; scopes: Record<string, string>}};
}

/** The `agent_gateway` security scheme of an A2A 0.3 card. */
export function gatewayScheme(card: CardJson): GatewayScheme {
    const schemes = (card.securitySchemes ?? {}) as Record<string, GatewayScheme>;
    expect(Object.keys(schemes), 'the card declares only the gateway scheme').toEqual(['agent_gateway']);
    return schemes.agent_gateway;
}
