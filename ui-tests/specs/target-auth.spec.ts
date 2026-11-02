/**
 * Target authentication tests
 *
 * Covers a Managed Agent's Target authentication from a credential provider: the gateway's
 * rules shown next to the fields and blocking Save, and a valid setting, scopes included,
 * saving and loading again unchanged.
 *
 * The gateway API is mocked with `page.route`. Line breaks cannot be typed into a text input
 * (the browser removes them), so the CR/LF rule is covered by a stored setting that already
 * carries one, which the dashboard keeps and warns about. The Jest suite covers typed values.
 *
 * Deleting a secret that credential providers use is covered by its own spec, added with the
 * secret delete guard.
 */

import type {Page, Request} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-target-auth';

const PROVIDER = {
    id: 'prov-1',
    name: 'Billing provider',
    provider_id: 'billing',
    provider_type: 'oauth2_client_credentials',
    token_endpoint: 'https://login.example.com/token',
    default_scopes: [],
    token_refresh_enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

type Json = Record<string, unknown>;

function surfaceFixture(options: {endpoint?: string; auth?: Json} = {}): Json {
    return {
        surface_id: SURFACE_ID,
        name: 'Target auth fixture',
        description: 'Playwright fixture',
        status: 'active',
        tags: [],
        access_point: {
            listen_address: '0.0.0.0:0',
            route: `/${SURFACE_ID}`,
            protocol: 'a2a',
            caller_authentication: {
                methods: [
                    {
                        type: 'api_key',
                        secret_id: 'caller-key',
                        extraction: {source: 'http_header', field: 'X-Api-Key'},
                    },
                ],
            },
            publish_to_did_document: false,
            terminate_trace_id: false,
        },
        target: {
            endpoint: options.endpoint ?? 'https://agent.example.com',
            mcp_tool_policies_enabled: false,
            identity_injection: {inject_vp: false},
            mpp_auto_pay: false,
            ...(options.auth ? {auth: options.auth} : {}),
        },
    };
}

/** Serves the surface and records each save; a later load returns the last saved surface. */
async function mockSurface(page: Page, initial: Json, saved: Request[]) {
    let current = initial;
    await page.route(/\/api\/v1\/credential-providers\/?$/, route => route.fulfill({json: [PROVIDER]}));
    await page.route('**/api/v1/secrets/', route => route.fulfill({json: []}));
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async route => {
        const request = route.request();
        if (request.method() === 'PUT') {
            saved.push(request);
            current = {...request.postDataJSON(), surface_id: SURFACE_ID};
            await route.fulfill({json: current});
        } else if (request.method() === 'GET') {
            await route.fulfill({json: current});
        } else {
            await route.fallback();
        }
    });
}

async function openTargetAuth(page: Page) {
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await page.getByTestId('surface-node-target').click();
    await page.getByTestId('managed-agent-auth-type').selectOption('custom');
    await page.getByRole('button', {name: /Configure/}).click();
    await expect(page.getByTestId('managed-agent-target-auth-source')).toBeVisible();
}

async function pickProvider(page: Page) {
    await page.getByTestId('managed-agent-target-auth-source').selectOption('provider');
    await page.getByTestId('managed-agent-target-auth-provider').selectOption('prov-1');
}

const saveButton = (page: Page) => page.locator('button.btn-primary:has(.fa-save)');

test.describe('Target authentication: credential provider', () => {
    test('a valid setting saves with its scopes and loads unchanged', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture(), saved);
        await openTargetAuth(page);

        await pickProvider(page);
        await page.getByTestId('managed-agent-target-auth-scopes').fill('read write');
        await page.locator('#target-auth-header-name').fill('X-Partner-Token');
        await page.locator('#target-auth-header-format').fill('Token {value}');
        await expect(page.getByTestId('managed-agent-target-auth-errors')).toHaveCount(0);

        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        const auth = (saved[0].postDataJSON().target as {auth: Json}).auth;
        expect(auth.method).toEqual({
            credential_provider: {
                provider_id: 'prov-1',
                header_name: 'X-Partner-Token',
                header_format: 'Token {value}',
                scopes: ['read', 'write'],
            },
        });

        await page.reload();
        await page.getByTestId('surface-node-target').click();
        await page.getByRole('button', {name: /Configure/}).click();
        await expect(page.getByTestId('managed-agent-target-auth-provider')).toHaveValue('prov-1');
        await expect(page.getByTestId('managed-agent-target-auth-scopes')).toHaveValue('read write');
        await expect(page.locator('#target-auth-header-name')).toHaveValue('X-Partner-Token');
        await expect(page.locator('#target-auth-header-format')).toHaveValue('Token {value}');

        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(2);
        expect((saved[1].postDataJSON().target as {auth: Json}).auth).toEqual(auth);
    });

    test('a reserved header name is refused next to the field and blocks Save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture(), saved);
        await openTargetAuth(page);
        await pickProvider(page);

        await page.locator('#target-auth-header-name').fill('Host');
        await expect(page.getByTestId('managed-agent-target-auth-header-name-error')).toHaveText(
            'Header name must not be the reserved header Host',
        );
        await saveButton(page).click();
        await page.waitForTimeout(300);
        expect(saved).toHaveLength(0);

        await page.locator('#target-auth-header-name').fill('X-Host');
        await expect(page.getByTestId('managed-agent-target-auth-header-name-error')).toHaveCount(0);
    });

    test('a format without {value} is refused next to the field and blocks Save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture(), saved);
        await openTargetAuth(page);
        await pickProvider(page);

        await page.locator('#target-auth-header-format').fill('Bearer');
        await expect(page.getByTestId('managed-agent-target-auth-header-format-error')).toHaveText(
            'Header format must contain {value} exactly once',
        );
        await saveButton(page).click();
        await page.waitForTimeout(300);
        expect(saved).toHaveLength(0);

        await page.locator('#target-auth-header-format').fill('Bearer {value}');
        await expect(page.getByTestId('managed-agent-target-auth-header-format-error')).toHaveCount(0);
    });

    test('a stored format with a line break is kept and only warns until it is edited', async ({page}) => {
        const saved: Request[] = [];
        const stored = {
            method: {
                credential_provider: {
                    provider_id: 'prov-1',
                    header_name: 'X-Partner-Token',
                    header_format: 'Token {value}\nX-Injected: 1',
                },
            },
            auth_type: 'custom',
            fallback: 'reject',
        };
        await mockSurface(page, surfaceFixture({auth: stored}), saved);
        await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
        await page.getByTestId('surface-node-target').click();
        await page.getByRole('button', {name: /Configure/}).click();

        await expect(page.getByTestId('managed-agent-target-auth-warnings')).toContainText(
            'Header format must not contain CR, LF or NUL',
        );
        await expect(page.getByTestId('managed-agent-target-auth-errors')).toHaveCount(0);

        await saveButton(page).click();
        await expect.poll(() => saved.length).toBe(1);
        expect((saved[0].postDataJSON().target as {auth: Json}).auth).toEqual(stored);
    });

    test('a credential on an http Target is refused and blocks Save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture({endpoint: 'http://agent.example.com'}), saved);
        await openTargetAuth(page);
        await pickProvider(page);

        await expect(page.getByTestId('managed-agent-target-auth-errors')).toContainText(
            'its Target must be an https URL',
        );
        await saveButton(page).click();
        await page.waitForTimeout(300);
        expect(saved).toHaveLength(0);
    });

    test('a provider method without a provider blocks Save', async ({page}) => {
        const saved: Request[] = [];
        await mockSurface(page, surfaceFixture(), saved);
        await openTargetAuth(page);
        await page.getByTestId('managed-agent-target-auth-source').selectOption('provider');

        await expect(page.getByTestId('managed-agent-target-auth-provider-error')).toBeVisible();
        await saveButton(page).click();
        await page.waitForTimeout(300);
        expect(saved).toHaveLength(0);
    });
});
