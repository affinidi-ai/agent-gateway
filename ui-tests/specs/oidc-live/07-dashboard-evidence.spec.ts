/**
 * Dashboard evidence
 *
 * An operator turns the audit log on in Settings, callers use the surface, and the dashboard shows
 * which call was allowed and who the caller was, which callers failed authentication, and the
 * gateway log lines for the same requests. The Access Point declares hydra-a, so the gateway
 * refuses a caller that failed authentication itself, after gateway policy and before the
 * surface's policy: such a caller leaves an authentication failure and no surface policy decision.
 */

import {APIRequestContext, Locator} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {callAgent} from '../../helpers/oidc-live/agent';
import {env} from '../../helpers/oidc-live/env';
import {ensureSurface} from '../../helpers/oidc-live/gateway-state';
import {accessToken, clientCredentialsToken, newContext} from '../../helpers/oidc-live/hydra';
import {names} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {ticket} from '../../helpers/ticket';

function decisionField(panel: Locator): Locator {
    return panel.locator('.audit-kv-row').filter({has: panel.page().locator('dt', {hasText: /^Decision$/})}).locator('dd');
}

test.describe('Dashboard evidence', () => {
    test.describe.configure({mode: 'serial'});

    let http: APIRequestContext;
    let world: World;
    let totalBefore = 0;

    test.beforeAll(async () => {
        http = await newContext();
        world = loadWorld();
        const api = await GatewayApi.connect();
        try {
            await ensureSurface(api, world);
        } finally {
            await api.dispose();
        }
    });

    test.afterAll(async () => {
        await http.dispose();
    });

    test('the operator turns the audit log on for policy decisions and failed authentication', async ({page}) => {
        ticket('FTL-30894');
        await page.goto('/settings?tab=security');
        const toggle = page.getByTestId('vp-audit-enabled-toggle');
        if (!(await toggle.isChecked())) await page.locator('label[for=audit_enabled]').click();
        await expect(page.getByTestId('vp-audit-picker')).toBeVisible();
        for (const event of ['policy_decision', 'auth_failed']) {
            await page.getByTestId(`vp-audit-event-${event}`).check({force: true});
        }
        const saved = page.waitForResponse(
            response => response.url().includes('/api/v1/settings') && ['PUT', 'POST', 'PATCH'].includes(response.request().method())
        );
        await page.getByTestId('vp-audit-save-button').click();
        expect((await saved).ok()).toBe(true);

        await page.reload();
        await expect(page.getByTestId('vp-audit-enabled-toggle')).toBeChecked();
        await expect(page.getByTestId('vp-audit-event-policy_decision')).toBeChecked();
        await expect(page.getByTestId('vp-audit-event-auth_failed')).toBeChecked();
    });

    test('three callers use the surface: one is allowed, two are refused before the surface policy', async ({page}) => {
        ticket('FTL-30892', 'FTL-30894');
        await page.goto('/audit');
        await expect(page.getByTestId('audit-refresh')).toBeVisible();
        await expect(page.getByTestId('audit-list').or(page.getByTestId('audit-empty'))).toBeVisible();
        const badge = page.getByTestId('audit-total-badge');
        totalBefore = (await badge.count()) === 0 ? 0 : Number(((await badge.textContent()) ?? '0').trim());

        const good = accessToken(
            await clientCredentialsToken(http, env.hydraA, world.good, {audience: env.entryPointUrl, scope: names.scopes.caller})
        );
        const noScope = accessToken(await clientCredentialsToken(http, env.hydraA, world.noScope, {audience: env.entryPointUrl}));
        expect((await callAgent(http, good)).status).toBe(200);
        const shortOfScope = await callAgent(http, noScope);
        expect(shortOfScope.status).toBe(403);
        expect(shortOfScope.headers['www-authenticate']).toContain('error="insufficient_scope"');
        const anonymous = await callAgent(http);
        expect(anonymous.status).toBe(401);
        expect(anonymous.headers['www-authenticate']).toContain('resource_metadata=');
    });

    test('the audit page lists the allowed call with its caller and the two failed authentications, with no policy denial', async ({page}) => {
        ticket('FTL-30892', 'FTL-30894');
        await page.goto('/audit');
        await expect(async () => {
            await page.getByTestId('audit-refresh').click();
            await expect(page.getByTestId('audit-total-badge')).toHaveText(String(totalBefore + 3), {timeout: 2_000});
        }).toPass();

        const newest = Array.from({length: 3}, (_, index) => page.getByTestId(`audit-item-${index}`));
        const texts = await Promise.all(newest.map(item => item.innerText()));
        expect(texts.filter(text => text.includes('Allowed POST'))).toHaveLength(1);
        expect(texts.filter(text => text.includes('auth failed'))).toHaveLength(2);
        expect(texts.filter(text => text.includes('Denied POST'))).toHaveLength(0);

        const allowedIndex = texts.findIndex(text => text.includes('Allowed POST'));
        await newest[allowedIndex].click();
        const allowed = page.getByTestId('audit-detail-panel');
        await expect(decisionField(allowed)).toHaveText('allow');
        await expect(allowed).toContainText('jwt_bearer');
        await expect(allowed).toContainText(env.hydraA.issuer);
        await expect(allowed).toContainText(env.entryPointUrl);
        await expect(allowed).toContainText(names.clients.good);
        await expect(allowed).toContainText('Deny unauthenticated callers');
    });

    test('the Deny filter leaves out the allowed call and the Allow filter keeps it', async ({page}) => {
        ticket('FTL-30894');
        await page.goto('/audit');
        await page.getByTestId('filter-chip-deny').click();
        await expect(page.getByTestId('audit-list').or(page.getByTestId('audit-empty'))).toBeVisible();
        await expect(page.getByTestId('audit-list').getByText('Allowed POST')).toHaveCount(0);

        await page.getByTestId('filter-chip-allow').click();
        await expect(page.getByTestId('audit-item-0')).toContainText('Allowed POST');
        await expect(page.getByTestId('audit-list').getByText('Denied POST')).toHaveCount(0);
    });

    test('the gateway log shows the same three requests with their status', async ({page}) => {
        ticket('FTL-30894');
        await page.goto('/logs');
        const route = env.route;
        for (const status of ['200', '403', '401']) {
            await expect(page.getByText(new RegExp(`HTTP POST ${route} → ${status} `)).first()).toBeVisible();
        }
    });
});
