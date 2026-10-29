/**
 * Dashboard evidence
 *
 * An operator turns the audit log on in Settings, callers use the surface, and the dashboard shows
 * which calls were allowed and which were denied, who the allowed caller was, and the gateway log
 * lines for the same requests.
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

    test('two callers use the surface: one is allowed, one is denied', async ({page}) => {
        await page.goto('/audit');
        await expect(page.getByTestId('audit-refresh')).toBeVisible();
        await expect(page.getByTestId('audit-list').or(page.getByTestId('audit-empty'))).toBeVisible();
        const badge = page.getByTestId('audit-total-badge');
        totalBefore = (await badge.count()) === 0 ? 0 : Number(((await badge.textContent()) ?? '0').trim());

        const good = accessToken(
            await clientCredentialsToken(http, env.hydraA, world.good, {audience: env.entryPointUrl, scope: names.scopes.caller})
        );
        expect((await callAgent(http, good)).status).toBe(200);
        expect((await callAgent(http)).status).toBe(403);
    });

    test('the audit page lists the allowed call with its caller and the denied call with its decision', async ({page}) => {
        await page.goto('/audit');
        await expect(async () => {
            await page.getByTestId('audit-refresh').click();
            await expect(page.getByTestId('audit-total-badge')).toHaveText(String(totalBefore + 3), {timeout: 2_000});
        }).toPass();

        const newest = Array.from({length: 3}, (_, index) => page.getByTestId(`audit-item-${index}`));
        const texts = await Promise.all(newest.map(item => item.innerText()));
        expect(texts.filter(text => text.includes('Allowed POST'))).toHaveLength(1);
        expect(texts.filter(text => text.includes('Denied POST'))).toHaveLength(1);
        expect(texts.filter(text => text.includes('auth failed'))).toHaveLength(1);

        const allowedIndex = texts.findIndex(text => text.includes('Allowed POST'));
        await newest[allowedIndex].click();
        const allowed = page.getByTestId('audit-detail-panel');
        await expect(decisionField(allowed)).toHaveText('allow');
        await expect(allowed).toContainText('jwt_bearer');
        await expect(allowed).toContainText(env.hydraA.issuer);
        await expect(allowed).toContainText(env.entryPointUrl);
        await expect(allowed).toContainText(names.clients.good);
        await expect(allowed).toContainText('Deny unauthenticated callers');

        const deniedIndex = texts.findIndex(text => text.includes('Denied POST'));
        await newest[deniedIndex].click();
        const denied = page.getByTestId('audit-detail-panel');
        await expect(decisionField(denied)).toHaveText('deny');
        await expect(denied).toContainText('Policy denied request');
        await expect(denied).toContainText('Access Point');
    });

    test('the Deny filter keeps only denied calls and the Allow filter only allowed ones', async ({page}) => {
        await page.goto('/audit');
        await page.getByTestId('filter-chip-deny').click();
        await expect(page.getByTestId('audit-item-0')).toContainText('Denied POST');
        await expect(page.getByTestId('audit-list').getByText('Allowed POST')).toHaveCount(0);

        await page.getByTestId('filter-chip-allow').click();
        await expect(page.getByTestId('audit-item-0')).toContainText('Allowed POST');
        await expect(page.getByTestId('audit-list').getByText('Denied POST')).toHaveCount(0);
    });

    test('the gateway log shows the same two requests with their status', async ({page}) => {
        await page.goto('/logs');
        const route = env.route;
        for (const status of ['200', '403']) {
            await expect(page.getByText(new RegExp(`HTTP POST ${route} → ${status} `)).first()).toBeVisible();
        }
    });
});
