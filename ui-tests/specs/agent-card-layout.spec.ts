/**
 * Agent Cards Tab Tests
 *
 * Covers the Agent Cards view of an A2A surface with a stubbed card preview:
 * - The view sits directly after Elements and before Monitoring
 * - The Managed Agent Card and the Gateway-Served Agent Card side by side, with
 *   added, modified and removed parts marked by colour, an icon and a text label,
 *   and both cards readable as raw JSON
 * - The Entry point URL stays in the Surface view; the tab links back to it and
 *   shows the served card discovery URL with a working copy button
 * - A failing first fetch names its cause with the HTTP status, keeps the served
 *   card readable, and Refresh recovers it
 * - The compare table follows the tab's own width: side by side when wide,
 *   stacked when narrow, never scrolling the page sideways
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {GatewayApi} from '../helpers/gateway-api';
import {attachCriterion, feature} from '../helpers/feature';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const RUN_ID = `${Date.now()}`;
const ROUTE = `/e2e-card-layout-${RUN_ID}`;
const LISTEN_ADDRESS = 'http://localhost:8711';
const MIN_CELL_WIDTH = 200;
const TAB_PADDING = 64;
const FEATURE = 'agent-card-tab-and-signin-settings';

const MANAGED_CARD = {
    protocolVersion: '0.3.0',
    name: 'Layout agent',
    url: 'https://agent.example.org/a2a/with/a/long/path/segment/that/keeps/going',
    securitySchemes: {
        agent_own_oauth: {
            type: 'oauth2',
            flows: {clientCredentials: {tokenUrl: 'https://idp.example.org/oauth2/token', scopes: {'agent.read': 'Read'}}},
        },
    },
    security: [{agent_own_oauth: ['agent.read']}],
    signatures: [{protected: 'p', signature: 's'}],
    skills: [{id: 'echo', name: 'Echo'}],
};

const SERVED_CARD = {
    protocolVersion: '0.3.0',
    name: 'Layout agent',
    url: 'https://gateway.example.org/layout-agent',
    securitySchemes: {
        agent_gateway: {
            type: 'oauth2',
            flows: {
                authorizationCode: {
                    authorizationUrl: 'https://as.example.org/authorize',
                    tokenUrl: 'https://as.example.org/token',
                    scopes: {'gw.invoke': 'Invoke'},
                },
            },
        },
    },
    security: [{agent_gateway: ['gw.invoke']}],
    skills: [{id: 'echo', name: 'Echo'}],
};

const PREVIEW = {
    supported: true,
    unsupported_reason: null,
    variant: null,
    generated: false,
    served_url: 'https://gateway.example.org/layout-agent/.well-known/agent-card.json',
    source_url: 'https://agent.example.org/.well-known/agent-card.json',
    source_url_query_hidden: false,
    fetched_at: '2026-10-23T10:00:00Z',
    cached: false,
    fetch: {status: 'ok', cause: null, http_status: null, duration_ms: 182},
    auth: {kind: 'none', result: 'not_configured', provider_name: null, token_expires_at: null, failure: null},
    payment_required: false,
    outcome: {variant: null, outcome: 'declare', reason: null, resource: 'https://gateway.example.org/layout-agent'},
    before: MANAGED_CARD,
    after: SERVED_CARD,
    before_bytes: 1412,
    after_bytes: 2950,
    display_limit_bytes: 262144,
    last_caller_fetch: null,
};

const FAILING_PREVIEW = {
    ...PREVIEW,
    fetch: {status: 'failed', cause: 'needs_token', http_status: 401, duration_ms: 95},
    before: null,
    before_bytes: null,
};

const CHANGE_KINDS = [
    {status: 'added', label: 'Added', icon: 'fa-plus'},
    {status: 'changed', label: 'Modified', icon: 'fa-pen'},
    {status: 'removed', label: 'Removed', icon: 'fa-minus'},
] as const;

interface Layout {
    pageOverflow: number;
    stacked: boolean;
    cellWidths: number[];
    rowCount: number;
    tabWidth: number;
}

async function measure(page: Page): Promise<Layout> {
    return page.evaluate(() => {
        const doc = document.documentElement;
        const rows = document.querySelectorAll<HTMLElement>('[data-testid^="agent-card-row-"]');
        const cells = Array.from(rows).flatMap(row => Array.from(row.querySelectorAll<HTMLElement>('td')));
        const first = cells[0];
        return {
            pageOverflow: doc.scrollWidth - doc.clientWidth,
            stacked: first ? getComputedStyle(first).display === 'block' : false,
            cellWidths: cells.map(cell => cell.getBoundingClientRect().width),
            rowCount: rows.length,
            tabWidth: document.querySelector('[data-testid="agent-card-tab"]')?.getBoundingClientRect().width ?? 0,
        };
    });
}

test.describe('Agent Cards tab', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    let surfaceId: string;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        const created = await api.post<{surface_id: string}>('/api/v1/surfaces', {
            name: `e2e-card-layout-${RUN_ID}`,
            status: 'active',
            access_point: {listen_address: LISTEN_ADDRESS, route: ROUTE, protocol: 'a2a'},
            target: {endpoint: 'https://agent.example.org/a2a'},
        });
        expect(created.status).toBe(201);
        surfaceId = created.body.surface_id;
    });

    test.afterAll(async () => {
        await api.delete(`/api/v1/surfaces/${surfaceId}`);
        await api.dispose();
    });

    test.beforeEach(() => feature(FEATURE));

    async function stubPreview(page: Page, preview: object = PREVIEW): Promise<void> {
        await page.route(`**/api/v1/surfaces/${surfaceId}/agent-card`, route =>
            route.fulfill({json: {...preview, surface_id: surfaceId}})
        );
    }

    async function openTab(page: Page, phone = false): Promise<void> {
        await stubPreview(page);
        await page.goto(`${BASE_URL}/surfaces/${surfaceId}`);
        if (phone) await page.locator('#sidebarToggleTop').click();
        await page.getByTestId('surface-view-agent-card').click();
        if (phone) await page.getByTitle('Collapse sidebar').click();
        await expect(page.getByTestId('agent-card-before')).toBeAttached();
        await expect(page.getByTestId('agent-card-row-signin')).toBeVisible();
    }

    test('places Agent Cards directly after Elements and before Monitoring', async ({page}) => {
        await page.setViewportSize({width: 1600, height: 900});
        await stubPreview(page);
        await page.goto(`${BASE_URL}/surfaces/${surfaceId}`);

        const view = page.getByTestId('surface-view-agent-card');
        await expect(view).toHaveText('Agent Cards');
        const order = await page
            .locator('[data-testid^="surface-view-"]')
            .evaluateAll(views => views.map(v => v.getAttribute('data-testid')));
        const index = order.indexOf('surface-view-agent-card');
        expect(index).toBeGreaterThan(0);
        expect(order[index - 1]).toBe('surface-view-elements');
        expect(order[index + 1]).toBe('surface-view-monitoring');

        await view.click();
        await expect(view).toHaveAttribute('aria-current', 'page');
        await expect(page.getByTestId('agent-card-heading')).toHaveText('Agent Cards');
        const first = await page.getByTestId('surface-view-surface').boundingBox();
        const last = await page.getByTestId('surface-view-config').boundingBox();
        if (!first || !last) throw new Error('The view list is not visible');
        const views = await page.screenshot({
            clip: {x: first.x, y: first.y, width: Math.max(first.width, last.width), height: last.y + last.height - first.y},
        });
        await attachCriterion(FEATURE, 1, 'Agent Cards tab placement', views);
    });

    test('shows both cards side by side with colour, icon and text change markers, and their raw JSON', async ({
        page,
    }) => {
        await page.setViewportSize({width: 1600, height: 1000});
        await openTab(page);

        const managed = page.getByTestId('agent-card-before');
        const served = page.getByTestId('agent-card-after');
        await expect(managed.locator('.agent-card-column-title')).toHaveText('Managed Agent Card');
        await expect(managed.locator('.agent-card-column-hint')).toHaveText("The agent's own card");
        await expect(served.locator('.agent-card-column-title')).toHaveText('Gateway-Served Agent Card');
        await expect(served.locator('.agent-card-column-hint')).toHaveText('What callers see');
        const managedBox = await managed.boundingBox();
        const servedBox = await served.boundingBox();
        if (!managedBox || !servedBox) throw new Error('The card columns are not visible');
        expect(servedBox.x).toBeGreaterThanOrEqual(managedBox.x + managedBox.width - 1);
        expect(Math.abs(managedBox.y - servedBox.y)).toBeLessThan(2);

        const rows = page.locator('[data-testid^="agent-card-row-"]');
        const colours: string[] = [];
        for (const kind of CHANGE_KINDS) {
            const legend = page.getByTestId(`agent-card-legend-${kind.status}`);
            await expect(legend).toHaveText(kind.label);
            await expect(legend.getByTestId('agent-card-status-icon')).toHaveClass(new RegExp(kind.icon));
            const marker = rows
                .locator(`[data-status="${kind.status}"]:has(> [data-testid="agent-card-status-icon"])`)
                .first();
            await expect(marker).toBeVisible();
            await expect(marker).toHaveText(kind.label);
            await expect(marker.getByTestId('agent-card-status-icon')).toHaveClass(new RegExp(kind.icon));
            colours.push(await legend.evaluate(el => getComputedStyle(el).color));
        }
        expect(new Set(colours).size).toBe(CHANGE_KINDS.length);
        await expect(page.getByTestId('agent-card-summary')).toContainText('added');
        await attachCriterion(FEATURE, 2, 'Managed and served cards side by side', page.getByTestId('agent-card-tab'));

        const toggle = page.getByTestId('agent-card-raw-toggle');
        await toggle.click();
        await expect(toggle).toHaveAttribute('aria-expanded', 'true');
        expect(JSON.parse((await page.getByTestId('agent-card-raw-before').textContent()) ?? '')).toEqual(MANAGED_CARD);
        expect(JSON.parse((await page.getByTestId('agent-card-raw-after').textContent()) ?? '')).toEqual(SERVED_CARD);
    });

    test('keeps the Entry point URL in the Surface view and copies the served card discovery URL', async ({page}) => {
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], {origin: new URL(BASE_URL).origin});
        await page.setViewportSize({width: 1600, height: 900});
        await stubPreview(page);
        await page.goto(`${BASE_URL}/surfaces/${surfaceId}`);
        const entryPoint = page.getByTestId('surface-entry-point-url');
        await expect(entryPoint).toContainText(`${LISTEN_ADDRESS}${ROUTE}`);

        await page.getByTestId('surface-view-agent-card').click();
        const tab = page.getByTestId('agent-card-tab');
        await expect(tab.getByTestId('agent-card-served-url')).toHaveText(PREVIEW.served_url);
        await expect(tab.getByTestId('surface-entry-point-url')).toHaveCount(0);
        await expect(tab).not.toContainText(`${LISTEN_ADDRESS}${ROUTE}`);
        await expect(tab.getByTestId('agent-card-surface-link')).toContainText('Entry point URL');

        const copy = tab.getByTestId('agent-card-url-copy-button');
        await copy.click();
        await expect(copy).toHaveText('Copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(PREVIEW.served_url);
        await attachCriterion(FEATURE, 3, 'Served card URL and link to the Surface', tab);

        await tab.getByTestId('agent-card-open-surface-button').click();
        const surfaceView = page.getByTestId('surface-view-surface');
        await expect(surfaceView).toHaveAttribute('aria-current', 'page');
        await expect(surfaceView).toBeFocused();
        await expect(entryPoint).toContainText(`${LISTEN_ADDRESS}${ROUTE}`);
    });

    test('keeps the served card readable while the first fetch fails, then recovers on Refresh', async ({page}) => {
        let current: object = FAILING_PREVIEW;
        await page.route(`**/api/v1/surfaces/${surfaceId}/agent-card`, route =>
            route.fulfill({json: {...current, surface_id: surfaceId}})
        );
        await page.route(`**/api/v1/surfaces/${surfaceId}/agent-card/refresh`, route => {
            current = PREVIEW;
            return route.fulfill({json: {...PREVIEW, surface_id: surfaceId}});
        });
        await page.setViewportSize({width: 1600, height: 1000});
        await page.goto(`${BASE_URL}/surfaces/${surfaceId}`);
        await page.getByTestId('surface-view-agent-card').click();

        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('Failing');
        await expect(page.getByTestId('agent-card-fetch-cause')).toHaveText('Needs a token — HTTP 401');
        await expect(page.getByTestId('agent-card-failed')).toHaveAttribute('role', 'alert');
        await expect(page.getByTestId('agent-card-failed-cause')).toContainText(
            'Set Target Authentication on the Managed Agent'
        );
        await expect(page.getByTestId('agent-card-raw-before-missing')).toContainText('Needs a token — HTTP 401');
        expect(JSON.parse((await page.getByTestId('agent-card-raw-after').textContent()) ?? '')).toEqual(SERVED_CARD);

        await page.getByTestId('agent-card-refresh-button').click();
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
        await expect(page.getByTestId('agent-card-refresh-status')).toHaveText('Card refreshed. The card fetch is OK.');
        await expect(page.getByTestId('agent-card-failed')).toHaveCount(0);
        await expect(page.getByTestId('agent-card-row-signin')).toBeVisible();
    });

    test('the tab scrolls with the mouse wheel when the card is taller than the panel', async ({page}) => {
        await page.setViewportSize({width: 1280, height: 600});
        await openTab(page);
        const tab = page.getByTestId('agent-card-tab');
        const before = await tab.evaluate(el => ({
            overflowY: getComputedStyle(el).overflowY,
            scrollHeight: el.scrollHeight,
            clientHeight: el.clientHeight,
        }));
        expect(before.scrollHeight).toBeGreaterThan(before.clientHeight);
        expect(['auto', 'scroll']).toContain(before.overflowY);
        await tab.hover();
        await page.mouse.wheel(0, 400);
        await expect.poll(() => tab.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
    });

    for (const width of [1600, 1280]) {
        test(`at ${width}px the rows sit side by side with readable cells`, async ({page}) => {
            await page.setViewportSize({width, height: 900});
            await openTab(page);
            const layout = await measure(page);
            expect(layout.pageOverflow).toBeLessThanOrEqual(0);
            expect(layout.stacked).toBe(false);
            expect(layout.rowCount).toBeGreaterThan(0);
            expect(Math.min(...layout.cellWidths)).toBeGreaterThanOrEqual(MIN_CELL_WIDTH);
        });
    }

    for (const width of [1024, 900, 768, 390, 320]) {
        test(`at ${width}px each row stacks, nothing scrolls sideways and cells use the full column`, async ({page}) => {
            await page.setViewportSize({width, height: 900});
            await openTab(page, width < 600);
            const layout = await measure(page);
            expect(layout.pageOverflow).toBeLessThanOrEqual(0);
            expect(layout.stacked).toBe(true);
            expect(layout.rowCount).toBeGreaterThan(0);
            expect(Math.min(...layout.cellWidths)).toBeGreaterThanOrEqual(layout.tabWidth - TAB_PADDING);
            await expect(page.getByTestId('agent-card-row-signin').locator('td').first()).toBeVisible();
        });
    }
});
