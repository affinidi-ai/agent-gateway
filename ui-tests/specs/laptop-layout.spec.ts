/**
 * Laptop layout
 *
 * Runs every dashboard page of the inventory (`helpers/layout-pages.ts`) at
 * every common laptop viewport, with the sidebar expanded, and fails when the
 * page or a list table scrolls sideways or a primary action is out of reach:
 * not visible, outside the viewport once scrolled into view, cut by a
 * clipping ancestor, or covered by another element.
 *
 * Set `AG_LAYOUT_SCREENSHOT_DIR` to also save `<page>__<w>x<h>.png` (and a
 * `__full.png` full-page shot for the Audit Log) before any assertion.
 */

import fs from 'fs';
import path from 'path';
import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {byTestId, expectActionReachable, expectNoSidewaysScroll, expectNoTableSidewaysScroll} from '../helpers/layout-assertions';
import {measureAuditLayout, measureBelowTopbar} from '../helpers/layout-audit';
import {installLayoutFixtures} from '../helpers/layout-fixtures';
import {measureFlowLabels, measureTasksHeader} from '../helpers/layout-page-checks';
import {LAYOUT_PAGES, LayoutPage} from '../helpers/layout-pages';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SCREENSHOT_DIR = process.env.AG_LAYOUT_SCREENSHOT_DIR;

export const LAPTOP_VIEWPORTS = [
    {width: 1280, height: 720},
    {width: 1366, height: 768},
    {width: 1536, height: 864},
    {width: 1440, height: 900},
    {width: 1920, height: 1080},
] as const;

type ViewportName = `${number}x${number}`;

/**
 * Page and viewport pairs that fail on the current layout. A listed pair is
 * expected to fail its layout assertions; it must still render every listed
 * test id, and it fails the run if it starts passing.
 */
export const EXPECTED_FAILURES: ReadonlyArray<{page: string; viewport: ViewportName}> = [];

const isExpectedFailure = (pageId: string, viewport: ViewportName) =>
    EXPECTED_FAILURES.some(pair => pair.page === pageId && pair.viewport === viewport);

/** Wait for web fonts and for any smooth scroll the page started to come to rest. */
async function settle(page: Page): Promise<void> {
    await page.evaluate(async () => {
        await document.fonts.ready;
        const frame = () => new Promise<number>(resolve => requestAnimationFrame(() => resolve(window.scrollY)));
        let last = await frame();
        for (let still = 0, frames = 0; still < 3 && frames < 120; frames++) {
            const current = await frame();
            still = current === last ? still + 1 : 0;
            last = current;
        }
    });
}

/** Expand the sidebar and answer the list requests with the layout fixtures. */
async function prepareLaptopPage(page: Page): Promise<void> {
    await page.addInitScript(() => {
        try {
            window.localStorage.removeItem('dashboard-sidebar-collapsed');
        } catch {
            // Storage is unavailable on about:blank.
        }
    });
    await installLayoutFixtures(page);
}

async function openPage(page: Page, entry: LayoutPage): Promise<void> {
    await page.goto(`${BASE_URL}${entry.route}`);
    const [root, ...data] = entry.testIds;
    await page.getByTestId(root).waitFor({state: 'visible'});
    if (entry.setup) {
        await entry.setup(page);
    }
    for (const testId of data) {
        await byTestId(page, testId)
            .waitFor({state: 'attached'})
            .catch(() => undefined);
    }
    await settle(page);
}

async function saveScreenshots(page: Page, entry: LayoutPage, viewport: ViewportName) {
    if (!SCREENSHOT_DIR) return;
    fs.mkdirSync(SCREENSHOT_DIR, {recursive: true});
    await page.screenshot({path: path.join(SCREENSHOT_DIR, `${entry.id}__${viewport}.png`)});
    if (entry.fullPageScreenshot) {
        await page.screenshot({path: path.join(SCREENSHOT_DIR, `${entry.id}__${viewport}__full.png`), fullPage: true});
    }
}

// A layout check is deterministic, so a retry only absorbs a stalled browser
// on a busy machine; a pair that keeps failing still fails the run.
test.describe.configure({retries: 1});

for (const size of LAPTOP_VIEWPORTS) {
    const viewport: ViewportName = `${size.width}x${size.height}`;

    test.describe(`Laptop layout at ${viewport}`, () => {
        test.use({viewport: {width: size.width, height: size.height}});

        test.beforeEach(async ({page}) => {
            await prepareLaptopPage(page);
        });

        for (const entry of LAYOUT_PAGES) {
            test(`${entry.id} at ${viewport}`, async ({page}) => {
                await openPage(page, entry);
                await saveScreenshots(page, entry, viewport);

                for (const testId of [...entry.testIds, ...entry.actions]) {
                    await expect(byTestId(page, testId), `${testId} is attached`).toBeAttached();
                }

                if (isExpectedFailure(entry.id, viewport)) {
                    test.fail();
                }

                await expectNoSidewaysScroll(page);
                await expectNoTableSidewaysScroll(page);
                for (const testId of entry.actions) {
                    await expectActionReachable(page, testId);
                }
            });
        }
    });
}

/**
 * The Audit Log stacks the list above the detail, and the page scrolls as
 * one, where two panels side by side would be too narrow to read;
 * elsewhere the panels sit side by side and fill the page height.
 */
const AUDIT_STACKED: ReadonlySet<ViewportName> = new Set<ViewportName>(['1280x720', '1366x768']);

/** Height a side-by-side panel needs to show its content readably. */
const MIN_PANEL_HEIGHT_PX = 300;

/** Sub-pixel rounding allowance for scroll and edge comparisons. */
const TOLERANCE_PX = 1;

const AUDIT_PAGE = LAYOUT_PAGES.find(entry => entry.id === 'audit');

for (const size of LAPTOP_VIEWPORTS) {
    const viewport: ViewportName = `${size.width}x${size.height}`;
    const stacked = AUDIT_STACKED.has(viewport);

    test.describe(`Audit Log layout at ${viewport}`, () => {
        test.use({viewport: {width: size.width, height: size.height}});

        test.beforeEach(async ({page}) => {
            await prepareLaptopPage(page);
            if (!AUDIT_PAGE) throw new Error('the page inventory has no audit entry');
            await openPage(page, AUDIT_PAGE);
        });

        if (stacked) {
            test(`audit stacks the list above the detail at ${viewport}`, async ({page}) => {
                const layout = await measureAuditLayout(page);
                expect(layout.shellDirection, '.audit-shell is a column').toBe('column');
                expect(layout.list.bottom, 'the list ends above the detail panel').toBeLessThanOrEqual(layout.detail.top + TOLERANCE_PX);
                expect(layout.selfScrollers, 'no element of the page scrolls by itself').toEqual([]);
                expect(layout.scrollY, 'the page opens at the top').toBe(0);

                await page.getByTestId('audit-item-3').click();
                await settle(page);
                const detail = await measureBelowTopbar(page, 'audit-detail-panel');
                expect(detail.box.top, 'the detail panel starts below the topbar').toBeGreaterThanOrEqual(detail.topbarBottom - TOLERANCE_PX);
                expect(detail.box.top, 'the detail panel starts in the top half of the viewport').toBeLessThanOrEqual(detail.viewportHeight / 2);

                await page.getByTestId('audit-detail-title').click();
                await settle(page);
                const item = await measureBelowTopbar(page, 'audit-item-3');
                expect(item.box.top, 'the selected entry starts below the topbar').toBeGreaterThanOrEqual(item.topbarBottom - TOLERANCE_PX);
                expect(item.box.bottom, 'the selected entry ends inside the viewport').toBeLessThanOrEqual(item.viewportHeight + TOLERANCE_PX);
            });
        } else {
            test(`audit keeps the list and detail side by side at ${viewport}`, async ({page}) => {
                const layout = await measureAuditLayout(page);
                expect(layout.shellDirection, '.audit-shell is a row').toBe('row');
                expect(
                    layout.documentScrollHeight,
                    `the page scrolls: scrollHeight ${layout.documentScrollHeight} > clientHeight ${layout.documentClientHeight}`,
                ).toBeLessThanOrEqual(layout.documentClientHeight);
                expect(layout.list.height, 'the list region is tall enough to read').toBeGreaterThanOrEqual(MIN_PANEL_HEIGHT_PX);
                expect(layout.drawerBody.height, 'the evidence body is tall enough to read').toBeGreaterThanOrEqual(MIN_PANEL_HEIGHT_PX);

                const before = layout.scrollY;
                await page.getByTestId('audit-item-3').click();
                await settle(page);
                const after = await measureAuditLayout(page);
                expect(after.scrollY, 'selecting an entry does not scroll the page').toBe(before);
            });
        }
    });
}

/** The flow chart cuts a long label to this many characters, ending in "...". */
const MAX_FLOW_LABEL_CHARS = 25;

/** The Refresh button sits at the right end of the Tasks header, inside its padding. */
const REFRESH_RIGHT_MARGIN_PX = 32;

const TASKS_PAGE = LAYOUT_PAGES.find(entry => entry.id === 'tasks');
const METRICS_PAGE = LAYOUT_PAGES.find(entry => entry.id === 'metrics');

for (const size of LAPTOP_VIEWPORTS) {
    const viewport: ViewportName = `${size.width}x${size.height}`;

    test.describe(`Page layout at ${viewport}`, () => {
        test.use({viewport: {width: size.width, height: size.height}});

        test.beforeEach(async ({page}) => {
            await prepareLaptopPage(page);
        });

        test(`tasks puts the tag filter under the title and Refresh at the right end at ${viewport}`, async ({page}) => {
            if (!TASKS_PAGE) throw new Error('the page inventory has no tasks entry');
            await openPage(page, TASKS_PAGE);
            await page.locator('[data-testid^="tasks-tag-filter-"]').first().waitFor({state: 'visible'});
            await settle(page);
            const header = await measureTasksHeader(page);
            expect(header.filterRowTop, 'the tag filter row starts below the title row').toBeGreaterThanOrEqual(
                header.titleRowBottom - TOLERANCE_PX,
            );
            expect(
                header.headerRight - header.refreshRight,
                'the Refresh button ends at the right end of the header',
            ).toBeLessThanOrEqual(REFRESH_RIGHT_MARGIN_PX);
        });

        test(`metrics keeps every flow chart label short and inside the chart at ${viewport}`, async ({page}) => {
            if (!METRICS_PAGE) throw new Error('the page inventory has no metrics entry');
            await openPage(page, METRICS_PAGE);
            await page.locator('text.node-label').first().waitFor({state: 'attached'});
            await settle(page);
            const chart = await measureFlowLabels(page);
            expect(chart.labels.length, 'the flow chart draws node labels').toBeGreaterThan(0);
            const long = chart.labels.filter(label => label.text.length > MAX_FLOW_LABEL_CHARS).map(label => label.text);
            expect(long, `labels over ${MAX_FLOW_LABEL_CHARS} characters`).toEqual([]);
            const outside = chart.labels
                .filter(label => label.left < chart.chartLeft - TOLERANCE_PX || label.right > chart.chartRight + TOLERANCE_PX)
                .map(label => label.text);
            expect(outside, 'labels outside the chart').toEqual([]);
        });
    });
}
