/**
 * Laptop layout
 *
 * Runs every dashboard page of the inventory (`helpers/layout-pages.ts`) at
 * every common laptop viewport, with the sidebar expanded, and fails when the
 * page scrolls sideways or a primary action is out of reach: not visible,
 * outside the viewport once scrolled into view, cut by a clipping ancestor,
 * or covered by another element.
 *
 * Set `AG_LAYOUT_SCREENSHOT_DIR` to also save `<page>__<w>x<h>.png` (and a
 * `__full.png` full-page shot for the Audit Log) before any assertion.
 */

import fs from 'fs';
import path from 'path';
import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {byTestId, expectActionReachable, expectNoSidewaysScroll} from '../helpers/layout-assertions';
import {installLayoutFixtures} from '../helpers/layout-fixtures';
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
export const EXPECTED_FAILURES: ReadonlyArray<{page: string; viewport: ViewportName}> = [
    {page: 'surfaces', viewport: '1280x720'},
    {page: 'identities', viewport: '1280x720'},
];

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

for (const size of LAPTOP_VIEWPORTS) {
    const viewport: ViewportName = `${size.width}x${size.height}`;

    test.describe(`Laptop layout at ${viewport}`, () => {
        test.use({viewport: {width: size.width, height: size.height}});

        test.beforeEach(async ({page}) => {
            await page.addInitScript(() => {
                try {
                    window.localStorage.removeItem('dashboard-sidebar-collapsed');
                } catch {
                    // Storage is unavailable on about:blank.
                }
            });
            await installLayoutFixtures(page);
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
                for (const testId of entry.actions) {
                    await expectActionReachable(page, testId);
                }
            });
        }
    });
}
