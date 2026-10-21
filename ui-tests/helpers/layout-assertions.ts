/**
 * Layout checks for the laptop layout spec: no sideways page scroll, no list
 * table that scrolls sideways inside its box, and a primary action a user can see and click without the page cutting it off.
 */

import {expect, Locator, Page} from '@playwright/test';

/** Sub-pixel rounding allowance when comparing element and viewport edges. */
const EDGE_TOLERANCE_PX = 1;

/**
 * Locate a test id. An id ending in `*` matches the first element whose
 * test id starts with the part before it, for rows keyed by a server id.
 */
export function byTestId(page: Page, testId: string): Locator {
    if (testId.endsWith('*')) {
        return page.locator(`[data-testid^="${testId.slice(0, -1)}"]`).first();
    }
    return page.getByTestId(testId);
}

/** The document never scrolls sideways. */
export async function expectNoSidewaysScroll(page: Page): Promise<void> {
    const {scrollWidth, clientWidth} = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth,
    }));
    expect(scrollWidth, `page scrolls sideways: scrollWidth ${scrollWidth} > clientWidth ${clientWidth}`).toBeLessThanOrEqual(
        clientWidth,
    );
}

/**
 * No list table scrolls sideways: every `.table-responsive` on the page is at
 * most as wide as its box, give or take a pixel of rounding.
 */
export async function expectNoTableSidewaysScroll(page: Page): Promise<void> {
    const wide = await page.evaluate(tolerance => {
        // List tables carry no test id of their own, so name the nearest ancestor that has one,
        // the table's position among that ancestor's tables and its column headers.
        const describe = (node: Element) => {
            const owner = node.closest('[data-testid]');
            const scope = owner ? `[data-testid="${owner.getAttribute('data-testid')}"]` : 'a .table-responsive without a test id';
            const siblings = owner === node ? [node] : Array.from((owner ?? document).querySelectorAll('.table-responsive'));
            const columns = Array.from(node.querySelectorAll('thead th'))
                .map(th => th.textContent?.trim())
                .filter(Boolean)
                .slice(0, 4)
                .join(', ');
            return `table ${siblings.indexOf(node) + 1} of ${siblings.length} in ${scope} (columns: ${columns || 'none'})`;
        };
        return Array.from(document.querySelectorAll('.table-responsive'))
            .filter(box => box.scrollWidth > box.clientWidth + tolerance)
            .map(box => `${describe(box)} scrolls sideways: scrollWidth ${box.scrollWidth} > clientWidth ${box.clientWidth}`);
    }, EDGE_TOLERANCE_PX);
    expect(wide, 'no list table scrolls sideways').toEqual([]);
}

interface ReachabilityReport {
    rect: {left: number; top: number; right: number; bottom: number};
    viewport: {width: number; height: number};
    clippedBy: string | null;
    topmost: string | null;
}

/**
 * A primary action is visible, sits fully inside the viewport once scrolled
 * into view, is not cut by an ancestor that clips its overflow, and is the
 * element a click at its centre would hit.
 */
export async function expectActionReachable(page: Page, testId: string): Promise<void> {
    const action = byTestId(page, testId);
    await expect(action, `${testId} is visible`).toBeVisible();
    await action.evaluate((el: Element) => el.scrollIntoView({block: 'center', inline: 'center', behavior: 'instant'}));

    const report: ReachabilityReport = await action.evaluate((el: Element) => {
        const describe = (node: Element) => {
            const id = node.getAttribute('data-testid');
            const cls = typeof node.className === 'string' && node.className ? `.${node.className.trim().split(/\s+/).join('.')}` : '';
            return id ? `[data-testid="${id}"]` : `${node.tagName.toLowerCase()}${cls}`;
        };
        const r = el.getBoundingClientRect();
        let clippedBy: string | null = null;
        for (let node = el.parentElement; node && node !== document.body && node !== document.documentElement; node = node.parentElement) {
            const style = getComputedStyle(node);
            const clipsX = style.overflowX !== 'visible';
            const clipsY = style.overflowY !== 'visible';
            if (!clipsX && !clipsY) continue;
            const box = node.getBoundingClientRect();
            const left = box.left + node.clientLeft;
            const top = box.top + node.clientTop;
            const right = left + node.clientWidth;
            const bottom = top + node.clientHeight;
            const cutX = clipsX && (r.left < left - 1 || r.right > right + 1);
            const cutY = clipsY && (r.top < top - 1 || r.bottom > bottom + 1);
            if (cutX || cutY) {
                clippedBy = describe(node);
                break;
            }
        }
        // Hit-test the first line box, so a link that wraps is probed on its text. A disabled
        // control has `pointer-events: none` from Bootstrap; lift that so the probe still
        // finds it when nothing covers it.
        const probe = el.getClientRects()[0] ?? r;
        const target = el as HTMLElement;
        const previous = target.style.getPropertyValue('pointer-events');
        const previousPriority = target.style.getPropertyPriority('pointer-events');
        target.style.setProperty('pointer-events', 'auto', 'important');
        const hit = document.elementFromPoint(probe.left + probe.width / 2, probe.top + probe.height / 2);
        target.style.setProperty('pointer-events', previous, previousPriority);
        const labels = el instanceof HTMLInputElement && el.labels ? Array.from(el.labels) : [];
        const reached = !!hit && (hit === el || el.contains(hit) || labels.some(label => label === hit || label.contains(hit)));
        const topmost = reached ? null : hit ? describe(hit) : 'nothing';
        return {
            rect: {left: r.left, top: r.top, right: r.right, bottom: r.bottom},
            viewport: {width: window.innerWidth, height: window.innerHeight},
            clippedBy,
            topmost,
        };
    });

    const {rect, viewport} = report;
    const inViewport =
        rect.left >= -EDGE_TOLERANCE_PX &&
        rect.top >= -EDGE_TOLERANCE_PX &&
        rect.right <= viewport.width + EDGE_TOLERANCE_PX &&
        rect.bottom <= viewport.height + EDGE_TOLERANCE_PX;
    expect(
        inViewport,
        `${testId} lies outside the ${viewport.width}x${viewport.height} viewport: ` +
            `left ${rect.left}, top ${rect.top}, right ${rect.right}, bottom ${rect.bottom}`,
    ).toBe(true);
    expect(report.clippedBy, `${testId} is cut by its ancestor ${report.clippedBy}`).toBeNull();
    expect(report.topmost, `${testId} is covered at its centre by ${report.topmost}`).toBeNull();
}
