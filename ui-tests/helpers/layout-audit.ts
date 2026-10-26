/**
 * DOM measurements for the Audit Log checks of the laptop layout spec: how
 * the list and detail panels are laid out, which elements scroll by
 * themselves, and where an element sits relative to the fixed topbar and,
 * while the page is stacked, the pinned filters and card header.
 */

import type {Page} from '@playwright/test';

export interface Box {
    top: number;
    bottom: number;
    height: number;
}

export interface AuditLayout {
    /** Computed `flex-direction` of `.audit-shell`: `column` when stacked. */
    shellDirection: string;
    list: Box;
    detail: Box;
    /** The evidence body inside the detail panel. */
    drawerBody: Box;
    scrollY: number;
    documentScrollHeight: number;
    documentClientHeight: number;
    viewportHeight: number;
    /** Bottom edge of the fixed topbar, in viewport pixels. */
    topbarBottom: number;
    /** Elements in the page that scroll vertically by themselves. */
    selfScrollers: string[];
}

/** Measure the Audit Log page as it is on screen now. */
export async function measureAuditLayout(page: Page): Promise<AuditLayout> {
    return page.evaluate(() => {
        const box = (selector: string) => {
            const el = document.querySelector(selector);
            if (!el) throw new Error(`${selector} is not on the page`);
            const r = el.getBoundingClientRect();
            return {top: r.top, bottom: r.bottom, height: r.height};
        };
        const describe = (node: Element) => {
            const id = node.getAttribute('data-testid');
            const cls = typeof node.className === 'string' && node.className ? `.${node.className.trim().split(/\s+/).join('.')}` : '';
            return id ? `[data-testid="${id}"]` : `${node.tagName.toLowerCase()}${cls}`;
        };
        const root = document.querySelector('[data-testid="page-audit"]');
        if (!root) throw new Error('page-audit is not on the page');
        const selfScrollers = [root, ...Array.from(root.querySelectorAll('*'))]
            .filter(el => {
                const overflowY = getComputedStyle(el).overflowY;
                return (overflowY === 'auto' || overflowY === 'scroll') && el.scrollHeight > el.clientHeight + 1;
            })
            .map(el => `${describe(el)} (scrollHeight ${el.scrollHeight}, clientHeight ${el.clientHeight})`);
        const shell = document.querySelector('.audit-shell');
        if (!shell) throw new Error('.audit-shell is not on the page');
        const topbar = document.querySelector('.topbar');
        return {
            shellDirection: getComputedStyle(shell).flexDirection,
            list: box('.audit-shell-list'),
            detail: box('[data-testid="audit-detail-panel"]'),
            drawerBody: box('.audit-drawer-body'),
            scrollY: window.scrollY,
            documentScrollHeight: document.documentElement.scrollHeight,
            documentClientHeight: document.documentElement.clientHeight,
            viewportHeight: window.innerHeight,
            topbarBottom: topbar ? topbar.getBoundingClientRect().bottom : 0,
            selfScrollers,
        };
    });
}

export interface BelowTopbar {
    box: Box;
    /** Bottom edge of the fixed topbar, in viewport pixels. */
    topbarBottom: number;
    /**
     * Bottom edge of everything pinned at the top of the viewport: the topbar,
     * and the Audit Log filters and card header while they are stuck there.
     */
    pinnedBottom: number;
    viewportHeight: number;
}

/** Where a test id sits in the viewport and where the pinned area at its top ends. */
export async function measureBelowTopbar(page: Page, testId: string): Promise<BelowTopbar> {
    return page.getByTestId(testId).evaluate((el: Element) => {
        const r = el.getBoundingClientRect();
        const topbar = document.querySelector('.topbar');
        const topbarBottom = topbar ? topbar.getBoundingClientRect().bottom : 0;
        // A sticky element is pinned when it sits at its `top` offset.
        const pinned = Array.from(document.querySelectorAll('.audit-filters, .audit-card-header'))
            .filter(node => {
                const style = getComputedStyle(node);
                return style.position === 'sticky' && Math.abs(node.getBoundingClientRect().top - parseFloat(style.top)) <= 1;
            })
            .map(node => node.getBoundingClientRect().bottom);
        return {
            box: {top: r.top, bottom: r.bottom, height: r.height},
            topbarBottom,
            pinnedBottom: Math.max(topbarBottom, ...pinned),
            viewportHeight: window.innerHeight,
        };
    });
}
