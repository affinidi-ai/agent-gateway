/**
 * DOM measurements for the page checks of the laptop layout spec: the Tasks
 * header (title row, tag filter row, Refresh) and the labels of the Metrics
 * request flow chart.
 */

import type {Page} from '@playwright/test';

export interface TasksHeaderLayout {
    /** Bottom edge of the title row (title, scope note and Refresh). */
    titleRowBottom: number;
    /** Top edge of the tag filter row. */
    filterRowTop: number;
    /** Right edge of the card header. */
    headerRight: number;
    /** Right edge of the Refresh button. */
    refreshRight: number;
}

/** Measure the Tasks card header as it is on screen now. */
export async function measureTasksHeader(page: Page): Promise<TasksHeaderLayout> {
    return page.getByTestId('tasks-refresh-button').evaluate((refresh: Element) => {
        const header = refresh.closest('.card-header');
        const tag = document.querySelector('[data-testid^="tasks-tag-filter-"]');
        if (!header || !header.firstElementChild) throw new Error('the Tasks page has no card header');
        if (!tag || !tag.parentElement) throw new Error('the Tasks page has no tag filter');
        return {
            titleRowBottom: header.firstElementChild.getBoundingClientRect().bottom,
            filterRowTop: tag.parentElement.getBoundingClientRect().top,
            headerRight: header.getBoundingClientRect().right,
            refreshRight: refresh.getBoundingClientRect().right,
        };
    });
}

export interface FlowLabel {
    text: string;
    left: number;
    right: number;
    top: number;
    bottom: number;
}

export interface FlowLabels {
    /** Left and right edge of the chart's `svg`. */
    chartLeft: number;
    chartRight: number;
    labels: FlowLabel[];
}

/** Measure every node label of the Metrics request flow chart. */
export async function measureFlowLabels(page: Page): Promise<FlowLabels> {
    return page.locator('text.node-label').first().evaluate((first: Element) => {
        const svg = (first as SVGGraphicsElement).ownerSVGElement;
        if (!svg) throw new Error('a node label is not inside an svg');
        const chart = svg.getBoundingClientRect();
        const labels = Array.from(svg.querySelectorAll('text.node-label')).map(label => {
            const r = label.getBoundingClientRect();
            return {text: label.textContent ?? '', left: r.left, right: r.right, top: r.top, bottom: r.bottom};
        });
        return {chartLeft: chart.left, chartRight: chart.right, labels};
    });
}
