/**
 * Surface Builder template protocol tests
 *
 * Asserts applying a partial template places a Transit Point that matches the
 * surface protocol, and skips one of the other protocol, leaving it off the
 * canvas and telling the operator why.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

const partial = (id: string, kind: string) => ({
    id,
    name: `Fixture ${kind}`,
    kind: 'partial',
    description: 'Playwright fixture',
    items: [{scope: 'transit_point', kind, config: {}}],
});

const A2A_TEMPLATE = partial('ui-test-tpl-transit-a2a', 'transit-point-a2a');
const MCP_TEMPLATE = partial('ui-test-tpl-transit-mcp', 'transit-point-mcp');

async function openTemplates(page: Page, protocol: 'a2a' | 'mcp') {
    await page.route(/\/api\/v1\/surface-templates(\?.*)?$/, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: [A2A_TEMPLATE, MCP_TEMPLATE]});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/new?protocol=${protocol}`);
    await expect(page.getByTestId('page-add-surface')).toBeVisible();
    await page.getByTestId('surface-view-templates').click();
}

async function applyTemplate(page: Page, id: string) {
    await page.getByTestId(`surface-template-apply-${id}`).click();
    await page.getByTestId('surface-view-surface').click();
}

test.describe('Surface Builder template protocol', () => {
    test('skips an A2A Transit Point template on an MCP surface and says why', async ({page}) => {
        await openTemplates(page, 'mcp');
        await page.getByTestId(`surface-template-apply-${A2A_TEMPLATE.id}`).click();

        await expect(page.getByTestId('app-toast')).toContainText(
            "No items from \"Fixture transit-point-a2a\" could be placed: 'transit-point-a2a' is not available on mcp surfaces",
        );
        await page.getByTestId('surface-view-surface').click();
        await expect(page.getByTestId('surface-node-transit-point-a2a')).toHaveCount(0);
    });

    test('places an MCP Transit Point template on an MCP surface', async ({page}) => {
        await openTemplates(page, 'mcp');
        await applyTemplate(page, MCP_TEMPLATE.id);

        await expect(page.getByTestId('surface-node-transit-point-mcp')).toBeVisible();
    });

    test('skips an MCP Transit Point template on an A2A surface and says why', async ({page}) => {
        await openTemplates(page, 'a2a');
        await page.getByTestId(`surface-template-apply-${MCP_TEMPLATE.id}`).click();

        await expect(page.getByTestId('app-toast')).toContainText(
            "'transit-point-mcp' is not available on a2a surfaces",
        );
        await page.getByTestId('surface-view-surface').click();
        await expect(page.getByTestId('surface-node-transit-point-mcp')).toHaveCount(0);
    });

    test('places an A2A Transit Point template on an A2A surface', async ({page}) => {
        await openTemplates(page, 'a2a');
        await applyTemplate(page, A2A_TEMPLATE.id);

        await expect(page.getByTestId('surface-node-transit-point-a2a')).toBeVisible();
    });
});
