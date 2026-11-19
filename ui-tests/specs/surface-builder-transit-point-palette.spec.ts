/**
 * Surface Builder Transit Point palette tests
 *
 * Asserts the palette offers the A2A Transit Point only on an A2A surface and
 * the MCP Transit Point only on an MCP surface, and never the hidden AP2 one.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

async function openPalette(page: Page, protocol: 'a2a' | 'mcp') {
    await page.goto(`${BASE_URL}/surfaces/new?protocol=${protocol}`);
    await page.getByPlaceholder('Filter elements…').fill('Transit Point');
}

test.describe('Surface Builder Transit Point palette', () => {
    test('offers only the A2A Transit Point on an A2A surface', async ({page}) => {
        await openPalette(page, 'a2a');

        await expect(page.getByTestId('palette-item-transit-point-a2a')).toBeVisible();
        await expect(page.getByTestId('palette-item-transit-point-mcp')).toHaveCount(0);
        await expect(page.getByTestId('palette-item-transit-point-ap2')).toHaveCount(0);
    });

    test('offers only the MCP Transit Point on an MCP surface', async ({page}) => {
        await openPalette(page, 'mcp');

        await expect(page.getByTestId('palette-item-transit-point-mcp')).toBeVisible();
        await expect(page.getByTestId('palette-item-transit-point-a2a')).toHaveCount(0);
        await expect(page.getByTestId('palette-item-transit-point-ap2')).toHaveCount(0);
    });
});
