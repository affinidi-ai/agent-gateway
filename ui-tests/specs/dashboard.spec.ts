/**
 * Dashboard Tests
 *
 * Real assertions against stable data-testid attributes on the dashboard.
 * Selector convention: ui-tests/README.md.
 */

import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test.describe('Dashboard', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard`);
        await expect(page.getByTestId('page-dashboard')).toBeVisible();
    });

    test('renders the page root and core stat cards', async ({page}) => {
        await expect(page.getByTestId('page-dashboard')).toBeVisible();
        await expect(page.getByTestId('dashboard-stat-identities')).toBeVisible();
        await expect(page.getByTestId('dashboard-stat-channels')).toBeVisible();
        await expect(page.getByTestId('dashboard-stat-connections')).toBeVisible();

        await page.screenshot({
            path: 'test_results/latest/screenshots/dashboard-loaded.png',
            fullPage: true,
        });
    });

    test('has a non-empty document title', async ({page}) => {
        const title = await page.title();
        expect(title.trim().length).toBeGreaterThan(0);
    });

    test('loads without console errors or failed network requests', async ({page}) => {
        const consoleErrors: string[] = [];
        const failedRequests: string[] = [];

        page.on('console', (msg) => {
            if (msg.type() === 'error') {
                consoleErrors.push(msg.text());
            }
        });
        page.on('requestfailed', (request) => {
            failedRequests.push(`${request.url()} - ${request.failure()?.errorText}`);
        });

        await page.reload();
        await expect(page.getByTestId('page-dashboard')).toBeVisible();

        const criticalConsoleErrors = consoleErrors.filter(
            (e) => !e.includes('favicon') && !e.includes('manifest')
        );
        const criticalFailures = failedRequests.filter(
            (r) =>
                !r.includes('favicon') &&
                !r.includes('manifest.json') &&
                !/^https?:\/\/(?!localhost)/i.test(r)
        );

        expect(criticalConsoleErrors, criticalConsoleErrors.join('\n')).toEqual([]);
        expect(criticalFailures, criticalFailures.join('\n')).toEqual([]);
    });

    test('renders at multiple viewport sizes', async ({page}) => {
        const viewports = [
            {width: 1920, height: 1080, name: 'desktop'},
            {width: 1024, height: 768, name: 'tablet-landscape'},
            {width: 768, height: 1024, name: 'tablet-portrait'},
        ];

        for (const viewport of viewports) {
            await page.setViewportSize({width: viewport.width, height: viewport.height});
            await expect(page.getByTestId('page-dashboard')).toBeVisible();
            await page.screenshot({
                path: `test_results/latest/screenshots/dashboard-${viewport.name}.png`,
                fullPage: true,
            });
        }
    });
});
