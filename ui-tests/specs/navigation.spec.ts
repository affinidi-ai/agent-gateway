/**
 * Navigation Tests
 *
 * Asserts the sidebar exposes stable nav-* test IDs and that direct URL
 * access does not crash the SPA.
 */

import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test.describe('Sidebar navigation', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard`);
        await expect(page.getByTestId('page-dashboard')).toBeVisible();
    });

    test('exposes the dashboard nav entry', async ({page}) => {
        await expect(page.getByTestId('nav-dashboard')).toBeVisible();
    });
});

test.describe('Direct URL access', () => {
    test('dashboard root renders the page-dashboard testid', async ({page}) => {
        await page.goto(`${BASE_URL}/`);
        await expect(page.getByTestId('page-dashboard')).toBeVisible();
    });

    test('unknown route does not crash the SPA', async ({page}) => {
        await page.goto(`${BASE_URL}/this-route-does-not-exist-12345`);
        // The SPA shell must still render. We don't assert any specific testid
        // because behavior here (404 page vs. redirect) is product-defined.
        await expect(page.locator('body')).toBeVisible();
        const html = await page.content();
        expect(html.toLowerCase()).not.toContain('cannot get');
    });
});
