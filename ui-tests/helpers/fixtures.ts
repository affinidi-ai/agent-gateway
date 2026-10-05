/**
 * Shared Playwright fixtures.
 *
 * Re-exports `test` and `expect` with a customised `context` fixture that
 * bridges authentication into `sessionStorage` before each page loads.
 *
 * Why this exists:
 *   - `auth.setup.ts` calls `/api/auth/test-login` and saves the resulting
 *     `session_token` into both `sessionStorage` and `localStorage`.
 *   - Playwright's `storageState` only serializes cookies and `localStorage`
 *     (`sessionStorage` is per-tab and is dropped between contexts), so
 *     subsequent test workers reload the token from `localStorage`.
 *   - The React dashboard (`www/default/src/api.ts`) reads `session_token`
 *     from `sessionStorage`, so we hydrate it via an init script that runs
 *     before the app boots on every page.
 *
 * All specs should `import {expect, test} from '../helpers/fixtures'` instead
 * of importing from '@playwright/test' directly.
 */

import {test as base, expect} from '@playwright/test';

export const test = base.extend({
    context: async ({context}, use) => {
        await context.addInitScript(() => {
            try {
                const token = window.localStorage.getItem('session_token');
                if (token && !window.sessionStorage.getItem('session_token')) {
                    window.sessionStorage.setItem('session_token', token);
                }
            } catch {
                // Some about:blank pages disallow storage access — ignore.
            }
        });
        await use(context);
    },
});

export {expect};
