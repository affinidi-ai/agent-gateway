/**
 * Test Authentication Helper
 *
 * Provides utilities for authenticating during UI tests using the
 * internal test-support auth endpoint. This bypasses passkey authentication for
 * automated testing.
 *
 * IMPORTANT: This only works when the gateway is running with
 * AG_TEST_MODE=true environment variable set.
 */

import {APIRequestContext, BrowserContext, Page} from '@playwright/test';

const TEST_TOKEN = process.env.AG_TEST_TOKEN || 'ui-test-token-32-plus-characters';
const TEST_AUTH_PATH = '/api/internal/test-support/auth/login';

export interface TestAuthResult {
    success: boolean;
    sessionToken?: string;
    username?: string;
    error?: string;
}

/**
 * Authenticate using the internal test-support auth endpoint.
 *
 * @param request - Playwright API request context
 * @param baseUrl - Base URL of the gateway
 * @param username - Optional custom username for the test session
 * @returns Authentication result with session token
 */
export async function authenticateTestUser(
    request: APIRequestContext,
    baseUrl: string,
    username?: string
): Promise<TestAuthResult> {
    try {
        const response = await request.post(`${baseUrl}${TEST_AUTH_PATH}`, {
            headers: {
                'Content-Type': 'application/json',
                'X-Test-Token': TEST_TOKEN,
            },
            data: JSON.stringify({
                username: username,
                role: 'administrator',
            }),
        });

        if (response.status() === 404) {
            return {
                success: false,
                error: 'Test mode is not enabled. Set AG_TEST_MODE=true on the gateway.',
            };
        }

        if (response.status() === 401) {
            return {
                success: false,
                error: 'Invalid test token. Check AG_TEST_TOKEN environment variable.',
            };
        }

        if (!response.ok()) {
            const body = await response.text();
            return {
                success: false,
                error: `Authentication failed: ${response.status()} - ${body}`,
            };
        }

        const data = await response.json();
        return {
            success: true,
            sessionToken: data.session_token,
            username: data.username,
        };
    } catch (error) {
        return {
            success: false,
            error: `Authentication request failed: ${error}`,
        };
    }
}

/**
 * Apply authentication to a browser context.
 *
 * Persists the session token in `localStorage` and registers an init script
 * that mirrors it into `sessionStorage` on every page load.
 *
 * Why not just write to `sessionStorage`?
 *   - Playwright's `storageState` only serializes cookies and `localStorage`.
 *     `sessionStorage` is per-tab and is dropped between contexts, so it
 *     cannot be used to carry auth across the worker pool.
 *   - The React dashboard reads `session_token` from `sessionStorage`, so we
 *     install an init script (which runs before the app boots) to bridge the
 *     value from `localStorage` into `sessionStorage` on every fresh page.
 *
 * The same bridge is registered in `helpers/fixtures.ts` for spec-level
 * tests; doing it here as well ensures `auth.setup.ts` (which uses the base
 * Playwright `test`, not our fixture) also benefits during its own
 * verification navigation.
 *
 * @param context - Playwright browser context
 * @param page - Playwright page used to seed `localStorage`
 * @param baseUrl - Base URL of the gateway
 * @param sessionToken - Session token from test-login
 */
export async function applyAuthToContext(
    context: BrowserContext,
    page: Page,
    baseUrl: string,
    sessionToken: string
): Promise<void> {
    await context.addInitScript((token) => {
        try {
            window.localStorage.setItem('session_token', token);
            if (!window.sessionStorage.getItem('session_token')) {
                window.sessionStorage.setItem('session_token', token);
            }
        } catch {
            // about:blank and similar disallow storage access — ignore.
        }
    }, sessionToken);

    // Navigate to the app so the init script runs and `localStorage` is
    // populated against the real origin (so `storageState` can serialize it).
    await page.goto(baseUrl, {waitUntil: 'domcontentloaded'});
}

/**
 * Authenticate and apply to page in one step.
 * Convenience function that combines authentication and context setup.
 *
 * @param page - Playwright page
 * @param baseUrl - Base URL of the gateway
 * @param username - Optional custom username
 * @returns True if authentication succeeded
 */
export async function loginAsTestUser(
    page: Page,
    baseUrl: string,
    username?: string
): Promise<boolean> {
    const result = await authenticateTestUser(page.request, baseUrl, username);

    if (!result.success || !result.sessionToken) {
        console.error('Test authentication failed:', result.error);
        return false;
    }

    await applyAuthToContext(page.context(), page, baseUrl, result.sessionToken);
    return true;
}

/**
 * Check if the current page is authenticated.
 *
 * @param page - Playwright page
 * @returns True if session token exists in sessionStorage
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
    try {
        const token = await page.evaluate(() => {
            return sessionStorage.getItem('session_token');
        });
        return !!token;
    } catch {
        return false;
    }
}

/**
 * Clear authentication from the page.
 *
 * @param page - Playwright page
 */
export async function clearAuth(page: Page): Promise<void> {
    await page.evaluate(() => {
        sessionStorage.removeItem('session_token');
    });
}
